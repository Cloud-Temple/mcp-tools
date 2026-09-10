# -*- coding: utf-8 -*-
"""Cycle de vie campagne/mandat, persistant et contrôlé par tenant."""

from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
from typing import Optional

from .config import CybersecSettings
from .identity import AuthorizationError, is_admin, may_access_tenant, require_admin
from .models import ValidationError, build_campaign_manifest, iso_now, parse_utc, require_identifier
from .storage import CybersecRepository, ObjectAlreadyExists


class CampaignService:
    def __init__(self, repository: CybersecRepository, settings: CybersecSettings):
        self.repository = repository
        self.settings = settings

    @staticmethod
    def _actor(token_info: dict) -> str:
        return str(token_info.get("client_name", "unknown"))[:128]

    def _tenant_for_lookup(self, token_info: dict, admin_tenant_id: Optional[str]) -> str:
        if is_admin(token_info):
            if not admin_tenant_id:
                raise ValidationError("tenant_id est requis pour cette opération administrateur.")
            return require_identifier(admin_tenant_id, "tenant_id")
        if admin_tenant_id and admin_tenant_id != token_info.get("tenant_id"):
            raise AuthorizationError("Un jeton de mission ne peut pas choisir un autre tenant.")
        tenant_id = token_info.get("tenant_id")
        if not tenant_id:
            raise AuthorizationError("Jeton de mission invalide : tenant_id absent.")
        return require_identifier(str(tenant_id), "tenant_id")

    async def create(self, manifest: dict, token_info: dict) -> dict:
        if is_admin(token_info):
            # Une identité admin prépare elle aussi une campagne sous un tenant
            # explicite du manifeste. Ce n'est jamais disponible à un agent.
            raw_tenant = manifest.get("tenant_id") if isinstance(manifest, dict) else None
            tenant_id = require_identifier(raw_tenant, "tenant_id")
        else:
            tenant_id = self._tenant_for_lookup(token_info, None)
        campaign = build_campaign_manifest(
            manifest,
            tenant_id=tenant_id,
            requested_by=self._actor(token_info),
            max_targets=self.settings.cybersec_max_targets_per_campaign,
            allow_lab_targets=self.settings.cybersec_lab_mode,
        )
        try:
            created = await self.repository.create_campaign(campaign)
        except ObjectAlreadyExists:
            created = False
        if not created:
            raise ValidationError("Une campagne avec cet identifiant existe déjà.")
        return campaign

    async def get(self, campaign_id: str, token_info: dict, *, admin_tenant_id: Optional[str] = None) -> dict:
        tenant_id = self._tenant_for_lookup(token_info, admin_tenant_id)
        campaign = await self.repository.get_campaign(tenant_id, campaign_id)
        if not may_access_tenant(token_info, campaign["tenant_id"]):
            raise AuthorizationError("Campagne hors tenant.")
        return await self._expire_if_needed(campaign)

    async def list(self, token_info: dict, *, admin_tenant_id: Optional[str] = None) -> list[dict]:
        if is_admin(token_info):
            campaigns = await self.repository.list_campaigns(admin_tenant_id)
        else:
            campaigns = await self.repository.list_campaigns(self._tenant_for_lookup(token_info, None))
        result = []
        for campaign in campaigns:
            if may_access_tenant(token_info, campaign["tenant_id"]):
                result.append(await self._expire_if_needed(campaign))
        return result

    async def approve(self, campaign_id: str, token_info: dict, *, admin_tenant_id: str) -> dict:
        if not is_admin(token_info):
            raise AuthorizationError("Permission administrateur humaine requise.")
        campaign = await self.get(campaign_id, token_info, admin_tenant_id=admin_tenant_id)
        if campaign.get("status") != "prepared":
            raise ValidationError("Seule une campagne prepared peut être approuvée.")
        now = datetime.now(timezone.utc)
        if parse_utc(campaign["window"]["ends_at"], "window.ends_at") <= now:
            raise ValidationError("La fenêtre de campagne est déjà expirée.")
        approved = deepcopy(campaign)
        approved["status"] = "approved"
        approved["approval"] = {
            "approved_by": self._actor(token_info),
            "approved_at": iso_now(),
            "manifest_hash": approved["manifest_hash"],
        }
        mandate_key = await self.repository.save_approved_mandate(approved)
        approved["approval"]["mandate_key"] = mandate_key
        await self.repository.save_campaign(approved)
        return approved

    async def cancel(self, campaign_id: str, token_info: dict, *, admin_tenant_id: Optional[str] = None, reason: str = "") -> dict:
        campaign = await self.get(campaign_id, token_info, admin_tenant_id=admin_tenant_id)
        if campaign.get("status") in {"completed", "failed", "partial", "cancelled", "expired"}:
            return campaign
        cancelled = deepcopy(campaign)
        cancelled["status"] = "cancelled"
        cancelled["cancellation"] = {
            "cancelled_by": self._actor(token_info),
            "cancelled_at": iso_now(),
            "reason": str(reason)[:256],
        }
        await self.repository.save_campaign(cancelled)
        return cancelled

    async def authorize(
        self,
        campaign_id: str,
        token_info: dict,
        *,
        required_test_class: str,
        admin_tenant_id: Optional[str] = None,
    ) -> dict:
        """Refuse avant émission réseau si la campagne n'est plus exécutable."""
        campaign = await self.get(campaign_id, token_info, admin_tenant_id=admin_tenant_id)
        if campaign.get("status") not in {"approved", "running"}:
            raise AuthorizationError("Aucun trafic n'est autorisé avant approbation ou après clôture de campagne.")
        now = datetime.now(timezone.utc)
        if not (
            parse_utc(campaign["window"]["starts_at"], "window.starts_at")
            <= now
            < parse_utc(campaign["window"]["ends_at"], "window.ends_at")
        ):
            raise AuthorizationError("Fenêtre de mandat fermée : trafic refusé.")
        if required_test_class not in campaign.get("allowed_test_classes", []):
            raise AuthorizationError(f"Classe de test non autorisée par le mandat : {required_test_class}.")
        if not campaign.get("approval") or campaign["approval"].get("manifest_hash") != campaign.get("manifest_hash"):
            raise AuthorizationError("Mandat approuvé absent ou incohérent : trafic refusé.")
        return campaign

    async def mark_running(self, campaign: dict) -> dict:
        if campaign.get("status") == "approved":
            campaign = deepcopy(campaign)
            campaign["status"] = "running"
            campaign["started_at"] = iso_now()
            await self.repository.save_campaign(campaign)
        return campaign

    async def set_terminal_state(self, campaign: dict, jobs: list[dict]) -> dict:
        """Ne présente jamais une campagne avec erreurs comme complète."""
        current = await self._expire_if_needed(campaign)
        if current.get("status") in {"cancelled", "expired"}:
            return current
        states = {job.get("status") for job in jobs}
        if states & {"queued", "running"}:
            return current
        updated = deepcopy(current)
        if states & {"failed", "interrupted", "partial"}:
            updated["status"] = "partial" if states - {"failed"} else "failed"
        elif states:
            updated["status"] = "completed"
        else:
            return updated
        updated["completed_at"] = iso_now()
        await self.repository.save_campaign(updated)
        return updated

    async def _expire_if_needed(self, campaign: dict) -> dict:
        status = campaign.get("status")
        if status not in {"prepared", "approved", "running"}:
            return campaign
        ends_at = parse_utc(campaign["window"]["ends_at"], "window.ends_at")
        if ends_at > datetime.now(timezone.utc):
            return campaign
        expired = deepcopy(campaign)
        expired["status"] = "expired"
        expired["expired_at"] = iso_now()
        await self.repository.save_campaign(expired)
        return expired
