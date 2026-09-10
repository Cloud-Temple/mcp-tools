# -*- coding: utf-8 -*-
"""Contrôle de périmètre DNS/IP/URL, appliqué avant chaque action réseau."""

from __future__ import annotations

import asyncio
import ipaddress
import socket
from datetime import datetime, timezone
from typing import Awaitable, Callable, Optional
from urllib.parse import urlsplit

from .campaigns import CampaignService
from .config import CybersecSettings
from .identity import AuthorizationError
from .models import ValidationError, normalize_host, normalize_url, parse_utc


Resolver = Callable[[str], Awaitable[list[str]]]


async def system_resolver(host: str) -> list[str]:
    """Résout IPv4 et IPv6, puis déduplique sans faire confiance à la sortie."""
    loop = asyncio.get_running_loop()
    try:
        records = await loop.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise ValidationError(f"Résolution DNS impossible pour {host}.") from exc
    addresses = sorted({record[4][0] for record in records})
    if not addresses:
        raise ValidationError(f"Aucune adresse DNS obtenue pour {host}.")
    return addresses


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _in_networks(address: ipaddress._BaseAddress, cidrs: list[str]) -> bool:
    return any(address in ipaddress.ip_network(value, strict=False) for value in cidrs)


def _url_in_scope(candidate: str, allowed_urls: list[str]) -> bool:
    parsed = urlsplit(candidate)
    for allowed in allowed_urls:
        scope = urlsplit(allowed)
        if parsed.scheme != scope.scheme or parsed.hostname != scope.hostname or parsed.port != scope.port:
            continue
        base_path = scope.path or "/"
        if base_path == "/" or parsed.path == base_path or parsed.path.startswith(base_path.rstrip("/") + "/"):
            return True
    return False


class ScopeGuard:
    """Le point unique de décision qui évite les divergences entre tools."""

    def __init__(self, campaigns: CampaignService, resolver: Resolver = system_resolver, settings: Optional[CybersecSettings] = None):
        self.campaigns = campaigns
        self.resolver = resolver
        self.settings = settings or campaigns.settings
        self._lab_networks = [
            ipaddress.ip_network(value.strip(), strict=False)
            for value in self.settings.cybersec_lab_allowed_cidrs.split(",") if value.strip()
        ]

    def _validated_ip(self, value: str, campaign: dict) -> ipaddress._BaseAddress:
        try:
            address = ipaddress.ip_address(value)
        except ValueError as exc:
            raise ValidationError("Adresse résolue invalide.") from exc
        if address.is_global:
            return address
        if (
            self.settings.cybersec_lab_mode
            and campaign.get("laboratory") is True
            and any(address in network for network in self._lab_networks)
        ):
            return address
        raise AuthorizationError("Adresse résolue privée, loopback, link-local, metadata ou réservée : trafic refusé.")

    @staticmethod
    def _target_host(target: str) -> str:
        if "://" in target:
            return normalize_host(urlsplit(normalize_url(target)).hostname or "")
        return normalize_host(target)

    @staticmethod
    def _is_excluded(campaign: dict, *, host: str, addresses: list[str], url: Optional[str] = None) -> Optional[str]:
        exclusions = campaign.get("exclusions", {})
        if host in exclusions.get("domains", []) or host in exclusions.get("ips", []):
            return "cible explicitement exclue"
        if url and _url_in_scope(url, exclusions.get("urls", [])):
            return "URL explicitement exclue"
        for value in addresses:
            address = ipaddress.ip_address(value)
            if str(address) in exclusions.get("ips", []) or _in_networks(address, exclusions.get("cidrs", [])):
                return "IP explicitement exclue"
        return None

    async def evaluate(
        self,
        campaign: dict,
        target: str,
        *,
        url: Optional[str] = None,
        port: Optional[int] = None,
    ) -> dict:
        """Vérifie hôte, DNS IPv4/IPv6, exclusions et URL sans rien émettre vers la cible."""
        host = self._target_host(target)
        targets = campaign["targets"]
        normalized_url = normalize_url(url) if url else None
        if normalized_url and self._target_host(normalized_url) != host:
            return {"allowed": False, "reason": "URL incohérente avec la cible", "host": host, "addresses": []}
        domain_allowed = host in targets.get("domains", [])
        url_allowed = bool(normalized_url and _url_in_scope(normalized_url, targets.get("urls", [])))

        if _is_ip(host):
            address = self._validated_ip(host, campaign)
            ip_allowed = str(address) in targets.get("ips", []) or _in_networks(address, targets.get("cidrs", []))
            if not ip_allowed and not url_allowed:
                return {"allowed": False, "reason": "IP absente du mandat", "host": host, "addresses": [str(address)]}
            addresses = [str(address)]
        else:
            if not domain_allowed and not url_allowed:
                url_host_known = any(
                    (urlsplit(value).hostname or "").lower() == host for value in targets.get("urls", [])
                )
                reason = (
                    "URL absente du mandat" if normalized_url and url_host_known
                    else "URL explicite requise par le mandat" if url_host_known
                    else "domaine absent du mandat"
                )
                return {"allowed": False, "reason": reason, "host": host, "addresses": []}
            addresses = [str(self._validated_ip(value, campaign)) for value in await self.resolver(host)]

        # Une URL doit rester dans le chemin explicitement autorisé. Un simple
        # même domaine ne suffit pas à élargir une URL restreinte du mandat.
        if normalized_url and not url_allowed and not domain_allowed:
            return {"allowed": False, "reason": "URL absente du mandat", "host": host, "addresses": addresses}

        requested_port = port
        if normalized_url:
            parsed_url = urlsplit(normalized_url)
            requested_port = parsed_url.port or (443 if parsed_url.scheme == "https" else 80)
        if (
            requested_port is not None
            and not targets.get("all_tcp", False)
            and requested_port not in targets.get("ports", [])
        ):
            return {"allowed": False, "reason": "port absent du mandat", "host": host, "addresses": addresses}

        exclusion_reason = self._is_excluded(campaign, host=host, addresses=addresses, url=normalized_url)
        if exclusion_reason:
            return {"allowed": False, "reason": exclusion_reason, "host": host, "addresses": addresses}
        return {"allowed": True, "reason": "cible et résolutions conformes au mandat", "host": host, "addresses": addresses, "url": normalized_url}

    async def check(
        self,
        campaign_id: str,
        target: str,
        token_info: dict,
        *,
        required_test_class: Optional[str] = None,
        url: Optional[str] = None,
        port: Optional[int] = None,
        admin_tenant_id: Optional[str] = None,
    ) -> dict:
        if required_test_class:
            campaign = await self.campaigns.authorize(
                campaign_id,
                token_info,
                required_test_class=required_test_class,
                admin_tenant_id=admin_tenant_id,
            )
        else:
            campaign = await self.campaigns.get(campaign_id, token_info, admin_tenant_id=admin_tenant_id)
        decision = await self.evaluate(campaign, target, url=url, port=port)
        if required_test_class and not decision["allowed"]:
            raise AuthorizationError(f"Périmètre refusé avant trafic : {decision['reason']}.")
        decision["campaign_id"] = campaign_id
        decision["campaign_status"] = campaign.get("status")
        decision["window_open"] = (
            parse_utc(campaign["window"]["starts_at"], "window.starts_at")
            <= datetime.now(timezone.utc)
            < parse_utc(campaign["window"]["ends_at"], "window.ends_at")
        )
        if required_test_class and not decision["window_open"]:
            raise AuthorizationError("Fenêtre de mandat fermée : trafic refusé.")
        return decision
