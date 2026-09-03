# -*- coding: utf-8 -*-
"""Jobs nmap/nuclei asynchrones, idempotents et arrêtables."""

from __future__ import annotations

import asyncio
import tempfile
from copy import deepcopy
from pathlib import Path
from typing import Optional

from .campaigns import CampaignService
from .config import CybersecSettings
from .findings import parse_nmap_findings, parse_nuclei_findings
from .identity import AuthorizationError
from .models import ValidationError, iso_now, redact_text
from .scanners import (
    DockerScannerRunner,
    ScannerRunner,
    build_nmap_arguments,
    build_nuclei_arguments,
    build_pinned_nuclei_targets,
)
from .scope import ScopeGuard
from .storage import CybersecRepository, ObjectNotFound, stable_job_id


_NMAP_PROFILE_CLASS = {
    "quick": "recon",
    "top-ports": "recon",
    "service": "recon",
    "full-tcp": "active_standard",
    "safe-scripts": "active_standard",
}


class ScanJobManager:
    def __init__(
        self,
        repository: CybersecRepository,
        campaigns: CampaignService,
        scope: ScopeGuard,
        settings: CybersecSettings,
        runner: Optional[ScannerRunner] = None,
    ):
        self.repository = repository
        self.campaigns = campaigns
        self.scope = scope
        self.settings = settings
        self.runner = runner or DockerScannerRunner(settings)
        self._tasks: dict[str, asyncio.Task] = {}

    async def start_nmap(
        self,
        *,
        campaign_id: str,
        target: str,
        idempotency_key: str,
        token_info: dict,
        profile: str = "quick",
        ports: Optional[list[int]] = None,
        discovery_only: bool = False,
        service_detection: bool = False,
        safe_scripts: bool = False,
        timing: int = 3,
        max_rate: int = 100,
        timeout: int = 600,
    ) -> dict:
        required_class = _NMAP_PROFILE_CLASS.get(profile)
        if required_class is None:
            raise ValidationError("Profil nmap invalide.")
        decision = await self.scope.check(
            campaign_id, target, token_info, required_test_class=required_class
        )
        campaign = await self.campaigns.get(campaign_id, token_info)
        mandate_ports = campaign["targets"].get("ports", [])
        selected_ports = mandate_ports if ports is None else ports
        if not all(isinstance(port, int) and port in mandate_ports for port in selected_ports):
            raise AuthorizationError("Un port nmap demandé est absent du mandat.")
        if len(selected_ports) > self.settings.cybersec_max_ports_per_scan:
            raise ValidationError("Trop de ports demandés.")
        arguments = build_nmap_arguments(
            profile=profile,
            ports=selected_ports,
            all_tcp=bool(campaign["targets"].get("all_tcp")),
            discovery_only=discovery_only,
            service_detection=service_detection,
            safe_scripts=safe_scripts,
            timing=timing,
            max_rate=max_rate,
            timeout=min(timeout, self.settings.cybersec_max_job_timeout),
            targets=decision["addresses"],
        )
        return await self._start(
            tool="nmap",
            campaign=campaign,
            token_info=token_info,
            idempotency_key=idempotency_key,
            selected_target=target,
            resolved_targets=decision["addresses"],
            required_test_class=required_class,
            profile=profile,
            arguments=arguments,
            timeout=min(timeout, self.settings.cybersec_max_job_timeout),
        )

    async def start_nuclei(
        self,
        *,
        campaign_id: str,
        target: str,
        idempotency_key: str,
        token_info: dict,
        profile: str = "recon",
        template_ids: Optional[list[str]] = None,
        tags: Optional[list[str]] = None,
        severities: Optional[list[str]] = None,
        rate_limit: int = 10,
        concurrency: int = 2,
        timeout: int = 600,
    ) -> dict:
        decision = await self.scope.check(
            campaign_id,
            target,
            token_info,
            required_test_class=profile,
            url=target if "://" in target else None,
        )
        campaign = await self.campaigns.get(campaign_id, token_info)
        # Le scanner ne reçoit jamais un hostname à résoudre lui-même : les IP
        # sont figées depuis ScopeGuard. Host/SNI conservent le nom mandaté si
        # nécessaire pour la virtualisation HTTP/TLS.
        pinned_targets, host_header, sni = build_pinned_nuclei_targets(
            target=decision.get("url") or target,
            addresses=decision["addresses"],
        )
        arguments = build_nuclei_arguments(
            profile=profile,
            template_ids=template_ids or [],
            tags=tags or [],
            severities=severities or [],
            rate_limit=min(rate_limit, campaign["rate_limit"]),
            concurrency=min(concurrency, campaign["concurrency"]),
            timeout=min(timeout, self.settings.cybersec_max_job_timeout),
            targets=pinned_targets,
            host_header=host_header,
            sni=sni,
        )
        return await self._start(
            tool="nuclei",
            campaign=campaign,
            token_info=token_info,
            idempotency_key=idempotency_key,
            selected_target=target,
            resolved_targets=decision["addresses"],
            required_test_class=profile,
            profile=profile,
            arguments=arguments,
            timeout=min(timeout, self.settings.cybersec_max_job_timeout),
        )

    async def _start(
        self,
        *,
        tool: str,
        campaign: dict,
        token_info: dict,
        idempotency_key: str,
        selected_target: str,
        resolved_targets: list[str],
        required_test_class: str,
        profile: str,
        arguments: list[str],
        timeout: int,
    ) -> dict:
        job_id = stable_job_id(campaign["tenant_id"], campaign["campaign_id"], tool, idempotency_key)
        job = {
            "schema_version": 1,
            "job_id": job_id,
            "tenant_id": campaign["tenant_id"],
            "campaign_id": campaign["campaign_id"],
            "tool": tool,
            "status": "queued",
            "created_at": iso_now(),
            "created_by": str(token_info.get("client_name", "unknown"))[:128],
            "idempotency_key_hash": stable_job_id(campaign["tenant_id"], campaign["campaign_id"], tool, idempotency_key).removeprefix("job_"),
            "selected_target": selected_target,
            "resolved_targets": resolved_targets,
            "required_test_class": required_test_class,
            "profile": profile,
            "arguments": arguments,
            "timeout": timeout,
            "engine": self._engine_metadata(tool),
            "evidence_refs": [],
            "findings_ref": None,
        }
        created = await self.repository.create_job(job)
        if not created:
            existing = await self.repository.get_job(campaign["tenant_id"], campaign["campaign_id"], job_id)
            return {
                "status": "accepted",
                "job_id": job_id,
                "job_status": existing.get("status"),
                "deduplicated": True,
                "traffic_emitted": False,
            }
        await self.campaigns.mark_running(campaign)
        self._tasks[job_id] = asyncio.create_task(self._run_job(job, token_info), name=f"cybersec-{job_id}")
        return {
            "status": "accepted",
            "job_id": job_id,
            "job_status": "queued",
            "deduplicated": False,
            "traffic_emitted": False,
        }

    def _engine_metadata(self, tool: str) -> dict:
        if tool == "nmap":
            return {"name": "nmap", "version": self.settings.cybersec_nmap_version, "image": self.settings.cybersec_nmap_image}
        return {
            "name": "nuclei",
            "version": self.settings.cybersec_nuclei_version,
            "image": self.settings.cybersec_nuclei_image,
            "templates_revision": self.settings.cybersec_nuclei_templates_revision,
        }

    async def _run_job(self, initial_job: dict, token_info: dict) -> None:
        job = deepcopy(initial_job)
        job["status"] = "running"
        job["started_at"] = iso_now()
        await self.repository.save_job(job)

        async def should_continue() -> bool:
            try:
                current = await self.repository.get_job(job["tenant_id"], job["campaign_id"], job["job_id"])
                if current.get("cancel_requested"):
                    return False
                await self.campaigns.authorize(
                    job["campaign_id"], token_info, required_test_class=job["required_test_class"]
                )
                # Revalider le DNS et le périmètre juste avant puis pendant le
                # scan : un rebinding ou une révocation arrête le conteneur.
                decision = await self.scope.check(
                    job["campaign_id"], job["selected_target"], token_info,
                    required_test_class=job["required_test_class"],
                    url=job["selected_target"] if "://" in job["selected_target"] else None,
                )
                if job["tool"] == "nmap" and set(decision["addresses"]) != set(job["resolved_targets"]):
                    return False
                return True
            except Exception:
                return False

        try:
            # Vérification synchrone avant que Docker ne reçoive la commande.
            if not await should_continue():
                raise AuthorizationError("Campagne annulée, expirée ou périmètre modifié avant le scan.")
            with tempfile.TemporaryDirectory(prefix=f"{job['job_id']}-") as directory:
                outcome = await self.runner.run(
                    job["tool"], job["job_id"], job["arguments"], Path(directory), should_continue
                )
            job["status"] = outcome.get("status", "failed")
            job["returncode"] = outcome.get("returncode")
            job["finished_at"] = iso_now()
            await self._persist_outcome(job, outcome)
        except asyncio.CancelledError:
            await self.runner.cancel(job["job_id"])
            job["status"] = "interrupted"
            job["finished_at"] = iso_now()
            job["interruption_reason"] = "service_task_cancelled"
            await self.repository.save_job(job)
            raise
        except AuthorizationError:
            job["status"] = "interrupted"
            job["finished_at"] = iso_now()
            job["interruption_reason"] = "mandate_revoked_or_scope_changed"
            await self.repository.save_job(job)
        except Exception as exc:
            job["status"] = "failed"
            job["finished_at"] = iso_now()
            job["error_type"] = type(exc).__name__
            await self.repository.save_job(job)
        finally:
            self._tasks.pop(job["job_id"], None)
            try:
                campaign = await self.repository.get_campaign(job["tenant_id"], job["campaign_id"])
                jobs = await self.repository.list_jobs(job["tenant_id"], job["campaign_id"])
                await self.campaigns.set_terminal_state(campaign, jobs)
            except Exception:
                pass

    async def _persist_outcome(self, job: dict, outcome: dict) -> None:
        evidence_refs = []
        artifacts = outcome.get("artifacts", {})
        for filename, body in artifacts.items():
            if not isinstance(filename, str) or not isinstance(body, (bytes, bytearray)):
                continue
            content_type = "application/xml" if filename.endswith(".xml") else "application/json" if filename.endswith(".jsonl") else "text/plain"
            safe_body = redact_text(bytes(body).decode("utf-8", errors="replace"), self.settings.cybersec_max_output_chars).encode("utf-8")
            record = await self.repository.write_evidence(
                job["tenant_id"], job["campaign_id"], job["job_id"], filename, safe_body, content_type=content_type
            )
            evidence_refs.append(record["evidence_ref"])
        metadata = {
            "job_id": job["job_id"],
            "tool": job["tool"],
            "status": job["status"],
            "engine": job["engine"],
            "profile": job["profile"],
            "selected_target": job["selected_target"],
            "resolved_targets": job["resolved_targets"],
            "started_at": job.get("started_at"),
            "finished_at": job.get("finished_at"),
            "returncode": job.get("returncode"),
        }
        metadata_record = await self.repository.write_evidence(
            job["tenant_id"], job["campaign_id"], job["job_id"], "metadata.json",
            __import__("json").dumps(metadata, ensure_ascii=False, sort_keys=True).encode("utf-8"),
            content_type="application/json",
        )
        evidence_refs.append(metadata_record["evidence_ref"])
        job["evidence_refs"] = evidence_refs
        findings: list[dict] = []
        if job["tool"] == "nmap" and isinstance(artifacts.get("nmap.xml"), (bytes, bytearray)):
            findings = parse_nmap_findings(
                artifacts["nmap.xml"], campaign_id=job["campaign_id"], job_id=job["job_id"],
                evidence_ref=f"{job['job_id']}/nmap.xml", version=job["engine"]["version"]
            )
        if job["tool"] == "nuclei" and isinstance(artifacts.get("nuclei.jsonl"), (bytes, bytearray)):
            findings = parse_nuclei_findings(
                artifacts["nuclei.jsonl"], campaign_id=job["campaign_id"], job_id=job["job_id"],
                evidence_ref=f"{job['job_id']}/nuclei.jsonl", version=job["engine"]["version"]
            )
        if findings:
            job["findings_ref"] = await self.repository.write_findings(
                job["tenant_id"], job["campaign_id"], job["job_id"], findings
            )
        await self.repository.save_job(job)

    async def cancel_campaign(self, campaign: dict) -> int:
        jobs = await self.repository.list_jobs(campaign["tenant_id"], campaign["campaign_id"])
        cancelled = 0
        for job in jobs:
            if job.get("status") not in {"queued", "running"}:
                continue
            job["cancel_requested"] = True
            job["cancel_requested_at"] = iso_now()
            await self.repository.save_job(job)
            await self.runner.cancel(job["job_id"])
            if job["status"] == "queued" and job["job_id"] not in self._tasks:
                job["status"] = "interrupted"
                job["finished_at"] = iso_now()
                job["interruption_reason"] = "cancelled_before_start"
                await self.repository.save_job(job)
            cancelled += 1
        return cancelled

    async def results(self, campaign: dict) -> dict:
        jobs = await self.repository.list_jobs(campaign["tenant_id"], campaign["campaign_id"])
        findings = []
        for job in jobs:
            if job.get("findings_ref"):
                try:
                    findings.extend(await self.repository.read_findings(campaign["tenant_id"], campaign["campaign_id"], job["job_id"]))
                except ObjectNotFound:
                    continue
        return {
            "campaign_id": campaign["campaign_id"],
            "campaign_status": campaign["status"],
            "jobs": jobs,
            "findings": findings,
            "coverage": {
                "completed_jobs": sum(job.get("status") == "completed" for job in jobs),
                "partial_jobs": sum(job.get("status") in {"partial", "interrupted"} for job in jobs),
                "failed_jobs": sum(job.get("status") == "failed" for job in jobs),
                "note": "Aucun finding ne vaut preuve de sécurité ; les couvertures partielles et erreurs restent visibles.",
            },
        }
