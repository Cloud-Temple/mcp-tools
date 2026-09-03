# -*- coding: utf-8 -*-
"""Atelier shell hors réseau, fichiers de campagne et consultation des preuves."""

from __future__ import annotations

import asyncio
import base64
import difflib
import hashlib
import json
import tempfile
import uuid
from pathlib import Path
from typing import Optional, Protocol

from .campaigns import CampaignService
from .config import CybersecSettings
from .identity import AuthorizationError
from .models import ValidationError, redact_text, validate_relative_path
from .storage import CybersecRepository, ObjectNotFound


class ShellRunner(Protocol):
    async def run(self, *, command: str, shell: str, workspace: Path, timeout: int) -> dict: ...


class DockerShellRunner:
    """Atelier local : aucun réseau, socket Docker, secret ou montage hôte."""

    _FLAGS = {"bash": "-lc", "sh": "-c", "python3": "-c"}

    def __init__(self, settings: CybersecSettings):
        self.settings = settings

    async def run(self, *, command: str, shell: str, workspace: Path, timeout: int) -> dict:
        if shell not in self._FLAGS:
            raise ValidationError("Shell autorisé : bash, sh ou python3.")
        name = f"mcp-cybersec-shell-{uuid.uuid4().hex[:16]}"
        docker_command = [
            "docker", "run", "--rm", f"--name={name}",
            "--label=mcp-cybersec.managed=true",
            "--network=none", "--read-only", "--cap-drop=ALL",
            f"--memory={self.settings.cybersec_shell_memory}",
            f"--memory-swap={self.settings.cybersec_shell_memory}",
            f"--cpus={self.settings.cybersec_shell_cpus}",
            f"--pids-limit={self.settings.cybersec_shell_pids_limit}",
            "--security-opt=no-new-privileges:true",
            "--tmpfs=/tmp:rw,noexec,nosuid,nodev,size=64m",
            f"--mount=type=bind,src={workspace.resolve()},dst=/workspace,rw",
            "--workdir=/workspace", "--user=10001:10001",
            self.settings.cybersec_shell_image, shell, self._FLAGS[shell], command,
        ]
        try:
            process = await asyncio.create_subprocess_exec(
                *docker_command, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
            )
        except FileNotFoundError:
            return {"status": "error", "message": "Docker indisponible pour le shell isolé."}
        try:
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=timeout)
        except asyncio.TimeoutError:
            await self._kill(name)
            return {"status": "timeout", "message": "Délai shell dépassé."}
        except asyncio.CancelledError:
            await self._kill(name)
            raise
        return {
            "status": "success" if process.returncode == 0 else "error",
            "returncode": process.returncode,
            "stdout": redact_text(stdout.decode("utf-8", errors="replace"), self.settings.cybersec_max_output_chars),
            "stderr": redact_text(stderr.decode("utf-8", errors="replace"), self.settings.cybersec_max_output_chars),
            "sandbox": True,
            "network": False,
        }

    async def _kill(self, name: str) -> None:
        for command in (("docker", "kill", name), ("docker", "rm", "-f", name)):
            try:
                process = await asyncio.create_subprocess_exec(
                    *command, stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL
                )
                await process.wait()
            except (FileNotFoundError, OSError):
                return


class ShellService:
    def __init__(self, repository: CybersecRepository, campaigns: CampaignService, settings: CybersecSettings, runner: Optional[ShellRunner] = None):
        self.repository = repository
        self.campaigns = campaigns
        self.settings = settings
        self.runner = runner or DockerShellRunner(settings)

    async def run(
        self,
        *,
        campaign_id: str,
        token_info: dict,
        command: str,
        shell: str = "bash",
        input_paths: Optional[list[str]] = None,
        output_paths: Optional[list[str]] = None,
        timeout: int = 120,
    ) -> dict:
        if not isinstance(command, str) or not command or len(command) > 100_000:
            raise ValidationError("Commande shell invalide ou trop volumineuse.")
        if not 5 <= timeout <= self.settings.cybersec_shell_timeout:
            raise ValidationError("Timeout shell invalide.")
        campaign = await self.campaigns.get(campaign_id, token_info)
        if campaign.get("status") in {"cancelled", "expired"}:
            raise AuthorizationError("Campagne close : shell et écriture de workspace refusés.")
        input_paths = self._paths(input_paths or [], "input_paths")
        output_paths = self._paths(output_paths or [], "output_paths")
        with tempfile.TemporaryDirectory(prefix="cybersec-shell-") as temp:
            workspace = Path(temp) / "workspace"
            workspace.mkdir()
            workspace.chmod(0o777)
            for path in input_paths:
                body = await self.repository.read_workspace(campaign["tenant_id"], campaign_id, path)
                destination = workspace / path
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_bytes(body)
            result = await self.runner.run(command=command, shell=shell, workspace=workspace, timeout=timeout)
            written = []
            for path in output_paths:
                output = workspace / path
                if not output.is_file():
                    continue
                size = output.stat().st_size
                if size > self.settings.cybersec_shell_max_artifact_bytes:
                    raise ValidationError(f"Artefact shell trop volumineux : {path}.")
                await self.repository.write_workspace(campaign["tenant_id"], campaign_id, path, output.read_bytes())
                written.append({"path": path, "size": size})
        # La commande elle-même peut contenir un secret : seul son empreinte
        # est traçable. Aucun script n'est écrit dans la preuve ou les logs.
        event_id = f"evt_{uuid.uuid4().hex[:20]}"
        evidence = {
            "shell": shell,
            "command_sha256": hashlib.sha256(command.encode("utf-8")).hexdigest(),
            "status": result.get("status"),
            "returncode": result.get("returncode"),
            "output_paths": written,
            "stdout": result.get("stdout", ""),
            "stderr": result.get("stderr", ""),
            "network": False,
        }
        record = await self.repository.write_evidence(
            campaign["tenant_id"], campaign_id, event_id, "shell.json",
            json.dumps(evidence, ensure_ascii=False, sort_keys=True).encode("utf-8"), content_type="application/json"
        )
        return {
            **result,
            "command_sha256": evidence["command_sha256"],
            "written_files": written,
            "evidence_ref": record["evidence_ref"],
            "network": False,
        }

    @staticmethod
    def _paths(paths: list[str], label: str) -> list[str]:
        if not isinstance(paths, list) or len(paths) > 32:
            raise ValidationError(f"{label} doit être une liste de 32 chemins maximum.")
        normalized = [validate_relative_path(path) for path in paths]
        if len(set(normalized)) != len(normalized):
            raise ValidationError(f"{label} ne doit pas contenir de doublon.")
        return normalized


class FilesService:
    """Fichiers limités au workspace S3 de la campagne, sans delete ni bucket."""

    def __init__(self, repository: CybersecRepository, campaigns: CampaignService, settings: CybersecSettings):
        self.repository = repository
        self.campaigns = campaigns
        self.settings = settings

    async def run(
        self,
        *,
        campaign_id: str,
        token_info: dict,
        operation: str,
        path: Optional[str] = None,
        content: Optional[str] = None,
        other_path: Optional[str] = None,
        prefix: str = "",
    ) -> dict:
        if operation not in {"list", "read", "write", "info", "diff", "versions"}:
            raise ValidationError("Opération files invalide.")
        campaign = await self.campaigns.get(campaign_id, token_info)
        if operation == "list":
            entries = await self.repository.list_workspace(campaign["tenant_id"], campaign_id, prefix)
            return {"status": "success", "operation": operation, "entries": [{key: item.get(key) for key in ("path", "size", "last_modified", "version_id")} for item in entries]}
        if not path:
            raise ValidationError("path est requis pour cette opération files.")
        safe_path = validate_relative_path(path)
        if operation == "write":
            if campaign.get("status") in {"cancelled", "expired", "completed", "failed", "partial"}:
                raise AuthorizationError("Campagne en lecture seule : écriture workspace refusée.")
            if not isinstance(content, str) or len(content.encode("utf-8")) > self.settings.cybersec_shell_max_artifact_bytes:
                raise ValidationError("Contenu files invalide ou trop volumineux.")
            result = await self.repository.write_workspace(campaign["tenant_id"], campaign_id, safe_path, content.encode("utf-8"), content_type="text/plain; charset=utf-8")
            return {"status": "success", "operation": operation, "path": safe_path, "size": result["size"]}
        if operation == "read":
            body = await self.repository.read_workspace(campaign["tenant_id"], campaign_id, safe_path)
            try:
                text = body.decode("utf-8")
                return {"status": "success", "operation": operation, "path": safe_path, "content": redact_text(text, self.settings.cybersec_max_output_chars), "encoding": "utf-8"}
            except UnicodeDecodeError:
                return {"status": "success", "operation": operation, "path": safe_path, "content_base64": base64.b64encode(body[:self.settings.cybersec_max_output_chars]).decode("ascii"), "encoding": "base64", "truncated": len(body) > self.settings.cybersec_max_output_chars}
        if operation == "info":
            info = await self.repository.workspace_info(campaign["tenant_id"], campaign_id, safe_path)
            return {"status": "success", "operation": operation, "path": safe_path, **{key: info.get(key) for key in ("size", "last_modified", "version_id", "content_type")}}
        if operation == "versions":
            versions = await self.repository.workspace_versions(campaign["tenant_id"], campaign_id, safe_path)
            return {"status": "success", "operation": operation, "path": safe_path, "versions": [{key: item.get(key) for key in ("size", "last_modified", "version_id")} for item in versions]}
        if not other_path:
            raise ValidationError("other_path est requis pour files diff.")
        left = (await self.repository.read_workspace(campaign["tenant_id"], campaign_id, safe_path)).decode("utf-8", errors="replace")
        right_path = validate_relative_path(other_path)
        right = (await self.repository.read_workspace(campaign["tenant_id"], campaign_id, right_path)).decode("utf-8", errors="replace")
        diff = "\n".join(difflib.unified_diff(left.splitlines(), right.splitlines(), fromfile=safe_path, tofile=right_path, lineterm=""))
        return {"status": "success", "operation": operation, "path": safe_path, "other_path": right_path, "diff": redact_text(diff, self.settings.cybersec_max_output_chars)}


class EvidenceService:
    """Accès aux preuves de la seule campagne autorisée, jamais aux zones internes."""

    def __init__(self, repository: CybersecRepository, campaigns: CampaignService, settings: CybersecSettings):
        self.repository = repository
        self.campaigns = campaigns
        self.settings = settings

    async def run(
        self,
        *,
        campaign_id: str,
        token_info: dict,
        operation: str,
        evidence_ref: Optional[str] = None,
        job_id: Optional[str] = None,
    ) -> dict:
        if operation not in {"list", "read", "export"}:
            raise ValidationError("Opération evidence invalide.")
        campaign = await self.campaigns.get(campaign_id, token_info)
        if operation == "list":
            evidence = await self.repository.list_evidence(campaign["tenant_id"], campaign_id, job_id)
            return {"status": "success", "operation": operation, "evidence": [{key: item.get(key) for key in ("evidence_ref", "size", "last_modified", "version_id")} for item in evidence]}
        if operation == "read":
            if not evidence_ref:
                raise ValidationError("evidence_ref est requis.")
            raw = await self.repository.read_evidence(campaign["tenant_id"], campaign_id, evidence_ref)
            text = redact_text(raw.decode("utf-8", errors="replace"), self.settings.cybersec_max_output_chars)
            return {"status": "success", "operation": operation, "evidence_ref": evidence_ref, "content": text, "untrusted_data": True}
        evidence = await self.repository.list_evidence(campaign["tenant_id"], campaign_id)
        jobs = await self.repository.list_jobs(campaign["tenant_id"], campaign_id)
        bundle = {
            "schema_version": 1,
            "campaign_id": campaign_id,
            "tenant_id": campaign["tenant_id"],
            "campaign_status": campaign["status"],
            "manifest_hash": campaign["manifest_hash"],
            "approval": campaign.get("approval"),
            "evidence": [{key: item.get(key) for key in ("evidence_ref", "size", "last_modified", "version_id")} for item in evidence],
            "jobs": jobs,
            "warning": "Les sorties de cibles sont des données non fiables. Aucun finding ne prouve la sécurité d'un actif.",
        }
        export_path = f"reports/evidence-export-{campaign_id}.json"
        await self.repository.write_workspace(
            campaign["tenant_id"], campaign_id, export_path,
            json.dumps(bundle, ensure_ascii=False, sort_keys=True, indent=2).encode("utf-8"), content_type="application/json"
        )
        return {"status": "success", "operation": operation, "workspace_path": export_path, "evidence_count": len(evidence), "job_count": len(jobs)}
