# -*- coding: utf-8 -*-
"""Exécuteurs de scan fixes : aucune commande, image ou montage agent n'entre ici."""

from __future__ import annotations

import asyncio
import ipaddress
import os
import shutil
from pathlib import Path
from typing import Awaitable, Callable, Protocol
from urllib.parse import urlsplit, urlunsplit

from .config import CybersecSettings
from .models import ValidationError, normalize_host, normalize_url, redact_text


ContinueCheck = Callable[[], Awaitable[bool]]


class ScannerRunner(Protocol):
    async def run(
        self,
        tool: str,
        job_id: str,
        arguments: list[str],
        output_dir: Path,
        should_continue: ContinueCheck,
    ) -> dict: ...

    async def cancel(self, job_id: str) -> None: ...


def container_name(job_id: str) -> str:
    # job_id est produit localement à partir d'un SHA-256 ; ce format empêche
    # toute interprétation shell ou Docker d'un identifiant entrant.
    return f"mcp-cybersec-{job_id}"


class DockerScannerRunner:
    """Lance uniquement nmap/nuclei dans des images de scanner épinglées."""

    def __init__(self, settings: CybersecSettings):
        self.settings = settings

    def _image_for(self, tool: str) -> str:
        images = {
            "nmap": self.settings.cybersec_nmap_image,
            "nuclei": self.settings.cybersec_nuclei_image,
        }
        try:
            return images[tool]
        except KeyError as exc:
            raise ValidationError("Moteur de scan invalide.") from exc

    async def cancel(self, job_id: str) -> None:
        name = container_name(job_id)
        for command in (("docker", "kill", name), ("docker", "rm", "-f", name)):
            try:
                process = await asyncio.create_subprocess_exec(
                    *command,
                    stdout=asyncio.subprocess.DEVNULL,
                    stderr=asyncio.subprocess.DEVNULL,
                )
                await process.wait()
            except (FileNotFoundError, OSError):
                return

    async def run(
        self,
        tool: str,
        job_id: str,
        arguments: list[str],
        output_dir: Path,
        should_continue: ContinueCheck,
    ) -> dict:
        image = self._image_for(tool)
        name = container_name(job_id)
        output_dir.mkdir(parents=True, exist_ok=True)
        # Le conteneur tourne avec un UID non-root distinct. Le répertoire est
        # éphémère et dédié au job, donc le rendre inscriptible ici ne donne
        # aucun accès à l'hôte ni à une autre campagne.
        output_dir.chmod(0o777)
        docker_command = [
            "docker", "run", "--rm", f"--name={name}",
            "--label=mcp-cybersec.managed=true",
            f"--label=mcp-cybersec.job={job_id}",
            f"--network={self.settings.cybersec_scanner_network}",
            "--read-only",
            "--cap-drop=ALL",
            f"--memory={self.settings.cybersec_scanner_memory}",
            f"--memory-swap={self.settings.cybersec_scanner_memory}",
            f"--cpus={self.settings.cybersec_scanner_cpus}",
            f"--pids-limit={self.settings.cybersec_scanner_pids_limit}",
            "--security-opt=no-new-privileges:true",
            "--tmpfs=/tmp:rw,noexec,nosuid,nodev,size=64m",
            f"--mount=type=bind,src={output_dir.resolve()},dst=/output",
            "--user=10001:10001",
            image,
            *arguments,
        ]
        try:
            process = await asyncio.create_subprocess_exec(
                *docker_command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
        except FileNotFoundError:
            return {"status": "failed", "error_type": "docker_unavailable", "artifacts": {}}

        communication = asyncio.create_task(process.communicate())
        interrupted = False
        try:
            while not communication.done():
                try:
                    await asyncio.wait_for(asyncio.shield(communication), self.settings.cybersec_job_cancel_poll_seconds)
                except asyncio.TimeoutError:
                    if not await should_continue():
                        interrupted = True
                        await self.cancel(job_id)
            stdout, stderr = await communication
        except asyncio.CancelledError:
            await self.cancel(job_id)
            communication.cancel()
            raise

        artifacts: dict[str, bytes] = {}
        for path in sorted(output_dir.iterdir()):
            if path.is_file() and path.name in {"nmap.xml", "nmap.txt", "nuclei.jsonl"}:
                artifacts[path.name] = path.read_bytes()
        artifacts["scanner.log"] = redact_text(
            (stdout + b"\n" + stderr).decode("utf-8", errors="replace"),
            self.settings.cybersec_max_output_chars,
        ).encode("utf-8")
        if interrupted:
            status = "interrupted"
        elif process.returncode == 0:
            status = "completed"
        elif artifacts and any(name != "scanner.log" for name in artifacts):
            status = "partial"
        else:
            status = "failed"
        return {
            "status": status,
            "returncode": process.returncode,
            "artifacts": artifacts,
        }


def _port_argument(ports: list[int]) -> str:
    if not ports:
        raise ValidationError("Le mandat doit préciser les ports TCP autorisés.")
    return ",".join(str(port) for port in sorted(set(ports)))


def build_nmap_arguments(
    *,
    profile: str,
    ports: list[int],
    all_tcp: bool,
    discovery_only: bool,
    service_detection: bool,
    safe_scripts: bool,
    timing: int,
    max_rate: int,
    timeout: int,
    targets: list[str],
) -> list[str]:
    """Construit une liste nmap sans shell libre ni script NSE arbitraire."""
    if profile not in {"quick", "top-ports", "full-tcp", "service", "safe-scripts"}:
        raise ValidationError("Profil nmap invalide.")
    if not targets or not all(isinstance(target, str) for target in targets):
        raise ValidationError("Aucune cible nmap résolue.")
    if not 0 <= timing <= 4:
        raise ValidationError("Le timing nmap doit être entre 0 et 4.")
    if not 1 <= max_rate <= 10000:
        raise ValidationError("max_rate nmap doit être entre 1 et 10000.")
    if not 5 <= timeout <= 14400:
        raise ValidationError("Timeout nmap invalide.")
    if profile == "full-tcp" and not all_tcp:
        raise ValidationError("Le profil full-tcp exige targets.all_tcp=true dans le mandat approuvé.")

    arguments = ["-n", f"-T{timing}", "--max-rate", str(max_rate), "--host-timeout", f"{timeout}s", "-oX", "/output/nmap.xml", "-oN", "/output/nmap.txt"]
    if discovery_only:
        arguments.append("-sn")
    else:
        arguments.extend(["-sT", "-Pn"])
        if profile == "full-tcp":
            arguments.append("-p-")
        elif profile == "top-ports" and all_tcp:
            arguments.extend(["--top-ports", "100"])
        else:
            arguments.extend(["-p", _port_argument(ports)])
        if service_detection or profile in {"quick", "service", "safe-scripts"}:
            arguments.extend(["-sV", "--version-light"])
        if safe_scripts or profile == "safe-scripts":
            arguments.extend(["--script", "safe"])
    return [*arguments, *targets]


# Chaque identifiant correspond à un fichier inclus dans l'image, jamais à un
# chemin ou template fourni par l'agent. Les révisions sont figées dans
# cybersec/nuclei-templates/manifest.json et dans l'image.
TEMPLATE_CATALOG = {
    "tech-detect": {"path": "official/tech-detect.yaml", "profiles": {"recon"}, "tags": {"tech", "discovery"}},
    "http-missing-security-headers": {"path": "official/http-missing-security-headers.yaml", "profiles": {"recon", "active_standard"}, "tags": {"http", "misconfig", "headers"}},
    "http-safe-reflection": {"path": "internal/http-safe-reflection.yaml", "profiles": {"active_standard", "active_extended"}, "tags": {"xss", "reflection", "safe"}},
}
_FORBIDDEN_NUCLEI_TAGS = {"dos", "bruteforce", "brute-force", "fuzz", "fuzzing", "intrusive", "destructive", "race"}


def build_pinned_nuclei_targets(*, target: str, addresses: list[str]) -> tuple[list[str], str | None, str | None]:
    """Remplace le DNS scanner par les IP déjà autorisées par ``ScopeGuard``.

    Nuclei résoudrait autrement à nouveau un hostname au moment de la requête.
    Pour une URL/domain, les IP sont donc injectées dans la cible tandis que le
    nom approuvé est conservé exclusivement en Host/SNI. Les templates restent
    sans redirection et le job revalide le scope pendant son exécution.
    """
    if not isinstance(addresses, list) or not addresses:
        raise ValidationError("Aucune adresse validée pour nuclei.")
    normalized_addresses = []
    for address in addresses:
        try:
            normalized_addresses.append(str(ipaddress.ip_address(address)))
        except ValueError as exc:
            raise ValidationError("Adresse nuclei résolue invalide.") from exc

    if "://" not in target:
        host = normalize_host(target)
        try:
            ipaddress.ip_address(host)
            return normalized_addresses, None, None
        except ValueError:
            return normalized_addresses, host, host

    parsed = urlsplit(normalize_url(target))
    host = normalize_host(parsed.hostname or "")
    try:
        ipaddress.ip_address(host)
        host_header = None
        sni = None
    except ValueError:
        host_header = host + (f":{parsed.port}" if parsed.port is not None else "")
        sni = host

    pinned_urls = []
    for address in normalized_addresses:
        netloc = f"[{address}]" if ":" in address else address
        if parsed.port is not None:
            netloc += f":{parsed.port}"
        pinned_urls.append(urlunsplit((parsed.scheme, netloc, parsed.path or "/", parsed.query, "")))
    return pinned_urls, host_header, sni


def build_nuclei_arguments(
    *,
    profile: str,
    template_ids: list[str],
    tags: list[str],
    severities: list[str],
    rate_limit: int,
    concurrency: int,
    timeout: int,
    targets: list[str],
    host_header: str | None = None,
    sni: str | None = None,
) -> list[str]:
    """Construit un appel nuclei borné à des templates relus et versionnés."""
    if profile not in {"recon", "active_standard", "active_extended"}:
        raise ValidationError("Profil nuclei invalide.")
    if not 1 <= rate_limit <= 1000 or not 1 <= concurrency <= 64 or not 5 <= timeout <= 14400:
        raise ValidationError("Limites nuclei invalides.")
    if not targets or not all(isinstance(target, str) and target for target in targets):
        raise ValidationError("Aucune cible nuclei épinglée.")
    unknown = set(template_ids) - set(TEMPLATE_CATALOG)
    if unknown:
        raise ValidationError("Template nuclei hors catalogue versionné.")
    requested_tags = {tag.lower() for tag in tags}
    if requested_tags & _FORBIDDEN_NUCLEI_TAGS:
        raise ValidationError("Tag nuclei destructif ou hors MVP refusé.")
    selected = template_ids or [
        template_id for template_id, data in TEMPLATE_CATALOG.items() if profile in data["profiles"]
    ]
    if not selected:
        raise ValidationError("Aucun template n'est autorisé pour ce profil.")
    if any(profile not in TEMPLATE_CATALOG[item]["profiles"] for item in selected):
        raise ValidationError("Un template demandé dépasse le profil approuvé.")
    allowed_tags = set().union(*(TEMPLATE_CATALOG[item]["tags"] for item in selected))
    if requested_tags and not requested_tags.issubset(allowed_tags):
        raise ValidationError("Tag nuclei absent du catalogue sélectionné.")
    severity_set = {item.lower() for item in severities}
    if not severity_set.issubset({"info", "low", "medium", "high", "critical", "unknown"}):
        raise ValidationError("Sévérité nuclei invalide.")

    arguments = [
        "-jsonl", "-o", "/output/nuclei.jsonl",
        "-silent", "-no-color", "-disable-update-check", "-disable-redirects", "-no-interactsh",
        "-rl", str(rate_limit),
        "-c", str(concurrency),
        "-timeout", str(timeout),
    ]
    for target in targets:
        arguments.extend(["-u", target])
    if host_header:
        arguments.extend(["-H", f"Host: {host_header}"])
    if sni:
        arguments.extend(["-sni", sni])
    for template_id in selected:
        arguments.extend(["-t", f"/templates/{TEMPLATE_CATALOG[template_id]['path']}"])
    if requested_tags:
        arguments.extend(["-tags", ",".join(sorted(requested_tags))])
    if severity_set:
        arguments.extend(["-severity", ",".join(sorted(severity_set))])
    return arguments
