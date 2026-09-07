# -*- coding: utf-8 -*-
"""Sondes réseau et HTTP mandatées, sans primitive de shell connectée."""

from __future__ import annotations

import asyncio
import hashlib
import json
import ssl
import tempfile
import uuid
from pathlib import Path
from typing import Optional, Protocol
from urllib.parse import urljoin, urlsplit

from .campaigns import CampaignService
from .config import CybersecSettings
from .identity import AuthorizationError
from .models import ValidationError, redact_text
from .scope import ScopeGuard
from .storage import CybersecRepository


class NetworkCommandRunner(Protocol):
    async def run(self, command: list[str], timeout: int) -> dict: ...


class DockerNetworkCommandRunner:
    """Conteneur de sonde fixe : seul le code choisit les sous-commandes."""

    def __init__(self, settings: CybersecSettings):
        self.settings = settings

    async def run(self, command: list[str], timeout: int) -> dict:
        name = f"mcp-cybersec-probe-{uuid.uuid4().hex[:16]}"
        docker_command = [
            "docker", "run", "--rm", f"--name={name}",
            "--label=mcp-cybersec.managed=true",
            f"--network={self.settings.cybersec_scanner_network}", "--read-only", "--cap-drop=ALL",
            "--cap-add=NET_RAW",
            f"--memory={self.settings.cybersec_scanner_memory}",
            f"--memory-swap={self.settings.cybersec_scanner_memory}",
            f"--cpus={self.settings.cybersec_scanner_cpus}",
            f"--pids-limit={self.settings.cybersec_scanner_pids_limit}",
            "--security-opt=no-new-privileges:true",
            "--tmpfs=/tmp:rw,noexec,nosuid,nodev,size=32m",
            "--user=10001:10001",
            self.settings.cybersec_network_image,
            *command,
        ]
        try:
            process = await asyncio.create_subprocess_exec(
                *docker_command, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
            )
        except FileNotFoundError:
            return {"status": "error", "message": "Docker indisponible pour la sonde réseau."}
        try:
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=timeout)
        except asyncio.TimeoutError:
            await self._kill(name)
            return {"status": "timeout", "message": "Délai de sonde dépassé."}
        except asyncio.CancelledError:
            await self._kill(name)
            raise
        return {
            "status": "success" if process.returncode == 0 else "error",
            "returncode": process.returncode,
            "stdout": redact_text(stdout.decode("utf-8", errors="replace"), self.settings.cybersec_max_output_chars),
            "stderr": redact_text(stderr.decode("utf-8", errors="replace"), self.settings.cybersec_max_output_chars),
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


class NetworkService:
    """DNS, reverse DNS, TCP, TLS, ping et traceroute, tous sous campagne."""

    def __init__(
        self,
        repository: CybersecRepository,
        campaigns: CampaignService,
        scope: ScopeGuard,
        settings: CybersecSettings,
        runner: Optional[NetworkCommandRunner] = None,
    ):
        self.repository = repository
        self.campaigns = campaigns
        self.scope = scope
        self.settings = settings
        self.runner = runner or DockerNetworkCommandRunner(settings)

    async def run(
        self,
        *,
        campaign_id: str,
        target: str,
        token_info: dict,
        operation: str,
        port: int = 443,
        timeout: int = 15,
        count: int = 2,
        max_hops: int = 10,
    ) -> dict:
        if operation not in {"dns", "reverse_dns", "ping", "traceroute", "tcp", "tls"}:
            raise ValidationError("Opération réseau invalide.")
        if not 1 <= port <= 65535 or not 1 <= timeout <= 120:
            raise ValidationError("Port ou timeout réseau invalide.")
        if not 1 <= count <= 5 or not 1 <= max_hops <= 30:
            raise ValidationError("Bornes de sonde réseau invalides.")
        decision = await self.scope.check(
            campaign_id, target, token_info, required_test_class="recon"
        )
        if operation == "dns":
            result = {"status": "success", "operation": operation, "host": decision["host"], "addresses": decision["addresses"]}
        elif operation == "reverse_dns":
            result = await self._reverse_dns(decision["addresses"])
            result.update({"operation": operation, "host": decision["host"], "addresses": decision["addresses"]})
        elif operation == "tcp":
            result = await self._tcp(decision["addresses"], port, timeout)
            result.update({"operation": operation, "host": decision["host"], "addresses": decision["addresses"], "port": port})
        elif operation == "tls":
            result = await self._tls(decision["host"], decision["addresses"], port, timeout)
            result.update({"operation": operation, "host": decision["host"], "addresses": decision["addresses"], "port": port})
        else:
            ip = decision["addresses"][0]
            command = (
                ["ping", "-c", str(count), "-W", str(timeout), ip]
                if operation == "ping"
                else ["traceroute", "-n", "-m", str(max_hops), "-w", str(timeout), ip]
            )
            result = await self.runner.run(command, timeout)
            result.update({"operation": operation, "host": decision["host"], "addresses": decision["addresses"]})
        evidence_ref = await self._store_evidence(campaign_id, token_info, "network", result)
        return {**result, "evidence_ref": evidence_ref, "traffic_emitted": True}

    async def _reverse_dns(self, addresses: list[str]) -> dict:
        loop = asyncio.get_running_loop()
        names = {}
        for address in addresses:
            try:
                names[address] = (await loop.getnameinfo((address, 0), 0))[0]
            except OSError:
                names[address] = None
        return {"status": "success", "reverse_dns": names}

    async def _tcp(self, addresses: list[str], port: int, timeout: int) -> dict:
        probes = []
        for address in addresses:
            try:
                reader, writer = await asyncio.wait_for(asyncio.open_connection(address, port), timeout=timeout)
                writer.close()
                await writer.wait_closed()
                probes.append({"address": address, "reachable": True})
            except (OSError, asyncio.TimeoutError):
                probes.append({"address": address, "reachable": False})
        return {"status": "success", "tcp": probes}

    async def _tls(self, hostname: str, addresses: list[str], port: int, timeout: int) -> dict:
        context = ssl.create_default_context()
        results = []
        for address in addresses:
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(address, port, ssl=context, server_hostname=hostname), timeout=timeout
                )
                ssl_object = writer.get_extra_info("ssl_object")
                certificate = ssl_object.getpeercert() if ssl_object else {}
                writer.close()
                await writer.wait_closed()
                results.append({
                    "address": address,
                    "reachable": True,
                    "tls_version": ssl_object.version() if ssl_object else None,
                    "cipher": ssl_object.cipher()[0] if ssl_object and ssl_object.cipher() else None,
                    "certificate_not_after": certificate.get("notAfter") if isinstance(certificate, dict) else None,
                })
            except (OSError, ssl.SSLError, asyncio.TimeoutError):
                results.append({"address": address, "reachable": False})
        return {"status": "success", "tls": results}

    async def _store_evidence(self, campaign_id: str, token_info: dict, kind: str, value: dict) -> str:
        campaign = await self.campaigns.get(campaign_id, token_info)
        event_id = f"evt_{uuid.uuid4().hex[:20]}"
        record = await self.repository.write_evidence(
            campaign["tenant_id"], campaign_id, event_id, f"{kind}.json",
            json.dumps(value, ensure_ascii=False, sort_keys=True).encode("utf-8"), content_type="application/json"
        )
        return record["evidence_ref"]


class HttpCommandRunner(Protocol):
    async def run_once(self, *, url: str, address: str, method: str, headers: dict[str, str], body: Optional[bytes], timeout: int) -> dict: ...


class DockerHttpCommandRunner:
    """curl avec ``--resolve`` : la connexion utilise l'IP vérifiée par scope."""

    def __init__(self, settings: CybersecSettings):
        self.settings = settings

    async def run_once(self, *, url: str, address: str, method: str, headers: dict[str, str], body: Optional[bytes], timeout: int) -> dict:
        parsed = urlsplit(url)
        if not parsed.hostname:
            raise ValidationError("URL HTTP invalide.")
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        name = f"mcp-cybersec-http-{uuid.uuid4().hex[:16]}"
        runtime_root = Path(self.settings.cybersec_runtime_host_dir)
        runtime_root.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="cybersec-http-", dir=runtime_root) as temp:
            root = Path(temp)
            output = root / "output"
            output.mkdir()
            output.chmod(0o777)
            mounts = [f"--mount=type=bind,src={output.resolve()},dst=/output"]
            command = [
                "curl", "--silent", "--show-error", "--request", method,
                "--max-time", str(timeout), "--connect-timeout", str(timeout),
                "--dump-header", "/output/headers.txt", "--output", "/output/body.txt",
                "--resolve", f"{parsed.hostname}:{port}:{address}",
            ]
            for name_header, value in headers.items():
                command.extend(["--header", f"{name_header}: {value}"])
            if body is not None:
                input_file = root / "body.bin"
                input_file.write_bytes(body)
                input_file.chmod(0o644)
                mounts.append(f"--mount=type=bind,src={input_file.resolve()},dst=/input/body.bin,readonly")
                command.extend(["--data-binary", "@/input/body.bin"])
            command.append(url)
            docker_command = [
                "docker", "run", "--rm", f"--name={name}",
                "--label=mcp-cybersec.managed=true",
                f"--network={self.settings.cybersec_scanner_network}", "--read-only", "--cap-drop=ALL",
                f"--memory={self.settings.cybersec_scanner_memory}",
                f"--memory-swap={self.settings.cybersec_scanner_memory}",
                f"--cpus={self.settings.cybersec_scanner_cpus}",
                f"--pids-limit={self.settings.cybersec_scanner_pids_limit}",
                "--security-opt=no-new-privileges:true",
                "--tmpfs=/tmp:rw,noexec,nosuid,nodev,size=32m",
                "--user=10001:10001", *mounts,
                self.settings.cybersec_network_image, *command,
            ]
            try:
                process = await asyncio.create_subprocess_exec(
                    *docker_command, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
                )
            except FileNotFoundError:
                return {"status": "error", "message": "Docker indisponible pour HTTP."}
            try:
                stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=timeout + 5)
            except asyncio.TimeoutError:
                await self._kill(name)
                return {"status": "timeout", "message": "Délai HTTP dépassé."}
            except asyncio.CancelledError:
                await self._kill(name)
                raise
            raw_headers = (output / "headers.txt").read_text(errors="replace") if (output / "headers.txt").exists() else ""
            raw_body = (output / "body.txt").read_text(errors="replace") if (output / "body.txt").exists() else ""
            return {
                "status": "success" if process.returncode == 0 else "error",
                "returncode": process.returncode,
                "headers_raw": raw_headers,
                "body": redact_text(raw_body, self.settings.cybersec_max_output_chars),
                "stderr": redact_text(stderr.decode("utf-8", errors="replace"), self.settings.cybersec_max_output_chars),
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


def _parse_headers(raw: str) -> tuple[Optional[int], dict[str, str]]:
    blocks = [block for block in raw.replace("\r\n", "\n").split("\n\n") if block.strip()]
    if not blocks:
        return None, {}
    lines = blocks[-1].splitlines()
    status = None
    if lines and len(lines[0].split()) >= 2:
        try:
            status = int(lines[0].split()[1])
        except ValueError:
            pass
    headers: dict[str, str] = {}
    for line in lines[1:]:
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        key = key.strip().lower()
        if key in {"authorization", "proxy-authorization", "cookie", "set-cookie"}:
            headers[key] = "[REDACTED]"
        else:
            headers[key] = value.strip()[:512]
    return status, headers


class HttpService:
    def __init__(
        self,
        repository: CybersecRepository,
        campaigns: CampaignService,
        scope: ScopeGuard,
        settings: CybersecSettings,
        runner: Optional[HttpCommandRunner] = None,
    ):
        self.repository = repository
        self.campaigns = campaigns
        self.scope = scope
        self.settings = settings
        self.runner = runner or DockerHttpCommandRunner(settings)

    async def request(
        self,
        *,
        campaign_id: str,
        url: str,
        token_info: dict,
        method: str = "GET",
        headers: Optional[dict[str, str]] = None,
        body: Optional[str] = None,
        follow_redirects: bool = True,
        timeout: int = 30,
    ) -> dict:
        method = method.upper()
        if method not in {"GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE"}:
            raise ValidationError("Méthode HTTP invalide.")
        if not 1 <= timeout <= 300:
            raise ValidationError("Timeout HTTP invalide.")
        required_class = "recon" if method in {"GET", "HEAD", "OPTIONS"} else "active_standard"
        if method == "DELETE":
            required_class = "active_extended"
        prepared_headers = self._validate_headers(headers or {})
        if body is not None and (not isinstance(body, str) or len(body.encode("utf-8")) > 1_000_000):
            raise ValidationError("Corps HTTP invalide ou trop volumineux.")

        current_url = url
        redirects = []
        responses = []
        for _ in range(self.settings.cybersec_max_http_redirects + 1):
            decision = await self.scope.check(
                campaign_id, current_url, token_info,
                required_test_class=required_class, url=current_url,
            )
            result = await self.runner.run_once(
                url=decision["url"], address=decision["addresses"][0], method=method,
                headers=prepared_headers, body=body.encode("utf-8") if body is not None else None, timeout=timeout,
            )
            status_code, response_headers = _parse_headers(result.pop("headers_raw", ""))
            response = {
                "status": result.get("status"),
                "status_code": status_code,
                "url": decision["url"],
                "address": decision["addresses"][0],
                "headers": response_headers,
                "body": redact_text(str(result.get("body", "")), self.settings.cybersec_max_output_chars),
                "stderr": result.get("stderr", ""),
            }
            responses.append(response)
            location = response_headers.get("location")
            if not (follow_redirects and status_code in {301, 302, 303, 307, 308} and location):
                break
            next_url = urljoin(decision["url"], location)
            redirects.append({"from": decision["url"], "to": next_url, "status_code": status_code})
            current_url = next_url
            if status_code == 303:
                method, body = "GET", None
        else:
            raise ValidationError("Nombre maximal de redirections dépassé.")
        final = responses[-1] if responses else {"status": "error", "message": "Aucune réponse HTTP."}
        evidence_ref = await self._store_evidence(campaign_id, token_info, method, url, prepared_headers, responses, redirects)
        return {
            "status": final.get("status", "error"),
            "method": method,
            "final_url": final.get("url"),
            "status_code": final.get("status_code"),
            "headers": final.get("headers", {}),
            "body": final.get("body", ""),
            "redirects": redirects,
            "evidence_ref": evidence_ref,
            "traffic_emitted": True,
        }

    @staticmethod
    def _validate_headers(headers: dict[str, str]) -> dict[str, str]:
        if not isinstance(headers, dict) or len(headers) > 32:
            raise ValidationError("Headers HTTP invalides ou trop nombreux.")
        result = {}
        for key, value in headers.items():
            if not isinstance(key, str) or not isinstance(value, str) or "\r" in key + value or "\n" in key + value:
                raise ValidationError("Header HTTP invalide.")
            normalized = key.lower().strip()
            if normalized in {"host", "authorization", "proxy-authorization", "cookie", "x-api-key"}:
                raise AuthorizationError("Header HTTP sensible hors MVP non authentifié.")
            if not normalized or len(normalized) > 128 or len(value) > 4096:
                raise ValidationError("Header HTTP hors bornes.")
            result[key.strip()] = value
        return result

    async def _store_evidence(self, campaign_id: str, token_info: dict, method: str, initial_url: str, headers: dict[str, str], responses: list[dict], redirects: list[dict]) -> str:
        campaign = await self.campaigns.get(campaign_id, token_info)
        event_id = f"evt_{uuid.uuid4().hex[:20]}"
        safe = {
            "method": method,
            "initial_url": initial_url,
            "request_header_names": sorted(headers),
            "responses": responses,
            "redirects": redirects,
        }
        record = await self.repository.write_evidence(
            campaign["tenant_id"], campaign_id, event_id, "http.json",
            json.dumps(safe, ensure_ascii=False, sort_keys=True).encode("utf-8"), content_type="application/json"
        )
        return record["evidence_ref"]
