# -*- coding: utf-8 -*-
"""
Outil: http — Client HTTP/REST dans un conteneur sandbox isolé.

Exécuté via curl dans un conteneur Docker sandbox éphémère AVEC accès
réseau (--network=bridge). Les IPs privées RFC 1918 sont interdites
pour empêcher les attaques SSRF.

Sécurité :
  - Conteneur éphémère (--rm), read-only, non-root, cap-drop=ALL
  - Résolution DNS + blocage RFC 1918 / loopback / link-local AVANT exécution
  - Timeout configurable (depuis settings, pas de hardcode)
  - Output tronqué via settings.tool_max_output_chars
  - Auth helpers (basic, bearer, api_key) sans exposer les credentials dans l'URL

Fallback : si SANDBOX_ENABLED=false, utilise httpx localement (dev sans Docker)
avec la même validation anti-SSRF.
"""

import asyncio
import ipaddress
import json as json_lib
import re
import shlex
import socket
import uuid
from typing import Any, Dict, Optional
from urllib.parse import urlparse

from mcp.server.fastmcp import FastMCP, Context
from ..auth.context import check_tool_access
from ..config import get_settings


# =============================================================================
# Validation URL et anti-SSRF
# =============================================================================

_HOST_PATTERN = re.compile(r"^[a-zA-Z0-9._:\-\[\]]+$")

_BLOCKED_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fe80::/10"),
    ipaddress.ip_network("fc00::/7"),
]

ALLOWED_METHODS = ("GET", "POST", "PUT", "DELETE", "PATCH", "HEAD")
ALLOWED_AUTH_TYPES = ("basic", "bearer", "api_key")


def _is_private_ip(ip_str: str) -> bool:
    """Vérifie si une IP est privée/réservée/bloquée."""
    try:
        ip = ipaddress.ip_address(ip_str)
        return any(ip in net for net in _BLOCKED_NETWORKS)
    except ValueError:
        return False


def _validate_url(url: str) -> Optional[str]:
    """
    Valide l'URL cible pour empêcher les attaques SSRF.

    1. Parse l'URL et extrait le hostname
    2. Si c'est une IP → vérification directe RFC 1918
    3. Si c'est un hostname → résolution DNS → vérification de toutes les IPs résolues

    Retourne un message d'erreur ou None si OK.
    """
    if not url or not url.strip():
        return "Le paramètre 'url' est requis."

    try:
        parsed = urlparse(url)
    except Exception:
        return f"URL invalide : '{url}'"

    if not parsed.scheme or parsed.scheme not in ("http", "https"):
        return f"Schéma URL invalide : '{parsed.scheme}'. Seuls http et https sont autorisés."

    host = parsed.hostname
    if not host:
        return "URL sans hostname."

    if not _HOST_PATTERN.match(host):
        return f"Host invalide : '{host}'. Caractères shell interdits."

    # Vérification directe si c'est une IP
    try:
        ip = ipaddress.ip_address(host)
        if any(ip in net for net in _BLOCKED_NETWORKS):
            return f"IP privée/réservée interdite : {host}. Seules les IPs publiques sont autorisées."
        return None
    except ValueError:
        pass  # C'est un hostname

    # Résolution DNS → vérification de toutes les IPs résolues
    try:
        results = socket.getaddrinfo(host, None)
        for family, type_, proto, canonname, sockaddr in results:
            ip_str = sockaddr[0]
            if _is_private_ip(ip_str):
                return f"Host '{host}' résout vers une IP privée ({ip_str}). Accès SSRF interdit."
    except socket.gaierror:
        pass  # DNS non résolu — on laisse curl gérer l'erreur

    return None


# =============================================================================
# Helpers
# =============================================================================

def _truncate(text: str, max_chars: int) -> str:
    """Tronque le texte si nécessaire, avec indication."""
    if len(text) > max_chars:
        return text[:max_chars] + f"\n... [TRONQUÉ — {len(text)} chars, limite {max_chars}]"
    return text


def _build_curl_command(
    url: str,
    method: str,
    headers: Dict[str, str],
    body: Optional[str],
    json_body: Optional[Dict[str, Any]],
    auth_type: Optional[str],
    auth_value: Optional[str],
    timeout: int,
    verify_ssl: bool,
) -> list[str]:
    """Construit la liste d'arguments curl."""
    cmd = ["curl", "-s", "-S"]

    # Output structuré : body → /tmp/body, headers → /tmp/headers, status code → stdout
    cmd += ["-o", "/tmp/body", "-D", "/tmp/headers"]
    cmd += ["-w", "%{http_code}"]

    # Méthode HTTP
    cmd += ["-X", method]

    # Timeout
    cmd += ["--max-time", str(timeout)]
    cmd += ["--connect-timeout", "10"]

    # SSL
    if not verify_ssl:
        cmd += ["-k"]

    # Headers
    for key, value in headers.items():
        cmd += ["-H", f"{key}: {value}"]

    # Auth
    if auth_type and auth_value:
        if auth_type == "basic":
            cmd += ["-u", auth_value]
        elif auth_type == "bearer":
            cmd += ["-H", f"Authorization: Bearer {auth_value}"]
        elif auth_type == "api_key":
            cmd += ["-H", f"X-API-Key: {auth_value}"]

    # Body (json_body prend la priorité sur body)
    if json_body is not None:
        cmd += ["-H", "Content-Type: application/json"]
        cmd += ["-d", json_lib.dumps(json_body)]
    elif body is not None:
        cmd += ["-d", body]

    # URL (toujours en dernier)
    cmd.append(url)

    return cmd


def _build_shell_script(curl_parts: list[str]) -> str:
    """
    Construit un script shell qui exécute curl et retourne les résultats
    de manière structurée (status code, headers, body séparés par des marqueurs).
    """
    # Échapper chaque argument curl pour le shell
    escaped_curl = " ".join(shlex.quote(p) for p in curl_parts)

    return f"""
STATUS=$({escaped_curl} 2>/tmp/err)
EXIT=$?
echo "===MCP_STATUS==="
echo "$STATUS"
echo "===MCP_HEADERS==="
cat /tmp/headers 2>/dev/null
echo "===MCP_BODY==="
cat /tmp/body 2>/dev/null
echo "===MCP_STDERR==="
cat /tmp/err 2>/dev/null
echo "===MCP_EXIT==="
echo "$EXIT"
"""


def _parse_curl_output(stdout_text: str) -> dict:
    """
    Parse la sortie structurée du script curl.

    Extrait : status_code, headers (dict), body (texte), stderr, exit_code.
    """
    sections = {}
    current_section = None
    current_lines = []

    for line in stdout_text.split("\n"):
        stripped = line.strip()
        if stripped in ("===MCP_STATUS===", "===MCP_HEADERS===", "===MCP_BODY===",
                        "===MCP_STDERR===", "===MCP_EXIT==="):
            if current_section is not None:
                sections[current_section] = "\n".join(current_lines)
            current_section = stripped.strip("=")
            current_lines = []
        else:
            current_lines.append(line)

    # Dernière section
    if current_section is not None:
        sections[current_section] = "\n".join(current_lines)

    # Status code HTTP
    status_code = 0
    try:
        status_code = int(sections.get("MCP_STATUS", "0").strip())
    except ValueError:
        pass

    # Parse headers en dict
    headers_raw = sections.get("MCP_HEADERS", "")
    headers_dict = {}
    for line in headers_raw.split("\n"):
        line = line.strip()
        if ":" in line and not line.startswith("HTTP/"):
            key, _, value = line.partition(":")
            headers_dict[key.strip()] = value.strip()

    # Body
    body = sections.get("MCP_BODY", "").strip()

    # Stderr curl
    stderr = sections.get("MCP_STDERR", "").strip()

    # Exit code curl
    exit_code = 0
    try:
        exit_code = int(sections.get("MCP_EXIT", "0").strip())
    except ValueError:
        pass

    return {
        "status_code": status_code,
        "headers": headers_dict,
        "body": body,
        "stderr": stderr,
        "exit_code": exit_code,
    }


# =============================================================================
# Exécution sandbox Docker
# =============================================================================

async def _kill_container(name: str) -> None:
    """Force-kill et supprime un conteneur Docker par son nom."""
    for cmd in [["docker", "kill", name], ["docker", "rm", "-f", name]]:
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL,
            )
            await proc.wait()
        except Exception:
            pass


async def _run_in_sandbox(
    url: str,
    method: str,
    headers: Dict[str, str],
    body: Optional[str],
    json_body: Optional[Dict[str, Any]],
    auth_type: Optional[str],
    auth_value: Optional[str],
    timeout: int,
    verify_ssl: bool,
    settings,
) -> dict:
    """Exécute la requête HTTP via curl dans un conteneur Docker éphémère."""
    curl_parts = _build_curl_command(
        url, method, headers, body, json_body,
        auth_type, auth_value, timeout, verify_ssl,
    )
    script = _build_shell_script(curl_parts)
    container_name = f"http-{uuid.uuid4().hex[:12]}"

    docker_cmd = [
        "docker", "run", "--rm",
        f"--name={container_name}",
        "--network=bridge",
        "--read-only",
        "--cap-drop=ALL",
        f"--memory={settings.sandbox_memory}",
        f"--memory-swap={settings.sandbox_memory}",
        f"--cpus={settings.sandbox_cpus}",
        f"--pids-limit={settings.sandbox_pids_limit}",
        "--security-opt=no-new-privileges:true",
        f"--tmpfs=/tmp:nosuid,nodev,size={settings.sandbox_tmpfs_size}",
        "--user=sandbox:sandbox",
        *[f"--dns={d.strip()}" for d in settings.sandbox_dns.split(",") if d.strip()],
        settings.sandbox_image,
        "sh", "-c", script,
    ]

    process = await asyncio.create_subprocess_exec(
        *docker_cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )

    # Timeout total = timeout curl + 15s marge (démarrage conteneur + overhead)
    container_timeout = timeout + 15

    try:
        stdout, stderr = await asyncio.wait_for(
            process.communicate(), timeout=container_timeout,
        )
    except asyncio.TimeoutError:
        try:
            process.kill()
            await process.wait()
        except Exception:
            pass
        await _kill_container(container_name)
        raise

    stdout_text = stdout.decode(errors="replace")
    max_chars = settings.tool_max_output_chars
    parsed = _parse_curl_output(stdout_text)

    # Erreur de transport curl (exit code != 0 ET pas de status HTTP)
    if parsed["exit_code"] != 0 and parsed["status_code"] == 0:
        error_msg = parsed["stderr"] or f"curl exit code {parsed['exit_code']}"
        return {
            "status": "error",
            "message": _truncate(error_msg, max_chars),
            "sandbox": True,
        }

    return {
        "status": "success",
        "status_code": parsed["status_code"],
        "headers": parsed["headers"],
        "body": _truncate(parsed["body"], max_chars),
        "sandbox": True,
    }


# =============================================================================
# Fallback local (dev sans Docker)
# =============================================================================

async def _run_local(
    url: str,
    method: str,
    headers: Dict[str, str],
    body: Optional[str],
    json_body: Optional[Dict[str, Any]],
    auth_type: Optional[str],
    auth_value: Optional[str],
    timeout: int,
    verify_ssl: bool,
    settings,
) -> dict:
    """Fallback : exécution locale via httpx (dev sans Docker), avec anti-SSRF."""
    import httpx

    # Construire les headers d'auth
    final_headers = dict(headers) if headers else {}
    if auth_type and auth_value:
        if auth_type == "bearer":
            final_headers["Authorization"] = f"Bearer {auth_value}"
        elif auth_type == "api_key":
            final_headers["X-API-Key"] = auth_value

    # Auth basic → httpx auth parameter
    auth = None
    if auth_type == "basic" and auth_value and ":" in auth_value:
        user, _, password = auth_value.partition(":")
        auth = httpx.BasicAuth(user, password)

    # Construire le body
    content = None
    json_data = None
    if json_body is not None:
        json_data = json_body
    elif body is not None:
        content = body.encode("utf-8")

    async with httpx.AsyncClient(verify=verify_ssl, timeout=timeout) as client:
        response = await client.request(
            method=method,
            url=url,
            headers=final_headers,
            json=json_data,
            content=content,
            auth=auth,
        )

        max_chars = settings.tool_max_output_chars
        response_body = response.text
        if len(response_body) > max_chars:
            response_body = response_body[:max_chars] + "... [TRUNCATED]"

        return {
            "status": "success",
            "status_code": response.status_code,
            "headers": dict(response.headers),
            "body": response_body,
            "sandbox": False,
        }


# =============================================================================
# Enregistrement MCP
# =============================================================================

def register(mcp: FastMCP) -> None:
    @mcp.tool()
    async def http(
        url: str,
        method: str = "GET",
        headers: Optional[Dict[str, str]] = None,
        body: Optional[str] = None,
        json_body: Optional[Dict[str, Any]] = None,
        auth_type: Optional[str] = None,
        auth_value: Optional[str] = None,
        timeout: int = 30,
        verify_ssl: bool = True,
        ctx: Optional[Context] = None,
    ) -> dict:
        """Client HTTP/REST dans un conteneur sandbox isolé (anti-SSRF, IPs privées bloquées). Méthodes : GET, POST, PUT, DELETE, PATCH, HEAD. Auth : basic, bearer, api_key."""
        try:
            check_tool_access("http")
            settings = get_settings()

            # Validation méthode
            method = method.upper()
            if method not in ALLOWED_METHODS:
                return {
                    "status": "error",
                    "message": f"Méthode '{method}' non autorisée. Valides : {', '.join(ALLOWED_METHODS)}",
                }

            # Validation auth_type
            if auth_type and auth_type not in ALLOWED_AUTH_TYPES:
                return {
                    "status": "error",
                    "message": f"Type d'auth '{auth_type}' non supporté. Valides : {', '.join(ALLOWED_AUTH_TYPES)}",
                }

            if auth_type and not auth_value:
                return {
                    "status": "error",
                    "message": f"auth_value requis quand auth_type est spécifié.",
                }

            # Validation anti-SSRF (URL + résolution DNS + RFC 1918)
            error = _validate_url(url)
            if error:
                return {"status": "error", "message": error}

            # Timeout depuis la config (pas de hardcode)
            timeout = max(1, min(timeout, settings.tool_max_timeout))

            # Headers par défaut
            final_headers = headers or {}

            # Exécution
            if settings.sandbox_enabled:
                result = await _run_in_sandbox(
                    url, method, final_headers, body, json_body,
                    auth_type, auth_value, timeout, verify_ssl, settings,
                )
            else:
                result = await _run_local(
                    url, method, final_headers, body, json_body,
                    auth_type, auth_value, timeout, verify_ssl, settings,
                )

            return result

        except asyncio.TimeoutError:
            return {"status": "error", "message": f"Timeout de {timeout}s dépassé."}
        except FileNotFoundError:
            return {"status": "error", "message": "Docker CLI non trouvé. Vérifiez que docker est installé et docker.sock monté."}
        except Exception as e:
            return {"status": "error", "message": str(e)}
