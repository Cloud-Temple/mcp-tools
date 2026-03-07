# -*- coding: utf-8 -*-
"""
Outil: network — Diagnostic réseau (ping, traceroute, nslookup, dig).

Exécuté dans un conteneur Docker sandbox éphémère AVEC accès réseau
(--network=bridge, --cap-add=NET_RAW). Les IPs privées RFC 1918
sont interdites pour empêcher le scan de l'infrastructure interne.

Sécurité :
  - Conteneur éphémère (--rm), read-only, non-root, cap-drop=ALL + cap-add=NET_RAW
  - Validation stricte du host (caractères autorisés)
  - Blocage des IPs privées RFC 1918, loopback, link-local
  - Timeout configurable, output tronqué
"""

import asyncio
import ipaddress
import re
import uuid
from typing import Optional
from mcp.server.fastmcp import FastMCP, Context
from ..auth.context import check_tool_access
from ..config import get_settings


# =============================================================================
# Validation du host
# =============================================================================

# Caractères autorisés dans un hostname/IP (alphanum, points, tirets, deux-points IPv6)
_HOST_PATTERN = re.compile(r"^[a-zA-Z0-9._:\-]+$")

# Réseaux bloqués (RFC 1918 + loopback + link-local + réservés)
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


def _validate_host(host: str) -> Optional[str]:
    """
    Valide le paramètre host. Retourne un message d'erreur ou None si OK.

    Vérifie :
    1. Caractères autorisés (pas d'injection)
    2. IP privée RFC 1918 interdite
    """
    if not host or not host.strip():
        return "Le paramètre 'host' est requis."

    host = host.strip()

    if not _HOST_PATTERN.match(host):
        return f"Host invalide : '{host}'. Seuls les caractères alphanumériques, points, tirets et deux-points sont autorisés."

    # Vérifier si c'est une IP privée
    try:
        ip = ipaddress.ip_address(host)
        for net in _BLOCKED_NETWORKS:
            if ip in net:
                return f"IP privée/réservée interdite : {host} (réseau {net}). Seules les IPs publiques sont autorisées."
    except ValueError:
        pass  # C'est un hostname, pas une IP → OK

    return None


# =============================================================================
# Helpers
# =============================================================================

def _truncate(text: str, max_chars: int) -> str:
    """Tronque le texte si nécessaire, avec indication."""
    if len(text) > max_chars:
        return text[:max_chars] + f"\n... [TRONQUÉ — {len(text)} chars, limite {max_chars}]"
    return text


# Caractères autorisés dans les extra_args (pas de ;|&$` ni backticks)
_ARG_PATTERN = re.compile(r"^[a-zA-Z0-9._:\-=+/@,]+$")


def _validate_extra_args(extra_args: str) -> Optional[str]:
    """Valide les arguments supplémentaires. Retourne un message d'erreur ou None."""
    if not extra_args:
        return None
    for arg in extra_args.split():
        if not _ARG_PATTERN.match(arg):
            return f"Argument invalide : '{arg}'. Caractères shell interdits (;|&$`)."
    return None


def _build_command(operation: str, host: str, extra_args: str = "") -> list[str]:
    """
    Construit la liste d'arguments pour la commande réseau.
    extra_args : arguments supplémentaires passés à la commande (ex: "-c 2", "-type=mx", "MX +short").
    Pour dig, les extra vont APRÈS le host. Pour les autres, AVANT.
    """
    extra = extra_args.split() if extra_args else []
    commands = {
        "ping":       ["ping"] + extra + [host],
        "traceroute": ["traceroute"] + extra + [host],
        "nslookup":   ["nslookup"] + extra + [host],
        "dig":        ["dig", host] + extra,
    }
    return commands.get(operation, [])


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


async def _run_in_sandbox(operation: str, host: str, extra_args: str, timeout: int, settings) -> dict:
    """Exécute la commande réseau dans un conteneur Docker éphémère avec accès réseau."""
    cmd_args = _build_command(operation, host, extra_args)
    container_name = f"network-{uuid.uuid4().hex[:12]}"

    docker_cmd = [
        "docker", "run", "--rm",
        f"--name={container_name}",
        "--network=bridge",
        "--read-only",
        "--cap-drop=ALL",
        "--cap-add=NET_RAW",
        f"--memory={settings.sandbox_memory}",
        f"--memory-swap={settings.sandbox_memory}",
        f"--cpus={settings.sandbox_cpus}",
        f"--pids-limit={settings.sandbox_pids_limit}",
        "--security-opt=no-new-privileges:true",
        f"--tmpfs=/tmp:noexec,nosuid,nodev,size={settings.sandbox_tmpfs_size}",
        "--user=sandbox:sandbox",
        *[f"--dns={d.strip()}" for d in settings.sandbox_dns.split(",") if d.strip()],
        settings.sandbox_image,
    ] + cmd_args

    process = await asyncio.create_subprocess_exec(
        *docker_cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )

    try:
        stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        try:
            process.kill()
            await process.wait()
        except Exception:
            pass
        await _kill_container(container_name)
        raise

    max_chars = settings.tool_max_output_chars
    return {
        "status": "success" if process.returncode == 0 else "error",
        "operation": operation,
        "host": host,
        "stdout": _truncate(stdout.decode(errors="replace").strip(), max_chars),
        "stderr": _truncate(stderr.decode(errors="replace").strip(), max_chars),
        "returncode": process.returncode,
        "sandbox": True,
    }


async def _run_local(operation: str, host: str, extra_args: str, timeout: int, settings) -> dict:
    """Fallback : exécution locale via subprocess (dev sans Docker)."""
    cmd_args = _build_command(operation, host, extra_args)

    process = await asyncio.create_subprocess_exec(
        *cmd_args,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )

    try:
        stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        try:
            process.kill()
            await process.wait()
        except Exception:
            pass
        raise

    max_chars = settings.tool_max_output_chars
    return {
        "status": "success" if process.returncode == 0 else "error",
        "operation": operation,
        "host": host,
        "stdout": _truncate(stdout.decode(errors="replace").strip(), max_chars),
        "stderr": _truncate(stderr.decode(errors="replace").strip(), max_chars),
        "returncode": process.returncode,
        "sandbox": False,
    }


# =============================================================================
# Enregistrement MCP
# =============================================================================

ALLOWED_OPERATIONS = ("ping", "traceroute", "nslookup", "dig")


def register(mcp: FastMCP) -> None:
    @mcp.tool()
    async def network(
        host: str,
        operation: str = "ping",
        extra_args: str = "",
        count: int = 4,
        timeout: int = 15,
        ctx: Optional[Context] = None,
    ) -> dict:
        """Diagnostic réseau dans un conteneur sandbox isolé. Opérations : ping, traceroute, nslookup, dig. Passez des arguments via extra_args (ex: '-c 2' pour ping, '-type=mx' pour nslookup, 'MX +short' pour dig). IPs privées RFC 1918 interdites."""
        try:
            check_tool_access("network")
            settings = get_settings()

            # Validation de l'opération
            if operation not in ALLOWED_OPERATIONS:
                return {
                    "status": "error",
                    "message": f"Opération '{operation}' non supportée. Valides : {', '.join(ALLOWED_OPERATIONS)}",
                }

            # Validation du host (caractères + RFC 1918)
            error = _validate_host(host)
            if error:
                return {"status": "error", "message": error}

            # Defaults par opération quand pas d'extra_args fourni
            if not extra_args:
                if operation == "ping":
                    count = max(1, min(count, 10))
                    extra_args = f"-c {count}"
                elif operation == "traceroute":
                    extra_args = "-m 15 -w 3"

            # Validation des extra_args (pas de caractères shell)
            error = _validate_extra_args(extra_args)
            if error:
                return {"status": "error", "message": error}

            # Bornes de sécurité
            timeout = max(1, min(timeout, 30))

            # Exécution
            if settings.sandbox_enabled:
                result = await _run_in_sandbox(operation, host, extra_args, timeout, settings)
            else:
                result = await _run_local(operation, host, extra_args, timeout, settings)

            return result

        except asyncio.TimeoutError:
            return {"status": "error", "message": f"Timeout de {timeout}s dépassé."}
        except FileNotFoundError:
            return {"status": "error", "message": "Docker CLI non trouvé. Vérifiez que docker est installé et docker.sock monté."}
        except Exception as e:
            return {"status": "error", "message": str(e)}
