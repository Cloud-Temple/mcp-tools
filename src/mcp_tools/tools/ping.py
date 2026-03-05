# -*- coding: utf-8 -*-
"""
Outil: ping — Diagnostic réseau (ping, traceroute, nslookup, dig).

Exécuté dans le conteneur MCP Tools (pas de sandbox nécessaire :
ces commandes sont read-only et ne prennent pas de code arbitraire).
"""

import asyncio
from typing import Optional
from mcp.server.fastmcp import FastMCP, Context
from ..auth.context import check_tool_access
from ..config import get_settings


def _truncate(text: str, max_chars: int) -> str:
    """Tronque le texte si nécessaire, avec indication."""
    if len(text) > max_chars:
        return text[:max_chars] + f"\n... [TRONQUÉ — {len(text)} chars, limite {max_chars}]"
    return text


def register(mcp: FastMCP) -> None:
    @mcp.tool()
    async def ping(
        host: str,
        operation: str = "ping",
        count: int = 4,
        timeout: int = 15,
        ctx: Optional[Context] = None,
    ) -> dict:
        """Diagnostic réseau : ping, traceroute, nslookup ou dig. Opérations disponibles : ping (test connectivité), traceroute (chemin réseau), nslookup (résolution DNS), dig (requête DNS détaillée)."""
        try:
            check_tool_access("ping")
            settings = get_settings()

            count = max(1, min(count, 10))
            timeout = max(1, min(timeout, 30))

            commands = {
                "ping": f"ping -c {count} {host}",
                "traceroute": f"traceroute -m 15 {host}",
                "nslookup": f"nslookup {host}",
                "dig": f"dig {host} +short",
            }

            if operation not in commands:
                return {
                    "status": "error",
                    "message": f"Opération '{operation}' non supportée. Valides: {list(commands.keys())}",
                }

            cmd = commands[operation]

            process = await asyncio.create_subprocess_shell(
                cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=timeout)

            max_chars = settings.tool_max_output_chars
            return {
                "status": "success" if process.returncode == 0 else "error",
                "stdout": _truncate(stdout.decode(errors="replace").strip(), max_chars),
                "stderr": _truncate(stderr.decode(errors="replace").strip(), max_chars),
            }

        except asyncio.TimeoutError:
            return {"status": "error", "message": f"Timeout de {timeout}s dépassé."}
        except Exception as e:
            return {"status": "error", "message": str(e)}
