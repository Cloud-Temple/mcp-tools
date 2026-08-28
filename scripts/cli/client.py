# -*- coding: utf-8 -*-
"""
Client Streamable HTTP pour communiquer avec le serveur MCP.

Ce client gère :
- La connexion Streamable HTTP (endpoint /mcp)
- L'appel d'outils MCP via le SDK officiel
- La réception des notifications de progression
- La gestion des erreurs et reconnexion
"""

import json
import asyncio
from typing import Optional, Callable, Any


class MCPClient:
    """Client MCP générique via Streamable HTTP."""

    def __init__(self, base_url: str, token: str = "", timeout: float = 300.0):
        self.base_url = base_url.rstrip("/")
        self.token = token
        self.timeout = timeout

    async def call_tool(
        self,
        tool_name: str,
        arguments: dict,
        on_progress: Optional[Callable] = None,
    ) -> dict:
        """
        Appelle un outil MCP via Streamable HTTP.

        Args:
            tool_name: Nom de l'outil (ex: "system_health")
            arguments: Paramètres de l'outil
            on_progress: Callback optionnel pour les notifications (async callable)

        Returns:
            Le résultat de l'outil (dict)
        """
        import httpx2
        from mcp import ClientSession
        from mcp.client.streamable_http import streamable_http_client

        headers = {}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"

        async def progress_callback(progress: float, total: float | None, message: str | None) -> None:
            if on_progress:
                label = message or (f"Progression : {progress:g}/{total:g}" if total is not None else f"Progression : {progress:g}")
                await on_progress(label)

        try:
            async with httpx2.AsyncClient(
                headers=headers,
                timeout=httpx2.Timeout(30, read=self.timeout),
                follow_redirects=True,
            ) as http_client:
                async with streamable_http_client(
                    f"{self.base_url}/mcp",
                    http_client=http_client,
                ) as (read, write):
                    async with ClientSession(read, write) as session:
                        await session.initialize()

                        result = await session.call_tool(
                            tool_name,
                            arguments,
                            progress_callback=progress_callback if on_progress else None,
                        )

                        # Parser la réponse MCP
                        if getattr(result, 'is_error', False):
                            error_msg = "Erreur serveur MCP"
                            if result.content:
                                error_msg = getattr(result.content[0], 'text', '') or error_msg
                            return {"status": "error", "message": error_msg}

                        text = ""
                        if result.content:
                            text = getattr(result.content[0], 'text', '') or ""
                        if not text:
                            return {"status": "error", "message": "Réponse vide"}

                        try:
                            return json.loads(text)
                        except json.JSONDecodeError:
                            return {"status": "ok", "raw": text}

        except ConnectionRefusedError:
            return {"status": "error", "message": f"Serveur non accessible: {self.base_url}"}
        except BaseException as e:
            # Extraire la vraie erreur des ExceptionGroup (MCP SDK TaskGroup)
            msg = self._extract_error(e)
            return {"status": "error", "message": msg}

    @staticmethod
    def _extract_error(exc: BaseException) -> str:
        """Extrait un message lisible, même depuis un ExceptionGroup."""
        if hasattr(exc, "exceptions"):
            # ExceptionGroup / TaskGroup — chercher la vraie sous-exception
            msgs = []
            for sub in exc.exceptions:
                sub_msg = MCPClient._extract_error(sub)  # récursif
                msgs.append(sub_msg)
            return "; ".join(msgs)

        msg = str(exc)

        # Détecter les erreurs d'auth courantes
        if "401" in msg or "Unauthorized" in msg:
            return "Authentification refusée (401). Vérifiez MCP_TOKEN ou ADMIN_BOOTSTRAP_KEY dans .env"
        if "403" in msg or "Forbidden" in msg:
            return "Accès interdit (403). Token insuffisant."

        return msg or type(exc).__name__

    async def call_rest(self, method: str = "GET", path: str = "/health") -> dict:
        """
        Appel REST simple (sans protocole MCP).
        Utile pour /health, /healthz, /ready qui ne nécessitent pas d'auth.
        """
        import httpx
        try:
            async with httpx.AsyncClient(timeout=10) as http:
                resp = await http.request(method, f"{self.base_url}{path}")
                try:
                    return resp.json()
                except Exception:
                    return {"status": "error", "message": resp.text, "status_code": resp.status_code}
        except httpx.ConnectError:
            return {"status": "error", "message": f"Serveur non accessible: {self.base_url}"}
        except Exception as e:
            return {"status": "error", "message": str(e)}

    async def list_tools(self) -> list:
        """Liste les outils MCP disponibles."""
        result = await self.call_tool("system_about", {})
        return result.get("tools", [])
