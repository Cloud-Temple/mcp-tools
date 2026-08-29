# -*- coding: utf-8 -*-
"""
Middlewares ASGI : authentification pour mcp-tools.
Vérifie le Bearer token et injecte ses infos pour les outils.
"""

import hmac
import json
import time
import sys
from typing import Optional

from .context import current_token_info
from ..config import get_settings
from ..observability import bind_activity, get_activity_context, record_activity


class AuthMiddleware:
    PUBLIC_PATHS = {"/health", "/healthz", "/ready", "/favicon.ico"}
    PUBLIC_PREFIXES = ("/static/",)

    # MCP SDK >= 2025-11-25 sonde ces endpoints après un 401 sur /mcp.
    # Un 401 ici = "serveur cassé" (le SDK abandonne).
    # Un 404 = "pas d'OAuth, utiliser un Bearer token statique".
    # Ref: RFC 9728, MCP Authorization spec 2025-11-25.
    OAUTH_DENY_PREFIXES = ("/.well-known/",)
    OAUTH_DENY_PATHS = {"/register"}

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] not in ("http", "websocket"):
            return await self.app(scope, receive, send)

        path = scope.get("path", "")

        if path in self.PUBLIC_PATHS:
            return await self.app(scope, receive, send)

        if any(path.startswith(p) for p in self.PUBLIC_PREFIXES):
            return await self.app(scope, receive, send)

        # OAuth discovery — retourner 404, jamais 401 (voir OAUTH_DENY_*)
        if path in self.OAUTH_DENY_PATHS or any(path.startswith(p) for p in self.OAUTH_DENY_PREFIXES):
            await self._send_error(send, 404, "Not Found")
            return

        token = self._extract_token(scope)
        token_info = None

        if token:
            token_info = self._validate_token(token)

        if token_info is None:
            if path == "/mcp":
                record_activity(
                    "auth.rejected", level="warning",
                    message="Authentification MCP refusée",
                    details={"reason": "missing_or_invalid_bearer"},
                )
            await self._send_error(send, 401, "Authorization header required ou invalide")
            return

        if path == "/mcp":
            actor = token_info.get("client_name", "?")
            bind_activity(actor=actor, auth_role="admin" if "admin" in token_info.get("permissions", []) else "access")
            record_activity(
                "auth.accepted", message="Authentification MCP acceptée",
                details={"role": "admin" if "admin" in token_info.get("permissions", []) else "access"},
            )

        tok = current_token_info.set(token_info)
        try:
            await self.app(scope, receive, send)
        finally:
            current_token_info.reset(tok)

    def _extract_token(self, scope) -> Optional[str]:
        """Extrait le Bearer token depuis le header Authorization uniquement.

        Note sécurité (§3.8) : le support query string (?token=) a été supprimé
        car les URLs sont loguées par les proxies, WAF, navigateurs et headers Referer.
        """
        headers = dict(scope.get("headers", []))
        auth = headers.get(b"authorization", b"").decode()
        if auth.startswith("Bearer "):
            return auth[7:]
        return None

    def _validate_token(self, token: str) -> Optional[dict]:
        settings = get_settings()

        # 1. Bootstrap key admin — comparaison temps constant (§3.6)
        if hmac.compare_digest(token, settings.admin_bootstrap_key):
            return {
                "client_name": "admin",
                "permissions": ["admin", "access"],
                "tool_ids": [],  # Admin = all tools
            }

        # 2. Lookup dans le Token Store S3
        from .token_store import get_token_store
        store = get_token_store()
        token_info = store.validate_token(token)
        if token_info is not None:
            return token_info

        return None

    async def _send_error(self, send, status: int, message: str):
        body = json.dumps({"error": message}).encode()
        await send({
            "type": "http.response.start",
            "status": status,
            "headers": [
                (b"content-type", b"application/json"),
                (b"content-length", str(len(body)).encode()),
            ],
        })
        await send({"type": "http.response.body", "body": body})

class LoggingMiddleware:
    _QUIET_PATHS = {"/health", "/admin/api/activity", "/admin/api/logs", "/admin/api/audit"}

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)

        path = scope.get("path", "")
        method = scope.get("method", "?")
        t0 = time.monotonic()
        status_code = 0

        async def send_wrapper(message):
            nonlocal status_code
            if message["type"] == "http.response.start":
                candidate_status = message.get("status", 0)
                await send(message)
                # L'ASGI aval a accepté les en-têtes : seulement maintenant
                # le statut est une observation fiable pour le journal HTTP.
                status_code = candidate_status
                return
            await send(message)

        try:
            await self.app(scope, receive, send_wrapper)
        except Exception:
            # Si un handler échoue avant d'émettre ses headers, l'ASGI
            # extérieur rendra un 500. Le journal doit refléter ce résultat,
            # pas le code sentinelle 0.
            if not status_code:
                status_code = 500
            raise
        finally:
            elapsed = round((time.monotonic() - t0) * 1000, 1)
            if path not in self._QUIET_PATHS and not path.startswith("/admin/static/"):
                print(f"📡 {method} {path} → {status_code} ({elapsed}ms)", file=sys.stderr)
                # Ce middleware voit la réponse effectivement émise, y compris
                # pour /admin/api. C'est donc la source unique du journal HTTP
                # corrélé : les handlers Admin ne doivent pas deviner un 200.
                try:
                    from ..admin.api import add_log
                    actor = str(get_activity_context().get("actor", ""))
                    add_log(method, path, status_code, elapsed, actor)
                except Exception:
                    # L'observabilité ne doit jamais altérer une réponse.
                    pass
