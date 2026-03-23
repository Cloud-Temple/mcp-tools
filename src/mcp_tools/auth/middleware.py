# -*- coding: utf-8 -*-
"""
Middlewares ASGI : authentification pour mcp-tools.
Vérifie le Bearer token et injecte ses infos pour les outils.
"""

import json
import time
import sys
from typing import Optional

from .context import current_token_info
from ..config import get_settings


class AuthMiddleware:
    PUBLIC_PATHS = {"/health", "/healthz", "/ready", "/favicon.ico"}
    PUBLIC_PREFIXES = ("/static/",)

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

        token = self._extract_token(scope)
        token_info = None

        if token:
            token_info = self._validate_token(token)

        if token_info is None:
            await self._send_error(send, 401, "Authorization header required ou invalide")
            return

        tok = current_token_info.set(token_info)
        try:
            await self.app(scope, receive, send)
        finally:
            current_token_info.reset(tok)

    def _extract_token(self, scope) -> Optional[str]:
        headers = dict(scope.get("headers", []))
        auth = headers.get(b"authorization", b"").decode()
        if auth.startswith("Bearer "):
            return auth[7:]

        qs = scope.get("query_string", b"").decode()
        for param in qs.split("&"):
            if param.startswith("token="):
                return param[6:]
        return None

    def _validate_token(self, token: str) -> Optional[dict]:
        settings = get_settings()

        # 1. Bootstrap key admin (fast path)
        if token == settings.admin_bootstrap_key:
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
                status_code = message.get("status", 0)
            await send(message)

        try:
            await self.app(scope, receive, send_wrapper)
        finally:
            elapsed = round((time.monotonic() - t0) * 1000, 1)
            if path not in ("/health",):
                print(f"📡 {method} {path} → {status_code} ({elapsed}ms)", file=sys.stderr)
