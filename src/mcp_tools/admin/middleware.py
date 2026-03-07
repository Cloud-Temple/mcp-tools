# -*- coding: utf-8 -*-
"""
AdminMiddleware — Sert l'interface /admin et route les /admin/api/*.

Intercepte :
  GET /admin          → admin.html (SPA)
  GET /admin/static/* → fichiers statiques (CSS, JS, images)
  *   /admin/api/*    → API REST admin (délégué à api.py)
"""

import mimetypes
from pathlib import Path

from .api import handle_admin_api

# Répertoire des fichiers statiques
STATIC_DIR = Path(__file__).parent.parent / "static"


class AdminMiddleware:
    """Middleware ASGI qui gère toute la partie /admin."""

    def __init__(self, app, mcp_instance):
        self.app = app
        self.mcp_instance = mcp_instance

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)

        path = scope.get("path", "")

        # ── /admin/api/* → API REST ──
        if path.startswith("/admin/api/"):
            return await handle_admin_api(scope, receive, send, self.mcp_instance)

        # ── /admin → SPA HTML ──
        if path in ("/admin", "/admin/"):
            return await self._serve_file(send, STATIC_DIR / "admin.html", "text/html")

        # ── /admin/static/* → fichiers statiques ──
        if path.startswith("/admin/static/"):
            rel = path[len("/admin/static/"):]
            file_path = STATIC_DIR / rel

            # Sécurité : pas de path traversal
            try:
                file_path = file_path.resolve()
                static_resolved = STATIC_DIR.resolve()
                if not str(file_path).startswith(str(static_resolved)):
                    return await self._send_404(send)
            except Exception:
                return await self._send_404(send)

            if file_path.is_file():
                content_type = mimetypes.guess_type(str(file_path))[0] or "application/octet-stream"
                return await self._serve_file(send, file_path, content_type)
            else:
                return await self._send_404(send)

        # ── Tout le reste → pipeline normal ──
        return await self.app(scope, receive, send)

    async def _serve_file(self, send, filepath: Path, content_type: str):
        """Sert un fichier statique."""
        try:
            body = filepath.read_bytes()
        except Exception:
            return await self._send_404(send)

        await send({
            "type": "http.response.start",
            "status": 200,
            "headers": [
                (b"content-type", content_type.encode()),
                (b"content-length", str(len(body)).encode()),
                (b"cache-control", b"no-cache"),
            ],
        })
        await send({"type": "http.response.body", "body": body})

    async def _send_404(self, send):
        """Retourne 404."""
        body = b'{"error": "Not found"}'
        await send({
            "type": "http.response.start",
            "status": 404,
            "headers": [
                (b"content-type", b"application/json"),
                (b"content-length", str(len(body)).encode()),
            ],
        })
        await send({"type": "http.response.body", "body": body})
