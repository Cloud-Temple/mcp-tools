# -*- coding: utf-8 -*-
"""Point d'entrée du service MCP séparé ``mcp-cybersec``."""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

from mcp.server.mcpserver import MCPServer

from .auth import CybersecAuthMiddleware
from .config import get_settings
from .services import CybersecServices, build_services


settings = get_settings()
mcp = MCPServer(name=settings.cybersec_mcp_server_name)

from .tools import register_all_tools
register_all_tools(mcp)

_services: CybersecServices | None = None


def get_services() -> CybersecServices:
    global _services
    if _services is None:
        _services = build_services(settings)
    return _services


class HealthCheckMiddleware:
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] == "http" and scope.get("path") in {"/health", "/healthz", "/ready"}:
            body = json.dumps({
                "status": "healthy", "service": settings.cybersec_mcp_server_name,
                "version": _version(), "transport": "streamable-http",
            }).encode("utf-8")
            await send({"type": "http.response.start", "status": 200, "headers": [(b"content-type", b"application/json"), (b"content-length", str(len(body)).encode())]})
            await send({"type": "http.response.body", "body": body})
            return
        await self.app(scope, receive, send)


def create_app():
    # Réutilisation de l'observabilité éprouvée du socle. Chaque service est
    # dans son conteneur/processus : les buffers et les identités restent isolés.
    from src.mcp_tools.auth.middleware import LoggingMiddleware
    from src.mcp_tools.observability import ActivityMiddleware
    from .admin import CybersecAdminMiddleware

    app = mcp.streamable_http_app(host=settings.cybersec_mcp_server_host)
    app = HealthCheckMiddleware(app)
    app = CybersecAdminMiddleware(app, mcp, get_services)
    app = CybersecAuthMiddleware(app, settings, lambda: get_services().tokens)
    app = LoggingMiddleware(app)
    app = ActivityMiddleware(app)
    return app


def _version() -> str:
    try:
        return (Path(__file__).resolve().parents[2] / "VERSION").read_text().strip()
    except OSError:
        return "dev"


async def _banner() -> str:
    tools = await mcp.list_tools()
    return "\n".join([
        "╔══════════════════════════════════════════════════╗",
        f"║ {settings.cybersec_mcp_server_name:<48} ║",
        "╠══════════════════════════════════════════════════╣",
        f"║ version {_version():<40} ║",
        f"║ outils {len(tools):<41} ║",
        f"║ http://{settings.cybersec_mcp_server_host}:{settings.cybersec_mcp_server_port}/mcp".ljust(49) + "║",
        "╚══════════════════════════════════════════════════╝",
    ])


def _security_checks() -> None:
    if settings.cybersec_admin_bootstrap_key == "change_me_in_production":
        print("⚠️  CYBERSEC_ADMIN_BOOTSTRAP_KEY utilise la valeur par défaut : déploiement interdit.", file=sys.stderr, flush=True)
    if not settings.cybersec_s3_endpoint_url:
        print("⚠️  CYBERSEC_S3_ENDPOINT_URL absent : les outils persistants échoueront fail-closed.", file=sys.stderr, flush=True)


def main() -> None:
    import uvicorn

    print(asyncio.run(_banner()), file=sys.stderr, flush=True)
    _security_checks()
    uvicorn.run(create_app(), host=settings.cybersec_mcp_server_host, port=settings.cybersec_mcp_server_port, log_level="warning")


if __name__ == "__main__":
    main()
