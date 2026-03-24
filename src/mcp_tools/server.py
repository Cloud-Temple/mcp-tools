# -*- coding: utf-8 -*-
"""
Serveur MCP Tools — Point d'entrée principal.
"""

import sys
import platform
from pathlib import Path

from mcp.server.fastmcp import FastMCP
from .config import get_settings

# =============================================================================
# Instance FastMCP
# =============================================================================

settings = get_settings()

mcp = FastMCP(
    name=settings.mcp_server_name,
    host=settings.mcp_server_host,
    port=settings.mcp_server_port,
)

# =============================================================================
# Import et enregistrement automatique des outils
# =============================================================================
# On importe les modules de tools qui contiendront les décorateurs @mcp.tool()
# Les outils s'enregistrent eux-mêmes auprès de l'instance `mcp`.

from .tools import register_all_tools
from .auth.context import check_tool_access

register_all_tools(mcp)


# =============================================================================
# Outils Systèmes MCP Tools
# =============================================================================

@mcp.tool()
async def system_health() -> dict:
    """Vérifie l'état de santé du service MCP Tools. Retourne le statut, la version, le nombre d'outils et l'état de la sandbox."""
    try:
        check_tool_access("system_health")

        version = "dev"
        version_file = Path(__file__).parent.parent.parent / "VERSION"
        if version_file.exists():
            version = version_file.read_text().strip()

        tools_count = len(mcp._tool_manager.list_tools())

        return {
            "status": "ok",
            "service_name": settings.mcp_server_name,
            "version": version,
            "tools_count": tools_count,
            "sandbox_enabled": settings.sandbox_enabled,
        }
    except Exception as e:
        return {"status": "error", "message": str(e)}

@mcp.tool()
async def system_about() -> dict:
    """Informations détaillées sur le service MCP Tools : version, plateforme, liste complète des outils avec descriptions."""
    try:
        check_tool_access("system_about")

        version = "dev"
        version_file = Path(__file__).parent.parent.parent / "VERSION"
        if version_file.exists():
            version = version_file.read_text().strip()

        tools = []
        for tool in mcp._tool_manager.list_tools():
            # Extraire uniquement la première ligne du docstring
            raw_desc = (tool.description or "").strip()
            first_line = raw_desc.split("\n")[0].strip()
            tools.append({
                "name": tool.name,
                "description": first_line,
            })

        return {
            "status": "ok",
            "service_name": settings.mcp_server_name,
            "version": version,
            "python_version": platform.python_version(),
            "platform": platform.platform(),
            "tools_count": len(tools),
            "tools": tools,
        }
    except Exception as e:
        return {"status": "error", "message": str(e)}


# =============================================================================
# Assemblage ASGI
# =============================================================================

def create_app():
    from .auth.middleware import AuthMiddleware, LoggingMiddleware
    from .admin.middleware import AdminMiddleware

    app = mcp.streamable_http_app()
    app = LoggingMiddleware(app)
    app = AuthMiddleware(app)
    app = HealthCheckMiddleware(app)
    app = AdminMiddleware(app, mcp)  # /admin, /admin/static/*, /admin/api/*

    return app


class HealthCheckMiddleware:
    """Middleware ASGI qui intercepte /health et retourne un JSON directement."""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] == "http" and scope.get("path") in ("/health", "/healthz", "/ready"):
            import json
            version = "dev"
            version_file = Path(__file__).parent.parent.parent / "VERSION"
            if version_file.exists():
                version = version_file.read_text().strip()
            body = json.dumps({
                "status": "healthy",
                "service": settings.mcp_server_name,
                "version": version,
                "transport": "streamable-http",
            }).encode()
            await send({
                "type": "http.response.start",
                "status": 200,
                "headers": [
                    (b"content-type", b"application/json"),
                    (b"content-length", str(len(body)).encode()),
                ],
            })
            await send({"type": "http.response.body", "body": body})
            return
        await self.app(scope, receive, send)

# =============================================================================
# Point d'entrée
# =============================================================================

def _display_width(text: str) -> int:
    """Largeur d'affichage terminal (emojis/CJK = 2 colonnes)."""
    import unicodedata
    return sum(2 if unicodedata.east_asian_width(c) in ('W', 'F') else 1 for c in text)


def _build_banner() -> str:
    """Construit la bannière de démarrage alignée proprement."""
    tools_list = mcp._tool_manager.list_tools()

    W = 50  # largeur totale d'affichage (╔ + ═*48 + ╗)
    IW = W - 2  # largeur intérieure entre les ║

    top    = "╔" + "═" * IW + "╗"
    sep    = "╠" + "═" * IW + "╣"
    bottom = "╚" + "═" * IW + "╝"
    empty  = "║" + " " * IW + "║"

    def pad(text: str) -> str:
        """Ligne ║ text...spaces ║ alignée sur IW colonnes."""
        dw = _display_width(text)
        return "║" + text + " " * max(0, IW - dw) + "║"

    def center(text: str) -> str:
        """Ligne ║ ...text centré... ║."""
        dw = _display_width(text)
        total_pad = IW - dw
        left = total_pad // 2
        right = total_pad - left
        return "║" + " " * left + text + " " * right + "║"

    lines = [top]
    lines.append(center(settings.mcp_server_name))
    lines.append(sep)
    lines.append(empty)

    # Liste complète des tools
    lines.append(pad(f"  🔧 Outils ({len(tools_list)}) :"))
    for t in tools_list:
        lines.append(pad(f"     • {t.name}"))
    lines.append(empty)

    # Infos serveur
    hp = f"{settings.mcp_server_host}:{settings.mcp_server_port}"
    lines.append(pad(f"  🌐 http://{hp}"))
    lines.append(pad(f"  🔗 http://{hp}/mcp"))
    lines.append(pad(f"  🛠️  http://{hp}/admin"))
    lines.append(empty)
    lines.append(bottom)

    return "\n".join(lines)


def _security_checks():
    """Vérifications de sécurité au démarrage (§3.7, sandbox)."""

    # §3.7 — Bootstrap key par défaut = risque critique
    if settings.admin_bootstrap_key == "change_me_in_production":
        print(
            "\n"
            "  ╔══════════════════════════════════════════════════╗\n"
            "  ║  ⚠️  SÉCURITÉ CRITIQUE                          ║\n"
            "  ║                                                  ║\n"
            "  ║  ADMIN_BOOTSTRAP_KEY est la valeur par défaut !  ║\n"
            "  ║  Toute personne ayant lu le code source peut     ║\n"
            "  ║  obtenir un accès admin complet au serveur.      ║\n"
            "  ║                                                  ║\n"
            "  ║  → Définir ADMIN_BOOTSTRAP_KEY dans .env         ║\n"
            "  ╚══════════════════════════════════════════════════╝\n",
            file=sys.stderr, flush=True,
        )

    # Warning si sandbox désactivée (exécution locale = RCE)
    if not settings.sandbox_enabled:
        print(
            "  ⚠️  SANDBOX DÉSACTIVÉE — les outils shell/calc/network s'exécutent "
            "directement sur l'hôte. Ne pas utiliser en production !",
            file=sys.stderr, flush=True,
        )


def main():
    import uvicorn

    print("\n" + _build_banner() + "\n", file=sys.stderr)

    # Vérifications de sécurité (§3.7, sandbox)
    _security_checks()

    # Initialiser le Token Store (charge les tokens depuis S3)
    from .auth.token_store import init_token_store
    init_token_store()

    app = create_app()

    uvicorn.run(
        app,
        host=settings.mcp_server_host,
        port=settings.mcp_server_port,
        log_level="warning",
    )

if __name__ == "__main__":
    main()
