# -*- coding: utf-8 -*-
"""
Serveur MCP — Point d'entrée principal.

Ce fichier :
1. Crée l'instance FastMCP
2. Déclare les outils MCP (@mcp.tool())
3. Assemble la chaîne de 5 middlewares ASGI
4. Démarre le serveur Uvicorn

Usage :
    python -m mon_service
"""

import sys
import json
import unicodedata
import platform
from typing import Optional
from pathlib import Path

from mcp.server.fastmcp import FastMCP, Context

from .config import get_settings
from .auth.context import check_access, check_write_permission

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
# Getters lazy-load pour les services métier
# =============================================================================
# Ajouter ici vos services (base de données, APIs externes, etc.)
# Ne JAMAIS instancier au top-level — toujours via getter singleton.

# _my_db = None
# def get_db():
#     global _my_db
#     if _my_db is None:
#         from .core.database import DatabaseService
#         _my_db = DatabaseService()
#     return _my_db


# =============================================================================
# Outils MCP — Système (inclus dans le boilerplate)
# =============================================================================

@mcp.tool()
async def system_health() -> dict:
    """
    Vérifie l'état de santé du service.

    Retourne le statut de chaque service backend.
    Cet outil ne nécessite aucune authentification.

    Returns:
        État global du système et détails par service
    """
    results = {}

    # TODO: Ajouter vos checks de services métier ici
    # Exemple :
    # try:
    #     results["database"] = await get_db().test_connection()
    # except Exception as e:
    #     results["database"] = {"status": "error", "message": str(e)}

    # Service factice pour le boilerplate
    results["server"] = {"status": "ok", "uptime": "running"}

    all_ok = all(r.get("status") == "ok" for r in results.values())

    return {
        "status": "ok" if all_ok else "error",
        "service_name": settings.mcp_server_name,
        "services": results,
    }


@mcp.tool()
async def system_about() -> dict:
    """
    Informations sur le service MCP.

    Retourne la version, les outils disponibles, et les infos système.
    Cet outil ne nécessite aucune authentification.

    Returns:
        Métadonnées du service
    """
    version = "dev"
    version_file = Path(__file__).parent.parent.parent / "VERSION"
    if version_file.exists():
        version = version_file.read_text().strip()

    tools = []
    for tool in mcp._tool_manager.list_tools():
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


# =============================================================================
# Outils MCP — Votre domaine métier
# =============================================================================
# Ajouter vos outils ici. Chaque outil suit le pattern :
#
# from typing import Annotated
# from pydantic import Field
#
# @mcp.tool()
# async def mon_outil(
#     resource_id: Annotated[str, Field(description="ID de la ressource à traiter")],
#     action: Annotated[str, Field(default="read", description="Action : read, write, delete")] = "read",
#     timeout: Annotated[int, Field(default=30, description="Timeout en secondes (max 60)")] = 30,
#     ctx: Optional[Context] = None,
# ) -> dict:
#     """Description courte visible par les agents IA et dans Cline."""
#     try:
#         access_err = check_access(resource_id)
#         if access_err:
#             return access_err
#         result = await get_my_service().do_something(resource_id)
#         return {"status": "ok", "data": result}
#     except Exception as e:
#         return {"status": "error", "message": str(e)}
#
# ⚠️ IMPORTANT : chaque paramètre DOIT utiliser Annotated[type, Field(description="...")]
#   pour que les clients MCP (Cline, Claude Desktop) affichent les descriptions.
#   Seul ctx: Optional[Context] est exempt (interne FastMCP).


# =============================================================================
# HealthCheckMiddleware — /health, /healthz, /ready (sans auth)
# =============================================================================

class HealthCheckMiddleware:
    """
    Middleware ASGI qui intercepte les endpoints de health check.

    Retourne un JSON directement SANS passer par MCP ni par l'auth.
    Permet au WAF/load balancer de vérifier l'état du service.
    """

    HEALTH_PATHS = {"/health", "/healthz", "/ready"}

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] == "http" and scope.get("path") in self.HEALTH_PATHS:
            version = "dev"
            version_file = Path(__file__).parent.parent.parent / "VERSION"
            if version_file.exists():
                version = version_file.read_text().strip()
            body = json.dumps({
                "status": "ok",
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
# Assemblage ASGI — Chaîne de 5 middlewares
# =============================================================================

def create_app():
    """
    Crée l'application ASGI complète avec les middlewares.

    Pile d'exécution (ext → int) :
        AdminMiddleware → HealthCheckMiddleware → AuthMiddleware → LoggingMiddleware → FastMCP

    L'AdminMiddleware intercepte /admin, /admin/static/*, /admin/api/*
    Le HealthCheckMiddleware intercepte /health, /healthz, /ready
    L'AuthMiddleware valide le Bearer token et injecte dans ContextVar
    Le LoggingMiddleware logue les requêtes dans un ring buffer mémoire
    Le FastMCP gère le protocole MCP (Streamable HTTP)
    """
    from .auth.middleware import AuthMiddleware, LoggingMiddleware
    from .admin.middleware import AdminMiddleware

    # L'app de base est le Streamable HTTP handler du SDK MCP
    app = mcp.streamable_http_app()

    # Empiler les middlewares (dernier ajouté = premier exécuté)
    app = LoggingMiddleware(app)                # Logging + ring buffer
    app = AuthMiddleware(app)                   # Auth Bearer + ContextVar
    app = HealthCheckMiddleware(app)            # /health, /healthz, /ready
    app = AdminMiddleware(app, mcp)             # /admin (outermost)

    return app


# =============================================================================
# Bannière de démarrage (dynamique)
# =============================================================================

def _display_width(text: str) -> int:
    """Largeur d'affichage terminal (emojis/CJK = 2 colonnes)."""
    return sum(2 if unicodedata.east_asian_width(c) in ('W', 'F') else 1 for c in text)


def _build_banner() -> str:
    """Construit la bannière de démarrage avec la liste dynamique des outils."""
    tools_list = mcp._tool_manager.list_tools()

    W = 50
    IW = W - 2

    top    = "╔" + "═" * IW + "╗"
    sep    = "╠" + "═" * IW + "╣"
    bottom = "╚" + "═" * IW + "╝"
    empty  = "║" + " " * IW + "║"

    def pad(text: str) -> str:
        dw = _display_width(text)
        return "║" + text + " " * max(0, IW - dw) + "║"

    def center(text: str) -> str:
        dw = _display_width(text)
        total_pad = IW - dw
        left = total_pad // 2
        right = total_pad - left
        return "║" + " " * left + text + " " * right + "║"

    lines = [top]
    lines.append(center(settings.mcp_server_name))
    lines.append(sep)
    lines.append(empty)

    lines.append(pad(f"  🔧 Outils ({len(tools_list)}) :"))
    for t in tools_list:
        lines.append(pad(f"     • {t.name}"))
    lines.append(empty)

    hp = f"{settings.mcp_server_host}:{settings.mcp_server_port}"
    lines.append(pad(f"  🌐 http://{hp}"))
    lines.append(pad(f"  🔗 http://{hp}/mcp"))
    lines.append(pad(f"  🛠️  http://{hp}/admin"))
    lines.append(empty)
    lines.append(bottom)

    return "\n".join(lines)


# =============================================================================
# Point d'entrée
# =============================================================================

def main():
    """Démarre le serveur MCP."""
    import uvicorn

    # Bannière dynamique (liste tous les outils enregistrés)
    print("\n" + _build_banner() + "\n", file=sys.stderr)

    # Initialiser le Token Store (charge les tokens depuis S3 si configuré)
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
