# -*- coding: utf-8 -*-
"""
Admin REST API — Endpoints pour l'interface d'administration.

Routes :
  GET  /admin/api/health         → état du serveur
  GET  /admin/api/tools          → liste des outils
  POST /admin/api/tools/run      → exécuter un outil
  GET  /admin/api/tokens         → lister les tokens
  POST /admin/api/tokens         → créer un token
  GET  /admin/api/tokens/{name}  → info token
  DELETE /admin/api/tokens/{name} → révoquer un token
"""

import json
import time
import platform
from pathlib import Path
from datetime import datetime, timezone
from typing import Optional

from ..config import get_settings

# Historique des logs en mémoire (ring buffer)
_logs: list = []
_MAX_LOGS = 200


def add_log(method: str, path: str, status: int, duration_ms: float, client: str = ""):
    """Ajoute une entrée de log au ring buffer."""
    _logs.append({
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "method": method,
        "path": path,
        "status": status,
        "duration_ms": round(duration_ms, 1),
        "client": client,
    })
    if len(_logs) > _MAX_LOGS:
        _logs.pop(0)


def _get_version() -> str:
    version_file = Path(__file__).parent.parent.parent.parent / "VERSION"
    if version_file.exists():
        return version_file.read_text().strip()
    return "dev"


def _validate_admin(scope) -> Optional[dict]:
    """Valide le Bearer token et vérifie les droits admin."""
    headers = dict(scope.get("headers", []))
    auth = headers.get(b"authorization", b"").decode()

    if not auth.startswith("Bearer "):
        return None

    token = auth[7:]
    settings = get_settings()

    # Bootstrap key = admin
    if token == settings.admin_bootstrap_key:
        return {"client_name": "admin", "permissions": ["admin"]}

    # Token S3
    from ..auth.token_store import get_token_store
    store = get_token_store()
    info = store.validate_token(token)
    if info and "admin" in info.get("permissions", []):
        return info

    return None


async def _read_body(receive) -> bytes:
    """Lit le body complet d'une requête ASGI."""
    body = b""
    while True:
        message = await receive()
        body += message.get("body", b"")
        if not message.get("more_body", False):
            break
    return body


async def _send_json(send, data: dict, status: int = 200):
    """Envoie une réponse JSON. Pas de CORS wildcard (same-origin uniquement)."""
    body = json.dumps(data, ensure_ascii=False, default=str).encode()
    await send({
        "type": "http.response.start",
        "status": status,
        "headers": [
            (b"content-type", b"application/json; charset=utf-8"),
            (b"content-length", str(len(body)).encode()),
        ],
    })
    await send({"type": "http.response.body", "body": body})


async def handle_admin_api(scope, receive, send, mcp_instance):
    """
    Routeur principal pour /admin/api/*.
    Vérifie l'auth admin puis dispatch vers le bon handler.
    """
    path = scope.get("path", "")
    method = scope.get("method", "GET")

    # OPTIONS preflight — same-origin uniquement, pas de CORS cross-origin
    if method == "OPTIONS":
        await send({
            "type": "http.response.start",
            "status": 204,
            "headers": [
                (b"allow", b"GET, POST, DELETE, OPTIONS"),
            ],
        })
        await send({"type": "http.response.body", "body": b""})
        return

    # Auth admin obligatoire
    admin_info = _validate_admin(scope)
    if admin_info is None:
        await _send_json(send, {"status": "error", "message": "Admin token requis"}, 401)
        return

    client_name = admin_info.get("client_name", "?")

    # ── Routing ──────────────────────────────────────────────────────

    t0 = time.monotonic()
    response_status = 200

    try:
        if path == "/admin/api/health" and method == "GET":
            await _handle_health(send, mcp_instance)

        elif path == "/admin/api/tools" and method == "GET":
            await _handle_tools_list(send, mcp_instance)

        elif path == "/admin/api/tools/run" and method == "POST":
            await _handle_tools_run(receive, send, mcp_instance, admin_info)

        elif path == "/admin/api/tokens" and method == "GET":
            await _handle_tokens_list(send)

        elif path == "/admin/api/tokens" and method == "POST":
            await _handle_tokens_create(receive, send)

        elif path.startswith("/admin/api/tokens/") and method == "GET":
            name = path.split("/admin/api/tokens/", 1)[1]
            await _handle_tokens_info(send, name)

        elif path.startswith("/admin/api/tokens/") and method == "DELETE":
            name = path.split("/admin/api/tokens/", 1)[1]
            await _handle_tokens_revoke(send, name)

        elif path == "/admin/api/logs" and method == "GET":
            await _handle_logs(send)

        else:
            response_status = 404
            await _send_json(send, {"status": "error", "message": "Route inconnue"}, 404)

    except Exception:
        response_status = 500
        raise
    finally:
        elapsed = round((time.monotonic() - t0) * 1000, 1)
        add_log(method, path, response_status, elapsed, client_name)


# ═══════════════ HANDLERS ═══════════════


async def _handle_health(send, mcp_instance):
    """GET /admin/api/health — État du serveur."""
    settings = get_settings()
    tools_count = len(mcp_instance._tool_manager.list_tools())

    await _send_json(send, {
        "status": "ok",
        "service": settings.mcp_server_name,
        "version": _get_version(),
        "python_version": platform.python_version(),
        "platform": platform.platform(),
        "tools_count": tools_count,
        "sandbox_enabled": settings.sandbox_enabled,
        "s3_configured": bool(settings.s3_endpoint_url and settings.s3_access_key_id),
        "perplexity_configured": bool(settings.perplexity_api_key),
        "host": f"{settings.mcp_server_host}:{settings.mcp_server_port}",
    })


# Mapping des valeurs enum connues pour les paramètres (non exposées par FastMCP)
_PARAM_ENUMS = {
    "network": {"operation": ["ping", "traceroute", "nslookup", "dig"]},
    "shell": {"shell": ["bash", "sh", "python3", "node"]},
    "http": {
        "method": ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD"],
        "auth_type": ["basic", "bearer", "api_key"],
    },
    "perplexity_search": {"detail_level": ["brief", "normal", "detailed"]},
    "date": {"operation": ["now", "today", "parse", "format", "add", "diff", "week_number", "day_of_week"]},
    "ssh": {"operation": ["exec", "status", "upload", "download"]},
    "files": {"operation": ["list", "read", "write", "delete", "info", "diff", "versions", "enable_versioning"]},
    "token": {"operation": ["create", "list", "info", "revoke"]},
}


async def _handle_tools_list(send, mcp_instance):
    """GET /admin/api/tools — Liste des outils."""
    tools = []
    for tool in mcp_instance._tool_manager.list_tools():
        raw_desc = (tool.description or "").strip()
        first_line = raw_desc.split("\n")[0].strip()

        # Extraire les paramètres depuis le schema (FastMCP: tool.parameters)
        params = []
        schema = tool.parameters if hasattr(tool, "parameters") else {}
        properties = schema.get("properties", {}) if isinstance(schema, dict) else {}
        required = schema.get("required", []) if isinstance(schema, dict) else []

        # Enums connus pour ce tool
        tool_enums = _PARAM_ENUMS.get(tool.name, {})

        for pname, pinfo in properties.items():
            # Type : gérer anyOf (Optional[str] → string)
            ptype = pinfo.get("type", "string")
            if not ptype and "anyOf" in pinfo:
                for variant in pinfo["anyOf"]:
                    if variant.get("type") != "null":
                        ptype = variant.get("type", "string")
                        break

            params.append({
                "name": pname,
                "type": ptype,
                "description": pinfo.get("description", "") or pinfo.get("title", ""),
                "required": pname in required,
                "default": pinfo.get("default"),
                "enum": pinfo.get("enum") or tool_enums.get(pname),
            })

        tools.append({
            "name": tool.name,
            "description": first_line,
            "full_description": raw_desc,
            "parameters": params,
        })

    tools.sort(key=lambda t: t["name"])
    await _send_json(send, {"status": "ok", "tools": tools, "count": len(tools)})


async def _handle_tools_run(receive, send, mcp_instance, admin_info):
    """POST /admin/api/tools/run — Exécuter un outil."""
    from ..auth.context import current_token_info

    body = await _read_body(receive)
    try:
        data = json.loads(body)
    except Exception:
        await _send_json(send, {"status": "error", "message": "JSON invalide"}, 400)
        return

    tool_name = data.get("tool_name", "")
    arguments = data.get("arguments", {})

    if not tool_name:
        await _send_json(send, {"status": "error", "message": "tool_name requis"}, 400)
        return

    # Injecter le contexte admin pour check_tool_access
    tok = current_token_info.set(admin_info)
    try:
        t0 = time.monotonic()
        result = await mcp_instance._tool_manager.call_tool(tool_name, arguments)
        elapsed = round((time.monotonic() - t0) * 1000, 1)

        # Extraire le contenu — gère dict, list de TextContent, ou autre
        if isinstance(result, dict):
            output_text = json.dumps(result, ensure_ascii=False, indent=2, default=str)
        elif isinstance(result, (list, tuple)):
            parts = []
            for item in result:
                if hasattr(item, "text"):
                    parts.append(item.text)
                elif hasattr(item, "data"):
                    parts.append(str(item.data))
                elif isinstance(item, dict):
                    parts.append(json.dumps(item, ensure_ascii=False, indent=2, default=str))
                else:
                    parts.append(str(item))
            output_text = "\n".join(parts)
        else:
            output_text = str(result)

        await _send_json(send, {
            "status": "ok",
            "tool_name": tool_name,
            "result": output_text,
            "duration_ms": elapsed,
        })
    except Exception as e:
        await _send_json(send, {
            "status": "error",
            "tool_name": tool_name,
            "message": str(e),
        })
    finally:
        current_token_info.reset(tok)


async def _handle_tokens_list(send):
    """GET /admin/api/tokens — Lister tous les tokens."""
    from ..auth.token_store import get_token_store
    store = get_token_store()
    result = store.list_tokens()
    await _send_json(send, result)


async def _handle_tokens_create(receive, send):
    """POST /admin/api/tokens — Créer un token."""
    from ..auth.token_store import get_token_store

    body = await _read_body(receive)
    try:
        data = json.loads(body)
    except Exception:
        await _send_json(send, {"status": "error", "message": "JSON invalide"}, 400)
        return

    client_name = data.get("client_name", "")
    permissions = data.get("permissions", ["read"])
    tool_ids = data.get("tool_ids", [])
    expires_days = data.get("expires_days", 90)

    if not client_name:
        await _send_json(send, {"status": "error", "message": "client_name requis"}, 400)
        return

    store = get_token_store()
    result = store.create(
        client_name=client_name,
        permissions=permissions,
        tool_ids=tool_ids,
        expires_days=expires_days,
        created_by="admin-ui",
    )
    await _send_json(send, result)


async def _handle_tokens_info(send, name: str):
    """GET /admin/api/tokens/{name} — Info d'un token."""
    from ..auth.token_store import get_token_store
    store = get_token_store()
    result = store.info(name)
    await _send_json(send, result)


async def _handle_tokens_revoke(send, name: str):
    """DELETE /admin/api/tokens/{name} — Révoquer un token."""
    from ..auth.token_store import get_token_store
    store = get_token_store()
    result = store.revoke(name)
    await _send_json(send, result)


async def _handle_logs(send):
    """GET /admin/api/logs — Logs récents."""
    await _send_json(send, {
        "status": "ok",
        "count": len(_logs),
        "logs": list(reversed(_logs)),  # Plus récents d'abord
    })
