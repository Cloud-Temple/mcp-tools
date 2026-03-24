# -*- coding: utf-8 -*-
"""
Admin REST API — Endpoints pour l'interface d'administration.

Routes :
  GET  /admin/api/health              → état du serveur
  GET  /admin/api/me                  → infos du token courant
  GET  /admin/api/tools               → liste des outils
  POST /admin/api/tools/run           → exécuter un outil
  GET  /admin/api/tokens              → lister les tokens
  POST /admin/api/tokens              → créer un token
  GET  /admin/api/tokens/{name}       → info token
  PUT  /admin/api/tokens/{name}       → modifier un token
  DELETE /admin/api/tokens/{name}     → révoquer un token
  POST /admin/api/tokens/purge        → purger les tokens expirés
  GET  /admin/api/logs                → logs HTTP récents
  GET  /admin/api/audit               → journal d'audit détaillé
"""

import hmac
import json
import sys
import time
import platform
from pathlib import Path
from datetime import datetime, timezone
from typing import Optional

from ..config import get_settings

# ═══════════════ LOGS HTTP (ring buffer) ═══════════════

_logs: list = []
_MAX_LOGS = 200


def add_log(method: str, path: str, status: int, duration_ms: float, client: str = ""):
    """Ajoute une entrée de log HTTP au ring buffer."""
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


# ═══════════════ JOURNAL D'AUDIT (ring buffer) ═══════════════

_audit: list = []
_MAX_AUDIT = 500


def add_audit(actor: str, action: str, target: str = "", details: str = "", status: str = "success"):
    """
    Ajoute une entrée au journal d'audit.

    Args:
        actor: Qui a fait l'action (client_name du token)
        action: Type d'action (token_create, token_update, token_revoke, token_purge, tool_run, login, login_failed)
        target: Cible de l'action (nom du token, nom de l'outil, etc.)
        details: Détails supplémentaires (permissions, tool_ids, etc.)
        status: Résultat (success, error)
    """
    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "actor": actor,
        "action": action,
        "target": target,
        "details": details,
        "status": status,
    }
    _audit.append(entry)
    if len(_audit) > _MAX_AUDIT:
        _audit.pop(0)

    # §3.9 — Persistance : écrire chaque entrée d'audit sur stderr en JSON
    # structuré pour collecte par Docker logs → Loki/ELK/CloudWatch
    print(json.dumps({"audit": entry}, ensure_ascii=False), file=sys.stderr, flush=True)


# ═══════════════ HELPERS ═══════════════


def _get_version() -> str:
    version_file = Path(__file__).parent.parent.parent.parent / "VERSION"
    if version_file.exists():
        return version_file.read_text().strip()
    return "dev"


def _validate_token(scope) -> Optional[dict]:
    """Valide le Bearer token (admin ou non). Retourne les infos du token."""
    headers = dict(scope.get("headers", []))
    auth = headers.get(b"authorization", b"").decode()

    if not auth.startswith("Bearer "):
        return None

    token = auth[7:]
    settings = get_settings()

    # Bootstrap key = admin — comparaison temps constant (§3.6)
    if hmac.compare_digest(token, settings.admin_bootstrap_key):
        return {"client_name": "admin", "permissions": ["admin", "access"], "tool_ids": []}

    # Token S3 (admin ou non)
    from ..auth.token_store import get_token_store
    store = get_token_store()
    info = store.validate_token(token)
    if info:
        return info

    return None


def _is_admin(token_info: dict) -> bool:
    """Vérifie si le token a la permission admin."""
    return "admin" in token_info.get("permissions", [])


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


# ═══════════════ ROUTEUR PRINCIPAL ═══════════════


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
                (b"allow", b"GET, POST, PUT, DELETE, OPTIONS"),
            ],
        })
        await send({"type": "http.response.body", "body": b""})
        return

    # Auth : tout token valide (admin ou non)
    token_info = _validate_token(scope)
    if token_info is None:
        add_audit("anonymous", "login_failed", details="Token invalide ou manquant", status="error")
        await _send_json(send, {"status": "error", "message": "Token requis"}, 401)
        return

    client_name = token_info.get("client_name", "?")
    is_admin = _is_admin(token_info)

    # ── Routing ──────────────────────────────────────────────────────

    t0 = time.monotonic()
    response_status = 200

    try:
        # Routes accessibles à tous les tokens authentifiés
        if path == "/admin/api/me" and method == "GET":
            await _handle_me(send, token_info)

        elif path == "/admin/api/health" and method == "GET":
            await _handle_health(send, mcp_instance)

        elif path == "/admin/api/tools" and method == "GET":
            await _handle_tools_list(send, mcp_instance, token_info)

        elif path == "/admin/api/tools/run" and method == "POST":
            await _handle_tools_run(receive, send, mcp_instance, token_info)

        # Routes admin uniquement — Tokens
        elif path == "/admin/api/tokens" and method == "GET":
            if not is_admin:
                response_status = 403
                await _send_json(send, {"status": "error", "message": "Permission admin requise"}, 403)
            else:
                await _handle_tokens_list(send)

        elif path == "/admin/api/tokens" and method == "POST":
            if not is_admin:
                response_status = 403
                await _send_json(send, {"status": "error", "message": "Permission admin requise"}, 403)
            else:
                await _handle_tokens_create(receive, send, client_name)

        elif path == "/admin/api/tokens/purge" and method == "POST":
            if not is_admin:
                response_status = 403
                await _send_json(send, {"status": "error", "message": "Permission admin requise"}, 403)
            else:
                await _handle_tokens_purge(send, client_name)

        elif path.startswith("/admin/api/tokens/") and method == "GET":
            if not is_admin:
                response_status = 403
                await _send_json(send, {"status": "error", "message": "Permission admin requise"}, 403)
            else:
                name = path.split("/admin/api/tokens/", 1)[1]
                await _handle_tokens_info(send, name)

        elif path.startswith("/admin/api/tokens/") and method == "PUT":
            if not is_admin:
                response_status = 403
                await _send_json(send, {"status": "error", "message": "Permission admin requise"}, 403)
            else:
                name = path.split("/admin/api/tokens/", 1)[1]
                await _handle_tokens_update(receive, send, name, client_name)

        elif path.startswith("/admin/api/tokens/") and method == "DELETE":
            if not is_admin:
                response_status = 403
                await _send_json(send, {"status": "error", "message": "Permission admin requise"}, 403)
            else:
                name = path.split("/admin/api/tokens/", 1)[1]
                await _handle_tokens_revoke(send, name, client_name)

        # Routes admin uniquement — Logs & Audit
        elif path == "/admin/api/logs" and method == "GET":
            if not is_admin:
                response_status = 403
                await _send_json(send, {"status": "error", "message": "Permission admin requise"}, 403)
            else:
                await _handle_logs(send)

        elif path == "/admin/api/audit" and method == "GET":
            if not is_admin:
                response_status = 403
                await _send_json(send, {"status": "error", "message": "Permission admin requise"}, 403)
            else:
                await _handle_audit(send)

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


async def _handle_me(send, token_info: dict):
    """GET /admin/api/me — Infos du token courant (permissions, tool_ids)."""
    await _send_json(send, {
        "status": "ok",
        "client_name": token_info.get("client_name", "?"),
        "permissions": token_info.get("permissions", []),
        "tool_ids": token_info.get("tool_ids", []),
        "is_admin": _is_admin(token_info),
    })


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
    "token": {"operation": ["create", "list", "info", "revoke", "update"]},
}


async def _handle_tools_list(send, mcp_instance, token_info: dict = None):
    """GET /admin/api/tools — Liste des outils (filtrée par tool_ids si non-admin)."""
    allowed_ids = token_info.get("tool_ids", []) if token_info else []

    tools = []
    for tool in mcp_instance._tool_manager.list_tools():
        # Filtrer par tool_ids si le token n'est pas admin
        if allowed_ids and tool.name not in allowed_ids:
            continue
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


async def _handle_tools_run(receive, send, mcp_instance, token_info: dict = None):
    """POST /admin/api/tools/run — Exécuter un outil (respecte tool_ids)."""
    from ..auth.context import current_token_info

    body = await _read_body(receive)
    try:
        data = json.loads(body)
    except Exception:
        await _send_json(send, {"status": "error", "message": "JSON invalide"}, 400)
        return

    tool_name = data.get("tool_name", "")
    arguments = data.get("arguments", {})
    actor = token_info.get("client_name", "?") if token_info else "?"

    if not tool_name:
        await _send_json(send, {"status": "error", "message": "tool_name requis"}, 400)
        return

    # Injecter le contexte token pour check_tool_access (respecte tool_ids)
    tok = current_token_info.set(token_info)
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

        # Audit : exécution d'outil
        args_summary = ", ".join(f"{k}={v!r}" for k, v in list(arguments.items())[:3])
        if len(arguments) > 3:
            args_summary += f", +{len(arguments)-3} params"
        add_audit(actor, "tool_run", tool_name, f"args: {args_summary}" if args_summary else "", "success")

        await _send_json(send, {
            "status": "ok",
            "tool_name": tool_name,
            "result": output_text,
            "duration_ms": elapsed,
        })
    except Exception as e:
        add_audit(actor, "tool_run", tool_name, f"error: {str(e)[:200]}", "error")
        await _send_json(send, {
            "status": "error",
            "tool_name": tool_name,
            "message": str(e),
        })
    finally:
        current_token_info.reset(tok)


# ═══════════════ TOKEN HANDLERS ═══════════════


async def _handle_tokens_list(send):
    """GET /admin/api/tokens — Lister tous les tokens."""
    from ..auth.token_store import get_token_store
    store = get_token_store()
    result = store.list_tokens()
    await _send_json(send, result)


async def _handle_tokens_create(receive, send, actor: str = "?"):
    """POST /admin/api/tokens — Créer un token."""
    from ..auth.token_store import get_token_store

    body = await _read_body(receive)
    try:
        data = json.loads(body)
    except Exception:
        await _send_json(send, {"status": "error", "message": "JSON invalide"}, 400)
        return

    client_name = data.get("client_name", "")
    permissions = data.get("permissions", ["access"])
    tool_ids = data.get("tool_ids", [])
    expires_days = data.get("expires_days", 90)
    email = data.get("email", "")

    if not client_name:
        await _send_json(send, {"status": "error", "message": "client_name requis"}, 400)
        return

    # Résoudre le mot-clé "all" dans tool_ids (aligné avec token.py)
    if tool_ids and len(tool_ids) == 1 and tool_ids[0].lower() == "all":
        from ..tools.token import ALL_TOOL_IDS
        tool_ids = list(ALL_TOOL_IDS)

    store = get_token_store()
    result = store.create(
        client_name=client_name,
        permissions=permissions,
        tool_ids=tool_ids,
        expires_days=expires_days,
        created_by=actor,
        email=email,
    )

    # Audit
    if result.get("status") == "success":
        tools_desc = f"{len(tool_ids)} outils" if tool_ids else "tous les outils"
        add_audit(actor, "token_create", client_name,
                  f"permissions={permissions}, tools={tools_desc}, expires={expires_days}j, email={email or '—'}")
    else:
        add_audit(actor, "token_create", client_name, f"error: {result.get('message', '')}", "error")

    await _send_json(send, result)


async def _handle_tokens_info(send, name: str):
    """GET /admin/api/tokens/{name} — Info d'un token."""
    from ..auth.token_store import get_token_store
    store = get_token_store()
    result = store.info(name)
    await _send_json(send, result)


async def _handle_tokens_update(receive, send, name: str, actor: str = "?"):
    """PUT /admin/api/tokens/{name} — Modifier un token."""
    from ..auth.token_store import get_token_store

    body = await _read_body(receive)
    try:
        data = json.loads(body)
    except Exception:
        await _send_json(send, {"status": "error", "message": "JSON invalide"}, 400)
        return

    permissions = data.get("permissions")
    tool_ids = data.get("tool_ids")
    email = data.get("email")

    # Résoudre le mot-clé "all" dans tool_ids
    if tool_ids and len(tool_ids) == 1 and tool_ids[0].lower() == "all":
        from ..tools.token import ALL_TOOL_IDS
        tool_ids = list(ALL_TOOL_IDS)

    store = get_token_store()
    result = store.update(
        client_name=name,
        permissions=permissions,
        tool_ids=tool_ids,
        email=email,
    )

    # Audit
    if result.get("status") == "success":
        changes = result.get("changes", [])
        add_audit(actor, "token_update", name, "; ".join(changes))
    else:
        add_audit(actor, "token_update", name, f"error: {result.get('message', '')}", "error")

    await _send_json(send, result)


async def _handle_tokens_revoke(send, name: str, actor: str = "?"):
    """DELETE /admin/api/tokens/{name} — Révoquer un token."""
    from ..auth.token_store import get_token_store
    store = get_token_store()
    result = store.revoke(name)

    # Audit
    if result.get("status") == "success":
        add_audit(actor, "token_revoke", name, "Token supprimé définitivement")
    else:
        add_audit(actor, "token_revoke", name, f"error: {result.get('message', '')}", "error")

    await _send_json(send, result)


async def _handle_tokens_purge(send, actor: str = "?"):
    """POST /admin/api/tokens/purge — Purger les tokens expirés."""
    from ..auth.token_store import get_token_store
    store = get_token_store()
    result = store.purge_expired()

    # Audit
    purged = result.get("purged", 0)
    clients = result.get("purged_clients", [])
    if result.get("status") == "success" and purged > 0:
        add_audit(actor, "token_purge", f"{purged} tokens",
                  f"Clients purgés : {', '.join(clients)}")
    elif result.get("status") == "success":
        add_audit(actor, "token_purge", "", "Aucun token expiré")
    else:
        add_audit(actor, "token_purge", "", f"error: {result.get('message', '')}", "error")

    await _send_json(send, result)


# ═══════════════ LOGS & AUDIT HANDLERS ═══════════════


async def _handle_logs(send):
    """GET /admin/api/logs — Logs HTTP récents."""
    await _send_json(send, {
        "status": "ok",
        "count": len(_logs),
        "logs": list(reversed(_logs)),  # Plus récents d'abord
    })


async def _handle_audit(send):
    """GET /admin/api/audit — Journal d'audit détaillé."""
    await _send_json(send, {
        "status": "ok",
        "count": len(_audit),
        "entries": list(reversed(_audit)),  # Plus récents d'abord
    })
