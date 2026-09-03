# -*- coding: utf-8 -*-
"""Console admin minimale cybersec : approbation, suivi, arrêt et consultation."""

from __future__ import annotations

import json
import mimetypes
from pathlib import Path
from urllib.parse import parse_qs, unquote

from .identity import current_token_info, is_admin
from .models import ValidationError


STATIC_DIR = Path(__file__).parent / "static"


async def _send_json(send, status: int, value: dict) -> None:
    body = json.dumps(value, ensure_ascii=False, default=str).encode("utf-8")
    await send({
        "type": "http.response.start", "status": status,
        "headers": [(b"content-type", b"application/json"), (b"content-length", str(len(body)).encode()), (b"cache-control", b"no-store")],
    })
    await send({"type": "http.response.body", "body": body})


async def _read_json_body(receive) -> dict:
    chunks = []
    total = 0
    while True:
        message = await receive()
        part = message.get("body", b"")
        total += len(part)
        if total > 1_000_000:
            raise ValidationError("Corps admin trop volumineux.")
        chunks.append(part)
        if not message.get("more_body"):
            break
    if not chunks or not b"".join(chunks):
        return {}
    value = json.loads(b"".join(chunks).decode("utf-8"))
    if not isinstance(value, dict):
        raise ValidationError("Corps admin JSON invalide.")
    return value


class CybersecAdminMiddleware:
    def __init__(self, app, mcp_instance, services_factory):
        self.app = app
        self.mcp_instance = mcp_instance
        self.services_factory = services_factory

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        path = scope.get("path", "")
        if path.startswith("/admin/api/"):
            return await self._api(scope, receive, send)
        if path in {"/admin", "/admin/"}:
            return await self._file(send, STATIC_DIR / "admin.html", "text/html; charset=utf-8")
        if path.startswith("/admin/static/"):
            relative = path[len("/admin/static/"):]
            candidate = (STATIC_DIR / relative).resolve()
            if not str(candidate).startswith(str(STATIC_DIR.resolve())) or not candidate.is_file():
                return await _send_json(send, 404, {"error": "Not found"})
            return await self._file(send, candidate, mimetypes.guess_type(str(candidate))[0] or "application/octet-stream")
        return await self.app(scope, receive, send)

    async def _file(self, send, path: Path, content_type: str):
        try:
            body = path.read_bytes()
        except OSError:
            return await _send_json(send, 404, {"error": "Not found"})
        await send({
            "type": "http.response.start", "status": 200,
            "headers": [(b"content-type", content_type.encode()), (b"content-length", str(len(body)).encode()), (b"cache-control", b"no-cache")],
        })
        await send({"type": "http.response.body", "body": body})

    async def _api(self, scope, receive, send):
        token = current_token_info.get()
        if not is_admin(token):
            return await _send_json(send, 401, {"error": "Administrateur requis"})
        path = scope.get("path", "")
        method = scope.get("method", "GET")
        query = parse_qs(scope.get("query_string", b"").decode("utf-8", errors="ignore"))
        tenant_id = query.get("tenant_id", [None])[0]
        try:
            services = self.services_factory()
            if path == "/admin/api/health" and method == "GET":
                return await _send_json(send, 200, {
                    "status": "ok", "service": services.settings.cybersec_mcp_server_name,
                    "storage": "s3-configured" if services.settings.cybersec_s3_endpoint_url else "s3-unconfigured",
                })
            if path == "/admin/api/tools" and method == "GET":
                tools = []
                for tool in await self.mcp_instance.list_tools():
                    # Le SDK MCP v2 expose son schéma public en snake_case.
                    # Ne pas utiliser l'ancien nom camelCase : l'admin doit
                    # rester strictement cohérent avec tools/list et la CLI.
                    schema = tool.input_schema if hasattr(tool, "input_schema") else {}
                    tools.append({"name": tool.name, "description": (tool.description or "").split("\n")[0], "input_schema": schema})
                return await _send_json(send, 200, {"status": "ok", "tools": tools, "count": len(tools)})
            if path == "/admin/api/campaigns" and method == "GET":
                campaigns = await services.campaigns.list(token, admin_tenant_id=tenant_id)
                return await _send_json(send, 200, {"status": "ok", "campaigns": campaigns})
            if path.startswith("/admin/api/campaigns/"):
                suffix = path[len("/admin/api/campaigns/"):]
                pieces = [unquote(item) for item in suffix.split("/") if item]
                if not pieces:
                    return await _send_json(send, 404, {"error": "Not found"})
                campaign_id = pieces[0]
                if len(pieces) == 1 and method == "GET":
                    campaign = await services.campaigns.get(campaign_id, token, admin_tenant_id=tenant_id)
                    return await _send_json(send, 200, {"status": "ok", "campaign": campaign})
                if len(pieces) == 2 and pieces[1] == "approve" and method == "POST":
                    body = await _read_json_body(receive)
                    campaign = await services.campaigns.approve(campaign_id, token, admin_tenant_id=body.get("tenant_id") or tenant_id or "")
                    return await _send_json(send, 200, {"status": "ok", "campaign": campaign})
                if len(pieces) == 2 and pieces[1] == "cancel" and method == "POST":
                    body = await _read_json_body(receive)
                    campaign = await services.campaigns.cancel(campaign_id, token, admin_tenant_id=body.get("tenant_id") or tenant_id, reason=body.get("reason", ""))
                    count = await services.jobs.cancel_campaign(campaign)
                    return await _send_json(send, 200, {"status": "ok", "campaign": campaign, "jobs_stop_requested": count})
                if len(pieces) == 2 and pieces[1] == "results" and method == "GET":
                    campaign = await services.campaigns.get(campaign_id, token, admin_tenant_id=tenant_id)
                    return await _send_json(send, 200, {"status": "ok", **(await services.jobs.results(campaign))})
                if len(pieces) == 2 and pieces[1] == "evidence" and method == "GET":
                    campaign = await services.campaigns.get(campaign_id, token, admin_tenant_id=tenant_id)
                    evidence = await services.repository.list_evidence(campaign["tenant_id"], campaign_id)
                    return await _send_json(send, 200, {"status": "ok", "evidence": evidence})
            if path == "/admin/api/tokens" and method == "GET":
                return await _send_json(send, 200, {"status": "ok", "tokens": await services.tokens.list()})
            if path == "/admin/api/tokens" and method == "POST":
                body = await _read_json_body(receive)
                created = await services.tokens.create(
                    client_name=body.get("client_name", ""), tenant_id=body.get("tenant_id"),
                    tool_ids=body.get("tool_ids", []), permissions=body.get("permissions"), expires_days=body.get("expires_days", 90),
                )
                return await _send_json(send, 201, created)
            if path.startswith("/admin/api/tokens/") and method == "DELETE":
                name = unquote(path.rsplit("/", 1)[-1])
                revoked = await services.tokens.revoke(name, token.get("client_name", "admin"))
                return await _send_json(send, 200, {"status": "ok", "revoked": revoked})
            if path == "/admin/api/activity" and method == "GET":
                from src.mcp_tools.observability import get_activity_snapshot
                limit = int(query.get("limit", [100])[0])
                return await _send_json(send, 200, {"status": "ok", **get_activity_snapshot(max(1, min(limit, 1000)), trace_id=query.get("trace_id", [None])[0], call_id=query.get("call_id", [None])[0])})
        except (ValidationError, ValueError) as exc:
            return await _send_json(send, 400, {"status": "error", "message": str(exc)})
        except Exception as exc:
            return await _send_json(send, 500, {"status": "error", "message": f"Erreur interne contrôlée : {type(exc).__name__}."})
        return await _send_json(send, 404, {"error": "Not found"})
