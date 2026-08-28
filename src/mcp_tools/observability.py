# -*- coding: utf-8 -*-
"""Traçabilité structurée et non persistante des appels MCP.

Le buffer est destiné au diagnostic temps réel : il ne conserve ni corps de
requête/réponse, ni arguments, ni secrets. L'archivage durable fait l'objet
des issues #9 et #10 et ne doit pas être implicite dans le chemin d'exécution.
"""

import asyncio
import functools
import inspect
import json
import re
import sys
import time
import uuid
from collections import deque
from contextvars import ContextVar
from datetime import datetime, timezone
from typing import Any, Awaitable, Callable, Optional, TypeVar


_MAX_ACTIVITY = 1000
_MAX_STRING_LENGTH = 256
_activity: deque[dict] = deque(maxlen=_MAX_ACTIVITY)
_activity_context: ContextVar[dict] = ContextVar("activity_context", default={})

_T = TypeVar("_T")
_SENSITIVE_FIELDS = {
    "password", "passwd", "secret", "token", "authorization", "cookie",
    "privatekey", "apikey", "accesskey", "credential", "body", "content",
    "command", "stdout", "stderr", "headers", "authvalue", "query",
    "expr", "script",
}
_SAFE_META_VALUE = re.compile(r"^[A-Za-z0-9_.:/-]{1,128}$")


def _compact(value: Any) -> Any:
    """Réduit une valeur à une forme bornée et sûre pour les journaux."""
    if value is None or isinstance(value, (bool, int, float)):
        return value
    if isinstance(value, str):
        return value[:_MAX_STRING_LENGTH]
    if isinstance(value, (list, tuple, set)):
        return [_compact(item) for item in list(value)[:20]]
    if isinstance(value, dict):
        return {
            str(key)[:80]: "[redacted]" if _is_sensitive_key(str(key)) else _compact(item)
            for key, item in list(value.items())[:30]
        }
    return str(value)[:_MAX_STRING_LENGTH]


def _is_sensitive_key(key: str) -> bool:
    normalized = "".join(char for char in key.lower() if char.isalnum())
    return normalized in _SENSITIVE_FIELDS or normalized.endswith(
        ("password", "secret", "token", "privatekey", "apikey", "accesskey")
    )


def _safe_meta_value(value: Any) -> Any:
    """N'accepte les corrélateurs venant du client que sous forme d'identifiant."""
    if isinstance(value, (bool, int, float)):
        return value
    if isinstance(value, str) and _SAFE_META_VALUE.fullmatch(value):
        return value
    return None


def bind_activity(**fields: Any) -> None:
    """Ajoute des métadonnées non sensibles au contexte de la trace courante."""
    context = dict(_activity_context.get())
    context.update({key: _compact(value) for key, value in fields.items() if value is not None})
    _activity_context.set(context)


def record_activity(event: str, *, level: str = "info", message: str = "", details: Optional[dict] = None, **fields: Any) -> dict:
    """Enregistre un événement sans jamais laisser l'observabilité casser un appel."""
    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event": event,
        "level": level,
        "message": message,
        **_activity_context.get(),
        **{key: _compact(value) for key, value in fields.items() if value is not None},
    }
    if details:
        entry["details"] = _compact(details)
    _activity.append(entry)
    try:
        print(json.dumps({"activity": entry}, ensure_ascii=False, default=str), file=sys.stderr, flush=True)
    except Exception:
        pass
    return entry


def get_activity(limit: int = 100) -> list[dict]:
    """Retourne les événements les plus récents, sans exposer la deque interne."""
    limit = max(1, min(int(limit), _MAX_ACTIVITY))
    return list(reversed(list(_activity)[-limit:]))


def activity_count() -> int:
    return len(_activity)


def _tool_call_summary(kwargs: dict) -> dict:
    """Conserve la forme de l'appel, jamais ses données potentiellement sensibles."""
    parameters = []
    for name in kwargs:
        if name == "ctx":
            continue
        parameters.append(name)
    return {"parameters": parameters}


def traced_tool(tool_name: str) -> Callable[[Callable[..., Awaitable[_T]]], Callable[..., Awaitable[_T]]]:
    """Décorateur commun : début, résultat, erreur ou annulation d'un outil MCP."""
    def decorate(func: Callable[..., Awaitable[_T]]) -> Callable[..., Awaitable[_T]]:
        signature = inspect.signature(func)

        @functools.wraps(func)
        async def wrapped(*args: Any, **kwargs: Any) -> _T:
            bound = signature.bind_partial(*args, **kwargs)
            summary = _tool_call_summary(bound.arguments)
            actor = None
            try:
                from .auth.context import current_token_info
                token_info = current_token_info.get() or {}
                actor = token_info.get("client_name")
            except Exception:
                pass

            bind_activity(tool=tool_name, actor=actor)
            started = time.monotonic()
            record_activity("tool.started", message="Exécution de l'outil démarrée", details=summary)
            try:
                result = await func(*args, **kwargs)
            except asyncio.CancelledError:
                record_activity(
                    "tool.cancelled", level="warning", message="Exécution de l'outil annulée",
                    details={"duration_ms": round((time.monotonic() - started) * 1000, 1)},
                )
                raise
            except Exception as error:
                record_activity(
                    "tool.failed", level="error", message="Exécution de l'outil en échec",
                    details={"duration_ms": round((time.monotonic() - started) * 1000, 1), "error_type": type(error).__name__},
                )
                raise

            status = result.get("status") if isinstance(result, dict) else None
            record_activity(
                "tool.completed", level="error" if status == "error" else "info",
                message="Exécution de l'outil terminée",
                details={
                    "duration_ms": round((time.monotonic() - started) * 1000, 1),
                    "status": status or "unknown",
                    "sandbox": result.get("sandbox") if isinstance(result, dict) else None,
                },
            )
            return result

        return wrapped
    return decorate


class ActivityMiddleware:
    """Trace les étapes HTTP/MCP sans capturer ni réémettre les payloads."""

    _QUIET_PATHS = {"/admin/api/activity", "/admin/api/logs", "/admin/api/audit"}
    _MAX_PARSE_BODY = 1_000_000

    def __init__(self, app: Callable):
        self.app = app

    async def __call__(self, scope: dict, receive: Callable, send: Callable) -> None:
        if scope.get("type") != "http" or scope.get("path") in self._QUIET_PATHS:
            await self.app(scope, receive, send)
            return

        started = time.monotonic()
        trace_token = _activity_context.set({
            "trace_id": f"tr_{uuid.uuid4().hex[:16]}",
            "path": scope.get("path", ""),
            "http_method": scope.get("method", "?"),
        })
        status_code = 0
        content_type = ""
        response_bytes = 0
        is_sse = False
        request_body = bytearray()
        request_too_large = False
        completed = False

        record_activity("http.received", message="Requête HTTP reçue")

        def trace_payload(payload: bytes) -> None:
            if not payload:
                return
            try:
                data = json.loads(payload)
            except (UnicodeDecodeError, json.JSONDecodeError):
                record_activity("mcp.request_unparsed", level="warning", message="Payload HTTP non JSON ou incomplet")
                return

            if not isinstance(data, dict):
                return
            rpc_method = data.get("method")
            params = data.get("params") if isinstance(data.get("params"), dict) else {}
            if rpc_method == "tools/call":
                name = params.get("name")
                if isinstance(name, str) and len(name) <= 100:
                    bind_activity(tool=name)
                meta = params.get("_meta") if isinstance(params.get("_meta"), dict) else {}
                fields = {key: _safe_meta_value(meta.get(key)) for key in ("call_id", "agent_id", "model", "generation")}
                bind_activity(rpc_method=rpc_method, **{key: value for key, value in fields.items() if value is not None})
                record_activity("mcp.tool_call_parsed", message="Appel d'outil MCP identifié")
            elif scope.get("path") == "/admin/api/tools/run":
                name = data.get("tool_name")
                if isinstance(name, str) and len(name) <= 100:
                    bind_activity(tool=name, rpc_method="admin.tools.run")
                    record_activity("admin.tool_call_parsed", message="Appel d'outil admin identifié")
            elif isinstance(rpc_method, str):
                bind_activity(rpc_method=rpc_method[:100])
                record_activity("mcp.request_parsed", message="Requête MCP identifiée")

        async def receive_wrapper() -> dict:
            nonlocal request_too_large
            message = await receive()
            if message.get("type") == "http.request":
                chunk = message.get("body", b"")
                if not request_too_large:
                    if len(request_body) + len(chunk) <= self._MAX_PARSE_BODY:
                        request_body.extend(chunk)
                    else:
                        request_too_large = True
                        request_body.clear()
                if not message.get("more_body", False):
                    if request_too_large:
                        record_activity("http.request_too_large", level="warning", message="Payload non analysé car trop volumineux")
                    else:
                        trace_payload(bytes(request_body))
            elif message.get("type") == "http.disconnect":
                record_activity("transport.client_disconnected", level="warning", message="Client HTTP déconnecté")
            return message

        async def send_wrapper(message: dict) -> None:
            nonlocal status_code, content_type, response_bytes, is_sse, completed
            if message.get("type") == "http.response.start":
                status_code = message.get("status", 0)
                headers = dict(message.get("headers", []))
                content_type = headers.get(b"content-type", b"").decode("latin-1").split(";", 1)[0].lower()
                is_sse = content_type == "text/event-stream"
                record_activity(
                    "http.response_started", message="Réponse HTTP démarrée",
                    details={"status_code": status_code, "content_type": content_type},
                )
            elif message.get("type") == "http.response.body":
                response_bytes += len(message.get("body", b""))
                if not message.get("more_body", False):
                    completed = True
                    record_activity(
                        "http.response_completed", message="Réponse HTTP terminée",
                        details={"status_code": status_code, "response_bytes": response_bytes},
                    )
                    # Les requêtes DELETE de fermeture de session streamable HTTP
                    # n'ont normalement pas de corps. Un POST MCP qui ferme un SSE
                    # vide est en revanche le symptôme transport observé le 28/08.
                    if is_sse and scope.get("method") == "POST" and response_bytes == 0:
                        record_activity(
                            "transport.sse_empty", level="warning",
                            message="Flux SSE fermé sans événement ni réponse terminale",
                            details={"status_code": status_code},
                        )
            await send(message)

        try:
            await self.app(scope, receive_wrapper, send_wrapper)
        except asyncio.CancelledError:
            record_activity("http.cancelled", level="warning", message="Traitement HTTP annulé")
            raise
        except Exception as error:
            record_activity("http.failed", level="error", message="Traitement HTTP en échec", details={"error_type": type(error).__name__})
            raise
        finally:
            record_activity(
                "http.closed", level="warning" if not completed else "info", message="Trace HTTP clôturée",
                details={
                    "duration_ms": round((time.monotonic() - started) * 1000, 1),
                    "status_code": status_code,
                    "response_completed": completed,
                    "response_bytes": response_bytes,
                },
            )
            _activity_context.reset(trace_token)
