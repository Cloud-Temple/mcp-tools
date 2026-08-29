# -*- coding: utf-8 -*-
"""Traçabilité structurée, corrélée et bornée des appels MCP.

Le journal temps réel garde les métadonnées nécessaires pour reconstituer un
appel, de sa réception HTTP à sa clôture. Il ne conserve jamais les corps,
arguments, sorties ou secrets. La persistance durable reste découplée du
chemin d'exécution : une archive ne doit pas rendre un tool indisponible.
"""

import asyncio
import functools
import hashlib
import inspect
import json
import os
import re
import sys
import time
import uuid
from collections import deque
from contextvars import ContextVar
from datetime import datetime, timedelta, timezone
from typing import Any, Awaitable, Callable, Optional, TypeVar

from .config import get_settings


_SETTINGS = get_settings()
_ACTIVITY_SCHEMA_VERSION = 2
_MAX_ACTIVITY = _SETTINGS.activity_max_events
_MAX_ACTIVITY_AGE_SECONDS = _SETTINGS.activity_max_age_seconds
_MAX_STRING_LENGTH = 256
_MAX_RESPONSE_PROBE_BYTES = 8_192
_SERVER_GENERATION = f"gen_{uuid.uuid4().hex[:12]}"

_activity: deque[dict] = deque(maxlen=_MAX_ACTIVITY)
_activity_context: ContextVar[dict] = ContextVar("activity_context", default={})
_activity_sequence = 0
_activity_capacity_evictions = 0
_activity_age_evictions = 0

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
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return value
    if isinstance(value, str) and _SAFE_META_VALUE.fullmatch(value):
        return value
    return None


def _safe_session_ref(value: Any) -> Optional[str]:
    """Référence un identifiant de session sans journaliser ce secret de transport."""
    if not isinstance(value, str) or not value or len(value) > 256:
        return None
    return f"sess_{hashlib.sha256(value.encode('utf-8')).hexdigest()[:16]}"


def _prune_activity(now: datetime) -> None:
    """Évince les événements trop anciens du buffer temps réel."""
    global _activity_age_evictions
    cutoff = (now - timedelta(seconds=_MAX_ACTIVITY_AGE_SECONDS)).isoformat()
    while _activity and _activity[0].get("timestamp", "") < cutoff:
        _activity.popleft()
        _activity_age_evictions += 1


def bind_activity(**fields: Any) -> None:
    """Ajoute des métadonnées non sensibles au contexte de la trace courante."""
    context = dict(_activity_context.get())
    context.update({key: _compact(value) for key, value in fields.items() if value is not None})
    _activity_context.set(context)


def get_activity_context() -> dict:
    """Expose les corrélateurs de la trace courante aux journaux admin."""
    allowed = {
        "trace_id", "server_generation", "process_id", "upstream_request_id",
        "mcp_session_ref", "rpc_request_id", "call_id", "actor", "agent_id",
        "model", "generation", "client_kind", "tool", "rpc_method",
    }
    return {key: value for key, value in _activity_context.get().items() if key in allowed}


def record_activity(
    event: str,
    *,
    level: str = "info",
    message: str = "",
    details: Optional[dict] = None,
    **fields: Any,
) -> dict:
    """Enregistre un événement sans jamais laisser l'observabilité casser un appel."""
    global _activity_sequence, _activity_capacity_evictions
    now = datetime.now(timezone.utc)
    _prune_activity(now)
    if len(_activity) == _MAX_ACTIVITY:
        _activity_capacity_evictions += 1
    _activity_sequence += 1
    entry = {
        "schema_version": _ACTIVITY_SCHEMA_VERSION,
        "sequence": _activity_sequence,
        "timestamp": now.isoformat(),
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
        # Le format JSONL est volontairement identique à celui renvoyé à
        # l'admin : la collecte Docker peut l'ingérer sans parser une phrase.
        print(json.dumps({"activity": entry}, ensure_ascii=False, default=str), file=sys.stderr, flush=True)
    except Exception:
        pass
    return entry


def activity_stats() -> dict:
    """Métriques du buffer local, utiles pour savoir si la vue est tronquée."""
    _prune_activity(datetime.now(timezone.utc))
    return {
        "max_events": _MAX_ACTIVITY,
        "max_age_seconds": _MAX_ACTIVITY_AGE_SECONDS,
        "stored_events": len(_activity),
        "evicted_capacity": _activity_capacity_evictions,
        "evicted_age": _activity_age_evictions,
        "server_generation": _SERVER_GENERATION,
    }


def get_activity(limit: int = 100) -> list[dict]:
    """Retourne les événements les plus récents, sans exposer la deque interne."""
    limit = max(1, min(int(limit), _MAX_ACTIVITY))
    return [dict(event) for event in reversed(list(_activity)[-limit:])]


def activity_count() -> int:
    return len(_activity)


def _last_value(events: list[dict], key: str) -> Any:
    for event in reversed(events):
        if event.get(key) is not None:
            return event[key]
    return None


def _terminal_state(
    execution_state: Optional[str],
    transport_state: Optional[str],
    remote_result: Optional[str],
    terminal_response_required: bool = False,
) -> str:
    """Retourne un verdict opératoire sans prétendre prouver la réception client."""
    if remote_result == "uncertain":
        return "remote_result_uncertain"
    if transport_state == "response_delivery_failed":
        return "response_delivery_failed"
    if transport_state in {"sse_empty", "sse_no_terminal"}:
        return "response_missing"
    if transport_state == "client_cancelled":
        return "client_cancelled"
    if transport_state == "transport_failed":
        return "transport_failed"
    if execution_state == "cancelled":
        return "cancelled"
    if execution_state == "failed":
        return "tool_failed"
    if execution_state == "succeeded":
        if transport_state == "mcp_terminal_emitted":
            return "succeeded"
        if transport_state == "asgi_response_completed":
            return "response_terminal_unobserved" if terminal_response_required else "succeeded"
        return "response_incomplete"
    if transport_state in {"mcp_terminal_emitted", "asgi_response_completed"}:
        return "transport_completed"
    return "incomplete"


def build_activity_calls(events: list[dict]) -> list[dict]:
    """Regroupe un flux d'événements en chronologies lisibles par appel."""
    grouped: dict[str, list[dict]] = {}
    for event in events:
        trace_id = event.get("trace_id")
        if isinstance(trace_id, str) and trace_id:
            grouped.setdefault(trace_id, []).append(dict(event))

    calls: list[dict] = []
    for trace_id, timeline in grouped.items():
        timeline.sort(key=lambda item: item.get("sequence", 0))
        first = timeline[0]
        last = timeline[-1]
        event_names = {event.get("event") for event in timeline}
        start_observed = "http.received" in event_names
        closed_observed = "trace.closed" in event_names
        execution_state = _last_value(timeline, "execution_state")
        transport_state = _last_value(timeline, "transport_state")
        remote_result = _last_value(timeline, "remote_result")
        terminal = _last_value(timeline, "terminal_state") or _terminal_state(
            execution_state,
            transport_state,
            remote_result,
            bool(_last_value(timeline, "mcp_terminal_required")),
        )
        tool = _last_value(timeline, "tool")
        rpc_method = _last_value(timeline, "rpc_method")
        if tool:
            kind = "tool_call"
        elif rpc_method:
            kind = "mcp_protocol"
        elif str(first.get("path", "")).startswith("/admin/api/"):
            kind = "admin"
        else:
            kind = "http"

        summary = {
            "trace_id": trace_id,
            "kind": kind,
            "started_at": first.get("timestamp"),
            "closed_at": last.get("timestamp"),
            "event_count": len(timeline),
            "start_observed": start_observed,
            "closed_observed": closed_observed,
            "timeline_complete": start_observed and closed_observed,
            "terminal_state": terminal,
            "execution_state": execution_state,
            "transport_state": transport_state,
            "tool_status": _last_value(timeline, "tool_status"),
            "remote_result": remote_result,
            "mcp_terminal_required": bool(_last_value(timeline, "mcp_terminal_required")),
            "response_terminal_observed": bool(_last_value(timeline, "response_terminal_observed")),
            "response_completed": bool(_last_value(timeline, "response_completed")),
            "response_status_code": _last_value(timeline, "response_status_code"),
            "response_bytes": _last_value(timeline, "response_bytes"),
            "duration_ms": _last_value(timeline, "duration_ms"),
            "events": timeline,
        }
        for field in (
            "server_generation", "process_id", "path", "http_method", "upstream_request_id",
            "mcp_session_ref", "rpc_request_id", "rpc_method", "call_id", "tool", "actor",
            "agent_id", "model", "generation", "client_kind",
        ):
            value = _last_value(timeline, field)
            if value is not None:
                summary[field] = value
        calls.append(summary)

    calls.sort(key=lambda item: item.get("started_at") or "", reverse=True)
    return calls


def get_activity_snapshot(
    limit: int = 100,
    *,
    trace_id: Optional[str] = None,
    call_id: Optional[str] = None,
    exclude_trace_id: Optional[str] = None,
) -> dict:
    """Retourne événements et chronologies complètes, éventuellement filtrés."""
    _prune_activity(datetime.now(timezone.utc))
    limit = max(1, min(int(limit), _MAX_ACTIVITY))
    all_events = list(_activity)
    if trace_id:
        all_events = [event for event in all_events if event.get("trace_id") == trace_id]
    if call_id:
        # Le call_id est découvert après http.received : filtrer chaque
        # événement sur ce champ tronquerait précisément le début de la
        # chronologie que l'opérateur cherche. On résout donc le ou les
        # trace_id concernés, puis on restitue leurs événements complets.
        trace_ids = {
            event.get("trace_id") for event in all_events
            if event.get("call_id") == call_id and event.get("trace_id")
        }
        if trace_ids:
            all_events = [event for event in all_events if event.get("trace_id") in trace_ids]
        else:
            all_events = [event for event in all_events if event.get("call_id") == call_id]
    if exclude_trace_id:
        all_events = [event for event in all_events if event.get("trace_id") != exclude_trace_id]

    calls = build_activity_calls(all_events)
    # Un filtre ciblé sert précisément à réexaminer une chronologie entière.
    if trace_id or call_id:
        visible_events = all_events
    else:
        visible_events = all_events[-limit:]
        visible_trace_ids = {event.get("trace_id") for event in visible_events}
        calls = [call for call in calls if call.get("trace_id") in visible_trace_ids]

    return {
        "events": [dict(event) for event in reversed(visible_events)],
        "calls": calls,
        "stats": activity_stats(),
    }


def _tool_call_summary(kwargs: dict) -> dict:
    """Conserve la forme de l'appel, jamais ses données potentiellement sensibles."""
    parameters = [name for name in kwargs if name != "ctx"]
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

            bind_activity(tool=tool_name, actor=actor, execution_state="running")
            started = time.monotonic()
            record_activity("tool.started", message="Exécution de l'outil démarrée", details=summary)
            try:
                result = await func(*args, **kwargs)
            except asyncio.CancelledError:
                duration_ms = round((time.monotonic() - started) * 1000, 1)
                bind_activity(execution_state="cancelled", tool_duration_ms=duration_ms)
                record_activity(
                    "tool.cancelled", level="warning", message="Exécution de l'outil annulée",
                    details={"duration_ms": duration_ms},
                )
                raise
            except Exception as error:
                duration_ms = round((time.monotonic() - started) * 1000, 1)
                bind_activity(execution_state="failed", tool_duration_ms=duration_ms)
                record_activity(
                    "tool.failed", level="error", message="Exécution de l'outil en échec",
                    details={"duration_ms": duration_ms, "error_type": type(error).__name__},
                )
                raise

            status = result.get("status") if isinstance(result, dict) else None
            execution_state = "failed" if status in {"error", "failed"} else "succeeded"
            duration_ms = round((time.monotonic() - started) * 1000, 1)
            bind_activity(
                execution_state=execution_state,
                tool_status=status or "unknown",
                tool_duration_ms=duration_ms,
            )
            record_activity(
                "tool.completed", level="error" if execution_state == "failed" else "info",
                message="Exécution de l'outil terminée",
                details={
                    "duration_ms": duration_ms,
                    "status": status or "unknown",
                    "sandbox": result.get("sandbox") if isinstance(result, dict) else None,
                },
            )
            return result

        return wrapped
    return decorate


class _TerminalResponseProbe:
    """Observe la seule enveloppe JSON-RPC d'une réponse, sans la conserver."""

    def __init__(self, content_type: str):
        self.content_type = content_type
        self._buffer = bytearray()
        self.observed = False

    def feed(self, body: bytes) -> bool:
        if self.observed or not body:
            return self.observed
        remaining = _MAX_RESPONSE_PROBE_BYTES - len(self._buffer)
        if remaining > 0:
            self._buffer.extend(body[:remaining])
        payload = bytes(self._buffer)
        if self.content_type == "application/json":
            candidates = (payload,)
        elif self.content_type == "text/event-stream":
            candidates = (
                line[5:].lstrip()
                for line in payload.splitlines()
                if line.startswith(b"data:")
            )
        else:
            candidates = ()
        self.observed = any(self._is_terminal_envelope(candidate) for candidate in candidates)
        if self.observed:
            self._buffer.clear()
        return self.observed

    @staticmethod
    def _is_terminal_envelope(candidate: bytes) -> bool:
        """Reconnaît une enveloppe JSON-RPC sans imposer l'ordre des clés.

        Le corps n'est jamais conservé ni journalisé ; ce parsing, borné à
        8 KiB, sert uniquement à établir le verdict de transport.
        """
        try:
            envelope = json.loads(candidate)
        except (UnicodeDecodeError, json.JSONDecodeError):
            return False
        return (
            isinstance(envelope, dict)
            and envelope.get("jsonrpc") == "2.0"
            and "id" in envelope
            and ("result" in envelope or "error" in envelope)
        )


class ActivityMiddleware:
    """Trace les étapes HTTP/MCP sans capturer ni réémettre les payloads."""

    _QUIET_PATHS = {"/admin/api/activity", "/admin/api/logs", "/admin/api/audit"}
    _MAX_PARSE_BODY = 1_000_000

    def __init__(self, app: Callable):
        self.app = app

    @classmethod
    def _should_trace(cls, path: str) -> bool:
        return path == "/mcp" or (path.startswith("/admin/api/") and path not in cls._QUIET_PATHS)

    async def __call__(self, scope: dict, receive: Callable, send: Callable) -> None:
        path = scope.get("path", "")
        if scope.get("type") != "http" or not self._should_trace(path):
            await self.app(scope, receive, send)
            return

        started = time.monotonic()
        headers = dict(scope.get("headers", []))
        upstream_request_id = _safe_meta_value(headers.get(b"x-request-id", b"").decode("latin-1"))
        session_ref = _safe_session_ref(headers.get(b"mcp-session-id", b"").decode("latin-1"))
        trace_id = f"tr_{uuid.uuid4().hex[:16]}"
        trace_token = _activity_context.set({
            "trace_id": trace_id,
            "server_generation": _SERVER_GENERATION,
            "process_id": os.getpid(),
            "path": path,
            "http_method": scope.get("method", "?"),
            **({"upstream_request_id": upstream_request_id} if upstream_request_id is not None else {}),
            **({"mcp_session_ref": session_ref} if session_ref is not None else {}),
        })
        status_code = 0
        content_type = ""
        response_bytes = 0
        is_sse = False
        request_body = bytearray()
        request_too_large = False
        completed = False
        response_probe: Optional[_TerminalResponseProbe] = None

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
            rpc_id = _safe_meta_value(data.get("id"))
            is_rpc_request = isinstance(rpc_method, str) and "id" in data
            if isinstance(rpc_method, str):
                bind_activity(
                    rpc_method=rpc_method[:100],
                    rpc_response_expected=is_rpc_request,
                    mcp_terminal_required=is_rpc_request,
                    **({"rpc_request_id": rpc_id} if rpc_id is not None else {}),
                )
            params = data.get("params") if isinstance(data.get("params"), dict) else {}
            if rpc_method == "tools/call":
                name = params.get("name")
                if isinstance(name, str) and len(name) <= 100:
                    bind_activity(tool=name)
                meta = params.get("_meta") if isinstance(params.get("_meta"), dict) else {}
                fields = {
                    key: _safe_meta_value(meta.get(key))
                    for key in ("call_id", "agent_id", "model", "generation", "client_kind")
                }
                bind_activity(**{key: value for key, value in fields.items() if value is not None})
                record_activity("mcp.tool_call_parsed", message="Appel d'outil MCP identifié")
            elif path == "/admin/api/tools/run":
                name = data.get("tool_name")
                if isinstance(name, str) and len(name) <= 100:
                    bind_activity(
                        tool=name,
                        rpc_method="admin.tools.run",
                        rpc_response_expected=True,
                        mcp_terminal_required=False,
                    )
                    record_activity("admin.tool_call_parsed", message="Appel d'outil admin identifié")
            elif isinstance(rpc_method, str):
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
                        # Le SDK accepte des requêtes MCP jusqu'à plusieurs
                        # MiB. Si leurs métadonnées ne peuvent être inspectées
                        # sans conserver le body, on conserve le verdict le
                        # plus prudent : une réponse MCP terminale reste due.
                        if path == "/mcp" and scope.get("method") == "POST":
                            bind_activity(
                                mcp_terminal_required=True,
                                request_metadata_unobserved=True,
                            )
                        record_activity("http.request_too_large", level="warning", message="Payload non analysé car trop volumineux")
                    else:
                        trace_payload(bytes(request_body))
            elif message.get("type") == "http.disconnect":
                # Un client de streaming ferme normalement sa lecture après la
                # dernière réponse. Ne pas présenter ce cas comme un incident
                # lorsque l'ASGI a déjà accepté le corps terminal.
                # Le serveur MCP peut lire et écrire depuis deux tâches ASGI
                # distinctes : leurs ContextVar ne se répercutent pas toujours.
                # Le flux global de cette trace est donc la source fiable pour
                # savoir si la réponse a déjà été acceptée.
                after_response = bool(_activity_context.get().get("response_completed")) or any(
                    event.get("trace_id") == trace_id and event.get("event") == "http.response_completed"
                    for event in _activity
                )
                bind_activity(client_disconnected=True)
                record_activity(
                    "transport.client_closed_after_response" if after_response else "transport.client_disconnected",
                    level="info" if after_response else "warning",
                    message=(
                        "Client HTTP a fermé la connexion après la réponse"
                        if after_response else "Client HTTP déconnecté avant la clôture de la réponse"
                    ),
                )
            return message

        async def send_wrapper(message: dict) -> None:
            nonlocal status_code, content_type, response_bytes, is_sse, completed, response_probe
            message_type = message.get("type")
            if message_type == "http.response.start":
                response_headers = list(message.get("headers", []))
                if not any(name.lower() == b"x-mcp-trace-id" for name, _ in response_headers):
                    response_headers.append((b"x-mcp-trace-id", trace_id.encode()))
                outbound = dict(message)
                outbound["headers"] = response_headers
                candidate_status = outbound.get("status", 0)
                candidate_headers = dict(response_headers)
                candidate_content_type = candidate_headers.get(b"content-type", b"").decode("latin-1").split(";", 1)[0].lower()
                try:
                    await send(outbound)
                except Exception as error:
                    bind_activity(transport_state="response_delivery_failed")
                    record_activity(
                        "transport.response_delivery_failed", level="error",
                        message="ASGI a refusé l'émission des en-têtes de réponse",
                        details={"stage": "response_start", "error_type": type(error).__name__},
                    )
                    raise
                status_code = candidate_status
                content_type = candidate_content_type
                is_sse = content_type == "text/event-stream"
                response_probe = _TerminalResponseProbe(content_type)
                bind_activity(response_status_code=status_code, transport_state="response_started")
                record_activity(
                    "http.response_started", message="En-têtes de réponse remis à l'ASGI",
                    details={"status_code": status_code, "content_type": content_type},
                )
                return

            if message_type == "http.response.body":
                body = message.get("body", b"")
                try:
                    await send(message)
                except Exception as error:
                    bind_activity(transport_state="response_delivery_failed")
                    record_activity(
                        "transport.response_delivery_failed", level="error",
                        message="ASGI a refusé l'émission du corps de réponse",
                        details={"stage": "response_body", "error_type": type(error).__name__},
                    )
                    raise
                response_bytes += len(body)
                terminal_observed = response_probe.feed(body) if response_probe is not None else False
                if terminal_observed and not _activity_context.get().get("response_terminal_observed"):
                    bind_activity(response_terminal_observed=True, transport_state="mcp_terminal_emitted")
                    record_activity(
                        "mcp.response_terminal_observed",
                        message="Réponse JSON-RPC terminale émise vers l'ASGI",
                    )
                if not message.get("more_body", False):
                    completed = True
                    bind_activity(response_completed=True, response_bytes=response_bytes)
                    terminal_required = bool(_activity_context.get().get("mcp_terminal_required"))
                    if is_sse and terminal_required and response_bytes == 0:
                        bind_activity(transport_state="sse_empty")
                        record_activity(
                            "transport.sse_empty", level="warning",
                            message="Flux SSE fermé sans événement ni réponse terminale",
                            details={"status_code": status_code},
                        )
                    elif is_sse and terminal_required and not _activity_context.get().get("response_terminal_observed"):
                        bind_activity(transport_state="sse_no_terminal")
                        record_activity(
                            "transport.sse_no_terminal", level="warning",
                            message="Flux SSE clôturé sans réponse JSON-RPC terminale observée",
                            details={"status_code": status_code, "response_bytes": response_bytes},
                        )
                    elif not _activity_context.get().get("response_terminal_observed"):
                        bind_activity(transport_state="asgi_response_completed")
                    record_activity(
                        "http.response_completed", message="Corps de réponse remis à l'ASGI",
                        details={"status_code": status_code, "response_bytes": response_bytes},
                    )
                return

            await send(message)

        try:
            await self.app(scope, receive_wrapper, send_wrapper)
        except asyncio.CancelledError:
            bind_activity(transport_state="client_cancelled")
            record_activity("http.cancelled", level="warning", message="Traitement HTTP annulé")
            raise
        except Exception as error:
            if _activity_context.get().get("transport_state") != "response_delivery_failed":
                bind_activity(transport_state="transport_failed")
            record_activity("http.failed", level="error", message="Traitement HTTP en échec", details={"error_type": type(error).__name__})
            raise
        finally:
            trace_events = [event for event in _activity if event.get("trace_id") == trace_id]
            execution_state = _last_value(trace_events, "execution_state")
            transport_state = _last_value(trace_events, "transport_state")
            remote_result = _last_value(trace_events, "remote_result")
            terminal_state = _terminal_state(
                execution_state,
                transport_state,
                remote_result,
                bool(_last_value(trace_events, "mcp_terminal_required")),
            )
            duration_ms = round((time.monotonic() - started) * 1000, 1)
            bind_activity(
                execution_state=execution_state,
                transport_state=transport_state or ("asgi_response_completed" if completed else "no_response"),
                terminal_state=terminal_state,
                duration_ms=duration_ms,
                response_completed=completed,
                response_bytes=response_bytes,
            )
            level = "info" if terminal_state in {"succeeded", "transport_completed"} else "warning"
            if terminal_state in {"tool_failed", "transport_failed", "response_delivery_failed"}:
                level = "error"
            record_activity(
                "trace.closed", level=level, message="Trace d'appel clôturée",
                details={
                    "duration_ms": duration_ms,
                    "status_code": status_code,
                    "response_completed": completed,
                    "response_bytes": response_bytes,
                    "terminal_state": terminal_state,
                },
            )
            _activity_context.reset(trace_token)
