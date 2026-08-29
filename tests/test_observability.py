# -*- coding: utf-8 -*-
"""Tests unitaires du contrat de traçabilité, sans service ni Docker."""

import asyncio
import io
import json
import unittest
from contextlib import redirect_stderr
from datetime import datetime, timedelta, timezone

from src.mcp_tools import observability
from src.mcp_tools.admin import api as admin_api
from src.mcp_tools.auth.middleware import LoggingMiddleware


class ActivityContractTests(unittest.TestCase):
    def setUp(self):
        observability._activity.clear()
        observability._activity_sequence = 0
        observability._activity_capacity_evictions = 0
        observability._activity_age_evictions = 0
        admin_api._logs.clear()

    def _run_asgi(
        self, app, payload, fail_response_body=False, fail_response_start=False,
        headers=None, path="/mcp",
    ):
        sent = []
        received = False

        async def receive():
            nonlocal received
            if received:
                return {"type": "http.disconnect"}
            received = True
            return {"type": "http.request", "body": payload, "more_body": False}

        async def send(message):
            if fail_response_start and message.get("type") == "http.response.start":
                raise RuntimeError("downstream closed")
            if fail_response_body and message.get("type") == "http.response.body":
                raise RuntimeError("downstream closed")
            sent.append(message)

        scope = {
            "type": "http",
            "path": path,
            "method": "POST",
            "headers": headers or [],
        }
        with redirect_stderr(io.StringIO()):
            asyncio.run(observability.ActivityMiddleware(app)(scope, receive, send))
        return sent

    @staticmethod
    def _tool_call_payload(call_id="call-42"):
        return json.dumps({
            "jsonrpc": "2.0",
            "id": 42,
            "method": "tools/call",
            "params": {
                "name": "date",
                "arguments": {"operation": "now"},
                "_meta": {"call_id": call_id, "agent_id": "agent-7"},
            },
        }).encode()

    def test_sse_empty_is_a_terminal_response_missing(self):
        async def app(scope, receive, send):
            await receive()
            await send({
                "type": "http.response.start", "status": 200,
                "headers": [(b"content-type", b"text/event-stream")],
            })
            await send({"type": "http.response.body", "body": b""})

        sent = self._run_asgi(app, self._tool_call_payload())
        snapshot = observability.get_activity_snapshot(call_id="call-42")
        self.assertEqual(1, len(snapshot["calls"]))
        call = snapshot["calls"][0]
        self.assertEqual("response_missing", call["terminal_state"])
        self.assertTrue(call["timeline_complete"])
        self.assertEqual("date", call["tool"])
        self.assertEqual("agent-7", call["agent_id"])
        self.assertIn("transport.sse_empty", {event["event"] for event in call["events"]})
        headers = dict(sent[0]["headers"])
        self.assertIn(b"x-mcp-trace-id", headers)

    def test_terminal_sse_response_is_distinguished_from_delivery(self):
        async def app(scope, receive, send):
            await receive()
            observability.bind_activity(execution_state="succeeded", tool_status="success")
            await send({
                "type": "http.response.start", "status": 200,
                "headers": [(b"content-type", b"text/event-stream")],
            })
            await send({
                "type": "http.response.body",
                # L'ordre des clés JSON n'est pas un contrat JSON-RPC.
                "body": b'event: message\r\ndata: {"result":{},"id":42,"jsonrpc":"2.0"}\r\n\r\n',
            })

        self._run_asgi(app, self._tool_call_payload("call-43"))
        call = observability.get_activity_snapshot(call_id="call-43")["calls"][0]
        self.assertEqual("succeeded", call["terminal_state"])
        self.assertTrue(call["response_terminal_observed"])
        self.assertEqual("mcp_terminal_emitted", call["transport_state"])
        self.assertIn("mcp.response_terminal_observed", {event["event"] for event in call["events"]})

    def test_targeted_lookup_keeps_the_full_timeline(self):
        token = observability._activity_context.set({"trace_id": "tr_a", "call_id": "call-a"})
        try:
            with redirect_stderr(io.StringIO()):
                observability.record_activity("http.received")
                observability.record_activity("tool.started")
                observability.record_activity("tool.completed")
                observability.record_activity("trace.closed", terminal_state="succeeded")
        finally:
            observability._activity_context.reset(token)

        snapshot = observability.get_activity_snapshot(limit=1, call_id="call-a")
        self.assertEqual(4, len(snapshot["events"]))
        self.assertEqual(4, snapshot["calls"][0]["event_count"])
        self.assertEqual("succeeded", snapshot["calls"][0]["terminal_state"])
        self.assertTrue(snapshot["calls"][0]["timeline_complete"])

    def test_asgi_send_failure_is_not_reported_as_a_completed_response(self):
        async def app(scope, receive, send):
            await receive()
            observability.bind_activity(execution_state="succeeded", tool_status="success")
            await send({
                "type": "http.response.start", "status": 200,
                "headers": [(b"content-type", b"text/event-stream")],
            })
            await send({
                "type": "http.response.body",
                "body": b'data: {"jsonrpc":"2.0","id":42,"result":{}}\n\n',
            })

        with self.assertRaisesRegex(RuntimeError, "downstream closed"):
            self._run_asgi(app, self._tool_call_payload("call-44"), fail_response_body=True)

        call = observability.get_activity_snapshot(call_id="call-44")["calls"][0]
        self.assertEqual("response_delivery_failed", call["terminal_state"])
        self.assertFalse(call["response_completed"])
        self.assertIn("transport.response_delivery_failed", {event["event"] for event in call["events"]})

    def test_client_close_after_response_is_not_an_incident(self):
        async def app(scope, receive, send):
            await receive()

            # Le SDK MCP peut écrire depuis une tâche fille alors que la tâche
            # principale attend le disconnect. Le ContextVar de la tâche
            # principale ne voit pas les métadonnées ajoutées par la fille.
            async def emit_response():
                await send({
                    "type": "http.response.start", "status": 200,
                    "headers": [(b"content-type", b"text/event-stream")],
                })
                await send({
                    "type": "http.response.body",
                    "body": b'data: {"jsonrpc":"2.0","id":42,"result":{}}\n\n',
                })

            await asyncio.create_task(emit_response())
            await receive()

        self._run_asgi(app, self._tool_call_payload("call-45"))
        call = observability.get_activity_snapshot(call_id="call-45")["calls"][0]
        closed = next(event for event in call["events"] if event["event"].startswith("transport.client_"))
        self.assertEqual("transport.client_closed_after_response", closed["event"])
        self.assertEqual("info", closed["level"])
        self.assertEqual("transport_completed", call["terminal_state"])

    def test_payload_and_bearer_value_are_never_retained(self):
        secret = "should-never-appear-in-activity"
        command = "echo private-command"
        payload = json.dumps({
            "jsonrpc": "2.0",
            "id": 46,
            "method": "tools/call",
            "params": {
                "name": "ssh",
                "arguments": {"password": secret, "command": command},
                "_meta": {"call_id": "call-46"},
            },
        }).encode()

        async def app(scope, receive, send):
            await receive()
            await send({
                "type": "http.response.start", "status": 200,
                "headers": [(b"content-type", b"text/event-stream")],
            })
            await send({
                "type": "http.response.body", "body": b""})

        self._run_asgi(
            app,
            payload,
            headers=[(b"authorization", f"Bearer {secret}".encode())],
        )
        serialized = json.dumps(observability.get_activity_snapshot(call_id="call-46"))
        self.assertNotIn(secret, serialized)
        self.assertNotIn(command, serialized)

    def test_large_mcp_request_requires_a_terminal_response_conservatively(self):
        async def app(scope, receive, send):
            await receive()
            observability.bind_activity(execution_state="succeeded", tool_status="success")
            await send({
                "type": "http.response.start", "status": 200,
                "headers": [(b"content-type", b"text/event-stream")],
            })
            await send({"type": "http.response.body", "body": b""})

        # Le JSON reste syntaxiquement valide, mais dépasse volontairement la
        # borne d'inspection mémoire ; les métadonnées MCP ne sont pas lues.
        payload = self._tool_call_payload("call-large") + b" " * 1_000_001
        self._run_asgi(app, payload)

        call = observability.get_activity_snapshot()["calls"][0]
        self.assertTrue(call["mcp_terminal_required"])
        self.assertEqual("response_missing", call["terminal_state"])
        self.assertIn("http.request_too_large", {event["event"] for event in call["events"]})

    def test_snapshot_prunes_an_expired_event_even_without_new_request(self):
        expired_at = datetime.now(timezone.utc) - timedelta(
            seconds=observability._MAX_ACTIVITY_AGE_SECONDS + 1
        )
        observability._activity.append({
            "timestamp": expired_at.isoformat(),
            "sequence": 1,
            "event": "http.received",
            "trace_id": "tr_expired",
        })

        snapshot = observability.get_activity_snapshot()

        self.assertEqual([], snapshot["events"])
        self.assertEqual(1, snapshot["stats"]["evicted_age"])

    def test_http_log_uses_the_admin_error_status_sent_downstream(self):
        async def app(scope, receive, send):
            await receive()
            await send({"type": "http.response.start", "status": 422, "headers": []})
            await send({"type": "http.response.body", "body": b""})

        self._run_asgi(
            LoggingMiddleware(app),
            b"{}",
            path="/admin/api/tools/run",
        )

        self.assertEqual(422, admin_api._logs[-1]["status"])
        self.assertEqual("/admin/api/tools/run", admin_api._logs[-1]["path"])

    def test_http_log_marks_an_admin_handler_exception_as_500(self):
        async def app(scope, receive, send):
            await receive()
            raise RuntimeError("store unavailable")

        with self.assertRaisesRegex(RuntimeError, "store unavailable"):
            self._run_asgi(
                LoggingMiddleware(app),
                b"{}",
                path="/admin/api/tools/run",
            )

        self.assertEqual(500, admin_api._logs[-1]["status"])

    def test_http_log_is_not_200_when_response_start_delivery_fails(self):
        async def app(scope, receive, send):
            await receive()
            await send({"type": "http.response.start", "status": 200, "headers": []})

        with self.assertRaisesRegex(RuntimeError, "downstream closed"):
            self._run_asgi(
                LoggingMiddleware(app),
                self._tool_call_payload("call-start-failure"),
                fail_response_start=True,
            )

        call = observability.get_activity_snapshot(call_id="call-start-failure")["calls"][0]
        self.assertEqual("response_delivery_failed", call["terminal_state"])
        self.assertEqual(500, admin_api._logs[-1]["status"])


if __name__ == "__main__":
    unittest.main()
