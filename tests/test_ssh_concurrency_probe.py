"""Tests hermétiques du probe de huit appels SSH concurrents."""

from __future__ import annotations

import asyncio
import contextlib
import importlib.util
import io
import json
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace


SCRIPT = Path(__file__).parents[1] / "scripts" / "ssh_concurrency_probe.py"
SPEC = importlib.util.spec_from_file_location("ssh_concurrency_probe", SCRIPT)
assert SPEC and SPEC.loader
probe = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = probe
SPEC.loader.exec_module(probe)


def tool_result(hostname: str = "canary-01") -> SimpleNamespace:
    payload = {
        "status": "success",
        "exit_code": 0,
        "stdout": f"{hostname}\n",
    }
    return SimpleNamespace(
        is_error=False,
        structured_content=payload,
        content=[SimpleNamespace(text=json.dumps(payload))],
    )


def config(**changes) -> probe.ProbeConfig:
    values = {
        "url": "https://mcp-tools.example.test/mcp",
        "host": "192.0.2.10",
        "username": "tester",
        "expected_hostname": "canary-01",
        "setup_timeout": 0.2,
        "teardown_timeout": 0.05,
    }
    values.update(changes)
    return probe.ProbeConfig(**values)


def config_with_call_timeout(seconds: float) -> SimpleNamespace:
    base = config()
    return SimpleNamespace(
        **base.__dict__,
        call_timeout=seconds,
    )


class SuccessfulWorker:
    instances = []
    ready_indexes = set()

    def __init__(self, index, worker_config, token):
        self.index = index
        self.timings = {}
        self.calls = 0
        self.lifecycle_task = None
        type(self).instances.append(self)

    async def prepare(self):
        self.lifecycle_task = asyncio.current_task()
        SuccessfulWorker.ready_indexes.add(self.index)
        await asyncio.sleep(0)

    async def call(self, private_key):
        assert asyncio.current_task() is self.lifecycle_task
        assert len(SuccessfulWorker.ready_indexes) == 8
        self.calls += 1
        await asyncio.sleep(0.01)
        return tool_result()

    async def close(self):
        if self.lifecycle_task is not None:
            assert asyncio.current_task() is self.lifecycle_task
        await asyncio.sleep(0)


class ProbeExecutionTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        SuccessfulWorker.instances = []
        SuccessfulWorker.ready_indexes = set()

    async def test_exactly_eight_calls_are_released(self):
        report = await probe.run_probe(
            config(), "token-secret", "key-secret", SuccessfulWorker
        )

        self.assertEqual(report["requested"], 8)
        self.assertEqual(report["initialized_count"], 8)
        self.assertEqual(report["attempted"], 8)
        self.assertEqual(report["succeeded"], 8)
        self.assertEqual(report["teardown_failed"], 0)
        self.assertEqual(report["probe_status"], "success")
        self.assertTrue(report["released"])
        self.assertEqual([worker.calls for worker in SuccessfulWorker.instances], [1] * 8)
        self.assertIsNotNone(report["dispatch_skew_ms"])
        statistics = report["call_tool_statistics"]
        self.assertEqual(statistics["sample_size"], 8)
        self.assertEqual(statistics["p95_ms"], statistics["max_ms"])

    async def test_one_immediate_failure_does_not_cancel_siblings(self):
        class OneFailureWorker(SuccessfulWorker):
            instances = []

            async def call(self, private_key):
                self.calls += 1
                if self.index == 0:
                    raise RuntimeError("key-secret must never appear")
                await asyncio.sleep(0.01)
                return tool_result()

        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            report = await probe.run_probe(
                config(), "token-secret", "key-secret", OneFailureWorker
            )

        self.assertEqual(report["attempted"], 8)
        self.assertEqual(report["succeeded"], 7)
        self.assertEqual([worker.calls for worker in OneFailureWorker.instances], [1] * 8)
        serialized = json.dumps(report)
        self.assertNotIn("key-secret", serialized)
        self.assertNotIn("must never appear", serialized)
        self.assertNotIn("key-secret", stderr.getvalue())
        self.assertNotIn("must never appear", stderr.getvalue())

    async def test_setup_failure_aborts_all_calls(self):
        class SetupFailureWorker(SuccessfulWorker):
            instances = []

            async def prepare(self):
                if self.index == 3:
                    raise RuntimeError("setup failed")

        report = await probe.run_probe(
            config(), "token-secret", "key-secret", SetupFailureWorker
        )

        self.assertFalse(report["released"])
        self.assertEqual(report["attempted"], 0)
        self.assertEqual([worker.calls for worker in SetupFailureWorker.instances], [0] * 8)

    async def test_setup_timeout_aborts_all_calls(self):
        class SetupTimeoutWorker(SuccessfulWorker):
            instances = []

            async def prepare(self):
                await asyncio.sleep(1)

        report = await probe.run_probe(
            config(setup_timeout=0.01),
            "token-secret",
            "key-secret",
            SetupTimeoutWorker,
        )

        self.assertEqual(report["attempted"], 0)
        self.assertEqual(
            [item["error_category"] for item in report["results"]],
            ["setup_timeout"] * 8,
        )
        self.assertLess(report["total_ms"], 500)

    async def test_call_timeout_is_bounded_for_all_eight(self):
        class CallTimeoutWorker(SuccessfulWorker):
            instances = []

            async def call(self, private_key):
                self.calls += 1
                await asyncio.sleep(1)

        report = await probe.run_probe(
            config_with_call_timeout(0.01),
            "token-secret",
            "key-secret",
            CallTimeoutWorker,
        )

        self.assertEqual(report["attempted"], 8)
        self.assertEqual(
            [item["error_category"] for item in report["results"]],
            ["call_timeout"] * 8,
        )
        self.assertLess(report["total_ms"], 500)

    async def test_teardown_timeout_is_bounded(self):
        class BlockingCloseWorker(SuccessfulWorker):
            instances = []

            async def close(self):
                await asyncio.sleep(1)

        report = await probe.run_probe(
            config(teardown_timeout=0.01),
            "token-secret",
            "key-secret",
            BlockingCloseWorker,
        )

        self.assertEqual(
            [item["teardown_status"] for item in report["results"]],
            ["timeout"] * 8,
        )
        self.assertLess(report["total_ms"], 500)

    async def test_real_sdk_worker_over_mock_transport(self):
        from unittest.mock import patch
        import httpx2
        from mcp.types import CallToolResult

        methods = []
        def handler(request):
            if request.method == "GET":
                return httpx2.Response(405)
            if request.method == "DELETE":
                return httpx2.Response(204)
            body = json.loads(request.content)
            method = body["method"]
            methods.append(method)
            if "id" not in body:
                return httpx2.Response(202)
            if method == "initialize":
                result = {"protocolVersion": "2025-06-18", "capabilities": {},
                          "serverInfo": {"name": "offline", "version": "1"}}
            elif method == "tools/list":
                result = {"tools": [{"name": "ssh", "inputSchema": {"type": "object"}}]}
            elif method == "tools/call":
                self.assertEqual(body["params"]["name"], "ssh")
                self.assertEqual(body["params"]["arguments"]["command"], "hostname")
                payload = {"status": "success", "exit_code": 0, "stdout": "canary-01\n"}
                result = {"content": [{"type": "text", "text": json.dumps(payload)}],
                          "structuredContent": payload, "isError": False}
            else:
                raise AssertionError(method)
            return httpx2.Response(200, headers={"mcp-session-id": "offline"},
                json={"jsonrpc": "2.0", "id": body["id"], "result": result})

        def client_factory(headers=None, timeout=None, auth=None):
            return httpx2.AsyncClient(headers=headers, timeout=timeout, auth=auth,
                                     transport=httpx2.MockTransport(handler), follow_redirects=False)
        worker = probe.MCPWorker(0, config(), "token-secret")
        with patch.object(probe, "_no_redirect_http_client", client_factory):
            try:
                await worker.prepare()
                result = await worker.call("key-secret")
                self.assertIsInstance(result, CallToolResult)
                self.assertEqual(probe.validate_tool_result(result, "canary-01")["ssh_exit_code"], 0)
            finally:
                await worker.close()
        self.assertIn("initialize", methods)
        self.assertIn("tools/call", methods)

    async def test_mcp_worker_fixes_tool_and_command(self):
        captured = {}

        class FakeSession:
            async def call_tool(self, name, arguments):
                captured.update(name=name, arguments=arguments)
                return tool_result()

        worker = probe.MCPWorker(0, config(), "token-secret")
        worker.session = FakeSession()
        await worker.call("key-secret")

        self.assertEqual(captured["name"], "ssh")
        self.assertEqual(captured["arguments"]["operation"], "exec")
        self.assertEqual(captured["arguments"]["command"], "hostname")
        self.assertFalse(captured["arguments"]["sudo"])

    @unittest.skipUnless(importlib.util.find_spec("httpx2"), "httpx not installed")
    async def test_http_client_disables_redirects(self):
        client = probe._no_redirect_http_client()
        try:
            self.assertFalse(client.follow_redirects)
        finally:
            await client.aclose()

    @unittest.skipUnless(importlib.util.find_spec("mcp"), "mcp SDK not installed")
    async def test_locked_mcp_session_lifecycle_same_task(self):
        import anyio
        from mcp import ClientSession

        inbound_writer, inbound_reader = anyio.create_memory_object_stream(1)
        outbound_writer, outbound_reader = anyio.create_memory_object_stream(1)
        try:
            async with ClientSession(inbound_reader, outbound_writer):
                pass
        finally:
            await inbound_writer.aclose()
            await outbound_reader.aclose()


class ResultValidationTests(unittest.TestCase):
    def test_strict_success(self):
        validated = probe.validate_tool_result(tool_result(), "canary-01")
        self.assertEqual(validated["observed_hostname"], "canary-01")

    def test_rejects_boolean_exit_code(self):
        result = tool_result()
        result.structured_content["exit_code"] = False
        result.content[0].text = json.dumps(result.structured_content)
        with self.assertRaises(ValueError):
            probe.validate_tool_result(result, "canary-01")

    def test_rejects_structured_text_disagreement(self):
        result = tool_result()
        result.content[0].text = json.dumps(
            {"status": "success", "exit_code": 0, "stdout": "other-host\n"}
        )
        with self.assertRaises(ValueError):
            probe.validate_tool_result(result, "canary-01")

    def test_rejects_extra_blank_hostname_lines(self):
        result = tool_result()
        result.structured_content["stdout"] = "\ncanary-01\n\n"
        result.content[0].text = json.dumps(result.structured_content)
        with self.assertRaises(ValueError):
            probe.validate_tool_result(result, "canary-01")

    def test_rejects_consistent_but_unexpected_hostname(self):
        with self.assertRaises(ValueError):
            probe.validate_tool_result(tool_result("other-host"), "canary-01")

    def test_nearest_rank_p95_of_eight_is_maximum(self):
        self.assertEqual(probe.nearest_rank(list(range(1, 9)), 95), 8)


class ConfigurationTests(unittest.TestCase):
    def test_requires_https_exact_mcp_path(self):
        for url in (
            "http://mcp-tools.example.test/mcp",
            "https://mcp-tools.example.test/mcp/",
            "https://mcp-tools.example.test/mcp?token=secret",
        ):
            with self.subTest(url=url), self.assertRaises(ValueError):
                probe.validate_config(config(url=url))

    @unittest.skipUnless(importlib.util.find_spec("mcp"), "mcp SDK not installed")
    def test_locked_mcp_client_import_surface(self):
        from mcp import ClientSession
        from mcp.client.streamable_http import streamable_http_client

        self.assertIsNotNone(ClientSession)
        self.assertTrue(callable(streamable_http_client))


if __name__ == "__main__":
    unittest.main()
