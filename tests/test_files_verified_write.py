"""Écriture texte vérifiée : vrai handler/script, transports S3 et PG doublés."""
import asyncio
import contextlib
import hashlib
import io
import json
import sys
from types import ModuleType, SimpleNamespace
from unittest.mock import AsyncMock, Mock

import pytest

from src.mcp_tools.auth.context import current_token_info
from src.mcp_tools.storage import files_service
from src.mcp_tools.tools import files

ORIGINAL = '{"preuve": "é", "n": 1}\r\n'
SHA = hashlib.sha256(ORIGINAL.encode("utf-8")).hexdigest()


def real_handler(monkeypatch, backend="s3"):
    class Registry:
        def tool(self):
            def capture(handler):
                self.handler = handler
                return handler
            return capture
    registry = Registry()
    # Seuls l'admission et le transport sont hors de ce contrat unitaire.
    monkeypatch.setattr(files, "traced_tool", lambda name: lambda handler: handler)
    monkeypatch.setattr(files, "check_tool_access", Mock())
    monkeypatch.setattr(files, "get_settings", lambda: SimpleNamespace(
        files_metadata_backend=backend, sandbox_enabled=True, tool_max_output_chars=50_000,
        s3_endpoint_url="https://s3.invalid", s3_access_key_id="test", s3_secret_access_key="test",
        s3_bucket_name="test", s3_region_name="test"))
    files.register(registry)
    return registry.handler


def sandbox(monkeypatch):
    puts = []
    client = SimpleNamespace(put_object=lambda **kw: puts.append(kw) or {"VersionId": "v1"})
    boto3 = ModuleType("boto3")
    boto3.client = lambda *a, **k: client
    botocore = ModuleType("botocore")
    config = ModuleType("botocore.config")
    config.Config = lambda **kw: None
    monkeypatch.setitem(sys.modules, "boto3", boto3)
    monkeypatch.setitem(sys.modules, "botocore", botocore)
    monkeypatch.setitem(sys.modules, "botocore.config", config)

    async def execute(script, timeout, settings):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            exec(compile(script, "<files-sandbox-test>", "exec"), {"__name__": "__main__"})  # noqa: S102 - script réel, boto3 doublé
        return json.loads(output.getvalue())
    monkeypatch.setattr(files, "_run_in_sandbox", execute)
    return puts


def test_write_preserves_exact_unicode_crlf_and_returns_digest(monkeypatch):
    handler = real_handler(monkeypatch)
    puts = sandbox(monkeypatch)
    result = asyncio.run(handler(operation="write", path="evidence.json", content=ORIGINAL,
                                 expected_sha256=SHA))
    assert result["status"] == "success"
    assert result["sha256"] == SHA
    assert result["size"] == len(ORIGINAL.encode("utf-8"))
    assert len(puts) == 1
    assert puts[0]["Body"] == ORIGINAL.encode("utf-8")


def test_real_mcp_schema_exposes_optional_checksum():
    from mcp.server.mcpserver import MCPServer
    server = MCPServer("verified-files-test")
    files.register(server)
    descriptors = asyncio.run(server.list_tools())
    schema = next(tool.input_schema for tool in descriptors if tool.name == "files")
    assert schema["properties"]["expected_sha256"]["anyOf"] == [
        {"type": "string"}, {"type": "null"}]
    assert "expected_sha256" not in schema.get("required", [])
    assert "operation" in schema["required"]


@pytest.mark.parametrize("backend", ["s3", "postgres"])
@pytest.mark.parametrize("kwargs,code", [
    ({"content": json.dumps(json.loads(ORIGINAL)), "expected_sha256": SHA}, "content_checksum_mismatch"),
    ({"expected_sha256": "bad"}, "invalid_expected_sha256"),
    ({"expected_sha256": True}, "invalid_expected_sha256"),
    ({"operation": "read", "expected_sha256": SHA}, "checksum_write_only"),
])
def test_bad_integrity_contract_never_starts_backend(monkeypatch, backend, kwargs, code):
    handler = real_handler(monkeypatch, backend)
    run = AsyncMock(side_effect=AssertionError("must not start sandbox"))
    monkeypatch.setattr(files, "_run_in_sandbox", run)
    initialize = Mock(side_effect=AssertionError("must not initialize catalogue"))
    monkeypatch.setattr(files_service, "get_files_service", initialize)
    arguments = {"operation": "write", "path": "evidence.json", "content": ORIGINAL, **kwargs}
    result = asyncio.run(handler(**arguments))
    assert result["status"] == "error"
    assert result["code"] == code
    assert result["effect_state"] == "not_published"
    assert ORIGINAL not in json.dumps(result)
    run.assert_not_awaited()
    initialize.assert_not_called()


def test_legacy_text_write_remains_available(monkeypatch):
    handler = real_handler(monkeypatch)
    puts = sandbox(monkeypatch)
    result = asyncio.run(handler(operation="write", path="legacy.txt", content=ORIGINAL))
    assert result["status"] == "success"
    assert puts[0]["Body"] == ORIGINAL.encode("utf-8")
    assert result["sha256"] == SHA


def test_generated_script_itself_refuses_mismatching_digest(monkeypatch):
    puts = sandbox(monkeypatch)
    script = files._build_python_script(
        operation="write", endpoint="https://s3.invalid", access_key="test", secret_key="test",
        bucket="test", region="test", path="evidence.json", path2=None, content="changed",
        prefix=None, max_keys=100, max_output_chars=50_000, expected_sha256=SHA)
    result = asyncio.run(files._run_in_sandbox(script, 30, None))
    assert result["code"] == "content_checksum_mismatch"
    assert result["effect_state"] == "not_published"
    assert puts == []


@pytest.mark.parametrize("content", ["\ud800", "é" * 2_500_001])
def test_verified_content_is_valid_utf8_and_bounded_in_bytes(monkeypatch, content):
    handler = real_handler(monkeypatch)
    run = AsyncMock(side_effect=AssertionError("must not start sandbox"))
    monkeypatch.setattr(files, "_run_in_sandbox", run)
    result = asyncio.run(handler(operation="write", path="evidence.json", content=content,
                                 expected_sha256=SHA))
    assert result["code"] == "invalid_verified_content"
    run.assert_not_awaited()


def test_catalogue_internal_entry_refuses_before_ready_or_mutation(monkeypatch):
    service = object.__new__(files_service.FilesService)
    service.ready = AsyncMock()
    service.mutate = AsyncMock()
    monkeypatch.setattr(files_service, "check_tool_access", Mock())
    result = asyncio.run(service.dispatch("write", {"content": "changed", "expected_sha256": SHA}))
    assert result["code"] == "content_checksum_mismatch"
    assert result["effect_state"] == "not_published"
    service.ready.assert_not_awaited()
    service.mutate.assert_not_awaited()


def test_catalogue_receives_verified_expectation_and_preserves_legacy_digest(monkeypatch):
    handler = real_handler(monkeypatch, "postgres")
    service = SimpleNamespace(dispatch=AsyncMock(return_value={"status": "ok", "sha256": SHA}))
    monkeypatch.setattr(files_service, "get_files_service", lambda: service)
    result = asyncio.run(handler(operation="write", path="evidence.json", content=ORIGINAL,
                                 expected_sha256=SHA))
    assert result["sha256"] == SHA
    args = service.dispatch.call_args.args[1]
    assert args["expected_sha256"] == SHA
    raw = object.__new__(files_service.FilesService)
    raw.s = SimpleNamespace(files_s3_prefix="p", s3_bucket_name="b")
    token = current_token_info.set({"credential_binding": "binding"})
    try:
        historical = files_service.digest({"profile": "p", "bucket": "b", "operation": "write",
            "path": "evidence.json", "binding": "binding", "content_sha256": SHA,
            "paths": None, "separator": None, "expected_revision": None})
        assert raw.request("write", {"path": "evidence.json", "content": ORIGINAL}) == historical
        assert raw.request("write", args) != historical
        assert raw.request("write", {**args, "expected_sha256": "0" * 64}) != raw.request("write", args)
    finally:
        current_token_info.reset(token)
