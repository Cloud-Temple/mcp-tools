"""Texte libre de forme JSON à travers le vrai SDK MCP 2.2 (#70).

Le SDK applique `json.loads` à toute chaîne destinée à un paramètre qui n'est
pas annoté `str` pur. Ces tests passent par `MCPServer.call_tool`, donc par
cette conversion, et regardent ce qui atteint le stockage ou le transport.
"""
import asyncio
import hashlib
import json
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

import pytest
from mcp.server.mcpserver import MCPServer

from src.mcp_tools.storage import files_service
from src.mcp_tools.tools import files, http, perplexity, ssh
from tests.test_files_verified_write import real_handler, real_server, sandbox, sdk_call

# Chaînes que le SDK de main décode : objet, liste (espaces compris), null.
JSON_SHAPED = ['{"b": 1,  "a": [1, 2]}\n', " [1, 2] ", "null", '{"preuve": "é"}']

REPORT = {"zeta": 1, "alpha": "é", "items": [1, {"k": None}], "ok": True}
# Forme exacte attendue : indentation 2, ordre reçu, UTF-8 brut, sans saut final.
REPORT_TEXT = """{
  "zeta": 1,
  "alpha": "é",
  "items": [
    1,
    {
      "k": null
    }
  ],
  "ok": true
}"""


def sha(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def no_backend(monkeypatch):
    run = AsyncMock(side_effect=AssertionError("no sandbox"))
    monkeypatch.setattr(files, "_run_in_sandbox", run)
    monkeypatch.setattr(files_service, "get_files_service",
                        Mock(side_effect=AssertionError("no catalogue")))
    return run


# --- files.content : texte intact ----------------------------------------------

@pytest.mark.parametrize("text", JSON_SHAPED)
def test_json_shaped_text_is_written_byte_for_byte(monkeypatch, text):
    server = real_server(monkeypatch)
    puts = sandbox(monkeypatch)
    result = sdk_call(server, operation="write", path="report.json", content=text,
                      expected_sha256=sha(text))
    assert result["status"] == "success"
    assert puts[0]["Body"] == text.encode("utf-8")
    assert result["sha256"] == sha(text)
    assert result["size"] == len(text.encode("utf-8"))


@pytest.mark.parametrize("text", JSON_SHAPED)
def test_catalogue_receives_json_shaped_text_unchanged(monkeypatch, text):
    server = real_server(monkeypatch, "postgres")
    service = SimpleNamespace(dispatch=AsyncMock(return_value={"status": "ok"}))
    monkeypatch.setattr(files_service, "get_files_service", lambda: service)
    sdk_call(server, operation="write", path="report.json", content=text)
    assert service.dispatch.call_args.args[1]["content"] == text


# --- files.content : objet ou liste tolérés -----------------------------------

def test_serialization_rule_is_pinned():
    from src.mcp_tools.storage.files_integrity import serialize_json_content
    assert serialize_json_content(REPORT) == REPORT_TEXT
    assert serialize_json_content([]) == "[]"


@pytest.mark.parametrize("value,text", [
    (REPORT, REPORT_TEXT),
    ([{"b": 2, "a": 1}], '[\n  {\n    "b": 2,\n    "a": 1\n  }\n]'),
    ({}, "{}"),
])
def test_object_or_list_is_serialized_and_digest_covers_written_bytes(monkeypatch, value, text):
    server = real_server(monkeypatch)
    puts = sandbox(monkeypatch)
    result = sdk_call(server, operation="write", path="report.json", content=value,
                      expected_sha256=sha(text))
    assert result["status"] == "success"
    assert puts[0]["Body"] == text.encode("utf-8")
    assert result["sha256"] == sha(text)
    assert result["size"] == len(text.encode("utf-8"))
    observed = sdk_call(server, operation="read", path="report.json")
    assert observed["content"] == text


def test_catalogue_receives_serialized_text_and_same_request_digest(monkeypatch):
    server = real_server(monkeypatch, "postgres")
    service = SimpleNamespace(dispatch=AsyncMock(return_value={"status": "ok"}))
    monkeypatch.setattr(files_service, "get_files_service", lambda: service)
    sdk_call(server, operation="write", path="report.json", content=REPORT,
             expected_sha256=sha(REPORT_TEXT))
    args = service.dispatch.call_args.args[1]
    assert args["content"] == REPORT_TEXT
    assert args["expected_sha256"] == sha(REPORT_TEXT)
    raw = object.__new__(files_service.FilesService)
    raw.s = SimpleNamespace(files_s3_prefix="p", s3_bucket_name="b")
    # Le reçu du catalogue est celui d'une écriture du même texte passé en chaîne.
    assert raw.request("write", args) == raw.request("write", {
        "path": "report.json", "content": REPORT_TEXT, "expected_sha256": sha(REPORT_TEXT)})


@pytest.mark.parametrize("backend", ["s3", "postgres"])
def test_object_with_source_digest_is_refused_and_says_it_was_serialized(monkeypatch, backend):
    server = real_server(monkeypatch, backend)
    run = no_backend(monkeypatch)
    compact = json.dumps(REPORT, ensure_ascii=False)
    result = sdk_call(server, operation="write", path="report.json", content=REPORT,
                      expected_sha256=sha(compact))
    assert result["code"] == "content_checksum_mismatch"
    assert result["effect_state"] == "not_published"
    assert "sérialisé" in result["message"]
    assert "comme chaîne" in result["message"]
    # Contraste : un texte refusé ne parle pas de sérialisation.
    text = sdk_call(server, operation="write", path="report.json", content=compact,
                    expected_sha256=sha("autre"))
    assert text["code"] == "content_checksum_mismatch"
    assert "sérialisé" not in text["message"]
    run.assert_not_awaited()


# --- files.content : types refusés ---------------------------------------------

@pytest.mark.parametrize("backend", ["s3", "postgres"])
@pytest.mark.parametrize("value,label", [(42, "nombre"), (1.5, "nombre"), (True, "booléen"), (False, "booléen")])
def test_scalar_content_is_refused_before_backend(monkeypatch, backend, value, label):
    server = real_server(monkeypatch, backend)
    run = no_backend(monkeypatch)
    result = sdk_call(server, operation="write", path="report.json", content=value)
    assert result["status"] == "error"
    assert result["code"] == "invalid_content_type"
    assert result["effect_state"] == "not_published"
    assert label in result["message"]
    assert '"42"' in result["message"]
    run.assert_not_awaited()


def test_null_text_is_written_but_json_null_keeps_content_required(monkeypatch):
    server = real_server(monkeypatch)
    puts = sandbox(monkeypatch)
    written = sdk_call(server, operation="write", path="report.txt", content="null")
    assert written["status"] == "success"
    assert puts[0]["Body"] == b"null"
    refused = sdk_call(server, operation="write", path="report.txt", content=None)
    assert refused == {"status": "error", "message": "Le paramètre 'content' est requis pour l'opération 'write'."}
    assert len(puts) == 1


@pytest.mark.parametrize("value,code", [
    (b"octets", "invalid_content_type"),
    ({"x": float("nan")}, "invalid_content_json"),
    ([float("inf")], "invalid_content_json"),
])
def test_direct_callers_cannot_write_bytes_or_non_standard_json(monkeypatch, value, code):
    # Le transport MCP ne porte ni octets ni NaN ; la CLI ou un test peuvent.
    handler = real_handler(monkeypatch)
    run = no_backend(monkeypatch)
    result = asyncio.run(handler(operation="write", path="report.json", content=value))
    assert result["code"] == code
    assert result["effect_state"] == "not_published"
    run.assert_not_awaited()


def test_object_content_is_ignored_outside_write(monkeypatch):
    server = real_server(monkeypatch)
    sandbox(monkeypatch)
    sdk_call(server, operation="write", path="a.txt", content="x")
    result = sdk_call(server, operation="read", path="a.txt", content={"ignored": True})
    assert result["status"] == "success"
    assert result["content"] == "x"


# --- schéma publié --------------------------------------------------------------

RAW_PARAMS = {
    files: ("files", ["content", "separator"]),
    http: ("http", ["body", "auth_value"]),
    ssh: ("ssh", ["content", "password"]),
    perplexity: ("perplexity_doc", ["context"]),
}


def descriptor(module, name):
    server = MCPServer(f"schema-{name}")
    module.register(server)
    return next(tool for tool in asyncio.run(server.list_tools()) if tool.name == name)


def test_files_documents_tolerance_while_every_schema_stays_optional_string():
    tool = descriptor(files, "files")
    content = tool.input_schema["properties"]["content"]["description"]
    assert "telle quelle" in content and "octet pour octet" in content
    assert "toléré" in content and "indent=2" in content
    assert "sha256" in content
    assert "toléré" in tool.description and "SHA-256" in tool.description
    # Le schéma ne déclare pas l'objet toléré : même forme que l'ancien
    # Optional[str], car un array sans items est refusé par certains fournisseurs.
    for module, (name, params) in RAW_PARAMS.items():
        properties = descriptor(module, name).input_schema["properties"]
        for param in params:
            schema = properties[param]
            assert schema["anyOf"] == [{"type": "string"}, {"type": "null"}], (name, param)
            assert "type" not in schema
            assert schema["description"]


# --- autres outils : la chaîne atteint le transport intacte --------------------

def register_for_test(module, monkeypatch, settings):
    monkeypatch.setattr(module, "traced_tool", lambda name: lambda handler: handler)
    monkeypatch.setattr(module, "check_tool_access", Mock())
    monkeypatch.setattr(module, "get_settings", lambda: settings)
    server = MCPServer(f"raw-{module.__name__}")
    module.register(server)
    return server


def call(server, name, **arguments):
    result = asyncio.run(server.call_tool(name, arguments))
    return result.structured_content or json.loads(result.content[0].text)


@pytest.mark.parametrize("text", JSON_SHAPED)
def test_http_body_and_auth_value_reach_transport_unchanged(monkeypatch, text):
    server = register_for_test(http, monkeypatch, SimpleNamespace(sandbox_enabled=True, tool_max_timeout=30))
    monkeypatch.setattr(http, "_validate_url", lambda url: None)
    run = AsyncMock(return_value={"status": "success"})
    monkeypatch.setattr(http, "_run_in_sandbox", run)
    call(server, "http", url="https://example.invalid", method="POST", body=text,
         auth_type="bearer", auth_value=text)
    args = run.call_args.args
    assert args[3] == text  # body
    assert args[6] == text  # auth_value
    # Contraste : un vrai objet reste refusé dans body, json_body existe pour lui.
    run.reset_mock()
    with pytest.raises(Exception, match="valid string"):
        asyncio.run(server.call_tool("http", {"url": "https://example.invalid", "body": {"a": 1}}))
    run.assert_not_awaited()


@pytest.mark.parametrize("text", JSON_SHAPED)
def test_ssh_content_and_password_reach_transport_unchanged(monkeypatch, text):
    server = register_for_test(ssh, monkeypatch, SimpleNamespace(sandbox_enabled=True))
    run = AsyncMock(return_value={"status": "success"})
    monkeypatch.setattr(ssh, "_run_in_sandbox", run)
    call(server, "ssh", operation="upload", host="example.invalid", username="audit",
         password=text, remote_path="/tmp/report.json", content=text)
    kwargs = run.call_args.kwargs
    assert kwargs["content"] == text
    assert kwargs["password"] == text


@pytest.mark.parametrize("text", JSON_SHAPED)
def test_perplexity_doc_context_reaches_request_unchanged(monkeypatch, text):
    settings = SimpleNamespace(perplexity_api_key="k", perplexity_model="m", perplexity_timeout=5,
                               perplexity_api_url="https://api.invalid", tool_max_output_chars=1000)
    server = register_for_test(perplexity, monkeypatch, settings)
    sent = []

    class Client:
        def __init__(self, **kwargs):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *exc):
            return False

        async def post(self, url, headers, json):
            sent.append(json)
            return SimpleNamespace(raise_for_status=lambda: None,
                                   json=lambda: {"choices": [{"message": {"content": "ok"}}]})
    monkeypatch.setattr(perplexity.httpx, "AsyncClient", Client)
    call(server, "perplexity_doc", query="FastAPI", context=text)
    assert sent[0]["messages"][1]["content"].endswith(text)


@pytest.mark.parametrize("text", ["[]", "{}", "null"])
def test_files_concat_separator_reaches_script_unchanged(monkeypatch, text):
    server = real_server(monkeypatch)
    build = Mock(return_value="script")
    monkeypatch.setattr(files, "_build_python_script", build)
    monkeypatch.setattr(files, "_run_in_sandbox", AsyncMock(return_value={"status": "success"}))
    sdk_call(server, operation="concat", path="out.txt", paths=["a.txt", "b.txt"], separator=text)
    assert build.call_args.kwargs["separator"] == text
