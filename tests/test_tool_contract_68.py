"""Contrat des outils vu par le modèle (#68).

`shell` : aucun état ne survit à l'appel, et la réponse le rappelle quand
l'échec en vient. `files` : `expected_sha256` et `content_base64` ne viennent
que d'un outil, et un refus d'empreinte dit au modèle comment reprendre.
"""
import asyncio
import base64
import hashlib
import json
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

import pytest
from mcp.server.mcpserver import MCPServer

from src.mcp_tools.storage import files_service
from src.mcp_tools.tools import files, shell
from tests.test_files_verified_write import real_server, sdk_call

# Texte non JSON : le SDK 2.2 pré-décode un objet JSON passé dans `content`.
TEXT = "preuve texte é\r\n"
SHA = hashlib.sha256(TEXT.encode("utf-8")).hexdigest()


def tool_descriptor(module, name):
    server = MCPServer(f"contract-{name}")
    module.register(server)
    return next(tool for tool in asyncio.run(server.list_tools()) if tool.name == name)


def shell_handler(monkeypatch, *, sandbox_enabled=True, result=None):
    class Registry:
        def tool(self):
            def capture(handler):
                self.handler = handler
                return handler
            return capture
    registry = Registry()
    monkeypatch.setattr(shell, "traced_tool", lambda name: lambda handler: handler)
    monkeypatch.setattr(shell, "check_tool_access", Mock())
    monkeypatch.setattr(shell, "get_settings", lambda: SimpleNamespace(
        sandbox_enabled=sandbox_enabled, sandbox_max_timeout=30))
    run = AsyncMock(return_value=dict(result))
    monkeypatch.setattr(shell, "_run_in_sandbox" if sandbox_enabled else "_run_local", run)
    shell.register(registry)
    return registry.handler, run


def sandbox_result(returncode, stderr="", stdout=""):
    return {"status": "success" if returncode == 0 else "error", "stdout": stdout,
            "stderr": stderr, "returncode": returncode, "sandbox": True}


# --- shell : schéma ---------------------------------------------------------

def test_shell_description_states_no_state_between_calls():
    tool = tool_descriptor(shell, "shell")
    description = tool.description
    assert "conteneur neuf" in description
    assert "une seule commande" in description
    assert "files" in description
    properties = tool.input_schema["properties"]
    assert "une seule commande" in properties["command"]["description"]
    assert "appel précédent" in properties["cwd"]["description"]
    assert "cd " in properties["cwd"]["description"]


# --- shell : indice dans la réponse ----------------------------------------

@pytest.mark.parametrize("stderr", [
    "bash: line 1: cd: /tmp/projet-1.6.0: No such file or directory\n",
    "cat: libguac/mem.h: No such file or directory\n",
])
def test_shell_failure_on_missing_path_carries_hint(monkeypatch, stderr):
    original = sandbox_result(1, stderr=stderr)
    handler, _ = shell_handler(monkeypatch, result=original)
    response = asyncio.run(handler(command="cd /tmp/projet-1.6.0 && make"))
    assert "conteneur neuf" in response["hint"]
    assert {k: v for k, v in response.items() if k != "hint"} == original


def test_shell_ignored_cwd_carries_hint_even_on_success(monkeypatch):
    original = sandbox_result(0, stdout="ok\n")
    handler, run = shell_handler(monkeypatch, result=original)
    response = asyncio.run(handler(command="ls", cwd="/tmp/projet"))
    assert "cwd" in response["hint"]
    assert "conteneur neuf" in response["hint"]
    assert {k: v for k, v in response.items() if k != "hint"} == original
    assert "/tmp/projet" not in run.await_args.args[0]


@pytest.mark.parametrize("original", [
    sandbox_result(0, stdout="ok\n"),
    sandbox_result(1, stderr="grep: aucune correspondance\n"),
    sandbox_result(0, stderr="ls: /x: No such file or directory\n"),
])
def test_shell_without_missing_path_failure_or_cwd_has_no_hint(monkeypatch, original):
    handler, _ = shell_handler(monkeypatch, result=original)
    response = asyncio.run(handler(command="true"))
    assert "hint" not in response
    assert response == original


def test_shell_timeout_with_ignored_cwd_keeps_hint(monkeypatch):
    handler, _ = shell_handler(monkeypatch, result={})
    monkeypatch.setattr(shell, "_run_in_sandbox", AsyncMock(side_effect=asyncio.TimeoutError()))
    response = asyncio.run(handler(command="make", cwd="/tmp/projet"))
    assert response["status"] == "error"
    assert "Timeout" in response["message"]
    assert "cwd" in response["hint"]


@pytest.mark.parametrize("sandbox_enabled,cwd", [(True, None), (True, ""), (False, "/tmp")])
def test_shell_timeout_without_ignored_cwd_has_no_hint(monkeypatch, sandbox_enabled, cwd):
    handler, _ = shell_handler(monkeypatch, sandbox_enabled=sandbox_enabled, result={})
    target = "_run_in_sandbox" if sandbox_enabled else "_run_local"
    monkeypatch.setattr(shell, target, AsyncMock(side_effect=asyncio.TimeoutError()))
    response = asyncio.run(handler(command="make", cwd=cwd))
    assert "Timeout" in response["message"]
    assert "hint" not in response


@pytest.mark.parametrize("cwd", [None, ""])
def test_shell_empty_cwd_is_not_an_ignored_cwd(monkeypatch, cwd):
    original = sandbox_result(0, stdout="ok\n")
    handler, _ = shell_handler(monkeypatch, result=original)
    assert "hint" not in asyncio.run(handler(command="ls", cwd=cwd))


def test_shell_local_mode_keeps_state_and_gets_no_hint(monkeypatch):
    original = {**sandbox_result(1, stderr="cd: x: No such file or directory\n"), "sandbox": False}
    handler, _ = shell_handler(monkeypatch, sandbox_enabled=False, result=original)
    response = asyncio.run(handler(command="cd x", cwd="/tmp"))
    assert "hint" not in response


# --- files : schéma ----------------------------------------------------------

def test_files_schema_reserves_checksum_and_base64_to_tool_output():
    properties = tool_descriptor(files, "files").input_schema["properties"]
    expected = properties["expected_sha256"]["description"]
    assert "jamais" in expected and "outil" in expected
    assert "omettre" in expected.lower()
    encoded = properties["content_base64"]["description"]
    assert "recommandé pour JSON" not in encoded
    assert "content" in encoded and "modèle" in encoded


# --- files : refus d'empreinte -------------------------------------------------

@pytest.mark.parametrize("backend", ["s3", "postgres"])
@pytest.mark.parametrize("arguments,code", [
    ({"content": TEXT + " ", "expected_sha256": SHA}, "content_checksum_mismatch"),
    ({"content": TEXT, "expected_sha256": "pas-une-empreinte"}, "invalid_expected_sha256"),
])
def test_checksum_refusal_tells_model_how_to_retry(monkeypatch, backend, arguments, code):
    server = real_server(monkeypatch, backend)
    run = AsyncMock(side_effect=AssertionError("no sandbox"))
    monkeypatch.setattr(files, "_run_in_sandbox", run)
    monkeypatch.setattr(files_service, "get_files_service",
                        Mock(side_effect=AssertionError("no catalogue")))
    result = sdk_call(server, operation="write", path="evidence.json", **arguments)
    # Forme lue par mcp-agent (#593) : inchangée.
    assert result["status"] == "error"
    assert result["code"] == code
    assert result["effect_state"] == "not_published"
    assert "Rien n'a été écrit" in result["message"]
    assert "sans expected_sha256" in result["message"]
    if code == "content_checksum_mismatch":
        assert "ne pas la retirer" in result["message"]
    else:
        # Un format invalide ne prouve pas que content diffère de la source.
        assert "diffère" not in result["message"]
        assert "valeur intégrale" in result["message"]
    actual = hashlib.sha256(arguments["content"].encode("utf-8")).hexdigest()
    assert actual not in json.dumps(result)
    assert "preuve texte" not in json.dumps(result)
    run.assert_not_awaited()


@pytest.mark.parametrize("arguments,code", [
    ({"content_base64": base64.b64encode(TEXT.encode()).decode(), "expected_sha256": "0" * 64},
     "content_checksum_mismatch"),
    ({"content_base64": base64.b64encode(TEXT.encode()).decode(), "expected_sha256": "zz"},
     "invalid_expected_sha256"),
    ({"content": "", "expected_sha256": "0" * 64}, "content_checksum_mismatch"),
])
def test_refusal_never_advises_dropping_a_required_digest(monkeypatch, arguments, code):
    # Retirer l'empreinte mènerait à expected_sha256_required (base64) ou à content requis (vide).
    server = real_server(monkeypatch)
    monkeypatch.setattr(files, "_run_in_sandbox", AsyncMock(side_effect=AssertionError("no sandbox")))
    result = sdk_call(server, operation="write", path="evidence.txt", **arguments)
    assert result["code"] == code
    assert result["effect_state"] == "not_published"
    assert "Rien n'a été écrit" in result["message"]
    assert "sans expected_sha256" not in result["message"]
    assert "ne jamais la calculer" in result["message"]


def test_refusal_is_a_structured_result_not_an_sdk_error(monkeypatch):
    # mcp-agent#593 n'attribue l'absence d'effet qu'à une réponse sans isError.
    server = real_server(monkeypatch)
    monkeypatch.setattr(files, "_run_in_sandbox", AsyncMock(side_effect=AssertionError("no sandbox")))
    raw = asyncio.run(server.call_tool("files", {
        "operation": "write", "path": "evidence.txt", "content": TEXT + " ", "expected_sha256": SHA}))
    assert raw.is_error is False
    payload = raw.structured_content or json.loads(raw.content[0].text)
    assert payload["status"] == "error"
    assert payload["code"] == "content_checksum_mismatch"
    assert payload["effect_state"] == "not_published"
