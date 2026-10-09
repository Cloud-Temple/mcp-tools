"""Contrats CLI avec le vrai SDK MCP, simulé uniquement à la frontière HTTP."""
import asyncio
import json
import sys
import ssl
from datetime import datetime, timedelta, timezone
from pathlib import Path

import httpx2
import httpx
import pytest
from click.testing import CliRunner

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from scripts.cli.client import MCPClient
from scripts.cli.commands import cli


def wire(monkeypatch, *, payload=None, delay=None, status=200, redirect=False):
    requests = []
    real_client = httpx2.AsyncClient

    async def handle(request):
        requests.append(request)
        if redirect and request.url.host == "source.test":
            return httpx2.Response(307, headers={"Location": "https://destination.test/mcp"})
        message = json.loads(request.content)
        method = message.get("method")
        if delay:
            await delay(method)
        if status != 200:
            return httpx2.Response(status, text="refus")
        if "id" not in message:
            return httpx2.Response(202)
        if method == "initialize":
            result = {"protocolVersion": "2025-06-18", "capabilities": {},
                      "serverInfo": {"name": "io-fixture", "version": "1"}}
        elif method == "tools/list":
            result = {"tools": [{"name": "files", "inputSchema": {"type": "object"}}]}
        else:
            result = {"content": [{"type": "text", "text": payload or '{"status":"ok"}'}]}
        return httpx2.Response(200, json={"jsonrpc": "2.0", "id": message["id"], "result": result})

    def factory(**kwargs):
        return real_client(transport=httpx2.MockTransport(handle), **kwargs)

    monkeypatch.setattr(httpx2, "AsyncClient", factory)
    return requests


def test_redirect_never_reaches_destination(monkeypatch):
    requests = wire(monkeypatch, redirect=True)
    result = asyncio.run(MCPClient("https://source.test", timeout=.05).call_tool("files", {}))
    assert result["status"] == "error"
    assert requests and {request.url.host for request in requests} == {"source.test"}


@pytest.mark.parametrize("phase", ["initialize", "tools/call"])
def test_original_budget_spans_initialize_and_call(monkeypatch, phase):
    async def delay(method):
        # Either phase alone completes before the budget; together they exceed it.
        if method == "initialize":
            await asyncio.sleep(.03 if phase == "tools/call" else .08)
        elif method == "tools/call":
            await asyncio.sleep(.03)

    wire(monkeypatch, delay=delay)
    result = asyncio.run(MCPClient("https://source.test", timeout=.05).call_tool("files", {}))
    assert result["status"] == "error"


@pytest.mark.parametrize("phase", ["initialize", "tools/call"])
def test_external_cancellation_propagates(monkeypatch, phase):
    async def run():
        entered = asyncio.Event()

        async def delay(method):
            if method == phase:
                entered.set()
                await asyncio.sleep(10)

        wire(monkeypatch, delay=delay)
        task = asyncio.create_task(MCPClient("https://source.test").call_tool("files", {}))
        await asyncio.wait_for(entered.wait(), 1)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

    asyncio.run(run())


@pytest.mark.parametrize("exception", [KeyboardInterrupt, SystemExit])
def test_process_control_exceptions_propagate(monkeypatch, exception):
    def fail(**kwargs):
        raise exception()

    monkeypatch.setattr(httpx2, "AsyncClient", fail)
    with pytest.raises(exception):
        asyncio.run(MCPClient("https://source.test").call_tool("files", {}))


@pytest.mark.parametrize("payload", ['{"status":"incomplete","confirmation":"unknown"}',
                                         '{"status":"error","message":"refus"}',
                                         '{"status":"ok","content":"écrit"}'])
def test_click_json_and_token_environment_preserved(monkeypatch, payload):
    requests = wire(monkeypatch, payload=payload)
    args = ["--url", "https://source.test", "files", "write", "-p", "proof", "-c", "synthétique", "--json"]
    result = CliRunner().invoke(cli, args, env={"MCP_TOKEN": "synthetic-token"})
    assert result.exit_code == 0, result.exception
    assert json.loads(result.stdout) == json.loads(payload)
    assert result.stderr == ""
    assert "synthetic-token" not in result.output and "synthetic-token" not in args
    assert all(r.headers["Authorization"] == "Bearer synthetic-token" for r in requests)
    call = next(json.loads(r.content) for r in requests if json.loads(r.content).get("method") == "tools/call")
    assert call["params"]["arguments"]["timeout"] == 30
    assert call["params"]["arguments"]["operation"] == "write"


def test_non_json_tool_text_preserved(monkeypatch):
    wire(monkeypatch, payload="texte brut")
    assert asyncio.run(MCPClient("https://source.test").call_tool("files", {})) == {"status": "ok", "raw": "texte brut"}


@pytest.mark.parametrize("status", [401, 403])
def test_click_auth_error_is_not_confirmation(monkeypatch, status):
    wire(monkeypatch, status=status)
    result = CliRunner().invoke(cli, ["--url", "https://source.test", "files", "read", "-p", "proof", "--json"])
    assert result.exit_code == 0
    assert json.loads(result.stdout)["status"] == "error"


def test_click_files_timeout_covers_initialization(monkeypatch):
    async def delay(method):
        if method in {"initialize", "tools/call"}:
            await asyncio.sleep(.6)

    wire(monkeypatch, delay=delay)
    result = CliRunner().invoke(cli, ["--url", "https://source.test", "files", "read",
                                     "-p", "proof", "--timeout", "1", "--json"])
    assert result.exit_code == 0
    assert json.loads(result.stdout)["status"] == "error"


def test_rest_health_redirect_and_json_contract(monkeypatch):
    requests = []
    real_client = httpx.AsyncClient

    async def handle(request):
        requests.append(request)
        return httpx.Response(307, headers={"Location": "https://destination.test/health"}, text="redirect")

    monkeypatch.setattr(httpx, "AsyncClient", lambda **kw: real_client(transport=httpx.MockTransport(handle), **kw))
    result = CliRunner().invoke(cli, ["--url", "https://source.test", "health", "--json"])
    assert result.exit_code == 0
    assert json.loads(result.stdout) == {"status": "error", "message": "redirect", "status_code": 307}
    assert [r.url.host for r in requests] == ["source.test"]


def test_rest_cancellation_propagates(monkeypatch):
    real_client = httpx.AsyncClient

    async def handle(request):
        raise asyncio.CancelledError()

    monkeypatch.setattr(httpx, "AsyncClient", lambda **kw: real_client(transport=httpx.MockTransport(handle), **kw))
    with pytest.raises(asyncio.CancelledError):
        asyncio.run(MCPClient("https://source.test").call_rest())


@pytest.mark.parametrize("trusted", [True, False])
@pytest.mark.parametrize("protocol", ["mcp", "rest"])
def test_real_tls_certificate_environment(monkeypatch, tmp_path, trusted, protocol):
    """Socket TLS loopback synthétique ; aucun service produit ni conteneur."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    def certificate(name):
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
        now = datetime.now(timezone.utc)
        cert = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject)
                .public_key(key.public_key()).serial_number(x509.random_serial_number())
                .not_valid_before(now - timedelta(minutes=1)).not_valid_after(now + timedelta(days=1))
                .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
                .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), critical=False)
                .sign(key, hashes.SHA256()))
        certpath = tmp_path / (name + ".pem")
        keypath = tmp_path / (name + ".key")
        certpath.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        keypath.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                             serialization.NoEncryption()))
        keypath.chmod(0o600)
        return certpath, keypath

    cert, key = certificate("fixture")
    wrong, _ = certificate("wrong")
    monkeypatch.setenv("SSL_CERT_FILE", str(cert if trusted else wrong))
    monkeypatch.delenv("SSL_CERT_DIR", raising=False)
    monkeypatch.setenv("NO_PROXY", "*")

    async def run():
        seen = []
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert, key)

        async def handle(reader, writer):
            try:
                headers = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 2)
                seen.append(headers.splitlines()[0])
                length = next((int(line.split(b":", 1)[1]) for line in headers.splitlines()
                               if line.lower().startswith(b"content-length:")), 0)
                body = await reader.readexactly(length)
                status = 200
                if protocol == "rest":
                    result = {"status": "ok"}
                else:
                    message = json.loads(body)
                    method = message.get("method")
                    if "id" not in message:
                        result, status = {}, 202
                    else:
                        if method == "initialize":
                            inner = {"protocolVersion": "2025-06-18", "capabilities": {},
                                     "serverInfo": {"name": "tls-fixture", "version": "1"}}
                        elif method == "tools/list":
                            inner = {"tools": [{"name": "files", "inputSchema": {"type": "object"}}]}
                        else:
                            inner = {"content": [{"type": "text", "text": '{"status":"ok"}'}]}
                        result = {"jsonrpc": "2.0", "id": message["id"], "result": inner}
                encoded = json.dumps(result).encode()
                writer.write(f"HTTP/1.1 {status} OK\r\nContent-Type: application/json\r\nContent-Length: {len(encoded)}\r\nConnection: close\r\n\r\n".encode() + encoded)
                await writer.drain()
            finally:
                writer.close()
                await writer.wait_closed()

        server = await asyncio.start_server(handle, "127.0.0.1", 0, ssl=context)
        async with server:
            port = server.sockets[0].getsockname()[1]
            client = MCPClient(f"https://localhost:{port}", timeout=2)
            result = await (client.call_tool("files", {}) if protocol == "mcp" else client.call_rest())
        assert result["status"] == ("ok" if trusted else "error")
        assert bool(seen) is trusted

    asyncio.run(run())
