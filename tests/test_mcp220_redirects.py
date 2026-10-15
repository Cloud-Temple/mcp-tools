"""Vault SQL credentials use the real SDK and never follow a redirect."""
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import httpx2
from src.mcp_tools.storage.files_credentials import Credentials, StorageUnavailable


class MCP220Redirects(unittest.IsolatedAsyncioTestCase):
    async def test_vault_credentials_positive_and_redirects(self):
        with tempfile.TemporaryDirectory() as directory:
            token = Path(directory) / "token"
            token.write_text("synthetic")
            token.chmod(0o600)
            cfg = SimpleNamespace(files_credentials_mode="vault", files_vault_token_file=str(token),
                files_vault_url="https://pinned.invalid", files_vault_ca_file=None,
                files_connect_timeout=1, files_vault_id="scoped", files_vault_path="connection",
                files_pg_database="tools", files_pg_role="app")
            expected = {"host": "database", "port": 5432, "dbname": "tools", "user": "app", "password": "synthetic"}
            for status in (None, 307, 308):
                for location in ("https://pinned.invalid/next", "https://other.invalid/next"):
                    with self.subTest(status=status, location=location):
                        seen = []
                        def handle(request):
                            seen.append((str(request.url), request.headers.get("authorization")))
                            if status is not None:
                                return httpx2.Response(status, headers={"Location": location})
                            if request.method != "POST":
                                return httpx2.Response(405)
                            body = json.loads(request.content)
                            if "id" not in body:
                                return httpx2.Response(202)
                            if body["method"] == "initialize":
                                result = {"protocolVersion": body["params"]["protocolVersion"], "capabilities": {},
                                    "serverInfo": {"name": "local-contract", "version": "1"}}
                            elif body["method"] == "tools/list":
                                result = {"tools": [{"name": "secret_read", "inputSchema": {"type": "object"}}]}
                            else:
                                payload = {"status": "ok", "vault_id": "scoped", "path": "connection", "data": expected}
                                result = {"content": [{"type": "text", "text": json.dumps(payload)}], "isError": False}
                            return httpx2.Response(200, json={"jsonrpc": "2.0", "id": body["id"], "result": result})
                        original = httpx2.AsyncClient
                        def factory(**kwargs):
                            return original(transport=httpx2.MockTransport(handle), **kwargs)
                        with patch.object(httpx2, "AsyncClient", side_effect=factory):
                            if status is None:
                                self.assertEqual(await Credentials(cfg).sql(), expected)
                            else:
                                with self.assertRaisesRegex(StorageUnavailable, "Vault non autorisé ou indisponible"):
                                    await Credentials(cfg).sql()
                        self.assertTrue(seen)
                        self.assertEqual(set(seen), {("https://pinned.invalid/mcp", "Bearer synthetic")})
                        if status is not None:
                            self.assertEqual(len(seen), 1)
