# -*- coding: utf-8 -*-
"""Jetons cybersec : hash seul, tenant obligatoire et révocation fail-closed."""

import unittest
from types import SimpleNamespace

from src.mcp_cybersec.admin import CybersecAdminMiddleware
from src.mcp_cybersec.auth import CybersecAuthMiddleware, CybersecTokenStore
from src.mcp_cybersec.config import CybersecSettings
from src.mcp_cybersec.identity import current_token_info
from src.mcp_cybersec.models import ValidationError
from src.mcp_cybersec.storage import CybersecRepository, MemoryObjectStore


class CybersecAuthTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.backend = MemoryObjectStore()
        self.repository = CybersecRepository(self.backend, "cybersec-test")
        self.tokens = CybersecTokenStore(self.repository)

    async def test_mission_token_persists_only_hash_and_derives_tenant(self):
        created = await self.tokens.create(
            client_name="mission-agent", tenant_id="tenant-a", tool_ids=["campaign", "scope"], expires_days=2
        )
        self.assertIn("token", created)
        self.assertNotIn(created["token"], "".join(self.backend.objects.keys()))
        serialised = b"".join(record["body"] for versions in self.backend.objects.values() for record in versions).decode("utf-8")
        self.assertNotIn(created["token"], serialised)
        validated = await self.tokens.validate(created["token"])
        self.assertEqual("tenant-a", validated["tenant_id"])
        listed = await self.tokens.list()
        self.assertNotIn("token", listed[0])

    async def test_mission_token_without_tenant_or_tools_is_refused(self):
        with self.assertRaises(ValidationError):
            await self.tokens.create(client_name="agent-a", tenant_id=None, tool_ids=["scope"])
        with self.assertRaises(ValidationError):
            await self.tokens.create(client_name="agent-a", tenant_id="tenant-a", tool_ids=[])

    async def test_revocation_fails_closed(self):
        created = await self.tokens.create(client_name="mission-agent", tenant_id="tenant-a", tool_ids=["scope"])
        self.assertTrue(await self.tokens.revoke("mission-agent", "human-admin"))
        self.assertIsNone(await self.tokens.validate(created["token"]))

    async def test_admin_tools_uses_public_mcp_v2_input_schema(self):
        """L'admin reste aligné sur MCP v2 (`input_schema`, pas camelCase)."""
        class FakeMcp:
            async def list_tools(self):
                return [SimpleNamespace(
                    name="scope", description="Périmètre\nDétail",
                    input_schema={"type": "object", "properties": {"target": {"type": "string"}}},
                )]

        async def app(_scope, _receive, _send):
            raise AssertionError("La route admin doit être interceptée")

        middleware = CybersecAdminMiddleware(
            app, FakeMcp(), lambda: SimpleNamespace(settings=SimpleNamespace(cybersec_mcp_server_name="mcp-cybersec")),
        )
        sent = []

        async def receive():
            return {"type": "http.request", "body": b"", "more_body": False}

        async def send(message):
            sent.append(message)

        context = current_token_info.set({"client_name": "human-admin", "permissions": ["admin"], "tool_ids": []})
        try:
            await middleware({"type": "http", "path": "/admin/api/tools", "method": "GET", "query_string": b""}, receive, send)
        finally:
            current_token_info.reset(context)
        self.assertEqual(200, sent[0]["status"])
        self.assertIn(b'"input_schema"', sent[1]["body"])

    async def test_admin_spa_is_public_but_admin_api_remains_fail_closed(self):
        calls = []

        async def app(scope, _receive, _send):
            calls.append(scope["path"])

        middleware = CybersecAuthMiddleware(app, CybersecSettings(), lambda: self.tokens)

        async def receive():
            return {"type": "http.request", "body": b"", "more_body": False}

        async def unused_send(_message):
            return None

        await middleware({"type": "http", "path": "/admin", "headers": []}, receive, unused_send)
        self.assertEqual(["/admin"], calls)

        sent = []

        async def send(message):
            sent.append(message)

        await middleware({"type": "http", "path": "/admin/api/tools", "headers": []}, receive, send)
        self.assertEqual(401, sent[0]["status"])
        self.assertEqual(["/admin"], calls)


if __name__ == "__main__":
    unittest.main()
