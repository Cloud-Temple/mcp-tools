"""Contrats locaux droits/identité/absence de replay ; aucun moteur simulé ne vaut qualification."""
import asyncio
import json
import threading
from types import SimpleNamespace
from unittest import IsolatedAsyncioTestCase, TestCase
from unittest.mock import AsyncMock, patch

from src.mcp_tools.auth.context import current_token_info
from src.mcp_tools.storage.files_credentials import Credentials, StorageUnavailable
from src.mcp_tools.storage.files_postgres import Catalog, Conflict
from src.mcp_tools.storage.files_service import FilesService
from src.mcp_tools.storage.files_s3 import Blobs


class RightsContracts(IsolatedAsyncioTestCase):
    async def test_http_readiness_fails_closed_while_liveness_remains_live(self):
        from src.mcp_tools import server
        fake=SimpleNamespace(files_metadata_backend="invalid",mcp_server_name="tools")
        app=server.HealthCheckMiddleware(AsyncMock())
        async def receive(): return {"type":"http.request","body":b""}
        with patch.object(server,"settings",fake):
            for path,status in (("/ready",503),("/health",200)):
                messages=[]
                async def send(message): messages.append(message)
                await app({"type":"http","path":path},receive,send)
                self.assertEqual(messages[0]["status"],status)

    async def test_denied_reads_do_not_touch_dependency_or_return_counts(self):
        service=object.__new__(FilesService)
        service.ready=AsyncMock()
        tok=current_token_info.set({"client_name":"same-name","permissions":["access"],"tool_ids":["calc"]})
        try:
            with self.assertRaises(ValueError):
                await service.dispatch("list",{})
            service.ready.assert_not_awaited()
        finally:
            current_token_info.reset(tok)

    async def test_nonadmin_reconcile_never_connects(self):
        service=object.__new__(FilesService)
        service.ready=AsyncMock()
        tok=current_token_info.set({"permissions":["access"],"tool_ids":["files"],"credential_binding":"origin"})
        try:
            with self.assertRaises(Conflict):
                await service.dispatch("reconcile",{"operation_id":"00000000-0000-0000-0000-000000000001"})
            service.ready.assert_not_awaited()
        finally:
            current_token_info.reset(tok)

    async def test_duplicate_id_only_inspects_never_prepares_or_puts(self):
        service=object.__new__(FilesService)
        service.request=lambda *a:"frozen-request"
        service.authorize_journal=lambda *a:None
        service.prepare=AsyncMock(side_effect=AssertionError("no prepare"))
        service.info=AsyncMock(return_value={"status":"incomplete","remote_result":"uncertain"})
        class Connection:
            async def __aenter__(self): return object()
            async def __aexit__(self,*a): return False
        service.catalog=SimpleNamespace(connection=lambda:Connection(),one=AsyncMock(return_value={"request_digest":"frozen-request"}))
        result=await service.mutate("write",{"path":"p","content":"a"},"00000000-0000-0000-0000-000000000001")
        service.prepare.assert_not_awaited()
        service.info.assert_awaited_once()
        self.assertEqual(result["remote_result"],"uncertain")

    async def test_explicit_vault_refusal_has_no_direct_fallback(self):
        s=SimpleNamespace(files_credentials_mode="vault",files_vault_url="http://untrusted.test")
        with self.assertRaises(StorageUnavailable):
            await Credentials(s).sql()
        with self.assertRaises(StorageUnavailable):
            await Credentials(s).sql("hidden-direct-service")

    async def test_s3_timeout_keeps_admission_until_thread_finishes(self):
        blobs=object.__new__(Blobs)
        blobs.slots=asyncio.Semaphore(1);blobs.jobs=set()
        release=threading.Event();started=threading.Event()
        def work():
            started.set();release.wait(2);return "observed"
        first=asyncio.create_task(blobs.run(work))
        try:
            while not started.is_set(): await asyncio.sleep(.005)
            first.cancel()
            with self.assertRaises(asyncio.CancelledError): await first
            self.assertTrue(blobs.slots.locked())
            self.assertEqual(len(blobs.jobs),1)
        finally:
            release.set()
            while blobs.jobs: await asyncio.sleep(.005)
        self.assertFalse(blobs.slots.locked())


class IdentityContracts(TestCase):
    def test_same_client_name_cannot_inherit_journal_after_credential_change(self):
        service=object.__new__(FilesService)
        tok=current_token_info.set({"client_name":"reused","permissions":["access"],"tool_ids":["files"],"credential_binding":"new"})
        try:
            with self.assertRaises(Conflict): service.authorize_journal({"binding":"revoked"})
            service.authorize_journal({"binding":"new"})
        finally:
            current_token_info.reset(tok)

    def test_bootstrap_without_binding_requires_admin_for_journal(self):
        service=object.__new__(FilesService)
        tok=current_token_info.set({"permissions":["access"],"tool_ids":["files"]})
        try:
            with self.assertRaises(Conflict): service.authorize_journal({"binding":None})
        finally:
            current_token_info.reset(tok)

    def test_roster_rejects_shared_member_identity(self):
        member={"id":"a","name":"a","role":"a","address":"192.0.2.1","slot":"a","dn":"CN=a"}
        second={**member,"id":"b","name":"b","role":"b","slot":"b","dn":"CN=b"}
        s=SimpleNamespace(files_pg_schema="tools_files",files_durability="remote_apply",
            files_pg_system_identifier="1",files_pg_timeline=1,files_quorum=2,
            files_replication_roster=json.dumps([member,second]))
        with self.assertRaises(StorageUnavailable): Catalog(s)
