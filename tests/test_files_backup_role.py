"""L’import transmet --role=owner en conservant propriétaires et ACL."""
import hashlib
import json
import tempfile
from contextlib import asynccontextmanager
from pathlib import Path
from types import SimpleNamespace
from unittest import IsolatedAsyncioTestCase
from unittest.mock import AsyncMock, patch

from src.mcp_tools.storage import files_backup


class RestoreRoleContract(IsolatedAsyncioTestCase):
    async def test_import_sets_existing_owner_without_discarding_acl(self):
        settings = SimpleNamespace(files_pg_schema="tools_files", files_pg_owner="domain_owner",
                                   files_pg_database="fresh_target")
        role = {"rolname": "domain_owner", "rolcanlogin": False, "rolsuper": False}
        class Catalog:
            @asynccontextmanager
            async def connection(self, operator=False):
                assert operator
                yield object()
            async def one(self, connection, query, params):
                return {"present": False} if "pg_namespace" in query else role
        with tempfile.TemporaryDirectory() as directory:
            archive = Path(directory)
            dump = archive / "domain.dump"
            dump.write_bytes(b"validated archive")
            manifest = archive / "manifest.jsonl"
            manifest.write_text(json.dumps({"header": {"schema": "tools_files", "roles": [role]}}) + "\n")
            for file in (dump, manifest):
                file.chmod(0o600)
            hashes = archive / "hashes.json"
            hashes.write_text(json.dumps({p.name: hashlib.sha256(p.read_bytes()).hexdigest()
                                          for p in (dump, manifest)}))
            hashes.chmod(0o600)
            job = AsyncMock()
            with patch.object(files_backup, "get_settings", return_value=settings), \
                 patch.object(files_backup, "Catalog", return_value=Catalog()), \
                 patch.object(files_backup, "RecoveryBlobs"), \
                 patch.object(files_backup, "pg_job", job):
                result = await files_backup.recipe(SimpleNamespace(action="import", archive=directory,
                                                                    max_generations=64))
            self.assertEqual(result["status"], "ok")
            job.assert_awaited_once_with(settings, ["pg_restore", "--exit-on-error", "--single-transaction",
                                                   "--role=domain_owner", "--dbname=fresh_target", str(dump)], None)
