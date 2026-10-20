"""Operator recipes use exact-version S3 I/O, never an invented MCP context.

SQL, S3 HTTP and PostgreSQL binaries are simulated boundaries, not native proof.
The real recipe, RecoveryBlobs, Blobs worker and runtime auth guards execute.
"""
import asyncio
import hashlib
import io
import json
from contextlib import asynccontextmanager
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

import pytest
from botocore.exceptions import ClientError, ReadTimeoutError

from src.mcp_tools.auth import access_runtime
from src.mcp_tools.auth.context import current_token_info
from src.mcp_tools.config import Settings
from src.mcp_tools.storage import files_backup
from src.mcp_tools.storage.files_credentials import StorageUnavailable
from src.mcp_tools.storage.files_s3 import Blobs


CONTENT = b"owned historical content"
PIN = {"key": "files-generations/12345678-1234-1234-1234-123456789abc",
       "version_id": "exact-version", "sha256": hashlib.sha256(CONTENT).hexdigest(),
       "size": len(CONTENT)}
ROLE = {"rolname": "domain_owner", "rolcanlogin": False, "rolsuper": False}
PG_JOB = files_backup.pg_job


class Catalog:
    """SQL frontier only; production role/identity checks are not claimed here."""
    @asynccontextmanager
    async def connection(self, operator=False):
        assert operator
        yield self

    async def infrastructure(self, c):
        assert c is self

    async def check_schema(self, c, role):
        assert c is self and role == "domain_app"

    async def one(self, c, query, params=()):
        if "pg_namespace" in query:
            return {"present": False}
        if "schema_version" in query:
            return {"version": 1, "checksum": "schema-fixture"}
        assert "pg_roles" in query
        return {**ROLE, "rolname": params[0]}

    async def execute(self, query, params=()):
        if "FROM generations" in query:
            rows = [{"id": "generation", "pin": dict(PIN)}] if params == ("",) else []
        elif "FROM pg_roles" in query:
            rows = [ROLE, {**ROLE, "rolname": "domain_app"}]
        else:
            rows = []
        return SimpleNamespace(fetchall=AsyncMock(return_value=rows))


@pytest.fixture
def operator(monkeypatch, tmp_path):
    settings = Settings(_env_file=None, access_backend="postgres",
                        s3_endpoint_url="https://s3.invalid", s3_bucket_name="owned",
                        s3_access_key_id="test-job", s3_secret_access_key="test-only",
                        files_pg_schema="tools_files", files_pg_owner="domain_owner",
                        files_pg_database="new_target")
    client = Mock(spec=["get_object", "get_bucket_versioning"])
    bodies = []
    def get(**kwargs):
        body = io.BytesIO(CONTENT)
        bodies.append(body)
        return {"Body": body, "VersionId": "exact-version"}
    client.get_object.side_effect = get
    client.get_bucket_versioning.return_value = {"Status": "Enabled"}
    monkeypatch.setattr("boto3.client", Mock(return_value=client))
    monkeypatch.setattr(files_backup, "get_settings", lambda: settings)
    monkeypatch.setattr(access_runtime, "get_settings", lambda: settings)
    monkeypatch.setattr(access_runtime, "get_access_store", lambda: SimpleNamespace(
        authenticate_binding=AsyncMock(return_value=None)))
    monkeypatch.setattr(files_backup, "Catalog", lambda s: Catalog())
    monkeypatch.setattr(files_backup, "structure", AsyncMock(return_value="a" * 64))
    monkeypatch.setattr(files_backup, "target_roles", AsyncMock())
    monkeypatch.setattr(files_backup, "project", AsyncMock())

    async def binary(s, argv, output):
        if output:
            output.write_bytes(b"simulated SQL dump, not a native archive")
            output.chmod(0o600)

    job = AsyncMock(side_effect=binary)
    monkeypatch.setattr(files_backup, "pg_job", job)
    token = current_token_info.set(None)
    yield SimpleNamespace(settings=settings, client=client, job=job, bodies=bodies,
                          archive=tmp_path / "archive")
    current_token_info.reset(token)


def arguments(op, action="export"):
    return SimpleNamespace(action=action, archive=str(op.archive), app_role="domain_app",
                           project_roles=False, max_generations=64)


def archive(op, pin=None):
    op.archive.mkdir(mode=0o700)
    dump = op.archive / "domain.dump"
    dump.write_bytes(b"simulated SQL dump, not a native archive")
    manifest = op.archive / "manifest.jsonl"
    header = {"schema": "tools_files", "roles": [ROLE, {**ROLE, "rolname": "domain_app"}],
              "structure_sha256": "a" * 64}
    manifest.write_text(json.dumps({"header": header}) + "\n" +
                        json.dumps({"generation": "generation", "pin": pin or PIN}) + "\n")
    for path in (dump, manifest):
        path.chmod(0o600)
    hashes = op.archive / "hashes.json"
    hashes.write_text(json.dumps({p.name: hashlib.sha256(p.read_bytes()).hexdigest()
                                 for p in (dump, manifest)}))
    hashes.chmod(0o600)


@pytest.mark.parametrize("action", ["export", "import", "project"])
def test_operator_recipe_without_mcp_context(operator, action):
    args = arguments(operator, "import" if action == "project" else action)
    args.project_roles = action == "project"
    if args.action == "import":
        archive(operator)
    result = asyncio.run(files_backup.recipe(args))
    assert result["status"] == "ok"
    operator.client.get_object.assert_called_once_with(
        Bucket="owned", Key=PIN["key"], VersionId=PIN["version_id"])
    operator.job.assert_awaited_once()
    argv = operator.job.await_args.args[1]
    assert argv[0] == ("pg_dump" if action == "export" else "pg_restore")
    assert ("--no-acl" in argv) == (action == "project")
    assert operator.bodies and all(body.closed for body in operator.bodies)
    assert current_token_info.get() is None


@pytest.mark.parametrize("pin", [
    {**PIN, "key": "neighbor/12345678-1234-1234-1234-123456789abc"},
    {**PIN, "key": "files-generations/not-an-uuid"},
    {**PIN, "version_id": "null"}, {**PIN, "version_id": ""},
    {**PIN, "sha256": "invalid"}, {**PIN, "size": -1}, {**PIN, "size": True},
])
def test_import_rejects_pin_before_s3_or_restore(operator, pin):
    archive(operator, pin)
    with pytest.raises(StorageUnavailable, match="outside the owned"):
        asyncio.run(files_backup.recipe(arguments(operator, "import")))
    operator.client.get_object.assert_not_called()
    operator.job.assert_not_awaited()


@pytest.mark.parametrize("fault", ["version", "sha", "size", "403", "timeout"])
@pytest.mark.parametrize("action", ["export", "import"])
def test_recipe_does_not_substitute_refused_or_damaged_s3(operator, fault, action):
    def get(**kwargs):
        if fault == "403":
            raise ClientError({"Error": {"Code": "AccessDenied"}}, "GetObject")
        if fault == "timeout":
            raise ReadTimeoutError(endpoint_url="https://s3.invalid")
        content = b"x" * len(CONTENT) if fault == "sha" else CONTENT
        if fault == "size":
            content = content[:-1]
        return {"Body": io.BytesIO(content),
                "VersionId": "other" if fault == "version" else "exact-version"}
    operator.client.get_object.side_effect = get
    if action == "import":
        archive(operator)
    with pytest.raises(StorageUnavailable):
        asyncio.run(files_backup.recipe(arguments(operator, action)))
    assert operator.client.get_object.call_count == 1
    operator.job.assert_not_awaited()


def test_implicit_s3_credentials_refused_before_archive(operator):
    operator.settings.s3_access_key_id = ""
    with pytest.raises(StorageUnavailable, match="Explicit owned S3"):
        asyncio.run(files_backup.recipe(arguments(operator, "import")))
    assert not operator.archive.exists()
    operator.client.get_object.assert_not_called()


def test_fresh_sql_authority_failure_does_not_borrow_s3_authority(operator, monkeypatch):
    @asynccontextmanager
    async def denied(*args, **kwargs):
        raise StorageUnavailable("SQL authority denied")
        yield  # pragma: no cover
    monkeypatch.setattr(Catalog, "connection", denied)
    with pytest.raises(StorageUnavailable, match="SQL authority denied"):
        asyncio.run(files_backup.recipe(arguments(operator)))
    operator.client.get_object.assert_not_called()
    operator.job.assert_not_awaited()


@pytest.mark.parametrize("action", ["export", "import"])
def test_pg_job_reauth_failure_after_s3_does_not_launch_sql(operator, monkeypatch, action):
    if action == "import":
        archive(operator)
    credentials = AsyncMock(side_effect=StorageUnavailable("Fresh SQL credentials refused"))
    process = AsyncMock()
    monkeypatch.setattr(files_backup, "pg_job", PG_JOB)
    monkeypatch.setattr(files_backup.Credentials, "sql", credentials)
    monkeypatch.setattr(asyncio, "create_subprocess_exec", process)
    with pytest.raises(StorageUnavailable, match="Fresh SQL credentials refused"):
        asyncio.run(files_backup.recipe(arguments(operator, action)))
    assert operator.client.get_object.call_count == 1
    credentials.assert_awaited_once()
    process.assert_not_awaited()


@pytest.mark.parametrize("operation", ["get", "put", "marker"])
@pytest.mark.parametrize("authority", ["absent", "revoked", "expired"])
def test_runtime_still_requires_current_access(operator, monkeypatch, operation, authority):
    async def scenario():
        store = SimpleNamespace(authenticate_binding=AsyncMock(return_value=None))
        monkeypatch.setattr(access_runtime, "get_access_store", lambda: store)
        token = current_token_info.set(None if authority == "absent" else
                                       {"credential_binding": "tools-token-v1:" + "a" * 64})
        try:
            blobs = Blobs(operator.settings)
            with pytest.raises(ValueError, match="required|revoked or expired"):
                if operation == "put":
                    await blobs.put(PIN["key"], CONTENT, PIN["sha256"])
                else:
                    await getattr(blobs, operation)(PIN)
            operator.client.get_object.assert_not_called()
            if authority == "absent":
                store.authenticate_binding.assert_not_awaited()
            else:
                store.authenticate_binding.assert_awaited_once()
        finally:
            current_token_info.reset(token)
    asyncio.run(scenario())
