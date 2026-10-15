"""Historical pins do not bypass a current logical deletion."""
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from types import SimpleNamespace

import pytest

from src.mcp_tools.storage.files_service import FilesService


class Catalog:
    def __init__(self):
        self.history_reads = 0

    @asynccontextmanager
    async def connection(self):
        yield self

    async def execute(self, *args):
        self.history_reads += 1
        return SimpleNamespace(fetchall=self.rows)

    async def rows(self):
        return [{'id': 'old', 'pin': {'version_id': 'v1', 'size': 4, 'sha256': 'a' * 64, 'etag': 'e'}, 'manifest': [], 'created_at': datetime.now(timezone.utc)}]


@pytest.mark.asyncio
@pytest.mark.parametrize('op', ['read', 'info', 'diff', 'versions'])
async def test_current_deletion_prevents_history_and_s3(monkeypatch, op):
    service = object.__new__(FilesService)
    service.catalog = Catalog()
    service.s = SimpleNamespace(tool_max_output_chars=50000)

    async def ref(*args, **kwargs):
        return {'path': 'owned', 'deleted': True, 'generation': 'old', 'revision': 2}

    async def forbidden_get(*args):
        pytest.fail('deleted content reached S3')

    monkeypatch.setattr(service, 'ref', ref)
    service.blobs = SimpleNamespace(get=forbidden_get)
    result = await service.read_operations(op, {'path': 'owned', 'path2': 'other',
                                               'version_id': 'v1', 'max_keys': 5})
    assert service.catalog.history_reads == 0
    assert result.get('content') is None
    if op == 'versions':
        assert result['versions'] == [] and result['count'] == 0
    else:
        assert result['effect_state'] == 'absent'


@pytest.mark.asyncio
async def test_deletion_during_s3_read_prevents_content_publication(monkeypatch):
    from src.mcp_tools.storage.files_postgres import Conflict

    service = object.__new__(FilesService)
    service.catalog = Catalog()
    service.s = SimpleNamespace(tool_max_output_chars=50000)
    row = {'path': 'owned', 'deleted': False, 'generation': 'old', 'revision': 1,
           'pin': {'version_id': 'v1', 'size': 4, 'sha256': 'a' * 64, 'etag': 'e'}}

    async def ref(*args, **kwargs):
        return dict(row)

    async def deleting_get(*args):
        row['deleted'] = True
        row['revision'] += 1
        return b'body'

    monkeypatch.setattr(service, 'ref', ref)
    service.blobs = SimpleNamespace(get=deleting_get)
    with pytest.raises(Conflict, match='retirée ou modifiée'):
        await service.read_operations('read', {'path': 'owned'})


@pytest.mark.asyncio
async def test_unapproved_recovery_projection_prevents_install_connection(monkeypatch):
    from src.mcp_tools.storage import files_bootstrap, files_recovery_contract
    from src.mcp_tools.storage.files_credentials import StorageUnavailable

    class NoConnection:
        def __init__(self, settings):
            pass

        def connection(self, **kwargs):
            pytest.fail('unapproved recovery schema reached SQL')

    settings = SimpleNamespace(files_credentials_mode='vault', files_recovery_enabled=True,
                               model_copy=lambda **kwargs: settings)
    monkeypatch.setattr(files_bootstrap, 'get_settings', lambda: settings)
    monkeypatch.setattr(files_bootstrap, 'Catalog', NoConnection)
    monkeypatch.setattr(files_recovery_contract, 'Path', lambda *a: SimpleNamespace(
        with_name=lambda *a: SimpleNamespace(read_text=lambda: '{}')))
    with pytest.raises(StorageUnavailable, match='schema/ACL drift'):
        await files_bootstrap.install(SimpleNamespace(schema='owned', app_role='app',
                                                      operator_service='private', check=False))


def test_recovery_window_has_thirty_day_minimum():
    from pydantic import ValidationError
    from src.mcp_tools.config import Settings

    with pytest.raises(ValidationError):
        Settings(files_recovery_days=29)
    assert Settings(files_recovery_days=30).files_recovery_days == 30


@pytest.mark.asyncio
async def test_recovery_reconcile_only_observes_exact_pin():
    from botocore.exceptions import ClientError
    from src.mcp_tools.storage.files_recovery_s3 import RecoveryBlobs

    calls = []

    def get(**kwargs):
        calls.append(kwargs)
        raise ClientError({'Error': {'Code': 'NoSuchVersion'}}, 'GetObject')

    async def run(work, **kwargs):
        assert kwargs == {'authorize': False}
        return work()

    recovery = object.__new__(RecoveryBlobs)
    recovery.io = SimpleNamespace(prefix='content/', bucket='owned', data_signature='s3',
                                  clients={'s3': SimpleNamespace(get_object=get)}, run=run)
    pin = {'key': 'content/12345678-1234-1234-1234-123456789abc', 'version_id': 'exact',
           'sha256': 'a' * 64, 'size': 4}
    assert await recovery.absence(pin) is True
    assert calls == [{'Bucket': 'owned', 'Key': pin['key'], 'VersionId': 'exact'}]


@pytest.mark.asyncio
@pytest.mark.parametrize('code', ['AccessDenied', '404', 'NoSuchBucket'])
async def test_recovery_refusal_is_never_absence(code):
    from botocore.exceptions import ClientError
    from src.mcp_tools.storage.files_recovery_s3 import RecoveryBlobs

    def get(**kwargs):
        raise ClientError({'Error': {'Code': code}}, 'GetObject')

    async def run(work, **kwargs):
        return work()

    recovery = object.__new__(RecoveryBlobs)
    recovery.io = SimpleNamespace(prefix='content/', bucket='owned', data_signature='s3',
                                  clients={'s3': SimpleNamespace(get_object=get)}, run=run)
    pin = {'key': 'content/12345678-1234-1234-1234-123456789abc', 'version_id': 'exact',
           'sha256': 'a' * 64, 'size': 4}
    with pytest.raises(ClientError):
        await recovery.absence(pin)


@pytest.mark.asyncio
async def test_collection_dispatches_one_exact_version_delete_and_observes_absence():
    import hashlib
    import io
    from botocore.exceptions import ClientError
    from src.mcp_tools.storage.files_recovery_s3 import RecoveryBlobs

    content = b'owned'
    reads, deletes, bodies = [], [], []

    def get(**kwargs):
        reads.append(kwargs)
        if deletes:
            raise ClientError({'Error': {'Code': 'NoSuchVersion'}}, 'GetObject')
        body = io.BytesIO(content)
        bodies.append(body)
        return {'Body': body, 'VersionId': 'exact'}

    def delete(**kwargs):
        deletes.append(kwargs)
        return {'VersionId': 'exact'}

    async def run(work, **kwargs):
        return work()

    recovery = object.__new__(RecoveryBlobs)
    recovery.io = SimpleNamespace(prefix='content/', bucket='owned', data_signature='s3',
        clients={'s3': SimpleNamespace(get_object=get, delete_object=delete)}, run=run)
    pin = {'key': 'content/12345678-1234-1234-1234-123456789abc', 'version_id': 'exact',
           'sha256': hashlib.sha256(content).hexdigest(), 'size': len(content)}
    assert await recovery.delete_once(pin) is True
    exact = {'Bucket': 'owned', 'Key': pin['key'], 'VersionId': 'exact'}
    assert deletes == [exact] and reads == [exact, exact]
    assert bodies[0].closed


@pytest.mark.asyncio
async def test_operator_recovery_rechecks_restored_pin_after_s3():
    from src.mcp_tools.storage.files_recovery import FileRecovery
    from src.mcp_tools.storage.files_credentials import StorageUnavailable

    seen = []

    class Recovery(FileRecovery):
        async def reference(self, **kwargs):
            seen.append(kwargs)
            return {'pin': {'version_id': 'before' if len(seen) == 1 else 'changed'}}

    async def read(pin):
        assert pin == {'version_id': 'before'}
        return b'owned'

    recovery = object.__new__(Recovery)
    recovery.blobs = SimpleNamespace(read=read)
    with pytest.raises(StorageUnavailable, match='changed during recovery'):
        await recovery.recover(path='owned', version_id='exact')
    assert seen == [{'path': 'owned', 'version_id': 'exact'}] * 2


def test_operator_profile_never_inherits_runtime_environment(monkeypatch):
    from src.mcp_tools.storage.files_recovery_cli import RecoverySettings

    monkeypatch.setenv('FILES_PG_ROLE', 'neighbor')
    assert RecoverySettings(_env_file=None, files_pg_role='maintenance').files_pg_role == 'maintenance'
