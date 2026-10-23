"""Seam HTTP843 avec vraies signatures, catalogue/S3 contrôlés ; PG natif distinct."""

import base64
import asyncio
import hashlib
import io
import json
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from uuid import uuid4

from botocore.exceptions import ClientError
import pytest

from test_hub_activity_31 import Client, Store, cfg, issuer
from test_postgres_access_contract_31 import NOW, HASH, row
from src.mcp_tools.auth import hub_activity as hub
from src.mcp_tools.auth.context import check_tool_access, current_token_info
from src.mcp_tools.auth.postgres_contract import authenticate_row
from src.mcp_tools.auth.token_store import TokenStoreUnavailable
from src.mcp_tools.storage import hub_files
from src.mcp_tools.storage.files_s3 import Blobs


@pytest.mark.parametrize('permissions', [['hub_read', 'access'], ['admin', 'hub_read'], ['hub_read', 'admin', 'access']])
def test_hub_reader_cannot_be_combined_with_execution_or_admin(permissions):
    with pytest.raises(TokenStoreUnavailable):
        authenticate_row(row(permissions=permissions), HASH, NOW)


def test_same_hub_reader_authenticates_but_cannot_dispatch_files_mutations():
    info = authenticate_row(row(permissions=['hub_read']), HASH, NOW)
    token = current_token_info.set(info)
    try:
        for tool in ('files', 'system_activity', 'tokens'):
            with pytest.raises(ValueError, match="permission 'access'"):
                check_tool_access(tool)
    finally:
        current_token_info.reset(token)


class Files:
    def __init__(self, call, operation):
        self.call, self.operation = call, operation
        self.generation = str(uuid4())
        self.content = b'PRIVATE-FILE-CANARY'
        self.pin = dict(version_id='historical-version', etag='old-etag', size=len(self.content),
                        sha256=hashlib.sha256(self.content).hexdigest(), key='NEVER-PUBLIC')
        self.catalog = self
        self.blobs = SimpleNamespace(get_hub=self.get_hub)
        self.reads = 0
        self.unavailable = self.removed = self.mutate_after_read = False

    @asynccontextmanager
    async def connection(self):
        yield self

    async def one(self, connection, query, args):
        if args != (self.operation, self.call) or self.removed:
            return None
        return dict(path='published/old.txt', revision=1, generation=self.generation, pin=self.pin)

    async def get(self, pin):
        assert pin is self.pin
        self.reads += 1
        if self.unavailable:
            raise RuntimeError('S3 unavailable CANARY')
        return self.content

    async def get_hub(self, pin, check):
        await check()
        value = await self.get(pin)
        if self.mutate_after_read:
            self.generation = str(uuid4())
        return value


class FileStore(Store):
    def __init__(self, call, operation):
        super().__init__()
        self.info['permissions'] = ['hub_read']
        self.call, self.operation = call, operation
        self.retained = True
        self.deadline = datetime.now(timezone.utc) + timedelta(days=1)

    async def hub_file_calls(self, requester, claims, calls):
        if calls != [self.call] or not self.retained:
            raise ValueError('Other call refused')
        return {self.call: self.operation}

    async def confirm_hub_files(self, requester, info, binding, claims, calls):
        if not self.retained:
            raise ValueError('Activity no longer retained')
        confirmed = await self.confirm_hub_access(requester, info, binding, claims)
        return {**confirmed, 'activity_expires_at': self.deadline}


async def request(store, body, monkeypatch, *, permission='tools.files.read', live=None, enabled=True,
                  tools_enabled=None):
    raw = json.dumps(body).encode()
    token, keys, _ = issuer(raw, permission)
    client = Client(keys, live or [True, True, True])
    monkeypatch.setattr(hub.ssl, 'create_default_context', lambda **kw: object())
    settings = cfg()
    settings.hub_files_page_bytes = 30000
    settings.hub_activity_enabled = enabled
    settings.hub_tools_enabled = tools_enabled
    async def inner(*args):
        raise AssertionError('Read must never execute MCP')
    middleware = hub.HubActivityMiddleware(inner, settings, client_factory=lambda **kw: client,
                                          store_factory=lambda: store)
    async def receive():
        return dict(type='http.request', body=raw, more_body=False)
    sent = []
    async def send(value):
        sent.append(value)
    await middleware(dict(type='http', path=hub.FILES_PATH, method='POST', query_string=b'',
                          headers=[(b'authorization', b'Bearer local-opaque'),
                                   (b'x-tools-activity-context', token.encode())]), receive, send)
    return sent[0]['status'], json.loads(sent[1]['body'])


def test_file_route_reads_exact_origin_and_pin_without_exposing_physical_location(monkeypatch):
    async def scenario():
        call, operation = str(uuid4()), str(uuid4())
        files, store = Files(call, operation), FileStore(call, operation)
        monkeypatch.setattr(hub_files, 'get_files_service', lambda: files)
        body = dict(mission_id='mis_1', root_agent_id='ag_root', call_ids=[call])
        code, data = await request(store, body, monkeypatch)
        assert code == 200 and data['files'][0]['version_id'] == 'historical-version'
        assert files.reads == 0 and 'PRIVATE' not in json.dumps(data) and 'NEVER-PUBLIC' not in json.dumps(data)
        code, data = await request(store, dict(**body, content=True, expected_generation=files.generation,
                                                offset=3, limit=4), monkeypatch)
        assert code == 200 and base64.b64decode(data['files'][0]['content_base64']) == files.content[3:7]
        assert data['files'][0]['next_offset'] == 7 and data['files'][0]['end'] is False
        # Un call différent ne rattache pas une opération connue à une autre publication.
        code, data = await request(store, {**body, 'call_ids': [str(uuid4())]}, monkeypatch)
        assert code == 403 and not {'files', 'count', 'cursor'} & data.keys()

    asyncio.run(scenario())


@pytest.mark.parametrize('failure', ['opaque', 'mapping-after', 'permission', 'live', 'capability', 'range'])
def test_revocation_capability_and_bad_range_never_return_private_projection(monkeypatch, failure):
    async def scenario():
        call, operation = str(uuid4()), str(uuid4())
        store, files = FileStore(call, operation), Files(call, operation)
        monkeypatch.setattr(hub_files, 'get_files_service', lambda: files)
        body = dict(mission_id='mis_1', root_agent_id='ag_root', call_ids=[call], content=True,
                    expected_generation=files.generation, offset=0, limit=30)
        if failure in {'opaque', 'mapping-after'}:
            store.change = 'mapping' if failure == 'mapping-after' else 'opaque'
        if failure == 'permission':
            store.info['permissions'] = ['access']
        if failure == 'range':
            body['limit'] = 30001
        code, data = await request(store, body, monkeypatch,
                                   permission='tools.activity.read' if failure == 'capability' else 'tools.files.read',
                                   live=[True, False] if failure == 'live' else None)
        assert code == (400 if failure == 'range' else 403)
        assert not {'files', 'count', 'cursor'} & data.keys()
        assert 'CANARY' not in json.dumps(data)

    asyncio.run(scenario())


def test_s3_fault_preserves_catalogue_metadata_but_content_is_unavailable(monkeypatch):
    async def scenario():
        call, operation = str(uuid4()), str(uuid4())
        store, files = FileStore(call, operation), Files(call, operation)
        files.unavailable = True
        monkeypatch.setattr(hub_files, 'get_files_service', lambda: files)
        body = dict(mission_id='mis_1', root_agent_id='ag_root', call_ids=[call])
        assert (await request(store, body, monkeypatch))[0] == 200
        code, data = await request(store, dict(**body, content=True, expected_generation=files.generation,
                                                offset=0, limit=30), monkeypatch)
        assert code == 503 and 'files' not in data and 'CANARY' not in json.dumps(data)
        files.removed = True
        code, data = await request(store, body, monkeypatch)
        assert code == 200 and data['files'] == [dict(call_id=call, reference_state='unavailable')]

    asyncio.run(scenario())


def test_real_blob_primitive_uses_hub_authority_without_opening_mcp_access(monkeypatch):
    async def scenario():
        from src.mcp_tools.auth import access_runtime

        call, operation = str(uuid4()), str(uuid4())
        store, files = FileStore(call, operation), Files(call, operation)
        blob = object.__new__(Blobs)
        blob.slots, blob.jobs, blob.data_signature, blob.bucket = asyncio.Semaphore(1), set(), 's3v4', 'test'
        reads = []
        def get_object(**kwargs):
            reads.append(kwargs)
            return dict(VersionId=files.pin['version_id'], Body=io.BytesIO(files.content))
        blob.clients = {'s3v4': SimpleNamespace(get_object=get_object)}
        files.blobs = blob
        monkeypatch.setattr(hub_files, 'get_files_service', lambda: files)
        async def refresh(tool):
            check_tool_access(tool)
        monkeypatch.setattr(access_runtime, 'refresh_access', refresh)
        info = current_token_info.set(dict(store.info))
        try:
            with pytest.raises(ValueError, match="permission 'access'"):
                await blob.get(files.pin)
            assert reads == []
            body = dict(mission_id='mis_1', root_agent_id='ag_root', call_ids=[call], content=True,
                        expected_generation=files.generation, offset=0, limit=30)
            code, data = await request(store, body, monkeypatch)
            assert code == 200 and base64.b64decode(data['files'][0]['content_base64']) == files.content
            assert reads == [dict(Bucket='test', Key=files.pin['key'], VersionId='historical-version')]
            assert not blob.jobs and not blob.slots.locked()
        finally:
            current_token_info.reset(info)

    asyncio.run(scenario())


@pytest.mark.parametrize('change', ['purge', 'expire'])
@pytest.mark.parametrize('surface', ['metadata', 'content'])
def test_activity_purged_or_expired_during_s3_is_not_projected(monkeypatch, change, surface):
    async def scenario():
        call, operation = str(uuid4()), str(uuid4())
        store, files = FileStore(call, operation), Files(call, operation)
        entered, release = asyncio.Event(), asyncio.Event()
        async def get_hub(pin, check):
            await check()
            entered.set()
            await release.wait()
            return files.content
        if surface == 'content':
            files.blobs = SimpleNamespace(get_hub=get_hub)
        else:
            original = files.one
            async def read_metadata(*args):
                entered.set()
                await release.wait()
                return await original(*args)
            files.one = read_metadata
        monkeypatch.setattr(hub_files, 'get_files_service', lambda: files)
        body = dict(mission_id='mis_1', root_agent_id='ag_root', call_ids=[call])
        if surface == 'content':
            body.update(content=True, expected_generation=files.generation, offset=0, limit=30)
        pending = asyncio.create_task(request(store, body, monkeypatch))
        await entered.wait()
        if change == 'purge':
            store.retained = False
        else:
            store.deadline = datetime.now(timezone.utc) - timedelta(seconds=1)
        release.set()
        code, data = await pending
        assert code == 403 and not {'files', 'count', 'cursor'} & data.keys()
        assert 'CANARY' not in json.dumps(data)
    asyncio.run(scenario())


@pytest.mark.parametrize('bad_generation', [None, 'PIN', 'A81E0D43-49B2-47CB-A94C-B50A3C1A4CC2'])
def test_content_requires_canonical_expected_generation_before_s3(monkeypatch, bad_generation):
    async def scenario():
        call, operation = str(uuid4()), str(uuid4())
        store, files = FileStore(call, operation), Files(call, operation)
        monkeypatch.setattr(hub_files, 'get_files_service', lambda: files)
        body = dict(mission_id='mis_1', root_agent_id='ag_root', call_ids=[call], content=True,
                    offset=0, limit=30)
        if bad_generation is not None:
            body['expected_generation'] = bad_generation
        code, data = await request(store, body, monkeypatch)
        assert code == 400 and data == {'status': 'error', 'code': 'FILE_REQUEST_INVALID'}
        assert files.reads == 0 and 'content_base64' not in data
    asyncio.run(scenario())


@pytest.mark.parametrize('when', ['before-s3', 'during-s3'])
def test_generation_change_returns_exact_409_without_content(monkeypatch, when):
    async def scenario():
        call, operation = str(uuid4()), str(uuid4())
        store, files = FileStore(call, operation), Files(call, operation)
        expected = files.generation
        monkeypatch.setattr(hub_files, 'get_files_service', lambda: files)
        if when == 'before-s3':
            files.generation = str(uuid4())
        else:
            files.mutate_after_read = True
        body = dict(mission_id='mis_1', root_agent_id='ag_root', call_ids=[call], content=True,
                    expected_generation=expected, offset=0, limit=30)
        code, data = await request(store, body, monkeypatch)
        assert code == 409 and data == {'status': 'error', 'code': 'FILE_GENERATION_CHANGED'}
        assert ('content_base64' not in data) and (files.reads == (0 if when == 'before-s3' else 1))
    asyncio.run(scenario())


def test_hub_tools_flag_false_closes_real_files_handler(monkeypatch):
    async def scenario():
        call, operation = str(uuid4()), str(uuid4())
        store, files = FileStore(call, operation), Files(call, operation)
        async def forbidden_store_access(*args):
            pytest.fail('hub_tools_enabled=false must close Files before store access')
        store.authenticate = forbidden_store_access
        monkeypatch.setattr(hub_files, 'get_files_service', lambda: files)
        body = dict(mission_id='mis_1', root_agent_id='ag_root', call_ids=[call], content=True,
                    expected_generation=files.generation, offset=0, limit=30)
        code, data = await request(store, body, monkeypatch, tools_enabled=False)
        assert code == 404 and data == {'status': 'error', 'code': 'DELEGATION_DISABLED'}
        assert files.reads == 0
    asyncio.run(scenario())


def test_hub_tools_flag_unset_preserves_files_handler(monkeypatch):
    async def scenario():
        call, operation = str(uuid4()), str(uuid4())
        store, files = FileStore(call, operation), Files(call, operation)
        monkeypatch.setattr(hub_files, 'get_files_service', lambda: files)
        body = dict(mission_id='mis_1', root_agent_id='ag_root', call_ids=[call], content=True,
                    expected_generation=files.generation, offset=0, limit=30)
        code, data = await request(store, body, monkeypatch)
        assert code == 200 and data['files'][0]['content_base64']
    asyncio.run(scenario())


def test_s3_nosuchkey_through_real_blob_handler_remains_503(monkeypatch):
    async def scenario():
        call, operation = str(uuid4()), str(uuid4())
        store, files = FileStore(call, operation), Files(call, operation)
        blob = object.__new__(Blobs)
        blob.slots, blob.jobs, blob.data_signature, blob.bucket = asyncio.Semaphore(1), set(), 's3v4', 'test'
        def get_object(**kwargs):
            assert kwargs == {'Bucket': 'test', 'Key': 'NEVER-PUBLIC', 'VersionId': 'historical-version'}
            raise ClientError({'Error': {'Code': 'NoSuchKey', 'Message': 'missing'}}, 'GetObject')
        blob.clients = {'s3v4': SimpleNamespace(get_object=get_object)}
        files.blobs = blob
        monkeypatch.setattr(hub_files, 'get_files_service', lambda: files)
        body = dict(mission_id='mis_1', root_agent_id='ag_root', call_ids=[call], content=True,
                    expected_generation=files.generation, offset=0, limit=30)
        code, data = await request(store, body, monkeypatch)
        assert code == 503 and data == {'status': 'error', 'code': 'DELEGATION_UNAVAILABLE'}
        assert 'files' not in data and not blob.jobs
    asyncio.run(scenario())
