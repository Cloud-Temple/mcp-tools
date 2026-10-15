"""Seam HTTP843 avec vraies signatures, catalogue/S3 contrôlés ; PG natif distinct."""

import base64
import hashlib
import json
from contextlib import asynccontextmanager
from types import SimpleNamespace
from uuid import uuid4

import pytest

from test_hub_activity_31 import Client, Store, cfg, issuer
from test_postgres_access_contract_31 import NOW, HASH, row
from src.mcp_tools.auth import hub_activity as hub
from src.mcp_tools.auth.context import check_tool_access, current_token_info
from src.mcp_tools.auth.postgres_contract import authenticate_row
from src.mcp_tools.auth.token_store import TokenStoreUnavailable
from src.mcp_tools.storage import hub_files


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
                        sha256=hashlib.sha256(self.content).hexdigest(), physical_key='NEVER-PUBLIC')
        self.catalog = self
        self.blobs = SimpleNamespace(get=self.get)
        self.reads = 0
        self.unavailable = self.removed = False

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


class FileStore(Store):
    def __init__(self, call, operation):
        super().__init__()
        self.info['permissions'] = ['hub_read']
        self.call, self.operation = call, operation

    async def hub_file_calls(self, requester, claims, calls):
        if calls != [self.call]:
            raise ValueError('Other call refused')
        return {self.call: self.operation}


async def request(store, body, monkeypatch, *, permission='tools.files.read', live=None):
    raw = json.dumps(body).encode()
    token, keys, _ = issuer(raw, permission)
    client = Client(keys, live)
    monkeypatch.setattr(hub.ssl, 'create_default_context', lambda **kw: object())
    settings = cfg()
    settings.hub_files_page_bytes = 30000
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


@pytest.mark.asyncio
async def test_file_route_reads_exact_origin_and_pin_without_exposing_physical_location(monkeypatch):
    call, operation = str(uuid4()), str(uuid4())
    files, store = Files(call, operation), FileStore(call, operation)
    monkeypatch.setattr(hub_files, 'get_files_service', lambda: files)
    body = dict(mission_id='mis_1', root_agent_id='ag_root', call_ids=[call])
    code, data = await request(store, body, monkeypatch)
    assert code == 200 and data['files'][0]['version_id'] == 'historical-version'
    assert files.reads == 0 and 'PRIVATE' not in json.dumps(data) and 'NEVER-PUBLIC' not in json.dumps(data)
    code, data = await request(store, dict(**body, content=True, offset=3, limit=4), monkeypatch)
    assert code == 200 and base64.b64decode(data['files'][0]['content_base64']) == files.content[3:7]
    assert data['files'][0]['next_offset'] == 7 and data['files'][0]['end'] is False
    # Un call différent ne rattache pas une opération connue à une autre publication.
    code, data = await request(store, {**body, 'call_ids': [str(uuid4())]}, monkeypatch)
    assert code == 403 and not {'files', 'count', 'cursor'} & data.keys()


@pytest.mark.asyncio
@pytest.mark.parametrize('failure', ['opaque', 'mapping-after', 'permission', 'live', 'capability', 'range'])
async def test_revocation_capability_and_bad_range_never_return_private_projection(monkeypatch, failure):
    call, operation = str(uuid4()), str(uuid4())
    store, files = FileStore(call, operation), Files(call, operation)
    monkeypatch.setattr(hub_files, 'get_files_service', lambda: files)
    body = dict(mission_id='mis_1', root_agent_id='ag_root', call_ids=[call], content=True, offset=0, limit=30)
    if failure in {'opaque', 'mapping-after'}:
        store.change = 'mapping' if failure == 'mapping-after' else 'opaque'
    if failure == 'permission':
        store.info['permissions'] = ['access']
    if failure == 'range':
        body['limit'] = 30001
    code, data = await request(store, body, monkeypatch,
                               permission='tools.activity.read' if failure == 'capability' else 'tools.files.read',
                               live=[True, False] if failure == 'live' else None)
    assert code == 403 and not {'files', 'count', 'cursor'} & data.keys()
    assert 'CANARY' not in json.dumps(data)


@pytest.mark.asyncio
async def test_s3_fault_preserves_catalogue_metadata_but_content_is_unavailable(monkeypatch):
    call, operation = str(uuid4()), str(uuid4())
    store, files = FileStore(call, operation), Files(call, operation)
    files.unavailable = True
    monkeypatch.setattr(hub_files, 'get_files_service', lambda: files)
    body = dict(mission_id='mis_1', root_agent_id='ag_root', call_ids=[call])
    assert (await request(store, body, monkeypatch))[0] == 200
    code, data = await request(store, dict(**body, content=True, offset=0, limit=30), monkeypatch)
    assert code == 503 and 'files' not in data and 'CANARY' not in json.dumps(data)
    files.removed = True
    code, data = await request(store, body, monkeypatch)
    assert code == 200 and data['files'] == [dict(call_id=call, reference_state='unavailable')]
