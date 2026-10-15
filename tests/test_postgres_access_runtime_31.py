"""Admission durable avant effet et absence de bypass ou de secours S3."""
import asyncio
import json
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from src.mcp_tools.auth import access_runtime as runtime
from src.mcp_tools.auth.context import current_token_info
from src.mcp_tools.auth.middleware import AuthMiddleware
from src.mcp_tools.auth.token_store import TokenStoreUnavailable
from src.mcp_tools.admin.postgres_api import handle_postgres_admin


class Store:
    def __init__(self):
        self.allowed = True
        self.current = True
        self.terminal_unknown = False
        self.admit_unknown = False
        self.terminals = []
        self.info = dict(client_name='reader', actor_id='actor', tenant_id='tenant', service_id='tools',
                         permissions=['access'], tool_ids=['files'], version=1,
                         credential_binding='tools-token-v1:'+'a'*64)

    async def authenticate(self, raw):
        assert raw == 'bootstrap-is-not-admin'
        return None

    async def authenticate_binding(self, binding):
        return self.info if self.current else None

    async def admit_binding(self, **kwargs):
        if self.admit_unknown:
            raise TokenStoreUnavailable('unconfirmed')
        return self.allowed

    async def finish(self, call, outcome):
        self.terminals.append(outcome)
        if self.terminal_unknown:
            raise TokenStoreUnavailable('unconfirmed')
        return True


def configure(monkeypatch, store):
    monkeypatch.setattr(runtime, 'get_settings', lambda: SimpleNamespace(access_backend='postgres'))
    monkeypatch.setattr(runtime, 'get_access_store', lambda: store)


@pytest.mark.parametrize('admission', ['denied', 'unavailable'])
def test_no_effect_before_confirmed_admission(monkeypatch, admission):
    store = Store()
    configure(monkeypatch, store)
    store.allowed = False
    store.admit_unknown = admission == 'unavailable'
    effects = []
    async def effect():
        effects.append(True)
    async def scenario():
        token = current_token_info.set(store.info)
        try:
            if admission == 'unavailable':
                with pytest.raises(TokenStoreUnavailable):
                    await runtime.run_durable_tool('files', effect, (), {})
            else:
                result = await runtime.run_durable_tool('files', effect, (), {})
                assert result['status'] == 'error' and store.terminals == ['denied']
        finally:
            current_token_info.reset(token)
    asyncio.run(scenario())
    assert effects == []


def test_terminal_uncertainty_never_returns_effect_result_or_replays(monkeypatch):
    store = Store()
    configure(monkeypatch, store)
    store.terminal_unknown = True
    effects = []
    async def effect():
        effects.append(True)
        return {'status': 'ok', 'body': 'PRIVATE-CANARY'}
    async def scenario():
        token = current_token_info.set(store.info)
        try:
            result = await runtime.run_durable_tool('files', effect, (), {})
            assert result['status'] == 'uncertain'
            assert 'PRIVATE-CANARY' not in json.dumps(result)
        finally:
            current_token_info.reset(token)
    asyncio.run(scenario())
    assert effects == [True] and store.terminals == ['completed']


def test_revocation_while_waiting_for_blob_slot_prevents_dispatch(monkeypatch):
    from src.mcp_tools.storage.files_s3 import Blobs
    store = Store()
    configure(monkeypatch, store)
    effects = []
    async def scenario():
        blob = Blobs.__new__(Blobs)
        blob.slots = asyncio.Semaphore(0)
        blob.jobs = set()
        token = current_token_info.set(store.info)
        try:
            pending = asyncio.create_task(blob.run(lambda: effects.append(True)))
            await asyncio.sleep(0)
            store.current = False
            blob.slots.release()
            with pytest.raises(ValueError, match='revoked'):
                await pending
            assert blob.slots._value == 1 and not blob.jobs
        finally:
            current_token_info.reset(token)
    asyncio.run(scenario())
    assert not effects


def test_pg_middleware_rejects_legacy_bootstrap_without_s3_fallback(monkeypatch):
    from src.mcp_tools.auth import middleware
    store = Store()
    configure(monkeypatch, store)
    monkeypatch.setattr(middleware, 'get_settings', lambda: SimpleNamespace(
        access_backend='postgres', admin_bootstrap_key='bootstrap-is-not-admin'))
    called, sent = [], []
    async def app(*args):
        called.append(True)
    async def send(value):
        sent.append(value)
    asyncio.run(AuthMiddleware(app)({'type': 'http', 'path': '/mcp',
        'headers': [(b'authorization', b'Bearer bootstrap-is-not-admin')]}, None, send))
    assert not called and sent[0]['status'] == 401


def test_pg_admin_returns_fresh_metadata_without_internal_binding(monkeypatch):
    from src.mcp_tools.admin import postgres_api
    store = Store()
    async def authenticate(raw): return store.info
    store.authenticate = authenticate
    monkeypatch.setattr(postgres_api, 'get_access_store', lambda: store)
    sent = []
    async def send(value): sent.append(value)
    asyncio.run(handle_postgres_admin({'path': '/admin/api/me', 'method': 'GET',
        'headers': [(b'authorization', b'Bearer opaque')], 'query_string': b''}, None, send, None))
    assert sent[0]['status'] == 200
    body = json.loads(sent[1]['body'])
    assert body['access_backend'] == 'postgres' and body['actor_id'] == 'actor'
    assert 'a'*64 not in json.dumps(body) and 'credential_binding' not in body
    assert current_token_info.get() is None
