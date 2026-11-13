"""Budget du vrai protocole credential, transport doublé sans réseau ni secret réel."""
import asyncio
import json
from contextlib import asynccontextmanager
from types import SimpleNamespace

import httpx2
import mcp
import mcp.client.streamable_http
import psycopg
import pytest

from src.mcp_tools.auth.postgres_credentials import AccessCredentials
from src.mcp_tools.auth.postgres_store import PostgresAccessStore
from src.mcp_tools.auth.token_store import TokenStoreUnavailable
from src.mcp_tools.storage import files_credentials


def settings(budget=3, total=5, refresh=30):
    return SimpleNamespace(access_pg_hosts='db', access_pg_database='tools', access_pg_role='app',
        access_vault_url='https://vault.example', access_vault_id='credentials', access_vault_path='connection',
        access_vault_token_file='private', access_vault_ca_file='ca', access_operation_timeout=total,
        access_vault_timeout_seconds=budget, access_vault_refresh_seconds=refresh,
        access_vault_validity_seconds=60)


# Le budget borne la première lecture, en relecture de fond (30) comme en retour arrière (0).
@pytest.mark.parametrize('refresh', [30, 0])
@pytest.mark.parametrize('budget,success', [(2, False), (3, True)])
def test_complete_protocol_over_two_seconds_obeys_configured_budget(monkeypatch, budget, success, refresh):
    calls = {'initialize': 0, 'read': 0, 'close': 0}
    monkeypatch.setattr(files_credentials, 'private_text', lambda _: 'synthetic-only')
    monkeypatch.setattr(files_credentials.ssl, 'create_default_context', lambda **_: object())

    @asynccontextmanager
    async def http(**_):
        yield object()

    @asynccontextmanager
    async def transport(*_, **__):
        yield object(), object()

    class Session:
        def __init__(self, *_): pass
        async def __aenter__(self): return self
        async def __aexit__(self, *_): calls['close'] += 1
        async def initialize(self):
            calls['initialize'] += 1
            await asyncio.sleep(2.05)
        async def call_tool(self, name, arguments):
            assert name == 'secret_read'
            calls['read'] += 1
            return SimpleNamespace(content=[SimpleNamespace(text=json.dumps({
                'status': 'ok', 'vault_id': 'credentials', 'path': 'connection',
                'data': dict(host='db', port=5432, dbname='tools', user='app', password='synthetic-only'),
            }))])

    monkeypatch.setattr(httpx2, 'AsyncClient', http)
    monkeypatch.setattr(mcp.client.streamable_http, 'streamable_http_client', transport)
    monkeypatch.setattr(mcp, 'ClientSession', Session)
    credential = AccessCredentials(settings(budget, refresh=refresh))
    if success:
        assert asyncio.run(credential.sql())['user'] == 'app'
    else:
        with pytest.raises(TokenStoreUnavailable):
            asyncio.run(credential.sql())
    assert calls == {'initialize': 1, 'read': int(success), 'close': 1}


def test_remaining_global_budget_stops_credentials_before_sql_dispatch(monkeypatch):
    calls = []
    credential = AccessCredentials(settings(3, total=2))

    async def slow():
        calls.append('read')
        await asyncio.sleep(1.5)
        return dict(host='db', port=5432, dbname='tools', user='app', password='synthetic-only')

    async def forbidden(**_):
        pytest.fail('le budget global doit arrêter avant SQL')

    credential.provider.sql = slow
    monkeypatch.setattr(psycopg.AsyncConnection, 'connect', forbidden)
    monkeypatch.setattr(psycopg.capabilities, 'has_cancel_safe', lambda: True)
    store = PostgresAccessStore(credential, ca_file='ca', role='app', database='tools', timeout=2)
    with pytest.raises(TokenStoreUnavailable):
        asyncio.run(store._run('SELECT something', ()))
    assert calls == ['read']
