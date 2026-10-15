"""Bornes transport et refus d'ACK inconnu ; aucune base ni API dans ces tests."""
import asyncio
import sys
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from src.mcp_tools.auth.postgres_store import PostgresAccessStore, _ACTIVE
from src.mcp_tools.auth.token_store import TokenStoreUnavailable


class Provider:
    calls = 0

    async def sql(self):
        self.calls += 1
        return dict(host='private', port=5432, dbname='access', user='app', password='PRIVATE-CANARY')


def contract_rows(query):
    from src.mcp_tools.auth.postgres_schema import VERSION, CHECKSUM
    if 'schema_contract' in query:
        return [{'version': VERSION, 'checksum': CHECKSUM}]
    if 'pg_roles' in query:
        return [{'role': 'app', 'db': 'access', 'recovery': False, 'privileged': False}]
    return [{'admitted': True}]


def test_uncertain_commit_never_returns_rows_or_retries(monkeypatch):
    import psycopg

    class Cursor:
        async def __aenter__(self): return self
        async def __aexit__(self, *args): pass
        async def execute(self, query, *args): self.query = query
        async def fetchall(self): return contract_rows(self.query)

    class Connection:
        pgconn = SimpleNamespace(finish=lambda: None)
        commits = 0
        def cursor(self): return Cursor()
        async def commit(self):
            self.commits += 1
            raise RuntimeError('PRIVATE-CANARY conninfo')

    conn = Connection()
    async def connect(**kwargs): return conn
    monkeypatch.setattr(psycopg.AsyncConnection, 'connect', connect)
    monkeypatch.setattr(psycopg.capabilities, 'has_cancel_safe', lambda: True)
    provider = Provider()
    store = PostgresAccessStore(provider, ca_file='ca', role='app', database='access')
    with pytest.raises(TokenStoreUnavailable) as error:
        asyncio.run(store._run('SELECT something', ()))
    assert 'PRIVATE' not in str(error.value)
    assert conn.commits == 1 and provider.calls == 1 and not _ACTIVE


def test_stalled_statement_is_cancelled_closed_and_bounded(monkeypatch):
    import psycopg

    flags = {'cancel': 0, 'close': 0}
    class Cursor:
        async def __aenter__(self): return self
        async def __aexit__(self, *args): pass
        async def execute(self, query, *args):
            self.query = query
            if 'schema_contract' not in query and 'pg_roles' not in query:
                await asyncio.sleep(30)
        async def fetchall(self): return contract_rows(self.query)
    def close(): flags['close'] += 1
    class Connection:
        pgconn = SimpleNamespace(finish=close)
        def cursor(self): return Cursor()
        async def commit(self): raise AssertionError('never reached')
        async def cancel_safe(self, **kwargs): flags['cancel'] += 1
    async def connect(**kwargs): return Connection()
    monkeypatch.setattr(psycopg.AsyncConnection, 'connect', connect)
    monkeypatch.setattr(psycopg.capabilities, 'has_cancel_safe', lambda: True)
    store = PostgresAccessStore(Provider(), ca_file='ca', role='app', database='access', timeout=2)
    before = time.monotonic()
    with pytest.raises(TokenStoreUnavailable):
        asyncio.run(store._run('SELECT pg_sleep(30)', ()))
    assert time.monotonic()-before < 2.2
    assert flags == {'cancel': 1, 'close': 1} and not _ACTIVE


def test_unavailable_transport_is_never_an_authentication_absence():
    class Unavailable(PostgresAccessStore):
        async def _run(self, *args): raise TokenStoreUnavailable('offline')
    store = Unavailable(Provider(), ca_file='ca', role='app', database='access')
    with pytest.raises(TokenStoreUnavailable):
        asyncio.run(store.authenticate('opaque'))


@pytest.mark.parametrize('cancel_mode', ['raises', 'blocks', 'late'])
def test_external_cancellation_during_commit_never_publishes_success(monkeypatch, cancel_mode):
    import psycopg

    async def scenario():
        committing = asyncio.Event()
        flags = {'closed': False}
        class Cursor:
            async def __aenter__(self): return self
            async def __aexit__(self, *args): pass
            async def execute(self, query, *args): self.query = query
            async def fetchall(self): return contract_rows(self.query)
        def close(): flags['closed'] = True
        class Connection:
            pgconn = SimpleNamespace(finish=close)
            def cursor(self): return Cursor()
            async def commit(self):
                committing.set()
                try:
                    await asyncio.sleep(30)
                except asyncio.CancelledError:
                    if cancel_mode != 'late':
                        raise
                    await asyncio.sleep(.05)
            async def cancel_safe(self, **kwargs):
                if cancel_mode == 'raises':
                    raise RuntimeError('PRIVATE-CANARY')
                if cancel_mode == 'blocks':
                    await asyncio.sleep(30)
        async def connect(**kwargs): return Connection()
        monkeypatch.setattr(psycopg.AsyncConnection, 'connect', connect)
        monkeypatch.setattr(psycopg.capabilities, 'has_cancel_safe', lambda: True)
        store = PostgresAccessStore(Provider(), ca_file='ca', role='app', database='access', timeout=2)
        task = asyncio.create_task(store._run('SELECT mutation', ()))
        await asyncio.wait_for(committing.wait(), .5)
        before = time.monotonic()
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        await asyncio.sleep(.06)
        assert flags['closed'] and not _ACTIVE
        assert time.monotonic()-before < 1
    asyncio.run(scenario())
