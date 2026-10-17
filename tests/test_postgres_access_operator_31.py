"""Le premier secret reste privé et n'est écrit qu'après COMMIT confirmé."""
import asyncio
import hashlib
import os
from pathlib import Path
import sys
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from src.mcp_tools.auth import postgres_operator as operator


def configure(monkeypatch, tmp_path, commit_failure=False, audit_failure=False):
    import psycopg
    settings = SimpleNamespace(access_backend='postgres', access_pg_ca_file='ca',
        access_pg_owner='access_owner', access_pg_role='access_install', access_pg_database='access')
    monkeypatch.setattr(operator, 'get_settings', lambda: settings)
    events = []

    class Provider:
        def __init__(self, settings): pass
        async def sql(self):
            return dict(host='pg', port=5432, dbname='access', user='access_install', password='PRIVATE')

    class Transaction:
        async def __aenter__(self): return self
        async def __aexit__(self, kind, value, tb):
            if kind is None:
                if commit_failure:
                    raise RuntimeError('COMMIT ACK unknown')
                events.append('committed')
            else:
                c.rows.clear()
                events.append('rolled_back')

    class Connection:
        def __init__(self):
            self.pgconn = SimpleNamespace(finish=lambda: events.append('closed'))
            self.rows = []
        def transaction(self): return Transaction()
        async def execute(self, query, params=()):
            self.query = str(query)
            self.params = params
            if 'INSERT INTO tools_access.access_credentials' in self.query:
                self.rows.append(params)
            if 'record_admin' in self.query:
                if audit_failure:
                    raise RuntimeError('audit unavailable')
                events.append('audited')
            return self
        async def fetchone(self):
            if 'current_user' in self.query:
                return {'role':'access_install', 'db':'access'}
            if 'count(*)' in self.query:
                return {'n':0}
            return {}

    c = Connection()
    async def connect(**kwargs):
        assert kwargs['sslmode']=='verify-full' and kwargs['target_session_attrs']=='read-write'
        events.append('connected')
        return c
    async def verify(*args, **kwargs): events.append('verified')
    monkeypatch.setattr(operator, 'AccessCredentials', Provider)
    monkeypatch.setattr(psycopg.AsyncConnection, 'connect', connect)
    monkeypatch.setattr(operator, 'verify', verify)
    token_file = tmp_path/'admin.token'
    tmp_path.chmod(0o700)
    args = SimpleNamespace(action='bootstrap', app_role='access_app',
        maintenance_role='access_maintenance', token_file=str(token_file),
        tenant_id='tenant', service_id='tools')
    original = operator.write_token
    def after_commit(path, raw):
        assert 'committed' in events
        original(path, raw)
        events.append('secret_written')
    monkeypatch.setattr(operator, 'write_token', after_commit)
    return args, c, events, token_file


def test_first_admin_file_is_0600_after_commit_without_raw_sql_or_stdout(monkeypatch, tmp_path, capsys):
    args, c, events, target = configure(monkeypatch, tmp_path)
    result = asyncio.run(operator.operate(args))
    raw = target.read_text().strip()
    assert result['status']=='ok' and os.stat(target).st_mode & 0o777 == 0o600
    assert events == ['connected','verified','audited','committed','secret_written','closed']
    assert c.rows[0][0] == hashlib.sha256(raw.encode()).hexdigest()
    assert raw not in repr(c.rows) and raw not in capsys.readouterr().out


def test_unknown_commit_does_not_write_or_retry_first_admin_secret(monkeypatch, tmp_path):
    args, c, events, target = configure(monkeypatch, tmp_path, commit_failure=True)
    with pytest.raises(RuntimeError, match='unknown'):
        asyncio.run(operator.operate(args))
    assert not target.exists() and len(c.rows)==1 and events[-1]=='closed'


def test_existing_file_refuses_before_sql_without_overwrite(monkeypatch, tmp_path):
    args, c, events, target = configure(monkeypatch, tmp_path)
    target.write_text('existing')
    with pytest.raises(ValueError, match='neuf'):
        asyncio.run(operator.operate(args))
    assert target.read_text()=='existing' and not events and not c.rows


def test_bootstrap_audit_failure_rolls_back_credential_and_never_writes_file(monkeypatch, tmp_path):
    args, c, events, target = configure(monkeypatch, tmp_path, audit_failure=True)
    with pytest.raises(RuntimeError, match='audit unavailable'):
        asyncio.run(operator.operate(args))
    assert not target.exists() and not c.rows
    assert 'rolled_back' in events and 'committed' not in events and 'secret_written' not in events
