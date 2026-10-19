"""Real Access/Files/job code, in-memory Vault wire and SQL connection boundary.

No libpq connection, server, SQL, S3 or TLS qualification is performed here.
The service trap uses hostaddr, which Access does not explicitly override.
"""
import asyncio
from contextlib import asynccontextmanager
import json
import os
from types import SimpleNamespace
from uuid import uuid4

import psycopg
import pytest
import certifi

from src.mcp_tools.auth.postgres_credentials import AccessCredentials
from src.mcp_tools.auth.postgres_store import PostgresAccessStore
from src.mcp_tools.auth import postgres_operator as operator
from src.mcp_tools.auth.token_store import TokenStoreUnavailable
from src.mcp_tools.config import Settings
from src.mcp_tools.storage.files_credentials import Credentials
from src.mcp_tools.storage.files_postgres import Catalog
from src.mcp_tools import retention_846


@pytest.fixture
def wiring(monkeypatch, tmp_path):
    for key in tuple(os.environ):
        if key.startswith('PG'):
            monkeypatch.delenv(key)
    service = tmp_path / 'service.conf'
    service.write_text('[tools-files]\nhost=files.invalid\nport=5432\n'
                       'dbname=files\nuser=files_app\n'
                       '[access-trap]\nhostaddr=192.0.2.1\nrequire_auth=none\n'
                       '[]\nhostaddr=192.0.2.1\nsslkey=/missing/canary.key\n')
    service.chmod(0o600)
    passfile = tmp_path / 'passfile'
    passfile.write_text('access.invalid:5432:tools:access_app:PASSFILE-CANARY\n')
    passfile.chmod(0o600)
    token = tmp_path / 'vault.token'
    token.write_text('SYNTHETIC-VAULT-BEARER')
    token.chmod(0o600)
    monkeypatch.setenv('PGSERVICEFILE', str(service))
    monkeypatch.setenv('PGPASSFILE', str(passfile))
    settings = Settings(_env_file=None, access_backend='postgres',
        access_pg_hosts='access.invalid', access_pg_role='access_app',
        access_pg_ca_file=certifi.where(),
        access_vault_url='https://vault.invalid', access_vault_id='tools',
        access_vault_path='app', access_vault_token_file=str(token),
        access_vault_ca_file=certifi.where(),
        access_mission_retention_enabled=True,
        files_metadata_backend='postgres', files_credentials_mode='direct',
        files_pg_system_identifier='123', files_pg_role='files_maintenance', files_pg_ca_file=certifi.where(),
        files_recovery_enabled=True, files_recovery_maintenance_role='files_maintenance',
        s3_endpoint_url='https://s3.invalid', s3_access_key_id='TEST', s3_secret_access_key='TEST')
    state = SimpleNamespace(settings=settings, reads=[], connects=[], queries=[], password='VAULT-CANARY')
    import mcp
    import mcp.client.streamable_http as transport

    @asynccontextmanager
    async def wire(*args, **kwargs):
        yield None, None

    class Session:
        def __init__(self, *args): pass
        async def __aenter__(self): return self
        async def __aexit__(self, *args): pass
        async def initialize(self): pass
        async def call_tool(self, name, args):
            assert name == 'secret_read'
            state.reads.append(dict(args))
            user = 'access_maintenance' if args['path'] == 'maintenance' else 'access_app'
            data = dict(host='access.invalid', port=5432, dbname='tools', user=user, password=state.password)
            return SimpleNamespace(is_error=False, content=[SimpleNamespace(text=json.dumps(
                dict(status='ok', vault_id=args['vault_id'], path=args['path'], data=data)))])
    monkeypatch.setattr(transport, 'streamable_http_client', wire)
    monkeypatch.setattr(mcp, 'ClientSession', Session)

    class Connection:
        def __init__(self, kwargs):
            self.kwargs = kwargs
            self.pgconn = SimpleNamespace(finish=lambda: None)
        def cursor(self): return self
        async def __aenter__(self): return self
        async def __aexit__(self, *args): pass
        async def execute(self, query, params=()):
            self.query = query
            state.queries.append(str(query))
            return self
        async def fetchone(self):
            if 'pg_control_system' in self.query:
                return dict(cluster='123', timeline=1, fsync=True)
            if 'pg_is_in_recovery' in self.query:
                return dict(role=self.kwargs['user'], db=self.kwargs['dbname'], recovery=False)
            if 'current_user' in self.query:
                return dict(role=self.kwargs['user'], db=self.kwargs['dbname'])
            return dict(removed=0)
        async def fetchall(self):
            from src.mcp_tools.auth.postgres_schema import VERSION, CHECKSUM
            from src.mcp_tools.auth import postgres_retention_846 as holds
            if 'schema_contract' in self.query:
                return [dict(version=VERSION, checksum=CHECKSUM)]
            if 'retention_846_contract' in self.query:
                return [dict(version=holds.VERSION, checksum=holds.CHECKSUM, coordination_required=True)]
            if 'pg_roles' in self.query:
                return [dict(role=self.kwargs['user'], db=self.kwargs['dbname'], recovery=False, privileged=False)]
            return [dict(ok=True)]
        async def commit(self): pass
        async def close(self): pass
        def add_notice_handler(self, callback): pass

    async def connect(**kwargs):
        state.connects.append(dict(kwargs))
        if 'service' in kwargs:
            assert kwargs['service'] == 'tools-app'
            await asyncio.sleep(0)
            return Connection(dict(kwargs, user='files_maintenance', dbname='tools'))
        assert 'service' not in kwargs and 'passfile' not in kwargs and 'hostaddr' not in kwargs
        assert kwargs['sslmode'] == 'verify-full' and kwargs['target_session_attrs'] == 'read-write'
        assert kwargs['password'] == 'VAULT-CANARY', 'wrong Vault password, no passfile fallback'
        await asyncio.sleep(0)
        return Connection(kwargs)
    monkeypatch.setattr(psycopg.AsyncConnection, 'connect', connect)
    monkeypatch.setattr(psycopg.capabilities, 'has_cancel_safe', lambda: True)
    monkeypatch.setattr(operator, 'get_settings', lambda: state.settings)
    from src.mcp_tools import config
    monkeypatch.setattr(config, 'get_settings', lambda: state.settings)
    return state


def store(state):
    return PostgresAccessStore(AccessCredentials(state.settings), ca_file=state.settings.access_pg_ca_file,
                               role='access_app', database='tools')


def test_file_selectors_work_without_changing_environment_and_vault_is_fresh(wiring):
    before = dict(os.environ)
    async def scenario():
        files = Catalog(wiring.settings)
        async def file_connection():
            async with files.connection(operator=True):
                return await files.credentials.sql()
        access = store(wiring)
        results = await asyncio.gather(access._run('SELECT software_probe', ()), file_connection(),
                                       access._run('SELECT software_probe', ()), file_connection())
        assert results[0] == results[2] == [dict(ok=True)]
        assert results[1] == results[3] == dict(service='tools-app')
    asyncio.run(scenario())
    assert len(wiring.reads) == 2 and len(wiring.connects) == 4 and dict(os.environ) == before
    assert sum('service' in row for row in wiring.connects) == 2
    assert all('PGPASSFILE' not in row and 'PGSERVICEFILE' not in row for row in wiring.connects)


@pytest.mark.parametrize('key,value', [('PGSERVICE', ''), ('PGSERVICE', 'access-trap'),
    ('PGHOST', 'other.invalid'), ('PGHOSTADDR', '192.0.2.1'), ('PGPORT', '5433'),
    ('PGDATABASE', 'other'), ('PGUSER', 'other'), ('PGPASSWORD', 'PASSFILE-CANARY'),
    ('PGOPTIONS', '-c statement_timeout=0'), ('PGCONNECT_TIMEOUT', '99'),
    ('PGSSLMODE', 'disable'), ('PGSSLCERT', '/missing'), ('PGSSLKEY', '/missing'),
    ('PGSSLROOTCERT', '/missing'), ('PGTARGETSESSIONATTRS', 'any'),
    ('PGSYSCONFDIR', '/missing'), ('PGUNKNOWN', 'enabled')])
def test_all_access_entrypoints_refuse_ambient_settings_before_vault_or_connect(wiring, monkeypatch, tmp_path, key, value):
    monkeypatch.setenv(key, value)
    with pytest.raises(TokenStoreUnavailable):
        asyncio.run(store(wiring)._run('SELECT software_probe', ()))
    args = SimpleNamespace(action='purge', app_role='access_app', maintenance_role='access_maintenance',
                           token_file=None, batch=1)
    with pytest.raises(ValueError):
        asyncio.run(operator.operate(args))
    args = SimpleNamespace(files_app_role='files_app', state_dir=tmp_path/'state', operation_id=str(uuid4()))
    with pytest.raises(retention_846.Refused):
        retention_846.build(args)
    assert not wiring.reads and not wiring.connects and not wiring.queries


def test_operator_and_retention_build_accept_only_file_selectors(wiring, tmp_path):
    wiring.settings = wiring.settings.model_copy(update={'access_pg_role':'access_maintenance',
                                                         'access_vault_path':'maintenance'})
    before = dict(os.environ)
    args = SimpleNamespace(action='purge', app_role='access_app', maintenance_role='access_maintenance',
                           token_file=None, batch=1)
    assert asyncio.run(operator.operate(args))['status'] == 'ok'
    (tmp_path/'state').mkdir(mode=0o700)
    args = SimpleNamespace(files_app_role='files_app', state_dir=tmp_path/'state', operation_id=str(uuid4()))
    core = retention_846.build(args)
    async def scenario():
        async with core.access(): pass
    asyncio.run(scenario())
    assert len(wiring.reads) == len(wiring.connects) == 2 and dict(os.environ) == before


@pytest.mark.parametrize('password', ['', None])
def test_empty_vault_password_refused_before_sql_connect(wiring, password):
    wiring.password = password
    with pytest.raises(TokenStoreUnavailable):
        asyncio.run(store(wiring)._run('SELECT software_probe', ()))
    assert len(wiring.reads) == 1 and not wiring.connects and not wiring.queries


def test_wrong_vault_password_never_uses_a_passfile_or_reports_success(wiring):
    wiring.password = 'WRONG-VAULT-CANARY'
    with pytest.raises(TokenStoreUnavailable) as error:
        asyncio.run(store(wiring)._run('SELECT software_probe', ()))
    assert len(wiring.reads) == len(wiring.connects) == 1 and not wiring.queries
    assert wiring.connects[0]['password'] == 'WRONG-VAULT-CANARY'
    assert 'passfile' not in wiring.connects[0] and 'service' not in wiring.connects[0]
    assert 'CANARY' not in str(error.value)
