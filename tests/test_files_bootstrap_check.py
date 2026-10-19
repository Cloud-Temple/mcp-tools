"""Control flow only; the PG17 fixture supplies the privilege-engine proof."""
import asyncio
from contextlib import asynccontextmanager
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from src.mcp_tools.config import Settings
from src.mcp_tools.storage import files_bootstrap as bootstrap
from src.mcp_tools.storage.files_credentials import StorageUnavailable
from src.mcp_tools.storage.files_postgres import Catalog, CommitUnknown
from src.mcp_tools.storage.files_schema import VERSION, CHECKSUM


def profile(**kwargs):
    return Settings(_env_file=None, files_pg_system_identifier='1', files_pg_timeline=1, files_durability='local', **kwargs)


@pytest.mark.parametrize('usage,can_set,become_owner', [(False, True, True), (True, True, False), (True, False, False), (False, False, False)])
def test_check_transaction_order_and_app_identity(usage, can_set, become_owner):
    events = []
    connection = SimpleNamespace(_tools_operator=True, _tools_notices=[])

    async def execute(query, parameters=()):
        text = query if isinstance(query, str) else query.as_string()
        events.append(text)
    connection.execute = execute

    class Seam(Catalog):
        @asynccontextmanager
        async def connection(self, service=None, operator=False):
            assert operator
            events.append('identity/base/cluster checked')
            try:
                yield connection
            finally:
                events.append('closed')

        @staticmethod
        async def one(c, query, parameters=()):
            text = query if isinstance(query, str) else query.as_string()
            events.append(text)
            if 'rolcanlogin' in text:
                return dict(rolcanlogin=parameters[0] == 'app', rolsuper=False,
                            rolcreatedb=False, rolcreaterole=False, rolreplication=False, rolbypassrls=False)
            if 'pg_namespace' in text:
                return {'present': True}
            if 'has_schema_privilege' in text:
                assert parameters == ('owned', 'owner')
                return {'usage': usage, 'can_set': can_set}
            if 'schema_version' in text:
                return {'version': VERSION, 'checksum': CHECKSUM}
            raise AssertionError(text)

        async def check_schema(self, c, role=None):
            assert role == 'app'
            events.append('app grants checked')

        async def infrastructure(self, c, bound=None):
            events.append('infrastructure checked')

    settings = profile(files_pg_schema='owned', files_pg_owner='owner')
    with patch.object(bootstrap, 'Catalog', Seam), patch.object(bootstrap, 'get_settings', return_value=settings):
        result = asyncio.run(bootstrap.install(SimpleNamespace(schema='owned', app_role='app', operator_service='job', check=True)))
    assert result['status'] == 'ok'
    begin = events.index('BEGIN ISOLATION LEVEL READ COMMITTED')
    assert events[0] == 'identity/base/cluster checked'
    assert events[begin + 1] == 'SET TRANSACTION READ ONLY'
    assert 'has_schema_privilege' in events[begin + 2]
    role_statements = [x for x in events if x.startswith('SET LOCAL ROLE')]
    assert role_statements == (['SET LOCAL ROLE "owner"'] if become_owner else [])
    search = events.index('SET LOCAL search_path TO pg_catalog, "owned"')
    version = next(i for i, x in enumerate(events) if 'FROM "owned".schema_version' in x)
    assert begin + 2 < search < version < events.index('app grants checked') < events.index('infrastructure checked') < events.index('COMMIT')
    assert events[-1] == 'closed'


@pytest.mark.parametrize('failure,expected', [('check', StorageUnavailable), ('commit', CommitUnknown)])
def test_check_failure_rolls_back_or_reports_unknown_commit_and_closes(failure, expected):
    events = []
    c = SimpleNamespace(_tools_operator=True, _tools_notices=[])

    async def execute(query, parameters=()):
        text = query if isinstance(query, str) else query.as_string()
        events.append(text)
        if text == 'COMMIT' and failure == 'commit':
            raise OSError('transport ended')
    c.execute = execute

    class Seam(Catalog):
        @asynccontextmanager
        async def connection(self, **kwargs):
            try:
                yield c
            finally:
                events.append('closed')

        @staticmethod
        async def one(c, query, parameters=()):
            text = query if isinstance(query, str) else query.as_string()
            if 'rolcanlogin' in text:
                return {'rolcanlogin': parameters[0] == 'app'}
            if 'pg_namespace' in text:
                return {'present': True}
            if 'has_schema_privilege' in text:
                return {'usage': False, 'can_set': True}
            return {'version': VERSION, 'checksum': CHECKSUM}

        async def check_schema(self, c, role=None):
            assert role == 'app'
            if failure == 'check':
                raise StorageUnavailable('application grants invalid')

        async def infrastructure(self, c, bound=None):
            pass

    settings = profile(files_pg_owner='owner')
    with patch.object(bootstrap, 'Catalog', Seam), patch.object(bootstrap, 'get_settings', return_value=settings):
        with pytest.raises(expected):
            asyncio.run(bootstrap.install(SimpleNamespace(schema='tools_files', app_role='app', operator_service=None, check=True)))
    assert events[-1] == 'closed'
    assert events.count('COMMIT') == (failure == 'commit')
    assert events.count('ROLLBACK') == (failure == 'check')


def test_operator_identity_failure_precedes_any_role_or_check_transaction():
    events = []

    class RefusedIdentity(Catalog):
        @asynccontextmanager
        async def connection(self, **kwargs):
            events.append('identity refused')
            raise StorageUnavailable('Cible SQL/identité invalide')
            yield

    with patch.object(bootstrap, 'Catalog', RefusedIdentity), patch.object(bootstrap, 'get_settings', return_value=profile()):
        with pytest.raises(StorageUnavailable, match='Cible SQL/identité invalide'):
            asyncio.run(bootstrap.install(SimpleNamespace(schema='tools_files', app_role='app', operator_service=None, check=True)))
    assert events == ['identity refused']
