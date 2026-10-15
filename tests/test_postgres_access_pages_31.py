"""Pagination expurgée et revalidation fraîche avant restitution, sans moteur."""
import asyncio
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from src.mcp_tools.auth.postgres_store import PostgresAccessStore

HASH = 'a'*64


class Store(PostgresAccessStore):
    def __init__(self):
        super().__init__(None, ca_file='ca', role='app', database='access')
        self.versions = [1, 1]
        self.parameters = []

    async def _reader(self, requester):
        assert requester == HASH
        return {'actor_id': 'actor', 'tenant_id': 'tenant', 'service_id': 'tools',
                'version': self.versions.pop(0), 'permissions': ['admin']}

    async def _run(self, query, parameters):
        self.parameters.append(parameters)
        if 'credential_list' in query:
            return [{'cursor_key': 'b'*64, 'token_prefix': 'b'*12, 'actor_id': uuid4(),
                     'tenant_id': 'tenant', 'service_id': 'tools', 'client_name': 'reader',
                     'permissions': ['access'], 'tool_ids': ['files'],
                     'created_at': datetime.now(timezone.utc), 'expires_at': None,
                     'revoked': False, 'version': 1, 'unexpected_secret': 'PRIVATE-CANARY'}]
        return [dict(call_id=uuid4(), actor_id=uuid4(), tenant_id='tenant', service_id='tools',
                     tool='files', trace_id=uuid4(), operation_id=None, mission_id=None,
                     category='technical', admission='admitted', created_at=datetime.now(timezone.utc),
                     expires_at=datetime.now(timezone.utc), outcome='completed', target_actor_id=None,
                     unexpected_body='PRIVATE-CANARY')]


def test_credential_cursor_hides_hash_and_rejects_reader_version_change():
    async def scenario():
        store = Store()
        first = await store.list_credentials(HASH, limit=1)
        encoded = json.dumps(first)
        assert HASH not in encoded and 'b'*64 not in encoded and 'PRIVATE-CANARY' not in encoded
        assert 'cursor_key' not in encoded and first['next_cursor']
        store.versions = [1, 1]
        await store.list_credentials(HASH, limit=1, cursor=first['next_cursor'])
        assert store.parameters[-1][1] == 'b'*64
        store.versions = [2]
        with pytest.raises(ValueError):
            await store.list_credentials(HASH, limit=1, cursor=first['next_cursor'])
        assert len(store.parameters) == 2
    asyncio.run(scenario())


@pytest.mark.parametrize('page', ['credentials', 'activity'])
def test_rights_changed_during_page_read_return_no_previous_rows(page):
    async def scenario():
        store = Store()
        store.versions = [1, 2]
        method = store.list_credentials if page == 'credentials' else store.activity_page
        with pytest.raises(ValueError, match='changed during'):
            await method(HASH, limit=1)
    asyncio.run(scenario())


def test_activity_page_contains_only_declared_metadata_and_opaque_cursor():
    async def scenario():
        store = Store()
        result = await store.activity_page(HASH, limit=1)
        assert result['next_cursor'] and result['page_complete']
        assert 'PRIVATE-CANARY' not in json.dumps(result)
        assert 'unexpected_body' not in result['calls'][0]
    asyncio.run(scenario())
