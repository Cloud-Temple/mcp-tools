"""CAS, identité stable, secret à création uniquement et ACK conservateur."""
import asyncio
from datetime import datetime, timedelta, timezone
import hashlib
import json
import sys
from pathlib import Path
from uuid import uuid4

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from src.mcp_tools.auth.postgres_store import PostgresAccessStore, AccessMutationUncertain
from src.mcp_tools.auth.token_store import TokenStoreUnavailable


class Store(PostgresAccessStore):
    def __init__(self):
        super().__init__(None, ca_file='ca', role='app', database='access')
        now = datetime.now(timezone.utc)
        self.row = dict(token_hash='a'*64, actor_id=str(uuid4()), tenant_id='tenant',
                        service_id='tools', client_name='reader', permissions=['access'],
                        tool_ids=['files'], created_at=now, expires_at=now+timedelta(days=1),
                        revoked_at=None, version=2)
        self.calls = []
        self.uncertain = False
        self.ambiguous = False

    async def _run(self, query, parameters):
        self.calls.append((query, parameters))
        if 'credential_target' in query:
            return [self.row, self.row] if self.ambiguous else [self.row]
        if self.uncertain:
            raise TokenStoreUnavailable('Access operation unavailable or uncertain')
        return [{'changed': True}]


def test_create_returns_raw_only_after_commit_and_never_sends_it_to_sql():
    async def scenario():
        store = Store()
        result = await store.create('requester', client_name='reader', tenant_id='tenant',
            service_id='tools', permissions=['access'], tool_ids=['files'])
        raw = result['token']
        assert raw and raw not in json.dumps(store.calls, default=str)
        assert store.calls[0][1][2] == hashlib.sha256(raw.encode()).hexdigest()
        assert 'token_hash' not in result
        assert 'created_at' not in result  # seule la liste/info restitue l'horloge SQL canonique
        store.uncertain = True
        with pytest.raises(AccessMutationUncertain) as unknown:
            await store.create('requester', client_name='reader2', tenant_id='tenant',
                service_id='tools', permissions=['access'], tool_ids=['files'])
        assert len(store.calls) == 2
        assert unknown.value.operation_id == store.calls[-1][1][1]
        assert raw not in str(unknown.value)
    asyncio.run(scenario())


def test_target_collision_and_stale_cas_refuse_before_mutation():
    async def scenario():
        store = Store()
        with pytest.raises(ValueError, match='version conflict'):
            await store.revoke('requester', 'a'*12, 1)
        assert len(store.calls) == 1
        store.ambiguous = True
        with pytest.raises(ValueError, match='ambiguous'):
            await store.update('requester', 'a'*12, 2, permissions=['admin'])
        assert len(store.calls) == 2
    asyncio.run(scenario())


def test_info_is_metadata_and_update_revoke_keep_hash_private_with_distinct_operations():
    async def scenario():
        store = Store()
        info = await store.info('requester', 'a'*12)
        assert 'a'*64 not in json.dumps(info) and 'token' not in info
        updated = await store.update('requester', 'a'*12, 2, tool_ids=['shell'])
        revoked = await store.revoke('requester', 'a'*12, 2)
        assert updated['version'] == revoked['version'] == 3
        assert updated['operation_id'] != revoked['operation_id']
        assert 'a'*64 not in json.dumps([updated, revoked])
        assert store.calls[-1][1][2:]==('a'*64, 2)
    asyncio.run(scenario())
