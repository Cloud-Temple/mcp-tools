"""Vault reste frais et le coffre ne peut déplacer le domaine SQL #31."""
import asyncio
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from src.mcp_tools.auth.postgres_credentials import AccessCredentials
from src.mcp_tools.auth.token_store import TokenStoreUnavailable


def provider():
    return AccessCredentials(SimpleNamespace(access_pg_hosts='pg1,pg2,pg3', access_pg_database='tools',
        access_pg_role='app', access_vault_url='https://vault', access_vault_id='access',
        access_vault_path='connection', access_vault_token_file='private',
        access_vault_ca_file='ca', access_operation_timeout=5))


def test_host_order_can_follow_primary_but_credentials_are_always_fresh():
    obj = provider()
    calls = []
    async def read():
        calls.append(1)
        return dict(host='pg3,pg1,pg2', port=5432, dbname='tools', user='app', password='private')
    obj.provider.sql = read
    async def scenario():
        await obj.sql()
        await obj.sql()
    asyncio.run(scenario())
    assert len(calls) == 2


@pytest.mark.parametrize('change', [{'host': 'pg1,pg1,pg3'}, {'host': 'pg1, pg2,pg3'},
    {'host': 'pg1,pg2,foreign'}, {'port': '5432'}, {'port': True}])
def test_corrupt_or_moved_target_is_unavailable(change):
    obj = provider()
    async def read():
        return dict(dict(host='pg1,pg2,pg3', port=5432, dbname='tools', user='app', password='private'), **change)
    obj.provider.sql = read
    with pytest.raises(TokenStoreUnavailable):
        asyncio.run(obj.sql())
