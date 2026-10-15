"""Historical pins do not bypass a current logical deletion."""
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from types import SimpleNamespace

import pytest

from mcp_tools.storage.files_service import FilesService


class Catalog:
    def __init__(self):
        self.history_reads = 0

    @asynccontextmanager
    async def connection(self):
        yield self

    async def execute(self, *args):
        self.history_reads += 1
        return SimpleNamespace(fetchall=self.rows)

    async def rows(self):
        return [{'id': 'old', 'pin': {'version_id': 'v1', 'size': 4, 'sha256': 'a' * 64, 'etag': 'e'}, 'manifest': [], 'created_at': datetime.now(timezone.utc)}]


@pytest.mark.asyncio
@pytest.mark.parametrize('op', ['read', 'info', 'diff', 'versions'])
async def test_current_deletion_prevents_history_and_s3(monkeypatch, op):
    service = object.__new__(FilesService)
    service.catalog = Catalog()
    service.s = SimpleNamespace(tool_max_output_chars=50000)

    async def ref(*args, **kwargs):
        return {'path': 'owned', 'deleted': True, 'generation': 'old', 'revision': 2}

    async def forbidden_get(*args):
        pytest.fail('deleted content reached S3')

    monkeypatch.setattr(service, 'ref', ref)
    service.blobs = SimpleNamespace(get=forbidden_get)
    result = await service.read_operations(op, {'path': 'owned', 'path2': 'other',
                                               'version_id': 'v1', 'max_keys': 5})
    assert service.catalog.history_reads == 0
    assert result.get('content') is None
    if op == 'versions':
        assert result['versions'] == [] and result['count'] == 0
    else:
        assert result['effect_state'] == 'absent'
