"""Public files concat/write/delete, real isolated PG, explicit in-memory S3.

RED old referenced() vs GREEN new referenced() inspect the SAME persisted graph,
no publication replay. This does not qualify S3/Vault/TLS/native delivery.
"""
import asyncio
import hashlib
from contextlib import asynccontextmanager, nullcontext
from datetime import timedelta
from types import ModuleType, SimpleNamespace
from unittest.mock import patch
from uuid import uuid4

import psycopg
from psycopg.rows import dict_row


async def exercise(args, save):
    from src.mcp_tools.auth.context import current_token_info
    from src.mcp_tools.config import Settings
    from src.mcp_tools.storage.files_credentials import StorageUnavailable
    from src.mcp_tools.storage.files_postgres import Catalog
    from src.mcp_tools.storage.files_recovery import FileRecovery
    from src.mcp_tools.storage.files_service import FilesService
    from src.mcp_tools.tools import files

    class FixtureCatalog(Catalog):
        @asynccontextmanager
        async def connection(self, *unused, **kwargs):
            # Only libpq establishment is controlled. SQL/barriers/COMMITs are real.
            async with await psycopg.AsyncConnection.connect(host=str(args.socket),
                    dbname=args.database, user=self.s.files_pg_role, autocommit=True, row_factory=dict_row) as c:
                await c.execute('SET search_path=tools_files,pg_catalog')
                await c.execute('SET statement_timeout=5000')
                await c.execute('SET lock_timeout=3000')
                c._tools_operator = False
                c._tools_notices = []
                c.add_notice_handler(lambda d: c._tools_notices.append((d.severity_nonlocalized, d.sqlstate)))
                yield c

    class MemoryBlobs:
        """Controlled byte store only; no claim of actual S3 publication."""
        def __init__(self):
            self.bytes = {}

        async def ready(self):
            pass

        async def put(self, key, body, sha):
            assert hashlib.sha256(body).hexdigest() == sha
            version = 'simulated-' + uuid4().hex
            self.bytes[(key, version)] = body
            return {'key': key, 'version_id': version, 'sha256': sha, 'size': len(body), 'etag': sha}

        async def get(self, pin):
            content = self.bytes[(pin['key'], pin['version_id'])]
            assert len(content) == pin['size'] and hashlib.sha256(content).hexdigest() == pin['sha256']
            return content

        async def marker(self, pin):
            assert (pin['key'], pin['version_id']) in self.bytes
            return {'key': pin['key'], 'version_id': 'simulated-marker-' + uuid4().hex}

    class Registry:
        def tool(self):
            def keep(function):
                self.call = function
                return function
            return keep

    async with await psycopg.AsyncConnection.connect(host=str(args.socket),
            dbname=args.database, user='postgres', autocommit=True, row_factory=dict_row) as c:
        identity = await (await c.execute('SELECT (pg_control_system()).system_identifier::text id,'
                                          '(pg_control_checkpoint()).timeline_id timeline')).fetchone()
    cfg = Settings(_env_file=None, files_metadata_backend='postgres', files_credentials_mode='direct',
        files_pg_schema='tools_files', files_pg_database=args.database, files_pg_owner=args.owner,
        files_pg_role=args.app, files_pg_system_identifier=identity['id'], files_pg_timeline=identity['timeline'],
        files_durability='local', files_recovery_enabled=True,
        files_recovery_maintenance_role=args.maintenance, files_s3_prefix='fixture845/',
        s3_endpoint_url='https://fixture.invalid', s3_access_key_id='synthetic',
        s3_secret_access_key='synthetic', s3_bucket_name='synthetic')
    catalog = FixtureCatalog(cfg)
    service = object.__new__(FilesService)
    service.s, service.catalog, service.blobs, service.calls = cfg, catalog, MemoryBlobs(), asyncio.Semaphore(4)
    registry = Registry()
    files.register(registry)
    baseline = ModuleType('baseline845')
    baseline.__package__ = 'src.mcp_tools.storage'
    exec(compile(args.transitive_baseline.read_text(), str(args.transitive_baseline), 'exec'), baseline.__dict__)
    original = baseline.FileRecovery.referenced
    calls = []

    async def call(operation, **kwargs):
        result = await registry.call(operation=operation, **kwargs)
        calls.append({'operation': operation, 'args': kwargs, 'result': result})
        save(args.output / ('public-' + str(len(calls)) + '.json'), calls[-1])
        return result

    async def state():
        async with catalog.connection() as c:
            rows = {table: await (await c.execute('SELECT * FROM ' + table + ' ORDER BY 1')).fetchall()
                    for table in ('refs', 'generations', 'operations')}
        async with await psycopg.AsyncConnection.connect(host=str(args.socket), dbname=args.database,
                user=args.maintenance, autocommit=True, row_factory=dict_row) as c:
            rows['blob_retirements'] = await (await c.execute('SELECT * FROM tools_files.blob_retirements ORDER BY 1')).fetchall()
        return rows

    async def observe(pin, label):
        before = await state()
        reader = FixtureCatalog(cfg.model_copy(update={'files_pg_role': args.maintenance}))
        async with reader.connection() as c:
            red = await original(c, pin)
            green = await FileRecovery.referenced(c, pin, dependencies=False)
        after = await state()
        # Observations are durable before assertions, including original false result.
        observation = {'red_original': red, 'green_candidate': green, 'before': before, 'after': after}
        save(args.output / (label + '.json'), observation)
        assert before == after and red is False and green is True
        # The real collector must also keep every retired source unarmed.
        # This fixture controls only the external backup provider/S3, not SQL guards.
        recovery = object.__new__(FileRecovery)
        recovery.settings = cfg.model_copy(update={'files_pg_role': args.maintenance})
        recovery.app_role = args.app
        recovery.catalog = FixtureCatalog(recovery.settings)
        class NoDelete:
            def checked(self, value):
                return dict(value)
            async def delete_once(self, value):
                raise AssertionError('transitively referenced pin reached DELETE')
            async def absence(self, value):
                raise AssertionError('transitively referenced pin reached reconciliation')
            async def drain(self):
                pass
        recovery.blobs = NoDelete()
        await recovery.acknowledge()
        async with recovery.connection() as c:
            expiry = await (await c.execute('SELECT max(recover_until) expiry FROM blob_retirements')).fetchone()
        control = SimpleNamespace(registry=SimpleNamespace(locked=lambda: nullcontext()),
            pending=lambda: False, protected=lambda ack: False, identity={'system_id': identity['id']})
        before_collect = await state()
        collected = await recovery.collect(control, now=expiry['expiry'] + timedelta(seconds=1))
        after_collect = await state()
        save(args.output / (label + '-collector.json'), {'before': before_collect,
            'result': collected, 'after': after_collect,
            'backup_provider': 'explicit no-backup seam, no native PITR claim'})
        assert collected['deleted'] == 0 and collected['protected'] >= 2 and before_collect == after_collect

    marker = current_token_info.set({'permissions': ['admin'], 'credential_binding': 'fixture845-public'})
    try:
        with patch('src.mcp_tools.tools.files.get_settings', return_value=cfg), \
             patch('src.mcp_tools.auth.access_runtime.get_settings', return_value=cfg), \
             patch('src.mcp_tools.storage.files_service.get_files_service', return_value=service):
            for op, params in [('write', {'path': 'A', 'content': 'source'}),
                               ('concat', {'path': 'B', 'paths': ['A']}),
                               ('concat', {'path': 'C', 'paths': ['B']}),
                               ('delete', {'path': 'A'}), ('delete', {'path': 'B'})]:
                result = await call(op, operation_id=str(uuid4()), **params)
                assert result['status'] == 'ok', result
            async with catalog.connection() as c:
                a = await (await c.execute("SELECT pin FROM generations WHERE path='A'")).fetchone()
            await observe(a['pin'], 'live-C-transitive-red-green')
            # Admit an intention from C, stop before its first S3 effect; then retire C.
            original_phase = service.phase
            async def stop_after_admission(oid, phase, detail=None):
                if phase == 'CONTENT_DISPATCH_ARMED':
                    raise StorageUnavailable('isolated fixture pause after durable admission')
                return await original_phase(oid, phase, detail)
            with patch.object(service, 'phase', stop_after_admission):
                interrupted = await call('concat', path='D', paths=['C'], operation_id=str(uuid4()))
            assert interrupted['status'] == 'incomplete'
            deleted = await call('delete', path='C', operation_id=str(uuid4()))
            assert deleted['status'] == 'ok', deleted
            await observe(a['pin'], 'open-D-transitive-red-green')
    finally:
        current_token_info.reset(marker)
    return {'public_concat_persistent_graph': True, 'live_root_red_green': True,
            'open_intent_red_green': True, 'S3': 'explicit in-memory seam, not qualified',
            'SQL': 'actual PG17, no business replay'}
