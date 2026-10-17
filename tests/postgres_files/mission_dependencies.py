"""#846 Mission file dependencies on an actual isolated PG17, explicit in-memory S3.

Run by the new-domain worker after the base schema, the #845 extension and
``install_dependencies``. SQL, triggers, locks and COMMITs are real; S3 bytes
are a controlled seam. This does not qualify S3, Vault, TLS or native delivery.

T7  A and B read the same object; retiring Mission A keeps B's dependency and
    B's historical consultation returns the same bytes and SHA-256.
T9  A retired dependency resolves to unavailable, without any byte read.
T10a Two sessions: an uncommitted acquisition holds refs FOR SHARE and the pin
    lock; a concurrent public delete waits, then its reservation sees the
    committed dependency under refs FOR UPDATE and rolls back. No operation stays
    open on the path (round 1 left one, one_active_path then blocked T10b).
T10c A dependency committed between reservation and publication: publish refuses
    under refs FOR UPDATE and closes the operation in the same transaction.
T10b A delete committed first makes generation_visible false; acquisition refuses.
"""
import asyncio
import hashlib
from contextlib import asynccontextmanager
from unittest.mock import patch
from uuid import uuid4

import psycopg
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

SCHEMA = 'tools_files'
PATH = 'shared/report.txt'


def install_dependencies(c, owner, app, maintenance):
    """Synchronous worker hook, inside its owner transaction after the 845 render."""
    from psycopg import sql

    from src.mcp_tools.storage.files_dependency_schema import render
    c.execute(sql.SQL('SET LOCAL ROLE {}').format(sql.Identifier(owner)))
    c.execute(render(SCHEMA, app, maintenance), prepare=False)


async def exercise(args, save):
    from src.mcp_tools.auth import hub_activity as hub
    from src.mcp_tools.auth.context import current_access_operation, current_token_info
    from src.mcp_tools.config import Settings
    from src.mcp_tools.storage.files_postgres import Catalog
    from src.mcp_tools.storage.files_recovery import FileRecovery
    from src.mcp_tools.storage.files_service import FilesService
    from src.mcp_tools.storage.hub_files import published
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
            self.bytes, self.reads = {}, 0

        async def ready(self):
            pass

        async def put(self, key, body, sha):
            assert hashlib.sha256(body).hexdigest() == sha
            version = 'simulated-' + uuid4().hex
            self.bytes[(key, version)] = body
            return {'key': key, 'version_id': version, 'sha256': sha, 'size': len(body), 'etag': sha}

        async def get(self, pin):
            self.reads += 1
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
        files_pg_schema=SCHEMA, files_pg_database=args.database, files_pg_owner=args.owner,
        files_pg_role=args.app, files_pg_system_identifier=identity['id'], files_pg_timeline=identity['timeline'],
        files_durability='local', files_recovery_enabled=True, files_mission_dependencies_enabled=True,
        files_recovery_maintenance_role=args.maintenance, files_s3_prefix='fixture846/',
        s3_endpoint_url='https://fixture.invalid', s3_access_key_id='synthetic',
        s3_secret_access_key='synthetic', s3_bucket_name='synthetic')
    catalog = FixtureCatalog(cfg)
    service = object.__new__(FilesService)
    service.s, service.catalog, service.blobs, service.calls = cfg, catalog, MemoryBlobs(), asyncio.Semaphore(4)
    maintenance = cfg.model_copy(update={'files_pg_role': args.maintenance})
    recovery = object.__new__(FileRecovery)
    recovery.settings, recovery.app_role = maintenance, args.app
    recovery.catalog = FixtureCatalog(maintenance)
    registry = Registry()
    files.register(registry)
    evidence = {}

    async def dependencies():
        async with await psycopg.AsyncConnection.connect(host=str(args.socket), dbname=args.database,
                user=args.maintenance, autocommit=True, row_factory=dict_row) as c:
            return await (await c.execute('SELECT call_id::text,generation::text,activity_operation_id::text,'
                'mission_id,state,revision FROM tools_files.mission_file_dependencies ORDER BY 1,2')).fetchall()

    async def open_operations():
        async with catalog.connection() as c:
            return (await (await c.execute('SELECT count(*) n FROM operations WHERE path=%s AND NOT closed',
                                           (PATH,))).fetchone())['n']

    async def ref():
        async with catalog.connection() as c:
            return await (await c.execute('SELECT revision,deleted,generation::text FROM refs WHERE path=%s',
                                          (PATH,))).fetchone()

    def claims(mission, root):
        return {'tenant_id': 'tenant', 'mission_id': mission, 'root_agent_id': root,
                'tool_id': 'files', 'call_id': str(uuid4())}

    async def delegated_read(scope):
        """Context posed by the /mcp delegation then run_durable_tool; no access PG here."""
        delegation = hub.Delegation(None, 'fixture846', scope, cfg)
        delegation.consumed = True
        operation = str(uuid4())
        tokens = (hub.current_hub_context.set(delegation), current_access_operation.set(operation))
        try:
            result = await service.read_operations('read', {'path': PATH})
        finally:
            hub.current_hub_context.reset(tokens[0])
            current_access_operation.reset(tokens[1])
        return operation, result

    async def public(op, **params):
        return await registry.call(operation=op, operation_id=str(uuid4()), **params)

    marker = current_token_info.set({'permissions': ['admin'], 'credential_binding': 'fixture846-public'})
    try:
        with patch('src.mcp_tools.tools.files.get_settings', return_value=cfg), \
             patch('src.mcp_tools.auth.access_runtime.get_settings', return_value=cfg), \
             patch('src.mcp_tools.storage.files_service.get_files_service', return_value=service):
            written = await public('write', path=PATH, content='shared bytes v1')
            assert written['status'] == 'ok', written

            # T7: A and B read the same generation; only real trigger-checked rows exist.
            scope_a, scope_b = claims('mis_A', 'ag_A'), claims('mis_B', 'ag_B')
            op_a, read_a = await delegated_read(scope_a)
            op_b, read_b = await delegated_read(scope_b)
            first = read_b['content'].encode()
            rows = await dependencies()
            save(args.output / 't7-acquired.json', rows)
            assert read_a['content'] == read_b['content'] and len(rows) == 2
            assert {r['state'] for r in rows} == {'active'}

            retired = await recovery.retire_dependencies(tenant_id='tenant', mission_id='mis_A',
                                                         root_agent_id='ag_A', batch=10)
            rows = await dependencies()
            save(args.output / 't7-after-retire-A.json', {'result': retired, 'rows': rows})
            assert retired['retired'] == 1 and retired['complete'] is True
            assert {r['mission_id']: r['state'] for r in rows} == {'mis_A': 'retired', 'mis_B': 'active'}

            row_b = await published(service, scope_b['call_id'], op_b, scope_b)
            reads = service.blobs.reads
            historical = await service.blobs.get(row_b['pin'])
            assert historical == first and hashlib.sha256(historical).hexdigest() == row_b['pin']['sha256']
            # T9: the retired dependency of A resolves to nothing, without any byte read.
            assert await published(service, scope_a['call_id'], op_a, scope_a) is None
            # T8 defense in depth: B's call with A's scope is refused by the resolver.
            assert await published(service, scope_b['call_id'], op_b, scope_a) is None
            assert service.blobs.reads == reads + 1
            evidence['t7_t8_t9'] = True

            # Public delete is refused while B is active (early check, then trigger).
            refused = await public('delete', path=PATH)
            assert refused['status'] != 'ok' and (await ref())['deleted'] is False, refused
            await recovery.retire_dependencies(tenant_id='tenant', mission_id='mis_B',
                                               root_agent_id='ag_B', batch=10)

            # T10a: an uncommitted acquisition holds refs FOR SHARE and the pin lock.
            # A concurrent public delete waits, then the refs trigger refuses it.
            current = await ref()
            async with catalog.connection() as c:
                generation = await (await c.execute('SELECT id::text,pin,path FROM generations WHERE id=%s',
                                                    (current['generation'],))).fetchone()
            holder = await psycopg.AsyncConnection.connect(host=str(args.socket), dbname=args.database,
                                                           user=args.app, row_factory=dict_row)
            try:
                await holder.execute('SET search_path=tools_files,pg_catalog')
                scope_c = claims('mis_C', 'ag_C')
                await holder.execute('''INSERT INTO mission_file_dependencies(call_id,generation,
                    activity_operation_id,path,pin,served_revision,tenant_id,mission_id,root_agent_id)
                    VALUES(%s,%s,%s,%s,%s,%s,'tenant','mis_C','ag_C')''',
                    (scope_c['call_id'], generation['id'], str(uuid4()), PATH,
                     Jsonb(generation['pin']), current['revision']))
                deleting = asyncio.create_task(public('delete', path=PATH))
                await asyncio.sleep(0.5)
                assert not deleting.done()
                await holder.commit()
            finally:
                await holder.close()
            raced = await deleting
            save(args.output / 't10a-delete-after-acquisition.json',
                 {'delete': raced, 'ref': await ref(), 'open_operations': await open_operations()})
            assert raced['status'] == 'error' and raced['code'] == 'mission_dependency_active', raced
            assert 'operation_id' not in raced, raced  # réservation annulée : aucune opération à nommer
            assert (await ref())['deleted'] is False and await open_operations() == 0
            await recovery.retire_dependencies(tenant_id='tenant', mission_id='mis_C',
                                               root_agent_id='ag_C', batch=10)

            # T10c: an acquisition commits after reservation, before publication.
            original = service.publish
            scope_e = claims('mis_E', 'ag_E')

            async def publish_after_acquisition(*a, **kw):
                service.publish = original
                async with await psycopg.AsyncConnection.connect(host=str(args.socket), dbname=args.database,
                        user=args.app, autocommit=True) as late:
                    await late.execute('SET search_path=tools_files,pg_catalog')
                    await late.execute('''INSERT INTO mission_file_dependencies(call_id,generation,
                        activity_operation_id,path,pin,served_revision,tenant_id,mission_id,root_agent_id)
                        VALUES(%s,%s,%s,%s,%s,%s,'tenant','mis_E','ag_E')''',
                        (scope_e['call_id'], generation['id'], str(uuid4()), PATH,
                         Jsonb(generation['pin']), current['revision']))
                return await original(*a, **kw)
            service.publish = publish_after_acquisition
            late_oid = str(uuid4())
            late = await registry.call(operation='delete', operation_id=late_oid, path=PATH)
            async with catalog.connection() as c:
                journal = await (await c.execute('''SELECT o.phase,o.closed,o.publication_allowed,
                    array_agg(r.kind ORDER BY r.created_at,r.id) kinds FROM operations o
                    JOIN receipts r ON r.operation=o.id WHERE o.id=%s GROUP BY 1,2,3''', (late_oid,))).fetchone()
            save(args.output / 't10c-delete-refused-at-publication.json',
                 {'delete': late, 'journal': journal, 'ref': await ref(), 'open_operations': await open_operations()})
            assert service.publish == original
            assert late['status'] == 'error' and late['code'] == 'mission_dependency_active', late
            assert late['operation_id'] == late_oid, late
            # Rejeu du même identifiant : relu depuis le journal, même refus final, rien redispatché.
            replay = await registry.call(operation='delete', operation_id=late_oid, path=PATH)
            assert replay['code'] == 'mission_dependency_active', replay
            assert replay['reconciliation_state'] == 'not_required', replay
            assert journal['closed'] is True and journal['publication_allowed'] is False
            assert journal['phase'] == 'PUBLICATION_ARMED' and journal['kinds'][-2:] == [
                'dependency_refusal', 'dependency_refusal_closed']
            assert (await ref())['deleted'] is False and await open_operations() == 0
            await recovery.retire_dependencies(tenant_id='tenant', mission_id='mis_E',
                                               root_agent_id='ag_E', batch=10)

            # T10b: a committed delete makes generation_visible false; acquisition refuses, no bytes.
            deleted = await public('delete', path=PATH)
            assert deleted['status'] == 'ok', deleted
            reads = service.blobs.reads
            _, absent = await delegated_read(claims('mis_D', 'ag_D'))
            assert absent['effect_state'] == 'absent' and 'content' not in absent
            async with catalog.connection() as c:
                try:
                    async with catalog.transaction(c):
                        await c.execute('''INSERT INTO mission_file_dependencies(call_id,generation,
                            activity_operation_id,path,pin,served_revision,tenant_id,mission_id,root_agent_id)
                            VALUES(%s,%s,%s,%s,%s,%s,'tenant','mis_D','ag_D')''',
                            (str(uuid4()), generation['id'], str(uuid4()), PATH,
                             Jsonb(generation['pin']), current['revision']))
                    raise AssertionError('acquisition after deletion committed')
                except psycopg.Error:
                    pass
            rows = await dependencies()
            save(args.output / 't10b-acquisition-after-delete.json', rows)
            assert service.blobs.reads == reads and 'mis_D' not in {r['mission_id'] for r in rows}
            evidence['t10'] = True
    finally:
        current_token_info.reset(marker)
    return {**evidence, 'S3': 'explicit in-memory seam, not qualified', 'SQL': 'actual PG17, no business replay'}
