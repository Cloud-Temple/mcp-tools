"""#846 Access + Files : retrait d'une Mission close sur un PG17 isolé, deux domaines.

Lancé par le worker r3 après ``mission_dependencies.exercise`` (domaine Files
845+846) et l'installation d'un domaine Access neuf avec l'extension holds846
(``postgres_operator.install``). SQL, triggers, verrous et COMMIT sont réels. La
preuve Mission est remplacée par une identité fixe (pas de callback HTTPS) et S3
par une mémoire contrôlée : ni Vault, ni TLS, ni la vraie claim ne sont qualifiés.

Access   verify refuse un trigger désactivé ; purge 846 garde un call mission ;
         la purge v1 est refusée (grant absent, puis trigger pour l'owner).
P3+P7    A et B lisent le même objet ; claim de A ; cinq étapes. Calls, events et
         dépendances de A retirés ; B et le même mission_id sous un autre tenant
         intacts ; lecture historique de B positive, mêmes octets et SHA-256 ;
         enveloppe acceptée par la copie figée du validateur Mission 9ded160c.
P4       Un call encore dans son échéance : access-prepare n'écrit rien.
P2-2     Claim à root vide : refus s'il existe un call, sinon tout scellé à zéro.
P5a      Admission non commitée contre access-prepare : prepare attend, la compte,
         puis une admission après prepare est refusée.
P5b      Acquisition Files non commitée contre files-prepare : même schéma.
P6       Rejeu de chaque étape identique ; autre operation_id et autre révision
         refusés ; session tuée avant le COMMIT d'access-retire, reconcile, reprise.
"""
import asyncio
import hashlib
import importlib.util
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import patch
from uuid import uuid4

import psycopg
from psycopg import sql
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

SCHEMA = 'tools_files'
PATH = 'shared/retention-846.txt'
TENANT, OTHER_TENANT = 'tenant', 'tenant-x'


async def install_access(access):
    """Domaine Access neuf par le chemin produit (profil 846) ; rend la projection observée.

    verify() n'est pas appelé ici : le worker écrit d'abord la projection, pour que
    l'exécutant puisse figer CATALOG même si la prédiction diffère.
    """
    from src.mcp_tools.auth import postgres_operator as operator
    async with await psycopg.AsyncConnection.connect(host=str(access.socket), dbname=access.database, user='postgres',
                                                     autocommit=True, row_factory=dict_row) as c:
        async with c.transaction():
            await operator.install(c, access.owner, access.app, access.maintenance, retention=True)
        async with c.transaction():
            return await operator.projection_846(c)


async def exercise(args, access, save):
    from src.mcp_tools import retention_846 as cli
    from src.mcp_tools.auth import hub_activity as hub
    from src.mcp_tools.auth import postgres_operator as operator
    from src.mcp_tools.auth.context import current_access_operation, current_token_info
    from src.mcp_tools.config import Settings
    from src.mcp_tools.storage.files_postgres import Catalog
    from src.mcp_tools.storage.files_recovery import FileRecovery
    from src.mcp_tools.storage.files_service import FilesService
    from src.mcp_tools.storage.hub_files import published
    from src.mcp_tools.tools import files

    spec = importlib.util.spec_from_file_location('mission_receipt_9ded160c', args.source / 'tests/mission_receipt_9ded160c.py')
    frozen = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(frozen)
    evidence = {}

    # Domaine Access : verify exact, trigger désactivé refusé, puis rétabli.
    async with await psycopg.AsyncConnection.connect(host=str(access.socket), dbname=access.database, user='postgres',
                                                     autocommit=True, row_factory=dict_row) as c:
        async with c.transaction():
            await operator.verify(c, access.owner, access.app, access.maintenance, retention=True)
        await c.execute('ALTER TABLE tools_access.activity_calls DISABLE TRIGGER retention_846_admission')
        try:
            async with c.transaction():
                await operator.verify(c, access.owner, access.app, access.maintenance, retention=True)
            raise AssertionError('disabled admission trigger accepted')
        except ValueError as error:
            evidence['verify_disabled_trigger'] = str(error)
        await c.execute('ALTER TABLE tools_access.activity_calls ENABLE TRIGGER retention_846_admission')
        async with c.transaction():
            await operator.verify(c, access.owner, access.app, access.maintenance, retention=True)

    @asynccontextmanager
    async def connect_access(user):
        async with await psycopg.AsyncConnection.connect(host=str(access.socket), dbname=access.database, user=user,
                autocommit=True, row_factory=dict_row, options='-c statement_timeout=5000 -c lock_timeout=3000') as c:
            yield c

    async def owner(statement, params=()):
        async with connect_access('postgres') as c, c.transaction():
            await c.execute(sql.SQL('SET LOCAL ROLE {}').format(sql.Identifier(access.owner)))
            cursor = await c.execute(statement, params)
            return await cursor.fetchall() if cursor.description else None

    async def add_call(tenant, mission, root, *, age_days=400, category='mission', events=True):
        call = str(uuid4())
        if category == 'technical':
            await owner('''INSERT INTO tools_access.activity_calls(id,tool,trace_id,category,admission,created_at,expires_at)
                VALUES(%s,'files',%s,'technical','denied',clock_timestamp()-make_interval(days=>%s),
                clock_timestamp()-make_interval(days=>%s)+interval '720 hours')''', (call, str(uuid4()), age_days, age_days))
            return call
        await owner('''INSERT INTO tools_access.activity_calls(id,actor_id,tenant_id,service_id,tool,trace_id,operation_id,
            mission_id,root_agent_id,request_sha256,hub_binding_id,hub_binding_version,category,admission,created_at,expires_at)
            SELECT %s,%s,%s,'tools','files',%s,%s,%s,%s,%s,%s,1,'mission','admitted',s,s+interval '8760 hours'
            FROM (SELECT clock_timestamp()-make_interval(days=>%s) s) stamp''',
            (call, str(uuid4()), tenant, str(uuid4()), str(uuid4()), mission, root, 'f' * 64, str(uuid4()), age_days))
        if events:
            await owner("INSERT INTO tools_access.activity_events(id,call_id,phase,outcome) VALUES(%s,%s,'terminal','completed')",
                        (str(uuid4()), call))
        return call

    async def calls(tenant, mission):
        async with connect_access('postgres') as c:
            return [r['id'] for r in await (await c.execute(
                'SELECT id::text FROM tools_access.activity_calls WHERE tenant_id=%s AND mission_id=%s ORDER BY 1',
                (tenant, mission))).fetchall()]

    # Access, purge 846 : technique de 31 jours retiré, mission de 400 jours gardé.
    technical = await add_call(None, None, None, age_days=31, category='technical')
    kept = await add_call(TENANT, 'mis_RP', 'ag_RP')
    async with connect_access(access.maintenance) as c:
        purged = await (await c.execute('SELECT * FROM tools_access.purge_expired_846(500)')).fetchone()
        try:
            await c.execute('SELECT * FROM tools_access.purge_expired(500)')
            raise AssertionError('v1 purge granted to maintenance')
        except psycopg.errors.InsufficientPrivilege:
            pass
    try:
        await owner('SELECT * FROM tools_access.purge_expired(500)')
        raise AssertionError('v1 purge deleted a mission call')
    except psycopg.errors.RaiseException as error:
        assert 'retained until a verified retirement' in str(error)
    assert await calls(TENANT, 'mis_RP') == [kept] and purged['calls'] >= 1
    async with connect_access('postgres') as c:
        assert (await (await c.execute('SELECT count(*) n FROM tools_access.activity_calls WHERE id=%s',
                                       (technical,))).fetchone())['n'] == 0
    evidence['purge_846_keeps_mission'] = True

    # Domaine Files : même harnais que mission_dependencies.exercise.
    class FixtureCatalog(Catalog):
        @asynccontextmanager
        async def connection(self, *unused, **kwargs):
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
        def __init__(self):
            self.bytes = {}

        async def ready(self):
            pass

        async def put(self, key, body, sha):
            version = 'simulated-' + uuid4().hex
            self.bytes[(key, version)] = body
            return {'key': key, 'version_id': version, 'sha256': sha, 'size': len(body), 'etag': sha}

        async def get(self, pin):
            return self.bytes[(pin['key'], pin['version_id'])]

        async def marker(self, pin):
            return {'key': pin['key'], 'version_id': 'simulated-marker-' + uuid4().hex}

    class Registry:
        def tool(self):
            def keep(function):
                self.call = function
                return function
            return keep

    async with await psycopg.AsyncConnection.connect(host=str(args.socket), dbname=args.database, user='postgres',
                                                     autocommit=True, row_factory=dict_row) as c:
        identity_row = await (await c.execute('SELECT (pg_control_system()).system_identifier::text id,'
                                              '(pg_control_checkpoint()).timeline_id timeline')).fetchone()
    cfg = Settings(_env_file=None, files_metadata_backend='postgres', files_credentials_mode='direct',
        files_pg_schema=SCHEMA, files_pg_database=args.database, files_pg_owner=args.owner,
        files_pg_role=args.app, files_pg_system_identifier=identity_row['id'], files_pg_timeline=identity_row['timeline'],
        files_durability='local', files_recovery_enabled=True, files_mission_dependencies_enabled=True,
        files_recovery_maintenance_role=args.maintenance, files_s3_prefix='fixture846/',
        s3_endpoint_url='https://fixture.invalid', s3_access_key_id='synthetic',
        s3_secret_access_key='synthetic', s3_bucket_name='synthetic')
    service = object.__new__(FilesService)
    service.s, service.catalog, service.blobs, service.calls = cfg, FixtureCatalog(cfg), MemoryBlobs(), asyncio.Semaphore(4)
    maintenance = cfg.model_copy(update={'files_pg_role': args.maintenance})
    recovery = object.__new__(FileRecovery)
    recovery.settings, recovery.app_role, recovery.catalog = maintenance, args.app, FixtureCatalog(maintenance)
    registry = Registry()
    files.register(registry)

    async def delegated_read(tenant, mission, root):
        scope = {'tenant_id': tenant, 'mission_id': mission, 'root_agent_id': root, 'tool_id': 'files',
                 'call_id': str(uuid4())}
        delegation = hub.Delegation(None, 'fixture846', scope, cfg)
        delegation.consumed = True
        operation = str(uuid4())
        tokens = (hub.current_hub_context.set(delegation), current_access_operation.set(operation))
        try:
            result = await service.read_operations('read', {'path': PATH})
        finally:
            hub.current_hub_context.reset(tokens[0])
            current_access_operation.reset(tokens[1])
        return scope, operation, result

    async def read_refused(tenant, mission, root):
        try:
            _, _, result = await delegated_read(tenant, mission, root)
        except Exception as error:
            return type(error).__name__
        assert 'content' not in result, result
        return result.get('code') or result.get('effect_state') or 'no content'

    async def dependencies(mission):
        async with await psycopg.AsyncConnection.connect(host=str(args.socket), dbname=args.database,
                user=args.maintenance, autocommit=True, row_factory=dict_row) as c:
            return await (await c.execute('SELECT tenant_id,root_agent_id,state FROM tools_files.mission_file_dependencies '
                                          'WHERE mission_id=%s ORDER BY 1,2', (mission,))).fetchall()

    def claim(tenant, mission, root, *, revision=4, retain_days_ago=1):
        retain = datetime.now(timezone.utc) - timedelta(days=retain_days_ago)
        return {'owner': 'tools', 'tenant_id': tenant, 'mission_id': mission, 'root_agent_id': root,
                'claim_id': str(uuid4()), 'claim_revision': revision,
                'terminal_at': (retain - timedelta(days=365)).isoformat(), 'retain_until': retain.isoformat(),
                'manifest_sha256': hashlib.sha256(mission.encode()).hexdigest()}

    def folder(name):
        path = args.output / ('state-' + name)
        path.mkdir(mode=0o700)
        return path

    def core(identity, operation, state, access_factory=None):
        expires = datetime.now(timezone.utc) + timedelta(seconds=30)  # même borne que la preuve Mission
        return cli.Retention846(access=access_factory or (lambda: connect_access(access.maintenance)),
                                files=recovery.connection, recovery=recovery, live=lambda token: (identity, expires),
                                state_dir=state, operation_id=operation)

    async def step(identity, operation, state, name, batch=500, access_factory=None):
        return await cli.run(core(identity, operation, state, access_factory), SimpleNamespace(step=name, batch=batch),
                             'fixture-proof')

    async def refused(coroutine, *errors):
        try:
            await coroutine
        except (cli.Refused, ValueError, psycopg.Error, *errors) as error:
            return type(error).__name__
        raise AssertionError('step accepted')

    marker = current_token_info.set({'permissions': ['admin'], 'credential_binding': 'fixture846-public'})
    try:
        with patch('src.mcp_tools.tools.files.get_settings', return_value=cfg), \
             patch('src.mcp_tools.auth.access_runtime.get_settings', return_value=cfg), \
             patch('src.mcp_tools.storage.files_service.get_files_service', return_value=service):
            written = await registry.call(operation='write', operation_id=str(uuid4()), path=PATH, content='retention bytes')
            assert written['status'] == 'ok', written

            # P3 + P7 : A, B et le même mission_id que A sous un autre tenant.
            a_calls = [await add_call(TENANT, 'mis_RA', 'ag_RA') for _ in range(3)]
            b_calls = [await add_call(TENANT, 'mis_RB', 'ag_RB')]
            x_calls = [await add_call(OTHER_TENANT, 'mis_RA', 'ag_RA')]
            scope_a, op_a, read_a = await delegated_read(TENANT, 'mis_RA', 'ag_RA')
            scope_b, op_b, read_b = await delegated_read(TENANT, 'mis_RB', 'ag_RB')
            await delegated_read(OTHER_TENANT, 'mis_RA', 'ag_RA')
            assert read_a['content'] == read_b['content'] == 'retention bytes'
            identity_a, operation_a, state_a = claim(TENANT, 'mis_RA', 'ag_RA'), str(uuid4()), folder('A')
            results = {}
            results['access-prepare'] = await step(identity_a, operation_a, state_a, 'access-prepare')
            # P5b' : après files-prepare, aucune nouvelle acquisition pour A.
            results['files-prepare'] = await step(identity_a, operation_a, state_a, 'files-prepare')
            evidence['p3_read_after_files_prepare'] = await read_refused(TENANT, 'mis_RA', 'ag_RA')
            batches = []
            while True:
                batches.append(await step(identity_a, operation_a, state_a, 'access-retire', batch=2))
                if not batches[-1]['has_more']:
                    break
            assert [b['has_more'] for b in batches] == [True, False] and batches[-1]['state'] == 'sealed'
            results['files-retire'] = await step(identity_a, operation_a, state_a, 'files-retire')
            results['receipt'] = await step(identity_a, operation_a, state_a, 'receipt')
            envelope = cli.load(state_a, 'envelope.json')
            frozen.validate_owner_receipt(envelope, frozen.RetentionClaim(**identity_a))
            expected_calls = hashlib.sha256('\n'.join(sorted(a_calls)).encode()).hexdigest()
            assert envelope['references'][0] == {'kind': 'tools_activity_calls', 'id': 'sha256:' + expected_calls,
                                                 'revision': 3, 'root_agent_id': 'ag_RA'}
            assert envelope['references'][2]['revision'] == 1
            assert await calls(TENANT, 'mis_RA') == [] and await calls(TENANT, 'mis_RB') == b_calls
            assert await calls(OTHER_TENANT, 'mis_RA') == x_calls
            assert [(r['tenant_id'], r['state']) for r in await dependencies('mis_RA')] == [
                (TENANT, 'retired'), (OTHER_TENANT, 'active')]
            assert [r['state'] for r in await dependencies('mis_RB')] == ['active']
            row_b = await published(service, scope_b['call_id'], op_b, scope_b)
            historical = await service.blobs.get(row_b['pin'])
            assert historical == read_b['content'].encode()
            assert hashlib.sha256(historical).hexdigest() == row_b['pin']['sha256']
            assert await published(service, scope_a['call_id'], op_a, scope_a) is None
            save(args.output / 'p3-envelope.json', envelope)
            evidence['p3_p7'] = {'batches': len(batches), 'references': len(envelope['references'])}

            # P6 : rejeu identique, autre opération, autre révision.
            # Un rejeu rend l'état stocké (scellé), sans nouvel effet ni nouvelle empreinte.
            sealed_access, sealed_files = batches[-1], results['files-retire']
            for name in ('access-prepare', 'files-prepare', 'access-retire', 'files-retire'):
                again = await step(identity_a, operation_a, state_a, name)
                assert again['state'] == 'sealed' and again['operation_id'] == operation_a, (name, again)
                if name.startswith('access'):
                    assert again['calls_sha256'] == sealed_access['calls_sha256'], (name, again)
                else:
                    assert again['dependencies_sha256'] == sealed_files['dependencies_sha256'], (name, again)
            assert await step(identity_a, operation_a, state_a, 'receipt') == results['receipt']
            assert cli.load(state_a, 'envelope.json') == envelope
            other = await refused(step(identity_a, str(uuid4()), folder('A-other'), 'access-prepare'))
            revised = {**identity_a, 'claim_revision': 5}
            revision = await refused(step(revised, operation_a, folder('A-revision'), 'access-prepare'))
            evidence['p6_replay'] = {'other_operation': other, 'other_revision': revision}

            # P4 : un call encore dans son échéance, rien n'est écrit.
            await add_call(TENANT, 'mis_RC', 'ag_RC', age_days=0)
            identity_c, operation_c = claim(TENANT, 'mis_RC', 'ag_RC'), str(uuid4())
            early = await step(identity_c, operation_c, folder('C'), 'access-prepare')
            async with connect_access(access.maintenance) as c, c.transaction():
                status = (await (await c.execute('SELECT tools_access.mission_retirement_status(%s,%s,%s) r',
                                                 (operation_c, TENANT, 'mis_RC'))).fetchone())['r']
            assert early['state'] == 'not_yet_eligible' and status['state'] == 'absent', (early, status)
            evidence['p4_not_yet_eligible'] = early['eligible_after']

            # P2-2 : claim à root vide. Un call sur le scope : refus, rien d'écrit.
            await add_call(TENANT, 'mis_RG', 'ag_RG')
            identity_g = claim(TENANT, 'mis_RG', '')
            evidence['p2_2_root_empty_with_call'] = await refused(
                step(identity_g, str(uuid4()), folder('G'), 'access-prepare'))
            assert len(await calls(TENANT, 'mis_RG')) == 1
            # Aucun call ni dépendance : cinq étapes, tout scellé à zéro, reçu accepté.
            identity_h, operation_h, state_h = claim(TENANT, 'mis_RH', ''), str(uuid4()), folder('H')
            for name in ('access-prepare', 'files-prepare', 'access-retire', 'files-retire', 'receipt'):
                await step(identity_h, operation_h, state_h, name)
            empty = cli.load(state_h, 'envelope.json')
            frozen.validate_owner_receipt(empty, frozen.RetentionClaim(**identity_h))
            assert [(r['revision'], r['root_agent_id']) for r in empty['references']] == [(0, '')] * 3
            assert {r['id'] for r in empty['references']} == {'sha256:' + hashlib.sha256(b'').hexdigest()}
            evidence['p2_2_root_empty_sealed_at_zero'] = True

            # P5a : admission non commitée contre access-prepare.
            await add_call(TENANT, 'mis_RE', 'ag_RE')
            holder = await psycopg.AsyncConnection.connect(host=str(access.socket), dbname=access.database, user='postgres',
                                                           row_factory=dict_row)
            try:
                await holder.execute(sql.SQL('SET ROLE {}').format(sql.Identifier(access.owner)))
                await holder.execute('''INSERT INTO tools_access.activity_calls(id,actor_id,tenant_id,service_id,tool,
                    trace_id,mission_id,root_agent_id,request_sha256,hub_binding_id,hub_binding_version,category,admission,
                    created_at,expires_at) SELECT gen_random_uuid(),gen_random_uuid(),%s,'tools','files',gen_random_uuid(),
                    'mis_RE','ag_RE',%s,gen_random_uuid(),1,'mission','admitted',s,s+interval '8760 hours'
                    FROM (SELECT clock_timestamp()-interval '400 days' s) stamp''', (TENANT, 'f' * 64))
                identity_e, operation_e = claim(TENANT, 'mis_RE', 'ag_RE'), str(uuid4())
                preparing = asyncio.create_task(step(identity_e, operation_e, folder('E'), 'access-prepare'))
                await asyncio.sleep(0.5)
                assert not preparing.done()
                await holder.commit()
            finally:
                await holder.close()
            prepared = await preparing
            assert prepared['state'] == 'prepared' and prepared['pending_calls'] == 2, prepared
            late_admission = await refused(add_call(TENANT, 'mis_RE', 'ag_RE'), psycopg.errors.InsufficientPrivilege)
            evidence['p5a_admission'] = {'pending_calls': prepared['pending_calls'], 'after_prepare': late_admission}

            # P5b : acquisition Files non commitée contre files-prepare.
            await add_call(TENANT, 'mis_RF', 'ag_RF')
            identity_f, operation_f, state_f = claim(TENANT, 'mis_RF', 'ag_RF'), str(uuid4()), folder('F')
            await step(identity_f, operation_f, state_f, 'access-prepare')
            async with service.catalog.connection() as c:
                generation = await (await c.execute('SELECT g.id::text,g.pin,r.revision FROM refs r '
                                                    'JOIN generations g ON g.id=r.generation WHERE r.path=%s', (PATH,))).fetchone()
            holder = await psycopg.AsyncConnection.connect(host=str(args.socket), dbname=args.database, user=args.app,
                                                           row_factory=dict_row)
            try:
                await holder.execute('SET search_path=tools_files,pg_catalog')
                await holder.execute('''INSERT INTO mission_file_dependencies(call_id,generation,activity_operation_id,
                    path,pin,served_revision,tenant_id,mission_id,root_agent_id) VALUES(%s,%s,%s,%s,%s,%s,%s,'mis_RF','ag_RF')''',
                    (str(uuid4()), generation['id'], str(uuid4()), PATH, Jsonb(generation['pin']), generation['revision'], TENANT))
                closing = asyncio.create_task(step(identity_f, operation_f, state_f, 'files-prepare'))
                await asyncio.sleep(0.5)
                assert not closing.done()
                await holder.commit()
            finally:
                await holder.close()
            assert (await closing)['state'] == 'prepared'
            evidence['p5b_read_after_files_prepare'] = await read_refused(TENANT, 'mis_RF', 'ag_RF')
            assert [r['state'] for r in await dependencies('mis_RF')] == ['active']

            # P6 : session tuée avant le COMMIT d'access-retire ; reconcile ; reprise.
            @asynccontextmanager
            async def killed_before_commit():
                async with connect_access(access.maintenance) as c:
                    pid = (await (await c.execute('SELECT pg_backend_pid() p')).fetchone())['p']
                    original = c.execute

                    async def execute(query, params=None, **kw):
                        if query == 'COMMIT':
                            async with connect_access('postgres') as killer:
                                await killer.execute('SELECT pg_terminate_backend(%s)', (pid,))
                            await asyncio.sleep(0.2)
                        return await original(query, params, **kw)
                    c.execute = execute
                    yield c
            unknown = await refused(step(identity_f, operation_f, state_f, 'access-retire',
                                         access_factory=killed_before_commit), cli.Unknown)
            assert unknown == 'Unknown' and (state_f / 'access-retire.unknown.json').exists()
            blocked = await refused(step(identity_f, operation_f, state_f, 'files-retire'))
            reconciled = await step(identity_f, operation_f, state_f, 'reconcile')
            assert reconciled['access']['state'] == 'prepared' and reconciled['next_step'] == 'access-retire', reconciled
            resumed = await step(identity_f, operation_f, state_f, 'access-retire')
            assert resumed['state'] == 'sealed' and await calls(TENANT, 'mis_RF') == []
            await step(identity_f, operation_f, state_f, 'files-retire')
            evidence['p6_unknown'] = {'blocked': blocked, 'next_step': reconciled['next_step']}
    finally:
        current_token_info.reset(marker)
    return evidence
