"""#846 Tools : dépendance Files d'une lecture Mission, résolveur hub et gardes owner.

Seams réelles (middleware hub, run_durable_tool, FilesService, published,
route /internal/hub/tools-files). Le catalogue en mémoire reproduit les seules
gardes SQL utiles (trigger d'acquisition, generation_visible, refus de
suppression) ; la preuve PG17 réelle est dans tests/postgres_files/mission_dependencies.py.
"""
import asyncio
import base64
import copy
import hashlib
import json
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from types import SimpleNamespace
from typing import ClassVar
from uuid import UUID, uuid4

import pytest
from test_hub_activity_31 import Client, Store, cfg, issuer
from test_hub_files_843 import FileStore, request

from src.mcp_tools.auth import access_runtime as runtime
from src.mcp_tools.auth import hub_activity as hub
from src.mcp_tools.auth.context import current_access_operation, current_token_info
from src.mcp_tools.storage import hub_files
from src.mcp_tools.storage.files_credentials import StorageUnavailable
from src.mcp_tools.storage.files_postgres import CommitUnknown, Conflict
from src.mcp_tools.storage.files_service import FilesService

PATH = 'shared/report.txt'
CLAIMS = dict(tenant_id='tenant', mission_id='mis_1', root_agent_id='ag_root')


class Result:
    def __init__(self, rows):
        self.rows = rows

    async def fetchall(self):
        return self.rows

    async def fetchone(self):
        return self.rows[0] if self.rows else None


class Memory:
    """Catalogue Files en mémoire : refs, générations, retraits 845 et dépendances 846."""

    def __init__(self, content=b'shared bytes v1'):
        self.content = content
        self.generation = str(uuid4())
        self.pin = dict(key='files-generations/' + self.generation, version_id='v-1', etag='e-1',
                        size=len(content), sha256=hashlib.sha256(content).hexdigest())
        self.refs = {PATH: dict(path=PATH, revision=3, generation=UUID(self.generation),
                                operation=UUID(str(uuid4())), deleted=False)}
        self.generations = {self.generation: dict(path=PATH, pin=copy.deepcopy(self.pin))}
        self.retired = set()
        self.deps = {}
        self.published = {}
        self.queries = []
        self.fail_commit = False
        self.overwrite = None

    @asynccontextmanager
    async def connection(self):
        yield self

    @asynccontextmanager
    async def transaction(self, c):
        before = copy.deepcopy(self.deps)
        try:
            yield
        except BaseException:
            self.deps = before
            raise
        if self.fail_commit:
            self.deps = before
            raise CommitUnknown('COMMIT/barrière non confirmés ; inspection requise')

    def visible(self, generation):
        g = self.generations.get(generation)
        r = self.refs.get(g['path']) if g else None
        return bool(r and not r['deleted'] and generation not in self.retired)

    async def one(self, c, query, args=()):
        return await (await self.execute(query, args)).fetchone()

    async def execute(self, query, args=()):
        q = ' '.join(query.split())
        self.queries.append(q)
        if q.startswith('INSERT INTO mission_file_dependencies'):
            call, generation, operation, path, pin, revision, tenant, mission, root, binding = args
            g = self.generations.get(generation)
            # guard_file_dependency : chemin vivant, pin servi exact, génération visible.
            if g is None or g['path'] != path or g['pin'] != pin.obj or not self.visible(generation):
                raise StorageUnavailable('dependency generation is not live')
            row = dict(call_id=UUID(call), generation=UUID(generation), activity_operation_id=UUID(operation),
                       path=path, pin=copy.deepcopy(pin.obj), served_revision=revision, tenant_id=tenant,
                       mission_id=mission, root_agent_id=root, credential_binding=binding, state='active',
                       revision=1)
            if self.overwrite:
                row.update(self.overwrite)
            self.deps.setdefault((call, generation), row)
            return Result([])
        if q.startswith('SELECT * FROM mission_file_dependencies WHERE call_id'):
            row = self.deps.get(tuple(args))
            return Result([copy.deepcopy(row)] if row else [])
        if 'FROM operations o JOIN generations g' in q:
            row = self.published.get(tuple(args))
            return Result([copy.deepcopy(row)] if row else [])
        if 'FROM mission_file_dependencies d JOIN generations g' in q:
            call, operation, tenant, mission, root = args
            rows = []
            for (dep_call, generation), d in sorted(self.deps.items()):
                g = self.generations[generation]
                if (dep_call == call and (None if d['activity_operation_id'] is None
                                          else str(d['activity_operation_id'])) == operation
                        and d['state'] == 'active' and (d['tenant_id'], d['mission_id'], d['root_agent_id'])
                        == (tenant, mission, root) and g['path'] == d['path'] and g['pin'] == d['pin']
                        and self.visible(generation)):
                    rows.append(dict(path=d['path'], revision=d['served_revision'],
                                     generation=UUID(generation), pin=copy.deepcopy(g['pin'])))
            return Result([{**rows[0], 'matches': len(rows)}] if rows else [])
        if q.startswith('SELECT EXISTS(SELECT 1 FROM mission_file_dependencies WHERE path'):
            return Result([dict(protected=any(d['path'] == args[0] and d['state'] == 'active'
                                              for d in self.deps.values()))])
        if q.startswith("SELECT id,pin,manifest FROM generations WHERE path=%s AND pin->>'version_id'=%s"):
            return Result([dict(id=UUID(g), pin=copy.deepcopy(v['pin']), manifest=[])
                           for g, v in self.generations.items() if v['path'] == args[0]
                           and v['pin']['version_id'] == args[1] and self.visible(g)])
        if q.startswith('SELECT') and 'mission_file_dependencies' not in q:
            return Result([])  # list, metadata_batch, versions : aucune ligne utile ici
        raise AssertionError('SQL inattendu : ' + q[:80])


class MemoryBlobs:
    def __init__(self, memory):
        self.memory, self.reads, self.on_hub_read = memory, 0, None

    async def get(self, pin):
        assert pin == self.memory.pin
        self.reads += 1
        return self.memory.content

    async def get_hub(self, pin, check):
        await check()
        data = await self.get(pin)
        if self.on_hub_read:
            self.on_hub_read()
        return data


def service(memory, enabled=True):
    files = object.__new__(FilesService)
    files.s = SimpleNamespace(tool_max_output_chars=50000, files_recovery_enabled=True,
                              files_mission_dependencies_enabled=enabled)
    files.catalog = memory
    files.blobs = MemoryBlobs(memory)

    async def ref(c, path, lock=False):
        r = memory.refs.get(path)
        if r is None:
            return None
        g = memory.generations.get(str(r['generation'])) if r['generation'] else None
        return {**copy.deepcopy(r), 'pin': copy.deepcopy(g['pin']) if g else None, 'manifest': []}
    files.ref = ref
    return files


def delegated(call=None, *, consumed=True, operation=None, binding='tools-token-v1:' + 'a' * 64):
    """Contexte posé par la route /mcp puis run_durable_tool, sans réseau."""
    delegation = hub.Delegation(None, 'signed', dict(CLAIMS, tool_id='files', call_id=call or str(uuid4())), cfg())
    delegation.consumed = consumed
    return delegation, operation or str(uuid4()), binding


@asynccontextmanager
async def under(delegation, operation, binding):
    tokens = (hub.current_hub_context.set(delegation), current_access_operation.set(operation),
              current_token_info.set(dict(Store().info, credential_binding=binding)))
    try:
        yield
    finally:
        hub.current_hub_context.reset(tokens[0])
        current_access_operation.reset(tokens[1])
        current_token_info.reset(tokens[2])


@pytest.fixture
def access(monkeypatch):
    store = Store()
    monkeypatch.setattr(runtime, 'get_settings', cfg)
    monkeypatch.setattr(runtime, 'get_access_store', lambda: store)
    return store


def mcp_read(monkeypatch, store, files, arguments):
    """T1 : vraie route /mcp déléguée, AuthMiddleware puis run_durable_tool."""
    from src.mcp_tools.auth import middleware as auth
    from src.mcp_tools.auth.middleware import AuthMiddleware

    monkeypatch.setattr(hub.ssl, 'create_default_context', lambda **kwargs: object())
    monkeypatch.setattr(auth, 'get_settings', cfg)
    body = json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': 'tools/call',
                       'params': {'name': 'files', 'arguments': {'operation': 'read', 'path': PATH}}}).encode()
    token, keys, claims = issuer(body, 'tools.activity.context')
    client, sent, results = Client(keys), [], []

    async def endpoint(scope, receive, send):
        await receive()
        result = await runtime.run_durable_tool('files', files.read_operations, ('read', arguments), {})
        results.append(result)
        await hub.response(send, 200, 'TEST_TOOL')

    async def scenario():
        async def receive():
            return {'type': 'http.request', 'body': body, 'more_body': False}

        async def send(value):
            sent.append(value)
        middleware = hub.HubActivityMiddleware(AuthMiddleware(endpoint), cfg(),
                                               client_factory=lambda **kwargs: client, store_factory=lambda: store)
        await middleware({'type': 'http', 'path': '/mcp', 'method': 'POST', 'headers': [
            (b'authorization', b'Bearer local-opaque'), (b'x-tools-activity-context', token.encode())]}, receive, send)
    asyncio.run(scenario())
    assert sent[0]['status'] == 200
    return claims, results[0]


def test_t1_read_only_reader_b_historical_consultation_is_available(monkeypatch, access):
    memory = Memory()
    files = service(memory)
    claims, result = mcp_read(monkeypatch, access, files, {'path': PATH})
    assert result['content'] == memory.content.decode() and result['activity_state'] == 'confirmed'
    admitted = access.admissions[0]
    assert admitted['call_id'] == claims['call_id'] and admitted['operation_id']
    # Une dépendance exacte, aucune opération ni reçu Files inventés pour une lecture.
    (dep,) = memory.deps.values()
    assert (str(dep['call_id']), str(dep['generation']), str(dep['activity_operation_id'])) == (
        claims['call_id'], memory.generation, admitted['operation_id'])
    assert (dep['tenant_id'], dep['mission_id'], dep['root_agent_id'], dep['pin']) == (
        'tenant', 'mis_1', 'ag_root', memory.pin)
    assert not [q for q in memory.queries if q.startswith(('INSERT INTO operations', 'INSERT INTO receipts'))]
    insert = memory.queries.index(next(q for q in memory.queries if q.startswith('INSERT INTO mission')))
    assert insert < len(memory.queries) and files.blobs.reads == 1

    monkeypatch.setattr(hub_files, 'get_files_service', lambda: files)
    store = FileStore(claims['call_id'], admitted['operation_id'])
    body = dict(mission_id='mis_1', root_agent_id='ag_root', call_ids=[claims['call_id']])
    code, data = asyncio.run(request(store, body, monkeypatch))
    item = data['files'][0]
    assert code == 200 and item['reference_state'] == 'available'
    assert (item['generation'], item['version_id'], item['revision']) == (memory.generation, 'v-1', 3)
    assert 'files-generations/' not in json.dumps(data)
    code, data = asyncio.run(request(store, dict(body, content=True, offset=0, limit=100), monkeypatch))
    content = base64.b64decode(data['files'][0]['content_base64'])
    assert code == 200 and content == memory.content
    assert hashlib.sha256(content).hexdigest() == memory.pin['sha256']


def test_t1_without_the_extension_the_same_reader_stays_unavailable(monkeypatch, access):
    """Défaut d'origine (main 843) et profil fermé : aucune dépendance, unavailable."""
    memory = Memory()
    files = service(memory, enabled=False)
    claims, result = mcp_read(monkeypatch, access, files, {'path': PATH})
    assert result['content'] == memory.content.decode() and memory.deps == {}
    monkeypatch.setattr(hub_files, 'get_files_service', lambda: files)
    store = FileStore(claims['call_id'], access.admissions[0]['operation_id'])
    code, data = asyncio.run(request(store, dict(mission_id='mis_1', root_agent_id='ag_root',
                                                 call_ids=[claims['call_id']]), monkeypatch))
    assert code == 200 and data['files'] == [dict(call_id=claims['call_id'], reference_state='unavailable')]


def dependency(memory, call, operation, **changes):
    row = dict(call_id=UUID(call), generation=UUID(memory.generation),
               activity_operation_id=None if operation is None else UUID(operation), path=PATH,
               pin=copy.deepcopy(memory.pin), served_revision=3, tenant_id='tenant', mission_id='mis_1',
               root_agent_id='ag_root', credential_binding=None, state='active', revision=1)
    row.update(changes)
    memory.deps[(call, memory.generation)] = row
    return row


def test_t2_resolver_with_null_operation_uses_only_an_exact_dependency():
    async def scenario():
        memory = Memory()
        files = service(memory)
        call = str(uuid4())
        assert await hub_files.published(files, call, None, CLAIMS) is None
        dependency(memory, call, None)
        row = await hub_files.published(files, call, None, CLAIMS)
        assert row == dict(path=PATH, revision=3, generation=UUID(memory.generation), pin=memory.pin)
        # Un operation_id réel ne retrouve pas une ligne posée avec NULL, et inversement.
        assert await hub_files.published(files, call, str(uuid4()), CLAIMS) is None
        # Sans claims (appelant 843) ou profil fermé : comportement 843 inchangé.
        assert await hub_files.published(files, call, None) is None
        files.s.files_mission_dependencies_enabled = False
        assert await hub_files.published(files, call, None, CLAIMS) is None

    asyncio.run(scenario())


@pytest.mark.parametrize('op', ['list', 'info', 'metadata_batch', 'versions'])
def test_t3_metadata_operations_never_create_a_dependency(op):
    async def scenario():
        memory = Memory()
        files = service(memory)
        delegation, operation, binding = delegated()

        async def refresh(tool=None):
            return current_token_info.get()
        files.current_read = lambda c, previous: refresh()
        async with under(delegation, operation, binding):
            result = await files.read_operations(op, {'path': PATH, 'paths': [PATH], 'max_keys': 5})
        assert result['status'] == 'ok' and memory.deps == {} and files.blobs.reads == 0
        assert not [q for q in memory.queries if 'mission_file_dependencies' in q]
        assert await hub_files.published(files, delegation.claims['call_id'], operation, CLAIMS) is None

    asyncio.run(scenario())


def test_t4_two_sources_or_two_dependencies_are_ambiguous():
    async def scenario():
        memory = Memory()
        files = service(memory)
        call, operation = str(uuid4()), str(uuid4())
        dependency(memory, call, operation)
        assert (await hub_files.published(files, call, operation, CLAIMS))['generation'] == UUID(memory.generation)
        memory.published[(operation, call)] = dict(path=PATH, revision=3, generation=UUID(memory.generation),
                                                   pin=memory.pin)
        assert await hub_files.published(files, call, operation, CLAIMS) is None
        memory.published.clear()
        other = str(uuid4())
        memory.generations[other] = dict(path=PATH, pin=dict(memory.pin, version_id='v-0'))
        memory.deps[(call, other)] = dict(memory.deps[(call, memory.generation)], generation=UUID(other),
                                          pin=dict(memory.pin, version_id='v-0'))
        assert await hub_files.published(files, call, operation, CLAIMS) is None

    asyncio.run(scenario())


@pytest.mark.parametrize('scope', [dict(tenant_id='other'), dict(mission_id='mis_2'), dict(root_agent_id='ag_x')])
def test_t8_resolver_refuses_claims_of_another_scope(scope):
    async def scenario():
        memory = Memory()
        files = service(memory)
        call, operation = str(uuid4()), str(uuid4())
        dependency(memory, call, operation)
        assert await hub_files.published(files, call, operation, dict(CLAIMS, **scope)) is None

    asyncio.run(scenario())


@pytest.mark.parametrize('retired', ['dependency', 'generation', 'ref'])
def test_t9_retired_pin_or_dependency_is_unavailable_without_bytes(monkeypatch, retired):
    async def scenario():
        memory = Memory()
        files = service(memory)
        call, operation = str(uuid4()), str(uuid4())
        dependency(memory, call, operation, state='retired' if retired == 'dependency' else 'active')
        if retired == 'generation':
            memory.retired.add(memory.generation)
        if retired == 'ref':
            memory.refs[PATH]['deleted'] = True
        monkeypatch.setattr(hub_files, 'get_files_service', lambda: files)
        code, data = await request(FileStore(call, operation), dict(
            mission_id='mis_1', root_agent_id='ag_root', call_ids=[call], content=True, offset=0, limit=10),
            monkeypatch)
        assert code == 200 and data['files'] == [dict(call_id=call, reference_state='unavailable')]
        assert files.blobs.reads == 0

    asyncio.run(scenario())


def test_t5_resolver_change_during_content_read_publishes_nothing(monkeypatch):
    async def scenario():
        memory = Memory()
        files = service(memory)
        call, operation = str(uuid4()), str(uuid4())
        row = dependency(memory, call, operation)
        files.blobs.on_hub_read = lambda: row.update(state='retired')
        monkeypatch.setattr(hub_files, 'get_files_service', lambda: files)
        code, data = await request(FileStore(call, operation), dict(
            mission_id='mis_1', root_agent_id='ag_root', call_ids=[call], content=True, offset=0, limit=10),
            monkeypatch)
        assert code == 403 and 'files' not in data and 'shared bytes' not in json.dumps(data)
        assert files.blobs.reads == 1

    asyncio.run(scenario())


@pytest.mark.parametrize('failure', ['not-live', 'commit', 'divergent', 'retired-row'])
def test_t6_unconfirmed_acquisition_delivers_no_content(failure):
    async def scenario():
        memory = Memory()
        files = service(memory)
        delegation, operation, binding = delegated()
        if failure == 'not-live':
            memory.retired.add(memory.generation)
        if failure == 'commit':
            memory.fail_commit = True
        if failure == 'divergent':
            memory.overwrite = dict(activity_operation_id=uuid4())
        if failure == 'retired-row':
            memory.overwrite = dict(state='retired')
        async with under(delegation, operation, binding):
            with pytest.raises(StorageUnavailable):
                await files.read_operations('read', {'path': PATH})
        assert files.blobs.reads == 0
        if failure in {'not-live', 'commit'}:
            assert memory.deps == {}

    asyncio.run(scenario())


def test_acquisition_requires_a_consumed_admission_and_skips_standalone():
    async def scenario():
        memory = Memory()
        files = service(memory)

        async def no_refresh(c, previous):
            return None
        files.current_read = no_refresh
        # Standalone : aucune délégation, aucune dépendance, lecture inchangée.
        assert (await files.read_operations('read', {'path': PATH}))['content'] == memory.content.decode()
        assert memory.deps == {}
        for delegation, operation, binding in (delegated(consumed=False), delegated()[:1] + (None, 'x')):
            async with under(delegation, operation, binding):
                with pytest.raises(Conflict, match="Origine d'admission"):
                    await files.read_operations('read', {'path': PATH})
        assert memory.deps == {} and files.blobs.reads == 1

    asyncio.run(scenario())


def test_dependency_values_come_from_served_row_and_claims_not_arguments():
    async def scenario():
        memory = Memory()
        files = service(memory)

        async def no_refresh(c, previous):
            return None
        files.current_read = no_refresh
        delegation, operation, binding = delegated()
        async with under(delegation, operation, binding):
            result = await files.read_operations('read', {'path': PATH, 'version_id': 'v-1',
                                                          'mission_id': 'mis_forged', 'tenant_id': 'forged'})
        (dep,) = memory.deps.values()
        assert result['version_id'] == 'v-1' and dep['mission_id'] == 'mis_1' and dep['tenant_id'] == 'tenant'
        assert dep['credential_binding'] == binding and dep['served_revision'] == 3

    asyncio.run(scenario())


@pytest.mark.parametrize('case', ['diff-missing', 'if-match'])
def test_refused_reads_do_not_acquire(case):
    async def scenario():
        memory = Memory()
        files = service(memory)
        delegation, operation, binding = delegated()
        args = ({'path': PATH, 'path2': 'absent.txt'} if case == 'diff-missing'
                else {'path': PATH, 'if_match': 'other-etag'})
        async with under(delegation, operation, binding):
            with pytest.raises(Conflict):
                await files.read_operations('diff' if case == 'diff-missing' else 'read', args)
        assert memory.deps == {} and files.blobs.reads == 0

    asyncio.run(scenario())


def test_diff_acquires_both_served_generations_and_stays_ambiguous_for_the_hub():
    async def scenario():
        memory = Memory()
        files = service(memory)
        second = str(uuid4())
        pin2 = dict(memory.pin, key='files-generations/' + second, version_id='v-2')
        memory.generations[second] = dict(path='other.txt', pin=pin2)
        memory.refs['other.txt'] = dict(path='other.txt', revision=1, generation=UUID(second),
                                        operation=UUID(str(uuid4())), deleted=False)

        async def get(pin):
            return memory.content
        files.blobs.get = get

        async def no_refresh(c, previous):
            return None
        files.current_read = no_refresh
        delegation, operation, binding = delegated()
        async with under(delegation, operation, binding):
            result = await files.read_operations('diff', {'path': PATH, 'path2': 'other.txt'})
        assert result['status'] == 'ok' and len(memory.deps) == 2
        assert await hub_files.published(files, delegation.claims['call_id'], operation, CLAIMS) is None

    asyncio.run(scenario())


def test_public_delete_is_refused_while_a_mission_dependency_is_active():
    async def scenario():
        memory = Memory()
        files = service(memory)
        dependency(memory, str(uuid4()), str(uuid4()))
        with pytest.raises(Conflict, match='dépendance Mission active'):
            await files.prepare('delete', {'path': PATH})
        for row in memory.deps.values():
            row['state'] = 'retired'
        expected, _body, manifest = await files.prepare('delete', {'path': PATH})
        assert expected == 3 and manifest[0]['generation'] == memory.generation

    asyncio.run(scenario())


class RootConnection:
    def __init__(self, roots, generations):
        self.roots, self.generations, self.queries = roots, generations, []

    async def execute(self, query, args=()):
        self.queries.append(query)
        if 'UNION ALL' in query:
            return Result([{'sources': s} for s in self.roots])
        return Result([self.generations[str(args[0])]] if str(args[0]) in self.generations else [])


@pytest.mark.parametrize('enabled', [False, True])
def test_collect_treats_an_active_dependency_as_a_root(enabled):
    from src.mcp_tools.storage.files_recovery import FileRecovery

    async def scenario():
        generation = str(uuid4())
        pin = dict(key='files-generations/' + generation, version_id='v-1', sha256='a' * 64, size=4)
        entry = dict(generation=generation, path=PATH, pin=pin)
        connection = RootConnection([[entry]] if enabled else [],
                                    {generation: dict(id=generation, path=PATH, pin=pin, manifest=[])})
        protected = await FileRecovery.referenced(connection, pin, dependencies=enabled)
        assert protected is enabled
        assert ('mission_file_dependencies' in connection.queries[0]) is enabled
        assert "d.state='active'" in connection.queries[0] or not enabled

    asyncio.run(scenario())


def recovery(enabled=True):
    from src.mcp_tools.storage.files_recovery import FileRecovery

    rec = object.__new__(FileRecovery)
    rec.settings = SimpleNamespace(files_mission_dependencies_enabled=enabled)
    rec.catalog = Memory()
    rec.seen = []

    class Connection:
        async def execute(self, query, args=()):
            rec.seen.append((' '.join(query.split()), args))
            if query.startswith('SET TRANSACTION'):
                return Result([])
            now = datetime.now(UTC)
            return Result([dict(call_id=UUID(int=1), generation=UUID(int=2), revision=2, activity_operation_id=None,
                                path=PATH, version_id='v-1', sha256='a' * 64, served_revision=3, state='retired',
                                acquired_at=now, retired_at=now, visible=True)])

    @asynccontextmanager
    async def connection():
        yield Connection()
    rec.connection = connection
    return rec


@pytest.mark.parametrize('scope', [
    dict(tenant_id='', mission_id='mis_1', root_agent_id='ag_root'),
    dict(tenant_id='tenant', mission_id='mission-1', root_agent_id='ag_root'),
    dict(tenant_id='tenant', mission_id='mis_1', root_agent_id='root'),
    dict(tenant_id='tenant', mission_id='mis_1', root_agent_id='ag_root', batch=0),
    dict(tenant_id='tenant', mission_id='mis_1', root_agent_id='ag_root', batch=1001),
    dict(tenant_id='tenant', mission_id='mis_1', root_agent_id='ag_root', enabled=False),
])
def test_operator_dependency_commands_refuse_inexact_scope_before_sql(scope):
    async def scenario():
        enabled = scope.pop('enabled', True)
        rec = recovery(enabled)
        for command in (rec.dependencies, rec.retire_dependencies):
            with pytest.raises(StorageUnavailable, match='Exact Mission scope'):
                await command(**scope)
        assert rec.seen == []

    asyncio.run(scenario())


def test_operator_retires_only_the_exact_mission_scope_and_inventories_without_physical_key():
    async def scenario():
        rec = recovery()
        result = await rec.retire_dependencies(tenant_id='tenant', mission_id='mis_1', root_agent_id='ag_root',
                                               batch=10)
        (query, args), = rec.seen
        assert query.startswith('UPDATE mission_file_dependencies SET state=\'retired\'')
        assert 'tenant_id=%s AND mission_id=%s AND root_agent_id=%s AND state=\'active\'' in query
        assert args == ('tenant', 'mis_1', 'ag_root', 10) and 'DELETE' not in query
        assert result['retired'] == 1 and result['complete'] is True
        rec.seen.clear()
        inventory = await rec.dependencies(tenant_id='tenant', mission_id='mis_1', root_agent_id='ag_root', batch=1)
        assert rec.seen[0][0] == 'SET TRANSACTION READ ONLY'
        assert rec.seen[1][1] == ('tenant', 'mis_1', 'ag_root', 2)
        assert "pin->>'key'" not in rec.seen[1][0] and 'generation_visible' not in rec.seen[1][0]
        assert inventory['category'] == 'tools_file_dependency' and inventory['complete'] is True
        assert inventory['rows'][0]['generation'] == str(UUID(int=2)) and 'key' not in inventory['rows'][0]
        json.dumps(inventory)

    asyncio.run(scenario())


def test_operator_cli_routes_dependency_commands_to_the_exact_scope(monkeypatch, tmp_path):
    from src.mcp_tools.storage import files_recovery_cli as cli

    calls = []

    class Recovery:
        def __init__(self, settings, *, app_role):
            calls.append(('init', app_role))

        async def dependencies(self, **scope):
            calls.append(('dependencies', scope))
            return {'category': 'tools_file_dependency'}

        async def retire_dependencies(self, **scope):
            calls.append(('retire', scope))
            return {'retired': 0, 'complete': True}

    monkeypatch.setattr(cli, 'private_text', lambda path: '{}')
    class Profile:
        model_fields: ClassVar[dict] = {}

        def __init__(self, **kwargs):
            self.files_credentials_mode = 'vault'
    monkeypatch.setattr(cli, 'RecoverySettings', Profile)
    monkeypatch.setattr(cli, 'FileRecovery', Recovery)
    for command in ('dependencies', 'retire-dependencies'):
        args = SimpleNamespace(profile=tmp_path / 'p', app_role='app', command=command, tenant_id='tenant',
                               mission_id='mis_1', root_agent_id='ag_root', batch=5)
        asyncio.run(cli.operation(args))
    scope = dict(tenant_id='tenant', mission_id='mis_1', root_agent_id='ag_root', batch=5)
    assert calls == [('init', 'app'), ('dependencies', scope), ('init', 'app'), ('retire', scope)]


def test_dependencies_require_the_recovery_extension():
    from pydantic import ValidationError

    from src.mcp_tools.config import Settings

    with pytest.raises(ValidationError, match='file recovery extension'):
        Settings(_env_file=None, files_mission_dependencies_enabled=True)
    assert Settings(_env_file=None).files_mission_dependencies_enabled is False


def test_dependency_ddl_grants_and_hash_are_finite():
    from src.mcp_tools.storage import files_dependency_schema as schema

    ddl = schema.DDL
    assert 'GRANT SELECT,INSERT ON {schema}.mission_file_dependencies TO {app};' in ddl
    assert 'UPDATE' not in ddl.split('TO {app};')[0].rsplit('GRANT', 1)[1]
    assert 'GRANT UPDATE(state,retired_at,revision) ON {schema}.mission_file_dependencies TO {maintenance};' in ddl
    assert 'DELETE' not in ''.join(line for line in ddl.splitlines() if line.startswith('GRANT'))
    assert ddl.count('SECURITY DEFINER') == 2 and 'FOR SHARE' in ddl
    assert "'files-recovery:' ||" in ddl and 'generation_visible(NEW.generation)' in ddl
    with pytest.raises(ValueError):
        schema.render('tools_files', 'same', 'same')


def test_dependency_profile_without_reviewed_capture_refuses_before_sql(monkeypatch):
    async def scenario():
        from src.mcp_tools.storage import files_bootstrap
        from src.mcp_tools.storage import files_recovery_contract as contract

        names = []

        class Missing:
            def __init__(self, name):
                names.append(name)

            def read_text(self):
                raise FileNotFoundError(names[-1])

        class NoConnection:
            def __init__(self, settings):
                pass

            def connection(self, **kwargs):
                pytest.fail('unreviewed dependency schema reached SQL')

        settings = SimpleNamespace(files_credentials_mode='vault', files_recovery_enabled=True,
                                   files_mission_dependencies_enabled=True, model_copy=lambda **kw: settings)
        monkeypatch.setattr(files_bootstrap, 'get_settings', lambda: settings)
        monkeypatch.setattr(files_bootstrap, 'Catalog', NoConnection)
        monkeypatch.setattr(contract, 'Path', lambda *a: SimpleNamespace(with_name=Missing))
        with pytest.raises(StorageUnavailable, match='projection unavailable'):
            await files_bootstrap.install(SimpleNamespace(schema='owned', app_role='app',
                                                          operator_service='private', check=False))
        assert names == ['files_dependency_contract.json']
        monkeypatch.undo()
        # Le profil 845 seul garde sa capture et son empreinte inchangées.
        assert contract.expected_projection(SimpleNamespace()) == contract.expected_projection()

    asyncio.run(scenario())


def test_dependency_capture_hash_covers_both_ddl(monkeypatch, tmp_path):
    from src.mcp_tools.storage import files_recovery_contract as contract
    from src.mcp_tools.storage.files_dependency_schema import DDL as DEPENDENCY_DDL
    from src.mcp_tools.storage.files_recovery_schema import DDL

    capture = tmp_path / 'files_dependency_contract.json'
    good = hashlib.sha256((DDL + DEPENDENCY_DDL).encode()).hexdigest()
    monkeypatch.setattr(contract, 'Path', lambda *a: SimpleNamespace(with_name=lambda name: tmp_path / name))
    enabled = SimpleNamespace(files_mission_dependencies_enabled=True)
    capture.write_text(json.dumps(dict(format_version=1, ddl_sha256=good, snapshot={'captured': True})))
    assert contract.expected_projection(enabled) == {'captured': True}
    capture.write_text(json.dumps(dict(format_version=1, ddl_sha256=hashlib.sha256(DDL.encode()).hexdigest(),
                                       snapshot={'captured': True})))
    with pytest.raises(StorageUnavailable, match='drift'):
        contract.expected_projection(enabled)
