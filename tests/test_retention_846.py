"""#846 Access : autorité unique, store 846, preuve, reçu, séquence et config.

Sans PostgreSQL : les connexions sont simulées au niveau du curseur. Les routines
SQL, triggers, verrous et COMMIT réels sont exercés par le kit PG17
(tests/postgres_files/mission_retention_846.py).
"""
import asyncio
import copy
import hashlib
import json
import time
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from uuid import uuid4

import jwt
import psycopg
import pytest
from cryptography.hazmat.primitives.asymmetric import ec
from jwt.algorithms import ECAlgorithm

from src.mcp_tools import retention_846 as cli
from src.mcp_tools import retention_proof_846 as proof
from src.mcp_tools.auth import postgres_operator as operator
from src.mcp_tools.auth import postgres_retention_846 as holds846
from src.mcp_tools.auth.postgres_store import _ACTIVE, _HUB_FILES_CONFIRM_846, PostgresAccessStore
from src.mcp_tools.auth.token_store import TokenStoreUnavailable
from src.mcp_tools.config import Settings
from src.mcp_tools.storage.files_credentials import StorageUnavailable
from src.mcp_tools.storage.files_recovery import FileRecovery

from mission_receipt_9ded160c import RetentionClaim, validate_owner_receipt
from test_hub_sql_refusal_31 import install_transport, sql_error
from test_postgres_access_store_31 import Provider


# U1. verify : marqueur, projection catalogue, prosrc, profil de routines.

class Catalog:
    """Réponses du catalogue réel pour les seules requêtes de verify_846."""
    def __init__(self, present=True, catalog=None, sources=None, marker=None):
        self.present, self.catalog = present, catalog or copy.deepcopy(holds846.CATALOG)
        self.sources = sources or holds846.function_sources()
        self.marker = marker or {'version': 1, 'checksum': holds846.CHECKSUM, 'coordination_required': True}

    async def execute(self, query, params=()):
        self.query = query
        return self

    async def fetchone(self):
        if 'to_regclass' in self.query:
            return {'present': self.present}
        if 'retention_846_version' in self.query:
            return self.marker
        raise AssertionError(self.query)

    async def fetchall(self):
        if 'prosrc' in self.query:
            return [{'proname': k, 'prosrc': v} for k, v in self.sources.items()]
        for name, query in operator._PROJECTION_846.items():
            if self.query == query:
                return self.catalog[name]
        raise AssertionError(self.query)


def run(coroutine):
    return asyncio.run(coroutine)


def test_verify_accepts_exact_extension_and_v1_without_marker():
    run(operator.verify_846(Catalog(), True))
    run(operator.verify_846(Catalog(present=False), False))


@pytest.mark.parametrize('present,retention', [(False, True), (True, False)])
def test_verify_refuses_marker_and_profile_mismatch_in_both_directions(present, retention):
    with pytest.raises(ValueError, match='Profil de rétention 846'):
        run(operator.verify_846(Catalog(present=present), retention))


def test_verify_refuses_disabled_trigger():
    """Le BEFORE INSERT est le seul garde contre une admission tardive."""
    catalog = copy.deepcopy(holds846.CATALOG)
    trigger = next(t for t in catalog['triggers'] if t['tgname'] == 'retention_846_admission')
    trigger['tgenabled'] = 'D'
    with pytest.raises(ValueError, match='Projection catalogue 846'):
        run(operator.verify_846(Catalog(catalog=catalog), True))


@pytest.mark.parametrize('mutation', ['trigger_dropped', 'constraint_changed', 'security_invoker', 'proconfig'])
def test_verify_refuses_any_catalog_drift(mutation):
    catalog = copy.deepcopy(holds846.CATALOG)
    if mutation == 'trigger_dropped':
        catalog['triggers'] = [t for t in catalog['triggers'] if t['tgname'] != 'retention_846_delete']
    elif mutation == 'constraint_changed':
        catalog['constraints'][0]['definition'] = 'CHECK (true)'
    elif mutation == 'security_invoker':
        next(f for f in catalog['functions'] if f['proname'] == 'mission_retirement_batch')['prosecdef'] = False
    else:
        next(f for f in catalog['functions'] if f['proname'] == 'guard_mission_admission_846')['proconfig'] = None
    with pytest.raises(ValueError, match='Projection catalogue 846'):
        run(operator.verify_846(Catalog(catalog=catalog), True))


def test_verify_refuses_modified_routine_source_and_marker():
    sources = holds846.function_sources()
    sources['guard_mission_delete_846'] = sources['guard_mission_delete_846'].replace("r.state='prepared'", 'true')
    with pytest.raises(ValueError, match='Source des routines 846'):
        run(operator.verify_846(Catalog(sources=sources), True))
    with pytest.raises(ValueError, match='Marqueur'):
        run(operator.verify_846(Catalog(marker={'version': 1, 'checksum': '0' * 64,
                                                'coordination_required': True}), True))


def test_profile_846_replaces_v1_routines_and_adds_tables_without_direct_rights():
    app, maintenance, tables = holds846.routine_profile(True)
    v1_app, v1_maintenance, v1_tables = holds846.routine_profile(False)
    for old, new in holds846.REPLACED.items():
        assert old not in app and old not in maintenance
        assert new in app + maintenance
    assert 'purge_expired_846(integer)' in maintenance and 'purge_expired(integer)' in v1_maintenance
    assert set(app) - set(v1_app) == {'activity_page_846(text,timestamptz,uuid,integer)',
        'hub_activity_page_846(text,text,text,text,text,text,text,timestamptz,uuid,integer)',
        'hub_file_calls_846(text,text,text,text,text,text,text,uuid[])',
        'hub_files_confirm_846(text,bigint,uuid,bigint,text,text,text,text,text,text,uuid[],uuid[])',
        'retention_846_contract()'}
    assert set(tables) - set(v1_tables) == {'retention_846_version', 'mission_retirements_846',
                                            'mission_retired_refs_846'}
    # Les routines de maintenance ne sont jamais accordées à l'application.
    assert not {name for name in maintenance if name.startswith('mission_retirement')} & set(app)


# U2. Store : routines 846, contrat runtime, échéance absente, refus métier.

def test_store_846_calls_replacement_routines_and_omits_mission_expiry(monkeypatch):
    from src.mcp_tools.auth.hub_activity import check_expiry
    store = PostgresAccessStore(Provider(), ca_file='ca', role='app', database='access', retention=True)
    queries = []
    now = datetime.now(timezone.utc)

    async def fake_run(query, parameters):
        queries.append(query)
        if 'hub_files_confirm' in query:
            return [{'credential_version': 3, 'binding_id': 'b', 'binding_version': 1, 'credential_expires_at': None,
                     'binding_expires_at': now + timedelta(hours=1), 'activity_expires_at': None}]
        if 'credential_get' in query:
            return []
        return []
    monkeypatch.setattr(store, '_run', fake_run)
    confirmed = run(store.confirm_hub_files('r', {'version': 3}, {'id': 'b', 'version': 1},
        {'iss': 'i', 'sub': 's', 'owner_id': 'o', 'tenant_id': 't', 'mission_id': 'mis_a', 'root_agent_id': 'ag_a'},
        {str(uuid4()): None}))
    assert 'activity_expires_at' not in confirmed
    check_expiry({'exp': time.time() + 30}, confirmed)
    expired = {**confirmed, 'binding_expires_at': now - timedelta(seconds=1)}
    with pytest.raises(ValueError, match='expired'):
        check_expiry({'exp': time.time() + 30}, expired)
    run(store.hub_activity_page('r', {'actor_id': 'a', 'tenant_id': 't', 'service_id': 's', 'version': 1},
        {'id': 'b', 'version': 1, 'expires_at': now}, {'iss': 'i', 'sub': 's', 'owner_id': 'o', 'tenant_id': 't',
        'mission_id': 'mis_a', 'root_agent_id': 'ag_a'}))
    assert queries[0] == _HUB_FILES_CONFIRM_846
    assert 'tools_access.hub_activity_page_846(' in queries[1]


def test_store_v1_keeps_strict_activity_expiry(monkeypatch):
    store = PostgresAccessStore(Provider(), ca_file='ca', role='app', database='access')
    expiry = datetime.now(timezone.utc) + timedelta(days=1)

    async def fake_run(query, parameters):
        assert '_846' not in query
        return [{'credential_version': 3, 'binding_id': 'b', 'binding_version': 1, 'credential_expires_at': None,
                 'binding_expires_at': expiry, 'activity_expires_at': expiry}]
    monkeypatch.setattr(store, '_run', fake_run)
    confirmed = run(store.confirm_hub_files('r', {'version': 3}, {'id': 'b', 'version': 1},
        {'iss': 'i', 'sub': 's', 'owner_id': 'o', 'tenant_id': 't', 'mission_id': 'mis_a', 'root_agent_id': 'ag_a'},
        {str(uuid4()): None}))
    assert confirmed['activity_expires_at'] == expiry


@pytest.mark.parametrize('kind', ['known', 'wrong_origin', 'v1_query_with_846_origin'])
def test_hub_files_confirm_846_refusal_mirrors_v1_translation(monkeypatch, kind):
    """Miroir de test_hub_sql_refusal_31 pour la routine de remplacement (P3-6)."""
    origin = ('PL/pgSQL function tools_access.hub_files_confirm_846(text,bigint,uuid,bigint,text,text,text,text,'
              'text,text,uuid[],uuid[]) line 40 at RAISE')
    context = origin.replace('tools_access.', 'other.') if kind == 'wrong_origin' else origin
    install_transport(monkeypatch, sql_error('current hub file access refused', context))
    store = PostgresAccessStore(Provider(), ca_file='ca', role='app', database='access')
    query = _HUB_FILES_CONFIRM_846 if kind != 'v1_query_with_846_origin' else 'SELECT * FROM tools_access.admit_mission()'
    with pytest.raises(ValueError if kind == 'known' else TokenStoreUnavailable):
        run(store._run(query, ()))
    assert not _ACTIVE


@pytest.mark.parametrize('contract,refused', [
    ([{'version': 1, 'checksum': holds846.CHECKSUM, 'coordination_required': True}], False),
    ([], True), ([{'version': 1, 'checksum': '0' * 64, 'coordination_required': True}], True)])
def test_store_846_checks_runtime_contract_on_every_connection(monkeypatch, contract, refused):
    from src.mcp_tools.auth.postgres_schema import CHECKSUM, VERSION

    class Cursor:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            pass

        async def execute(self, query, *args):
            self.query = query

        async def fetchall(self):
            if 'retention_846_contract' in self.query:
                return contract
            if 'schema_contract' in self.query:
                return [{'version': VERSION, 'checksum': CHECKSUM}]
            if 'pg_roles' in self.query:
                return [{'role': 'app', 'db': 'access', 'recovery': False, 'privileged': False}]
            return [{'ok': True}]

    class Connection:
        pgconn = SimpleNamespace(finish=lambda: None)

        def cursor(self):
            return Cursor()

        async def commit(self):
            pass

    async def connect(**kwargs):
        return Connection()
    monkeypatch.setattr(psycopg.AsyncConnection, 'connect', connect)
    monkeypatch.setattr(psycopg.capabilities, 'has_cancel_safe', lambda: True)
    store = PostgresAccessStore(Provider(), ca_file='ca', role='app', database='access', retention=True)
    if refused:
        with pytest.raises(TokenStoreUnavailable):
            run(store._run('SELECT 1', ()))
    else:
        assert run(store._run('SELECT 1', ())) == [{'ok': True}]


# U3. Preuve copiée de Vault : audience et owner seulement.

KEY = ec.generate_private_key(ec.SECP256R1())
JWK = {**json.loads(ECAlgorithm.to_jwk(KEY.public_key())), 'kid': 'k1'}
SETTINGS = SimpleNamespace(access_retention_issuer='https://mission.test', access_retention_audience='tools-846',
                           access_retention_jwks_url='https://mission.test/jwks', access_retention_callback_seconds=5)
TERMINAL = datetime(2025, 1, 1, tzinfo=timezone.utc)


def identity(root='ag_root1', owner='tools'):
    return {'owner': owner, 'tenant_id': 'tenant-a', 'mission_id': 'mis_a', 'root_agent_id': root,
            'claim_id': str(uuid4()), 'claim_revision': 4, 'terminal_at': TERMINAL.isoformat(),
            'retain_until': (TERMINAL + timedelta(days=365)).isoformat(), 'manifest_sha256': 'a' * 64}


def token(body, audience='tools-846'):
    stamp = int(time.time())
    claims = {**body, 'iss': SETTINGS.access_retention_issuer, 'aud': audience,
              'sub': 'mission-retention-maintenance', 'purpose': 'mission-retention-v1',
              'iat': stamp, 'nbf': stamp, 'exp': stamp + 30, 'jti': 'b' * 32}
    return jwt.encode(claims, KEY, algorithm='ES256', headers={'kid': 'k1'})


def test_proof_accepts_tools_owner_and_audience():
    body = identity()
    decoded, expires = proof.decode(SETTINGS, [JWK], token(body))
    assert decoded == body and expires > datetime.now(timezone.utc)


@pytest.mark.parametrize('audience,owner', [('vault-846', 'tools'), ('tools-846', 'vault')])
def test_proof_refuses_other_audience_or_owner(audience, owner):
    with pytest.raises(ValueError, match='Retention proof refused'):
        proof.decode(SETTINGS, [JWK], token(identity(owner=owner), audience=audience))


# U4. Reçu : test croisé contre la copie figée du validateur Mission 9ded160c.

SEALED_A = {'state': 'sealed', 'calls': 2, 'events': 2, 'calls_sha256': 'c' * 64, 'events_sha256': 'e' * 64,
            'sealed_at': '2026-10-17T10:00:01.5+02:00'}
SEALED_F = {'state': 'sealed', 'dependencies': 0, 'dependencies_sha256': hashlib.sha256(b'').hexdigest(),
            'sealed_at': '2026-10-17T08:00:00.000001+00:00'}


@pytest.mark.parametrize('root', ['ag_root1', ''])
def test_envelope_passes_frozen_mission_validator_with_three_explicit_categories(root):
    body = identity(root=root)
    operation = str(uuid4())
    private, value = cli.envelope(body, operation, SEALED_A, SEALED_F)
    assert validate_owner_receipt(value, RetentionClaim(**body)) is value
    assert [ref['kind'] for ref in value['references']] == ['tools_activity_calls', 'tools_activity_events',
                                                            'tools_file_dependencies']
    assert value['references'][2] == {'kind': 'tools_file_dependencies', 'revision': 0, 'root_agent_id': root,
                                      'id': 'sha256:' + hashlib.sha256(b'').hexdigest()}
    assert private['composed_at'] == '2026-10-17T08:00:01.500000+00:00'
    # sealed_at en UTC : un autre TimeZone de session donne les mêmes octets.
    assert private['access']['sealed_at'] == '2026-10-17T08:00:01.500000+00:00'
    assert private['files']['sealed_at'] == '2026-10-17T08:00:00.000001+00:00'
    shifted = {**SEALED_A, 'sealed_at': '2026-10-17T03:00:01.5-05:00'}
    assert cli.envelope(body, operation, shifted, dict(SEALED_F)) == (private, value)
    assert cli.envelope(body, operation, dict(SEALED_A), dict(SEALED_F)) == (private, value)
    # Une autre claim (révision) est refusée par Mission : le reçu est lié à son identité.
    with pytest.raises(ValueError):
        validate_owner_receipt(value, RetentionClaim(**{**body, 'claim_revision': 5}))


# U5. Séquence : ordre, UNKNOWN, reconcile, root vide.

class Conn:
    def __init__(self, log, results, flags=None):
        self.log, self.results, self.flags = log, results, flags or {}
        self._tools_notices = []

    async def execute(self, query, params=()):
        self.log.append(query)
        if query == 'COMMIT' and self.flags.get('fail_commit'):
            raise OSError('connection lost after COMMIT')
        self.last = query
        return self

    async def fetchone(self):
        for marker, value in self.results.items():
            if marker in self.last:
                return {'result': value}
        return None


class Recovery:
    def __init__(self, log, flags=None):
        self.log, self.state = log, 'absent'
        self.settings = SimpleNamespace(files_recovery_enabled=True, files_mission_dependencies_enabled=True)
        flags = flags if flags is not None else {}

        class Tx:
            def transaction(_, c):
                from contextlib import asynccontextmanager

                from src.mcp_tools.storage.files_postgres import CommitUnknown

                @asynccontextmanager
                async def tx():
                    await c.execute('BEGIN')
                    yield
                    await c.execute('COMMIT')
                    if flags.get('fail_files_commit'):
                        # COMMIT appliqué (l'effet est déjà dans self.state), ACK perdu.
                        raise CommitUnknown('COMMIT diagnostic inconnu')
                return tx()
        self.catalog = Tx()

    def view(self, claim):
        return {'operation_id': self.operation, 'state': self.state, 'claim_sha256': claim,
                **({'dependencies': 0, 'dependencies_sha256': hashlib.sha256(b'').hexdigest(),
                    'sealed_at': '2026-10-17T09:00:00+00:00'} if self.state == 'sealed' else {})}

    async def closure_prepare(self, c, *, operation_id, claim_sha256, root_agent_id, **scope):
        self.operation, self.state = operation_id, 'sealed' if not root_agent_id else 'prepared'
        self.log.append('closure_prepare')
        return self.view(claim_sha256)

    async def closure_retire(self, c, *, operation_id, claim_sha256, batch):
        self.state = 'sealed'
        self.log.append('closure_retire')
        return {**self.view(claim_sha256), 'has_more': False, 'retired': 0}

    async def closure_status(self, c, *, operation_id, tenant_id, mission_id):
        self.operation = operation_id
        return self.view(self.claim)


def harness(tmp_path, root='ag_root1', fail_commit=False):
    tmp_path.chmod(0o700)
    body = identity(root=root)
    digest = proof.fingerprint(body)
    expires = datetime.now(timezone.utc) + timedelta(seconds=30)
    operation = str(uuid4())
    log = []
    flags = {'fail_commit': fail_commit}
    recovery = Recovery(log, flags)
    recovery.claim = digest
    access_state = {'state': 'absent'}
    sealed = {'operation_id': operation, 'state': 'sealed', 'claim_sha256': digest, **SEALED_A}

    def results():
        return {'mission_retirement_prepare': {'operation_id': operation, 'state': 'prepared', 'claim_sha256': digest},
                'mission_retirement_batch': {**sealed, 'has_more': False},
                'mission_retirement_status': access_state}
    from contextlib import asynccontextmanager

    @asynccontextmanager
    async def access():
        yield Conn(log, results(), flags)

    @asynccontextmanager
    async def files():
        yield Conn(log, {})
    core = cli.Retention846(access=access, files=files, recovery=recovery, live=lambda t: (body, expires),
                            state_dir=tmp_path, operation_id=operation)
    core.flags = flags
    return core, log, access_state, sealed


def step(core, name, batch=500):
    return run(cli.run(core, SimpleNamespace(step=name, batch=batch), 'proof'))


def test_full_sequence_in_order_then_identical_reissue(tmp_path):
    core, log, access_state, sealed = harness(tmp_path)
    for name in ('access-prepare', 'files-prepare', 'access-retire', 'files-retire'):
        step(core, name)
    access_state.update(sealed)
    first = step(core, 'receipt')
    envelope = json.loads((tmp_path / 'envelope.json').read_text())
    assert first['references'] == 3 and envelope['receipt_sha256'] == first['receipt_sha256']
    assert step(core, 'receipt') == first
    assert (tmp_path / 'envelope.json').stat().st_mode & 0o777 == 0o600
    assert log.count('COMMIT') >= 4 and 'ROLLBACK' not in log


@pytest.mark.parametrize('premature', ['files-prepare', 'access-retire', 'files-retire', 'receipt'])
def test_each_step_refuses_before_its_predecessor_without_effect(tmp_path, premature):
    core, log, _, _ = harness(tmp_path)
    if premature != 'files-prepare':
        step(core, 'access-prepare')
    if premature in ('files-retire', 'receipt'):
        step(core, 'files-prepare')
    def effects():
        return [q for q in log if 'retirement_prepare' in q or 'retirement_batch' in q
                or q in ('closure_prepare', 'closure_retire')]
    before = effects()
    with pytest.raises(cli.Refused):
        step(core, premature)
    assert effects() == before
    assert not (tmp_path / (premature + '.json')).exists()


def test_uncertain_commit_stops_until_reconcile_reports_next_step(tmp_path):
    core, log, access_state, _ = harness(tmp_path, fail_commit=True)
    with pytest.raises(cli.Unknown):
        step(core, 'access-prepare')
    assert (tmp_path / 'access-prepare.unknown.json').exists()
    assert not (tmp_path / 'access-prepare.json').exists()
    with pytest.raises(cli.Refused, match='reconcile first'):
        step(core, 'files-prepare')
    # Le registre lu sous verrou dit si l'effet a commité ; ici oui.
    access_state.update({'operation_id': core.operation, 'state': 'prepared',
                         'claim_sha256': proof.fingerprint(core.live('x')[0])})
    core.flags['fail_commit'] = False
    result = run(cli.run(core, SimpleNamespace(step='reconcile', batch=1)))
    assert result['next_step'] == 'files-prepare'
    assert not list(tmp_path.glob('*.unknown.json')) and (tmp_path / 'access-prepare.reconciled.json').exists()


# P2-A. COMMIT effectif sans ACK : reconcile réécrit le fichier de l'étape que le
# registre confirme, sinon l'étape suivante que reconcile annonce serait refusée.
TRANSITIONS = [('access-prepare', 'files-prepare', 'fail_commit'),
               ('files-prepare', 'access-retire', 'fail_files_commit'),
               ('access-retire', 'files-retire', 'fail_commit')]


@pytest.mark.parametrize('lost,following,flag', TRANSITIONS)
def test_reconcile_confirms_committed_step_without_ack_then_next_step_runs(tmp_path, lost, following, flag):
    core, log, access_state, sealed = harness(tmp_path)
    digest = proof.fingerprint(core.live('x')[0])
    order = ['access-prepare', 'files-prepare', 'access-retire', 'files-retire']
    for name in order[:order.index(lost)]:
        step(core, name)
    core.flags[flag] = True
    with pytest.raises(cli.Unknown):
        step(core, lost)
    core.flags[flag] = False
    # Le COMMIT a eu lieu : le registre Access porte l'effet (Files : déjà dans recovery.state).
    if lost == 'access-prepare':
        access_state.update({'operation_id': core.operation, 'state': 'prepared', 'claim_sha256': digest})
    elif lost == 'access-retire':
        access_state.update(sealed)
    else:
        access_state.update({'operation_id': core.operation, 'state': 'prepared', 'claim_sha256': digest})
    assert not (tmp_path / (lost + '.json')).exists()
    # Le défaut corrigé : sans fichier de l'étape perdue, l'étape suivante est refusée.
    method = {'files-prepare': core.files_prepare, 'access-retire': lambda t: core.access_retire(t, 500),
              'files-retire': lambda t: core.files_retire(t, 500)}[following]
    with pytest.raises(cli.Refused, match='Previous confirmed step required: ' + lost):
        run(method('proof'))
    reconciled = run(cli.run(core, SimpleNamespace(step='reconcile', batch=1)))
    assert reconciled['next_step'] == following
    written = json.loads((tmp_path / (lost + '.json')).read_text())
    assert written['confirmed_by'] == 'reconcile' and written['operation_id'] == core.operation
    assert written['claim_sha256'] == digest
    assert (tmp_path / (lost + '.json')).stat().st_mode & 0o777 == 0o600
    before = len(log)
    accepted = step(core, following)
    assert accepted['state'] in ('prepared', 'sealed') and len(log) > before


def test_reconcile_writes_nothing_when_commit_did_not_happen(tmp_path):
    core, log, access_state, _ = harness(tmp_path, fail_commit=True)
    with pytest.raises(cli.Unknown):
        step(core, 'access-prepare')
    core.flags['fail_commit'] = False
    # Registre absent : le COMMIT n'a pas eu lieu, la même étape se relance.
    reconciled = run(cli.run(core, SimpleNamespace(step='reconcile', batch=1)))
    assert reconciled['next_step'] == 'access-prepare'
    assert not (tmp_path / 'access-prepare.json').exists()
    with pytest.raises(cli.Refused, match='Previous confirmed step required'):
        step(core, 'files-prepare')


def test_reconcile_protects_scope_bound_to_another_claim(tmp_path):
    core, log, access_state, _ = harness(tmp_path, fail_commit=True)
    with pytest.raises(cli.Unknown):
        step(core, 'access-prepare')
    core.flags['fail_commit'] = False
    access_state.update({'operation_id': core.operation, 'state': 'prepared', 'claim_sha256': 'f' * 64})
    reconciled = run(cli.run(core, SimpleNamespace(step='reconcile', batch=1)))
    assert reconciled['next_step'] == 'protected'
    assert not (tmp_path / 'access-prepare.json').exists()
    with pytest.raises(cli.Refused, match='Previous confirmed step required'):
        step(core, 'files-prepare')


def test_reconcile_upgrades_partial_retire_file_to_sealed(tmp_path):
    """Un lot partiel confirmé laisse access-retire.json à prepared ; le dernier lot sans ACK le scelle."""
    core, log, access_state, sealed = harness(tmp_path)
    for name in ('access-prepare', 'files-prepare'):
        step(core, name)
    from src.mcp_tools.retention_846 import save
    save(tmp_path, 'access-retire.json', {'operation_id': core.operation, 'state': 'prepared',
                                          'claim_sha256': sealed['claim_sha256'], 'has_more': True})
    access_state.update(sealed)
    run(cli.run(core, SimpleNamespace(step='reconcile', batch=1)))
    assert json.loads((tmp_path / 'access-retire.json').read_text())['state'] == 'sealed'
    assert step(core, 'files-retire')['state'] == 'sealed'


# P3. Ce qui sort sur stdout : nos refus et les messages primaires de nos RAISE SQL.

def test_cli_reason_exposes_only_fixed_texts():
    from pydantic import ValidationError
    assert cli.reason(cli.Refused('Both sealed registries required')) == 'Both sealed registries required'
    raised = sql_error('retention scope bound to another operation', '', psycopg.errors.RaiseException)
    assert cli.reason(raised) == 'retention scope bound to another operation'
    denied = sql_error('mission retention closed', '', psycopg.errors.InsufficientPrivilege)
    assert cli.reason(denied) == 'mission retention closed'
    # Autre sqlstate : le message primaire peut porter une valeur, seul le nom sort.
    assert cli.reason(sql_error('duplicate key (PRIVATE)', '', psycopg.errors.UniqueViolation)) == 'UniqueViolation'
    with pytest.raises(ValidationError) as caught:
        Settings(_env_file=None, access_retention_callback_seconds='/private/path/canary')
    assert '/private/path' in str(caught.value) and cli.reason(caught.value) == 'ValidationError'
    assert cli.reason(ValueError('Invalid isoformat string: PRIVATE')) == 'ValueError'


def test_main_prints_reason_without_private_value(monkeypatch, tmp_path, capsys):
    monkeypatch.setattr('sys.argv', ['retention_846', 'reconcile', '--operation-id', str(uuid4()),
                                     '--state-dir', str(tmp_path), '--files-app-role', 'app'])

    def build(args):
        raise ValueError('Invalid isoformat string: PRIVATE-CANARY')
    monkeypatch.setattr(cli, 'build', build)
    assert cli.main() == 1
    out = json.loads(capsys.readouterr().out)
    assert out['status'] == 'refused' and out['reason'] == 'ValueError'


@pytest.mark.parametrize('seconds,accepted', [(15, True), (15.5, False), (30, False)])
def test_callback_budget_stays_under_transaction_idle_timeout(seconds, accepted):
    if accepted:
        assert Settings(_env_file=None, access_retention_callback_seconds=seconds)
    else:
        with pytest.raises(ValueError):
            Settings(_env_file=None, access_retention_callback_seconds=seconds)
    # Le second callback tient dans la transaction : borne max strictement sous le SET LOCAL de _step.
    import inspect
    import re
    idle = re.search(r"idle_in_transaction_session_timeout='(\d+)ms'", inspect.getsource(cli.Retention846._step))
    bound = [m.le for m in Settings.model_fields['access_retention_callback_seconds'].metadata
             if getattr(m, 'le', None) is not None]
    assert bound and max(bound) < int(idle.group(1)) / 1000


@pytest.mark.parametrize('access,files,expected', [
    ('absent', 'absent', 'access-prepare'), ('prepared', 'absent', 'files-prepare'),
    ('prepared', 'prepared', 'access-retire'), ('prepared', 'sealed', 'access-retire'),
    ('sealed', 'absent', 'files-prepare'), ('sealed', 'prepared', 'files-retire'),
    ('sealed', 'sealed', 'receipt'), ('absent', 'prepared', 'protected'), ('weird', 'absent', 'protected')])
def test_reconcile_next_step_for_each_registry_state(access, files, expected):
    assert cli.next_step({'state': access}, {'state': files}) == expected


def test_claim_change_between_proofs_rolls_back(tmp_path):
    core, log, _, _ = harness(tmp_path)
    answers = iter([core.live('x'), (identity(), datetime.now(timezone.utc) + timedelta(seconds=30))])
    core.live = lambda t: next(answers)
    with pytest.raises(cli.Refused, match='claim changed'):
        step(core, 'access-prepare')
    assert log[-1] == 'ROLLBACK' and 'COMMIT' not in log


# U5 bis. Files : clôture d'un root vide (P2-2) et d'un autre root, sur SQL simulé.

class FilesConn:
    def __init__(self, counts, existing=None):
        self.counts, self.existing, self.inserted = counts, existing, None

    async def execute(self, query, params=()):
        self.query, self.params = query, params
        return self

    async def fetchone(self):
        if 'count(*)' in self.query:
            return {'n': self.counts}
        if self.query.startswith('SELECT * FROM mission_dependency_closures'):
            return self.existing
        if 'INSERT INTO mission_dependency_closures' in self.query:
            self.inserted = self.query
            state = 'sealed' if "'sealed'" in self.query else 'prepared'
            return {'operation_id': self.params[0], 'state': state, 'claim_sha256': 'd' * 64,
                    'dependencies': 0 if state == 'sealed' else None, 'sealed_at': None,
                    'dependencies_sha256': hashlib.sha256(b'').hexdigest() if state == 'sealed' else None}
        return None


def recovery():
    r = object.__new__(FileRecovery)
    r.settings = SimpleNamespace(files_mission_dependencies_enabled=True)
    return r


@pytest.mark.parametrize('root', ['', 'ag_root1'])
def test_files_prepare_protects_scope_with_foreign_rows(root):
    c = FilesConn(counts=1)
    with pytest.raises(StorageUnavailable, match='protected'):
        run(recovery().closure_prepare(c, operation_id=str(uuid4()), tenant_id='tenant-a', mission_id='mis_a',
                                       root_agent_id=root, claim_sha256='d' * 64))
    assert c.inserted is None
    # Root vide : la requête compte toutes les lignes du scope (root_agent_id<>'' couvre tous les roots ag_).
    assert c.params == ('tenant-a', 'mis_a', root)


def test_files_prepare_empty_root_seals_at_zero_without_mission_scope():
    c = FilesConn(counts=0)
    view = run(recovery().closure_prepare(c, operation_id=str(uuid4()), tenant_id='tenant-a', mission_id='mis_a',
                                          root_agent_id='', claim_sha256='d' * 64))
    assert view['state'] == 'sealed' and view['dependencies'] == 0
    assert view['dependencies_sha256'] == hashlib.sha256(b'').hexdigest()


def test_files_closure_view_normalizes_sealed_at_to_utc():
    stamp = datetime(2026, 10, 17, 10, 0, 0, 1, tzinfo=timezone(timedelta(hours=2)))
    view = FileRecovery.closure_view({'operation_id': uuid4(), 'state': 'sealed', 'claim_sha256': 'd' * 64,
                                      'dependencies': 0, 'dependencies_sha256': 'e' * 64, 'sealed_at': stamp})
    assert view['sealed_at'] == '2026-10-17T08:00:00.000001+00:00'


def test_files_prepare_refuses_other_operation_on_closed_scope():
    existing = {'operation_id': uuid4(), 'root_agent_id': 'ag_root1', 'claim_sha256': 'd' * 64, 'state': 'prepared'}
    with pytest.raises(StorageUnavailable, match='another operation'):
        run(recovery().closure_prepare(FilesConn(0, existing), operation_id=str(uuid4()), tenant_id='tenant-a',
                                       mission_id='mis_a', root_agent_id='ag_root1', claim_sha256='d' * 64))


# U6. Config : Files 846 face à Access PG exige l'extension Access.

def test_files_dependencies_require_access_retention_with_postgres_access():
    base = dict(_env_file=None, files_metadata_backend='postgres', files_recovery_enabled=True,
                files_recovery_maintenance_role='maint', files_mission_dependencies_enabled=True)
    with pytest.raises(ValueError, match='Access retention extension'):
        Settings(**base, access_backend='postgres')
    assert Settings(**base, access_backend='postgres', access_mission_retention_enabled=True)
    assert Settings(**base)  # Access S3 : pas d'autorité d'activité PG, règle 845/846 inchangée.


# U1 ter. verify() complet : profil 846 appliqué aux grants, aux tables et au marqueur.

class VerifyTarget:
    """Cible où l'app et la maintenance ont exactement les grants du profil 846."""
    def __init__(self):
        self.tables = set()
        app, maintenance, _ = holds846.routine_profile(True)
        v1_app, v1_maintenance, _ = holds846.routine_profile(False)
        self.granted = {'app': set(app), 'maint': set(maintenance)}
        self.signatures = set(app) | set(maintenance) | set(v1_app) | set(v1_maintenance)

    async def execute(self, query, params=()):
        self.query, self.params = str(query), params
        return self

    async def fetchone(self):
        q, p = self.query, self.params
        if 'FROM pg_roles WHERE rolname=%s' in q:
            return {'rolcanlogin': p[0] != 'owner', 'rolsuper': False, 'rolcreatedb': False, 'rolcreaterole': False,
                    'rolreplication': False, 'rolbypassrls': False}
        if 'schema_version' in q:
            from src.mcp_tools.auth.postgres_schema import CHECKSUM, VERSION
            return {'version': VERSION, 'checksum': CHECKSUM}
        if 'has_database_privilege' in q:
            return {'usable': True, 'bad': False}
        if "'USAGE'" in q:
            return {'usable': True}
        if 'to_regprocedure' in q:
            return {'oid': p[0].removeprefix('tools_access.')}
        if 'has_table_privilege' in q:
            self.tables.add(p[1])
            return {'bad': False}
        return {'bad': False}

    async def fetchall(self):
        role = self.params[0]
        return [{'oid': s, 'owner': 'owner', 'allowed': s in self.granted[role], 'delegable': False}
                for s in sorted(self.signatures)]


def test_verify_applies_846_profile_to_grants_tables_and_marker(monkeypatch):
    called = []

    async def marker(c, retention):
        called.append(retention)
    monkeypatch.setattr(operator, 'verify_846', marker)
    target = VerifyTarget()
    run(operator.verify(target, 'owner', 'app', 'maint', retention=True))
    assert called == [True]
    assert {'tools_access.' + t for t in holds846.TABLES} <= target.tables
    # Le même domaine lu avec le profil v1 voit des grants 846 inattendus : refus.
    with pytest.raises(ValueError, match='Grants des routines'):
        run(operator.verify(VerifyTarget(), 'owner', 'app', 'maint', retention=False))


# P3-7. La maintenance Files voit exactement la table de clôture en plus.

class SnapshotTarget:
    def __init__(self, closures):
        self.closures = closures

    async def execute(self, query, params=()):
        self.query, self.params = query, params
        return self

    async def fetchone(self):
        if 'rolinherit' in self.query or 'rolsuper' in self.query:
            return {'rolcanlogin': self.params[0] != 'owner', 'rolsuper': False}
        if 'pg_auth_members m\n' in self.query or 'present' in self.query:
            return {'present': False}
        return {'bad': False, 'write': False}

    async def fetchall(self):
        if 'm.admin_option' in self.query:
            return [{'rolname': 'pg_read_all_stats', 'admin_option': False, 'inherit_option': True, 'set_option': True}]
        if 'has_any_column_privilege' in self.query:
            tables = {'schema_version', 'refs', 'generations', 'operations', 'receipts', 'mission_file_dependencies'}
            if self.params[0] == 'maint':
                tables |= {'blob_retirements'} | ({'mission_dependency_closures'} if self.closures else set())
            return [{'nspname': 'tools_files', 'relname': t} for t in tables]
        if 'pg_get_function_identity_arguments' in self.query and self.params[0] == 'app':
            return [{'nspname': 'tools_files', 'proname': 'files_infrastructure', 'arguments': ''},
                    {'nspname': 'tools_files', 'proname': 'generation_visible', 'arguments': 'wanted uuid'}]
        # Atteint seulement après le contrôle des tables de la maintenance.
        raise LookupError('table authority accepted')


@pytest.mark.parametrize('closures', [True, False])
def test_files_maintenance_table_authority_includes_closure_registry(closures):
    from src.mcp_tools.storage.files_recovery_contract import snapshot
    settings = SimpleNamespace(files_pg_schema='tools_files', files_pg_owner='owner',
                               files_recovery_maintenance_role='maint', files_mission_dependencies_enabled=True)
    expected = LookupError if closures else StorageUnavailable
    with pytest.raises(expected):
        run(snapshot(SnapshotTarget(closures), settings, app_role='app'))
