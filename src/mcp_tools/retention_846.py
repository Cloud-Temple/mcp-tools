"""#846 : retrait Tools d'une Mission close, une étape par invocation, sans replay aveugle.

Étapes, dans cet ordre : access-prepare, files-prepare, access-retire (le dernier
lot scelle), files-retire (idem), receipt. `reconcile` lit les deux registres sans
preuve. Chaque étape mutante : preuve vérifiée (callback Mission), transaction,
effet SQL borné par l'échéance de la preuve, preuve revérifiée sous verrou, COMMIT.
Un COMMIT sans ACK rend `unknown` : marqueur privé, aucune étape avant `reconcile`.
Access et Files sont deux bases ; le lien est l'operation_id et l'empreinte de claim.
"""
import argparse
import asyncio
import hashlib
import json
import os
import stat
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from uuid import UUID

from .retention_proof_846 import fingerprint

STEPS = ('access-prepare', 'files-prepare', 'access-retire', 'files-retire', 'receipt', 'reconcile')
CONTRACTS = {'activity31': 'v1', 'files843': 'v1', 'recovery845': 'v1', 'holds846': 'v1'}


class Unknown(Exception):
    """COMMIT envoyé sans ACK : l'effet peut exister, rien n'est rejoué."""


class Refused(Exception):
    """Aucun effet confirmé ; l'état reste protégé."""


def canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(',', ':'), allow_nan=False)


def private_dir(path):
    info = os.lstat(path)
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
        raise Refused('Private owned state directory required')
    return Path(path)


def save(directory, name, value):
    target, temporary = directory / name, directory / ('.' + name + '.tmp')
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'w') as stream:
        stream.write(canonical(value))
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, target)
    handle = os.open(directory, os.O_DIRECTORY)
    try:
        os.fsync(handle)
    finally:
        os.close(handle)


def load(directory, name):
    path = directory / name
    return json.loads(path.read_text()) if path.exists() else None


def next_step(access, files):
    """Prochaine étape permise d'après les deux registres lus sous verrou."""
    a, f = access.get('state'), files.get('state')
    if a == 'absent':
        return 'access-prepare' if f == 'absent' else 'protected'
    if a == 'prepared':
        return 'files-prepare' if f == 'absent' else 'access-retire'
    if a == 'sealed':
        return {'absent': 'files-prepare', 'prepared': 'files-retire', 'sealed': 'receipt'}.get(f, 'protected')
    return 'protected'


def utc(value):
    return datetime.fromisoformat(value).astimezone(timezone.utc)


def envelope(identity, operation_id, access, files):
    """Trois références agrégées (empreinte, compteur dans revision), toujours présentes."""
    root = identity['root_agent_id']
    refs = [{'kind': 'tools_activity_calls', 'id': 'sha256:' + access['calls_sha256'],
             'revision': access['calls'], 'root_agent_id': root},
            {'kind': 'tools_activity_events', 'id': 'sha256:' + access['events_sha256'],
             'revision': access['events'], 'root_agent_id': root},
            {'kind': 'tools_file_dependencies', 'id': 'sha256:' + files['dependencies_sha256'],
             'revision': files['dependencies'], 'root_agent_id': root}]
    # Horodatage fixe, lu en base : une réémission donne le même reçu, octet pour octet.
    composed = max(utc(access['sealed_at']), utc(files['sealed_at'])).isoformat()
    private = {'format': 1, 'identity': identity, 'operation_id': operation_id, 'composed_at': composed,
               'access': {k: access[k] for k in ('calls', 'events', 'calls_sha256', 'events_sha256', 'sealed_at')},
               'files': {k: files[k] for k in ('dependencies', 'dependencies_sha256', 'sealed_at')}}
    value = {**identity, 'state': 'retired_confirmed', 'inventory_complete': True, 'operation_id': operation_id,
             'receipt_sha256': hashlib.sha256(canonical(private).encode()).hexdigest(),
             'references': refs, 'contracts': dict(CONTRACTS)}
    return private, value


class Retention846:
    def __init__(self, *, access, files, recovery, live, state_dir, operation_id,
                 now=lambda: datetime.now(timezone.utc)):
        if str(UUID(operation_id)) != operation_id:
            raise Refused('Canonical operation UUID required')
        self.access, self.files, self.recovery, self.live = access, files, recovery, live
        self.dir, self.operation, self.now = private_dir(state_dir), operation_id, now

    @asynccontextmanager
    async def _access_tx(self, c):
        await c.execute('BEGIN')
        try:
            yield
        except BaseException:
            try:
                await c.execute('ROLLBACK')
            except Exception:
                pass
            raise
        try:
            await c.execute('COMMIT')
        except BaseException as exc:
            raise Unknown('Access COMMIT unconfirmed') from exc

    @asynccontextmanager
    async def _files_tx(self, c):
        from .storage.files_postgres import CommitUnknown
        try:
            async with self.recovery.catalog.transaction(c):
                yield
        except CommitUnknown as exc:
            raise Unknown('Files COMMIT unconfirmed') from exc

    def _intent(self, identity, create=False):
        expected = {'operation_id': self.operation, 'tenant_id': identity['tenant_id'],
                    'mission_id': identity['mission_id'], 'root_agent_id': identity['root_agent_id'],
                    'claim_sha256': fingerprint(identity)}
        current = load(self.dir, 'intent.json')
        if current is None and create:
            save(self.dir, 'intent.json', expected)
        elif current != expected:
            raise Refused('Operation intent differs from this claim')

    def _require(self, name, states, identity):
        result = load(self.dir, name)
        if (not isinstance(result, dict) or result.get('state') not in states
                or result.get('operation_id') != self.operation or result.get('claim_sha256') != fingerprint(identity)):
            raise Refused('Previous confirmed step required: ' + name)

    async def _step(self, connect, transaction, token, effect):
        identity, expires = self.live(token)
        async with connect() as c, transaction(c):
            # Le callback de la seconde vérification tient dans la transaction.
            await c.execute("SET LOCAL idle_in_transaction_session_timeout='20000ms'")
            result = await effect(c, identity, expires)
            if self.live(token) != (identity, expires):
                raise Refused('Retention claim changed')
            if self.now() >= expires:
                raise Refused('Retention proof expired')
        return result

    async def access_prepare(self, token):
        async def effect(c, identity, expires):
            self._intent(identity, create=True)
            row = await (await c.execute(
                'SELECT tools_access.mission_retirement_prepare(%s,%s,%s,%s,%s,%s,%s,%s,%s) AS result',
                (self.operation, identity['tenant_id'], identity['mission_id'], identity['root_agent_id'],
                 identity['claim_id'], identity['claim_revision'], fingerprint(identity),
                 identity['retain_until'], expires))).fetchone()
            return row['result']
        return await self._step(self.access, self._access_tx, token, effect)

    async def files_prepare(self, token):
        async def effect(c, identity, expires):
            self._intent(identity)
            self._require('access-prepare.json', {'prepared', 'sealed'}, identity)
            return await self.recovery.closure_prepare(
                c, operation_id=self.operation, tenant_id=identity['tenant_id'], mission_id=identity['mission_id'],
                root_agent_id=identity['root_agent_id'], claim_sha256=fingerprint(identity))
        return await self._step(self.files, self._files_tx, token, effect)

    async def access_retire(self, token, batch):
        async def effect(c, identity, expires):
            self._intent(identity)
            self._require('files-prepare.json', {'prepared', 'sealed'}, identity)
            row = await (await c.execute('SELECT tools_access.mission_retirement_batch(%s,%s,%s,%s) AS result',
                                         (self.operation, fingerprint(identity), expires, batch))).fetchone()
            return row['result']
        return await self._step(self.access, self._access_tx, token, effect)

    async def files_retire(self, token, batch):
        async def effect(c, identity, expires):
            self._intent(identity)
            # Les calls partent d'abord ; la protection des fichiers est libérée en dernier.
            self._require('access-retire.json', {'sealed'}, identity)
            return await self.recovery.closure_retire(c, operation_id=self.operation,
                                                      claim_sha256=fingerprint(identity), batch=batch)
        return await self._step(self.files, self._files_tx, token, effect)

    async def _status(self, scope):
        async with self.access() as c, self._access_tx(c):
            await c.execute('SET TRANSACTION READ ONLY')
            access = (await (await c.execute('SELECT tools_access.mission_retirement_status(%s,%s,%s) AS result',
                                             (self.operation, *scope))).fetchone())['result']
        async with self.files() as c, self._files_tx(c):
            await c.execute('SET TRANSACTION READ ONLY')
            files = await self.recovery.closure_status(c, operation_id=self.operation,
                                                       tenant_id=scope[0], mission_id=scope[1])
        return access, files

    async def receipt(self, token):
        if not (getattr(self.recovery.settings, 'files_recovery_enabled', False)
                and getattr(self.recovery.settings, 'files_mission_dependencies_enabled', False)):
            raise Refused('recovery845 and Files dependencies required for a Tools receipt')
        identity, expires = self.live(token)
        self._intent(identity)
        access, files = await self._status((identity['tenant_id'], identity['mission_id']))
        digest = fingerprint(identity)
        if (access.get('state'), files.get('state')) != ('sealed', 'sealed') or {
                access.get('claim_sha256'), files.get('claim_sha256')} != {digest}:
            raise Refused('Both sealed registries required')
        private, value = envelope(identity, self.operation, access, files)
        for name, content in (('receipt.private.json', private), ('envelope.json', value)):
            existing = load(self.dir, name)
            if existing is not None and existing != content:
                raise Refused('Existing receipt differs; protected')
        if self.live(token) != (identity, expires) or self.now() >= expires:
            raise Refused('Retention claim changed')
        save(self.dir, 'receipt.private.json', private)
        save(self.dir, 'envelope.json', value)
        return {'state': 'sealed', 'operation_id': self.operation, 'claim_sha256': digest,
                'receipt_sha256': value['receipt_sha256'], 'references': len(value['references'])}

    async def reconcile(self):
        intent = load(self.dir, 'intent.json')
        if not isinstance(intent, dict) or intent.get('operation_id') != self.operation:
            raise Refused('Operation intent required')
        access, files = await self._status((intent['tenant_id'], intent['mission_id']))
        for stale in sorted(self.dir.glob('*.unknown.json')):
            os.replace(stale, stale.with_name(stale.name.replace('.unknown.json', '.reconciled.json')))
        return {'operation_id': self.operation, 'access': access, 'files': files,
                'next_step': next_step(access, files)}


async def run(core, args, token=None):
    """Une étape ; le résultat n'est écrit qu'après un COMMIT confirmé."""
    if args.step != 'reconcile' and any(core.dir.glob('*.unknown.json')):
        raise Refused('Unknown step outcome: reconcile first')
    try:
        if args.step == 'reconcile':
            observed = await core.reconcile()
        elif args.step == 'access-prepare':
            observed = await core.access_prepare(token)
        elif args.step == 'files-prepare':
            observed = await core.files_prepare(token)
        elif args.step == 'access-retire':
            observed = await core.access_retire(token, args.batch)
        elif args.step == 'files-retire':
            observed = await core.files_retire(token, args.batch)
        else:
            observed = await core.receipt(token)
    except Unknown:
        save(core.dir, args.step + '.unknown.json', {'step': args.step, 'operation_id': core.operation,
                                                    'status': 'unknown', 'blind_replay': False})
        raise
    save(core.dir, args.step + '.json', observed)
    return observed


def build(args):
    """Profil unique : Access maintenance (access_pg_role), Files maintenance (files_pg_role)."""
    import psycopg
    from psycopg.rows import dict_row

    from . import retention_proof_846
    from .auth import postgres_retention_846 as holds846
    from .auth.postgres_credentials import AccessCredentials
    from .config import get_settings
    from .storage.files_recovery import FileRecovery

    s = get_settings()
    if (s.access_backend != 'postgres' or not s.access_pg_ca_file or not s.access_mission_retention_enabled
            or any(key.startswith('PG') and value for key, value in os.environ.items())):
        raise Refused('Explicit Access 846 profile required')

    @asynccontextmanager
    async def access():
        credential = await AccessCredentials(s).sql()
        c = await psycopg.AsyncConnection.connect(**credential, autocommit=True, sslmode='verify-full',
            sslrootcert=s.access_pg_ca_file, target_session_attrs='read-write', connect_timeout=2,
            row_factory=dict_row, options='-c statement_timeout=5000 -c lock_timeout=3000')
        try:
            row = await (await c.execute('SELECT current_user AS role,current_database() AS db')).fetchone()
            contract = await (await c.execute('SELECT * FROM tools_access.retention_846_contract()')).fetchall()
            if row != {'role': s.access_pg_role, 'db': s.access_pg_database} or contract != [{
                    'version': holds846.VERSION, 'checksum': holds846.CHECKSUM, 'coordination_required': True}]:
                raise Refused('Access 846 maintenance identity or contract invalid')
            yield c
        finally:
            c.pgconn.finish()

    recovery = FileRecovery(s, app_role=args.files_app_role)
    return Retention846(access=access, files=recovery.connection, recovery=recovery,
                        live=lambda token: retention_proof_846.live(s, token),
                        state_dir=args.state_dir, operation_id=args.operation_id)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('step', choices=STEPS)
    parser.add_argument('--operation-id', required=True)
    parser.add_argument('--state-dir', type=Path, required=True)
    parser.add_argument('--proof-file', type=Path)
    parser.add_argument('--files-app-role', required=True)
    parser.add_argument('--batch', type=int, default=500)
    args = parser.parse_args()
    result = {'step': args.step, 'operation_id': args.operation_id, 'status': 'refused', 'blind_replay': False}
    try:
        token = None
        if args.step != 'reconcile':
            from .storage.files_credentials import private_text
            if not args.proof_file:
                raise Refused('Private proof file required')
            token = private_text(str(args.proof_file)).strip()
        core = build(args)
        result.update(status='ok', result=asyncio.run(asyncio.wait_for(run(core, args, token), 60)))
    except Unknown:
        result['status'] = 'unknown'
    except Exception as exc:
        # Nos refus sont des textes fixes ; un autre diagnostic (libpq, HTTP) ne sort pas.
        result['reason'] = str(exc) if isinstance(exc, (Refused, ValueError)) else type(exc).__name__
    print(json.dumps({k: v for k, v in result.items() if k != 'result'}
                     | {'state': (result.get('result') or {}).get('state'),
                        'next_step': (result.get('result') or {}).get('next_step')}))
    return 0 if result['status'] == 'ok' else 1


if __name__ == '__main__':
    raise SystemExit(main())
