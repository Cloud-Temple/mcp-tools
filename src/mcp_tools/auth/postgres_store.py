"""Backend async des routines #31, sans cache d'autorité ni retry d'écriture."""
from __future__ import annotations

import asyncio
import hashlib
import secrets
import re
import os
import time
from datetime import datetime, timedelta, timezone
from uuid import UUID, uuid4

from .postgres_contract import Credential, authenticate_row, utc
from .access_cursors import AccessCursors
from .context import current_access_operation
from .token_store import TokenStoreUnavailable

# Retenir les tâches jusqu'à leur terminaison, même pendant l'arrêt d'un appel.
_ACTIVE: set[asyncio.Task] = set()
_HUB_ACCESS_CONFIRM = 'SELECT * FROM tools_access.hub_access_confirm(%s,%s,%s,%s,%s,%s,%s,%s)'
_HUB_ACCESS_REFUSALS = {'local access changed', 'local binding changed', 'local access or binding changed'}
_HUB_ACCESS_ORIGIN = (
    r'PL/pgSQL function tools_access\.hub_access_confirm\(text,bigint,uuid,bigint,text,text,text,text\) '
    r'line [0-9]+ at RAISE'
)


class AccessMutationUncertain(TokenStoreUnavailable):
    """Référence publique disponible même si le COMMIT n'est pas confirmé."""
    def __init__(self, operation_id):
        super().__init__('Access mutation unavailable or uncertain; inspect without replay')
        self.operation_id = operation_id


def _finished(task):
    _ACTIVE.discard(task)
    if not task.cancelled():
        # Consommer l'exception d'une tâche tardive sans journaliser un diagnostic
        # libpq susceptible de contenir le conninfo.
        task.exception()


class PostgresAccessStore:
    """Le provider fourni lit Vault à chaque connexion ; aucun credential conservé."""

    def __init__(self, credentials, *, ca_file, role, database, timeout=5.0,
                 cursor_ttl=60, cursor_capacity=1024):
        if not 2 <= timeout <= 5:
            raise ValueError('Access operation budget must be between 2 and 5 seconds')
        self.credentials = credentials
        self.ca_file = ca_file
        self.role = role
        self.database = database
        self.timeout = timeout
        self.cursors = AccessCursors(ttl=cursor_ttl, capacity=cursor_capacity)

    async def _run(self, query, parameters):
        import psycopg
        from psycopg.rows import dict_row

        if any(key.startswith('PG') and value for key, value in os.environ.items()):
            raise TokenStoreUnavailable('Ambient PostgreSQL settings forbidden')
        if not psycopg.capabilities.has_cancel_safe():
            raise TokenStoreUnavailable('Access cancellation unavailable')
        deadline = time.monotonic() + self.timeout
        connection = None
        task = None
        try:
            async with asyncio.timeout(max(.001, deadline-time.monotonic()-1)):
                credential = await self.credentials.sql()
                if (credential.get('user') != self.role
                        or credential.get('dbname') != self.database
                        or set(credential) != {'host', 'port', 'dbname', 'user', 'password'}):
                    raise TokenStoreUnavailable('Access SQL identity invalid')
                connection = await psycopg.AsyncConnection.connect(
                    **credential, sslmode='verify-full', sslrootcert=self.ca_file,
                    target_session_attrs='read-write',
                    connect_timeout=2, row_factory=dict_row,
                    options='-c statement_timeout=2000 -c lock_timeout=1000 -c idle_in_transaction_session_timeout=3000')
                from .postgres_schema import CHECKSUM, VERSION
                async with connection.cursor() as check:
                    await check.execute('SELECT * FROM tools_access.schema_contract()', ())
                    if await check.fetchall() != [{'version': VERSION, 'checksum': CHECKSUM}]:
                        raise TokenStoreUnavailable('Access schema incompatible')
                    await check.execute("SELECT current_user AS role,current_database() AS db,pg_is_in_recovery() AS recovery,"
                        "(rolsuper OR rolcreatedb OR rolcreaterole OR rolreplication OR rolbypassrls) AS privileged "
                        "FROM pg_roles WHERE rolname=current_user", ())
                    if await check.fetchall() != [{'role': self.role, 'db': self.database,
                                                   'recovery': False, 'privileged': False}]:
                        raise TokenStoreUnavailable('Access SQL authority invalid')

            async def operation():
                async with connection.cursor() as cursor:
                    await cursor.execute(query, parameters)
                    rows = await cursor.fetchall()
                await connection.commit()
                return rows

            task = asyncio.create_task(operation())
            _ACTIVE.add(task)
            task.add_done_callback(_finished)
            done, _ = await asyncio.wait({task}, timeout=max(.001, deadline-time.monotonic()-1))
            if not done:
                raise TimeoutError()
            return task.result()
        except asyncio.CancelledError:
            raise
        except Exception as error:
            # Seul le refus métier connu de la décision finale devient un 403.
            # Une ACL refusée, un autre SQL42501 ou un diagnostic inattendu reste panne.
            if (query == _HUB_ACCESS_CONFIRM
                    and isinstance(error, psycopg.errors.InsufficientPrivilege)
                    and error.diag.message_primary in _HUB_ACCESS_REFUSALS
                    and re.fullmatch(_HUB_ACCESS_ORIGIN, error.diag.context or '')):
                raise ValueError('Current local hub access refused') from None
            # Aucun détail libpq/HTTP/conninfo ou résultat d'écriture sans ACK.
            raise TokenStoreUnavailable('Access operation unavailable or uncertain') from None
        finally:
            if connection is not None:
                if task is not None and not task.done():
                    try:
                        async with asyncio.timeout(min(.3, max(.001, deadline-time.monotonic()))):
                            await connection.cancel_safe(timeout=.2)
                    except BaseException:
                        pass
                # PQfinish ferme immédiatement le socket, sans ROLLBACK réseau
                # ou nouvelle tentative ; le serveur peut avoir déjà COMMIT.
                connection.pgconn.finish()
            if task is not None:
                if not task.done():
                    task.cancel()
                try:
                    async with asyncio.timeout(min(.3, max(.001, deadline-time.monotonic()))):
                        await asyncio.shield(task)
                except BaseException:
                    pass

    async def authenticate(self, bearer):
        if not isinstance(bearer, str) or not bearer or len(bearer) > 8192:
            return None
        binding = hashlib.sha256(bearer.encode()).hexdigest()
        return await self.authenticate_binding(binding)

    async def ready(self):
        """Contrat, identité et privilèges frais, sans credential utilisateur."""
        from .postgres_schema import APP_ROUTINES
        routines = ['tools_access.' + name for name in APP_ROUTINES]
        rows = await self._run("SELECT bool_and(has_function_privilege(current_user,r,'EXECUTE')) AS allowed "
            "FROM unnest(%s::text[]) r", (routines,))
        if rows != [{'allowed': True}]:
            raise TokenStoreUnavailable('Access SQL grants unavailable')
        return True

    async def authenticate_binding(self, binding):
        rows = await self._run('SELECT * FROM tools_access.credential_get(%s)', (binding,))
        if len(rows) > 1:
            raise TokenStoreUnavailable('Access credential multiplicity invalid')
        return authenticate_row(rows[0] if rows else None, binding, datetime.now(timezone.utc))

    async def _reader(self, requester):
        info = await self.authenticate_binding(requester)
        if info is None:
            raise ValueError('Current access required')
        return info

    async def list_credentials(self, requester, *, cursor=None, limit=50):
        """Le hash de tri reste privé ; continuation opaque liée aux droits frais."""
        if type(limit) is not int or not 1 <= limit <= 100:
            raise ValueError('Access page limit invalid')
        info = await self._reader(requester)
        if 'admin' not in info['permissions']:
            raise ValueError('Current admin required')
        binding = (requester, info['actor_id'], info['tenant_id'], info['service_id'],
                   info['version'], 'credentials', limit)
        after = self.cursors.resolve(cursor, binding) if cursor is not None else None
        rows = await self._run('SELECT * FROM tools_access.credential_list(%s,%s,%s)',
                               (requester, after, limit))
        # Aucune collection totale n'est annoncée : pages indépendantes et fraîches.
        fields = ('token_prefix', 'actor_id', 'tenant_id', 'service_id', 'client_name',
                  'permissions', 'tool_ids', 'created_at', 'expires_at', 'revoked', 'version')
        public = [{k: row[k] for k in fields} for row in rows]
        for row in public:
            row['expired'] = row['expires_at'] is not None and utc(row['expires_at']) <= datetime.now(timezone.utc)
            for key in ('actor_id', 'created_at', 'expires_at'):
                if row.get(key) is not None:
                    row[key] = str(row[key])
        continuation = (self.cursors.issue(binding, rows[-1]['cursor_key'])
                        if len(rows) == limit else None)
        # Un changement de droits pendant la lecture ne publie pas l'ancienne page.
        fresh = await self._reader(requester)
        if fresh['version'] != info['version'] or 'admin' not in fresh['permissions']:
            raise ValueError('Access changed during page read')
        return {'status': 'success', 'tokens': public, 'count': len(public),
                'next_cursor': continuation, 'page_complete': True}

    async def activity_page(self, requester, *, cursor=None, limit=50):
        if type(limit) is not int or not 1 <= limit <= 100:
            raise ValueError('Activity page limit invalid')
        info = await self._reader(requester)
        binding = (requester, info['actor_id'], info['tenant_id'], info['service_id'],
                   info['version'], 'activity', limit)
        stamp, call_id = self.cursors.resolve(cursor, binding) if cursor is not None else (None, None)
        rows = await self._run('SELECT * FROM tools_access.activity_page(%s,%s,%s,%s)',
                               (requester, stamp, call_id, limit))
        continuation = (self.cursors.issue(binding, (rows[-1]['created_at'], rows[-1]['call_id']))
                        if len(rows) == limit else None)
        fresh = await self._reader(requester)
        if fresh['version'] != info['version']:
            raise ValueError('Access changed during activity read')
        fields = ('call_id', 'actor_id', 'tenant_id', 'service_id', 'tool', 'trace_id',
                  'operation_id', 'mission_id', 'category', 'admission', 'created_at',
                  'expires_at', 'outcome', 'target_actor_id')
        public = [{k: str(row[k]) if isinstance(row[k], (UUID, datetime)) else row[k]
                   for k in fields} for row in rows]
        return {'status': 'ok', 'storage_backend': 'postgres', 'calls': public, 'count': len(public),
                'next_cursor': continuation, 'page_complete': True}

    async def _target(self, requester, reference):
        if not isinstance(reference, str) or not re.fullmatch(r'[0-9a-f]{12}', reference):
            raise ValueError('Access reference must come from the current list')
        rows = await self._run('SELECT * FROM tools_access.credential_target(%s,%s)',
                               (requester, reference))
        if len(rows) != 1:
            raise ValueError('Access reference absent or ambiguous; refresh the list')
        return Credential.from_row(rows[0])

    async def _mutation(self, query, parameters, operation, *, changed=True):
        try:
            rows = await self._run(query, parameters)
            if changed:
                self._changed(rows)
            return rows
        except TokenStoreUnavailable:
            raise AccessMutationUncertain(operation) from None

    async def info(self, requester, reference):
        current = await self._target(requester, reference)
        return {'status': 'success', **current.public_view(),
                'expired': current.expires_at is not None and current.expires_at <= datetime.now(timezone.utc),
                'token_prefix': current.token_hash[:12]}

    async def create(self, requester, *, client_name, tenant_id, service_id,
                     permissions, tool_ids, expires_days=90, actor_id=None):
        if type(expires_days) is not int or not 0 <= expires_days <= 3650:
            raise ValueError('Access expiry must be between 0 and 3650 days')
        raw = secrets.token_urlsafe(32)
        now = datetime.now(timezone.utc)
        current = self._request_credential(dict(token_hash=hashlib.sha256(raw.encode()).hexdigest(),
            actor_id=str(UUID(str(actor_id))) if actor_id is not None else str(uuid4()),
            tenant_id=tenant_id, service_id=service_id, client_name=client_name,
            permissions=permissions, tool_ids=tool_ids, created_at=now,
            expires_at=now+timedelta(days=expires_days) if expires_days else None,
            revoked_at=None, version=1))
        operation = current_access_operation.get() or str(uuid4())
        await self._mutation('SELECT tools_access.credential_create(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) AS changed',
            (requester, operation, current.token_hash, current.actor_id, tenant_id, service_id,
             client_name, list(current.permissions), list(current.tool_ids), current.expires_at), operation)
        # Le brut n'est publié qu'après l'ACK confirmé de COMMIT par _run.
        public = current.public_view()
        # created_at est DEFAULT clock_timestamp() en SQL : ne pas fabriquer
        # une date canonique depuis l'horloge du processus avant l'insertion.
        public.pop('created_at', None)
        return {'status': 'success', 'token': raw, 'token_prefix': current.token_hash[:12],
                'operation_id': operation, **public}

    @staticmethod
    def _request_credential(row):
        try:
            return Credential.from_row(row)
        except TokenStoreUnavailable:
            raise ValueError('Access request fields invalid') from None

    @staticmethod
    def _changed(rows):
        if len(rows) != 1 or rows[0].get('changed') is not True:
            raise TokenStoreUnavailable('Access mutation unconfirmed')

    async def update(self, requester, reference, expected_version, *, permissions=None,
                     tool_ids=None, client_name=None):
        current = await self._target(requester, reference)
        if type(expected_version) is not int or expected_version != current.version:
            raise ValueError('Access version conflict; refresh before retrying')
        # Validation locale stricte ; la routine SQL vérifie à nouveau ses contraintes.
        proposed = self._request_credential({**current.__dict__,
            'permissions': list(current.permissions) if permissions is None else permissions,
            'tool_ids': list(current.tool_ids) if tool_ids is None else tool_ids,
            'client_name': current.client_name if client_name is None else client_name})
        operation = current_access_operation.get() or str(uuid4())
        await self._mutation('SELECT tools_access.credential_update(%s,%s,%s,%s,%s,%s,%s) AS changed',
            (requester, operation, current.token_hash, expected_version, proposed.client_name,
             list(proposed.permissions), list(proposed.tool_ids)), operation)
        return {'status': 'success', 'operation_id': operation, 'version': expected_version+1}

    async def revoke(self, requester, reference, expected_version):
        current = await self._target(requester, reference)
        if type(expected_version) is not int or expected_version != current.version:
            raise ValueError('Access version conflict; refresh before retrying')
        operation = current_access_operation.get() or str(uuid4())
        await self._mutation('SELECT tools_access.credential_revoke(%s,%s,%s,%s) AS changed',
            (requester, operation, current.token_hash, expected_version), operation)
        return {'status': 'success', 'operation_id': operation, 'version': expected_version+1,
                'revoked': True}

    async def admit(self, *, call_id, bearer, tool, trace_id, operation_id=None):
        return await self.admit_binding(call_id=call_id, binding=hashlib.sha256(bearer.encode()).hexdigest(),
                                        tool=tool, trace_id=trace_id, operation_id=operation_id)

    async def admit_binding(self, *, call_id, binding, tool, trace_id, operation_id=None):
        # UUIDs fournis avant toute écriture ; aucun renouvellement si incertitude.
        ids = tuple(str(UUID(str(value))) if value is not None else None
                    for value in (call_id, trace_id, operation_id))
        rows = await self._run('SELECT tools_access.admit_technical(%s,%s,%s,%s,%s) AS admitted',
                               (ids[0], binding, tool, ids[1], ids[2]))
        if len(rows) != 1 or type(rows[0].get('admitted')) is not bool:
            raise TokenStoreUnavailable('Access admission invalid')
        return rows[0]['admitted']

    async def finish(self, call_id, outcome):
        rows = await self._run('SELECT tools_access.finish_activity(%s,%s) AS inserted',
                               (str(UUID(str(call_id))), outcome))
        if len(rows) != 1 or type(rows[0].get('inserted')) is not bool:
            raise TokenStoreUnavailable('Access terminal invalid')
        return rows[0]['inserted']

    async def hub_binding(self, requester, claims):
        rows = await self._run('SELECT * FROM tools_access.hub_binding_get(%s,%s,%s,%s,%s)',
            (requester, claims['iss'], claims['sub'], claims['owner_id'], claims['tenant_id']))
        if len(rows) != 1:
            raise ValueError('Current local hub binding required')
        row = rows[0]
        if (row['revoked_at'] is not None or utc(row['expires_at']) <= datetime.now(timezone.utc)):
            raise ValueError('Local hub binding expired or revoked')
        return row

    async def admit_mission(self, *, call_id, binding, tool, trace_id, operation_id, claims):
        ids = tuple(str(UUID(str(value))) for value in (call_id, trace_id, operation_id))
        rows = await self._run('SELECT tools_access.admit_mission(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) AS admitted',
            (ids[0], binding, tool, ids[1], ids[2], claims['iss'], claims['sub'], claims['owner_id'],
             claims['tenant_id'], claims['mission_id'], claims['root_agent_id'], claims['request_sha256'],
             datetime.fromtimestamp(claims['exp'], timezone.utc)))
        if rows != [{'admitted': True}]:
            raise ValueError('Mission admission refused')
        return True

    async def confirm_hub_access(self, requester, info, local, claims):
        """Une seule transaction verrouille et compare credential ET mapping."""
        rows = await self._run(_HUB_ACCESS_CONFIRM,
            (requester, info['version'], str(local['id']), local['version'], claims['iss'],
             claims['sub'], claims['owner_id'], claims['tenant_id']))
        if len(rows) != 1:
            raise ValueError('Final local access unavailable')
        row = rows[0]
        if (row.get('credential_version') != info['version'] or str(row.get('binding_id')) != str(local['id'])
                or row.get('binding_version') != local['version']):
            raise ValueError('Final local access version changed')
        return {**row, 'credential_expires_at': utc(row['credential_expires_at']) if row['credential_expires_at'] is not None else None,
                'binding_expires_at': utc(row['binding_expires_at'])}

    async def hub_activity_page(self, requester, info, local, claims, *, cursor=None, limit=50):
        if type(limit) is not int or not 1 <= limit <= 100:
            raise ValueError('Invalid batch limit')
        binding = (requester, info['actor_id'], info['tenant_id'], info['service_id'], info['version'],
            'hub-activity', str(local['id']), local['version'], str(local['expires_at']),
            claims['iss'], claims['sub'], claims['owner_id'], claims['mission_id'], claims['root_agent_id'], limit)
        stamp, call = self.cursors.resolve(cursor, binding) if cursor is not None else (None, None)
        rows = await self._run('SELECT * FROM tools_access.hub_activity_page(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)',
            (requester, claims['iss'], claims['sub'], claims['owner_id'], claims['tenant_id'],
             claims['mission_id'], claims['root_agent_id'], stamp, call, limit))
        fields = ('call_id', 'actor_id', 'tenant_id', 'service_id', 'tool', 'trace_id', 'operation_id',
                  'mission_id', 'category', 'admission', 'created_at', 'expires_at', 'outcome', 'target_actor_id')
        calls = [{key: str(row[key]) if isinstance(row[key], (UUID, datetime)) else row[key]
                  for key in fields} for row in rows]
        cursor = self.cursors.issue(binding, (rows[-1]['created_at'], rows[-1]['call_id'])) if len(rows) == limit else None
        return {'calls': calls, 'count': len(calls), 'next_cursor': cursor, 'page_complete': True}

    async def hub_file_calls(self, requester, claims, calls):
        ids = [str(UUID(value)) for value in calls]
        if not 1 <= len(ids) <= 64 or len(set(ids)) != len(ids):
            raise ValueError('Invalid hub file batch')
        rows = await self._run('SELECT * FROM tools_access.hub_file_calls(%s,%s,%s,%s,%s,%s,%s,%s)',
            (requester, claims['iss'], claims['sub'], claims['owner_id'], claims['tenant_id'],
             claims['mission_id'], claims['root_agent_id'], ids))
        if {str(r['call_id']) for r in rows} != set(ids) or len(rows) != len(ids):
            raise ValueError('Hub file reference refused')
        return {str(r['call_id']): str(r['operation_id']) if r['operation_id'] is not None else None
                for r in rows}

    async def create_hub_binding(self, requester, *, actor_id, issuer, subject, owner_id, tenant_id, expires_at):
        # Expiry et identités sont ensuite contraintes par SQL ; pas de mapping implicite.
        operation = current_access_operation.get() or str(uuid4())
        expiry = utc(datetime.fromisoformat(expires_at))
        rows = await self._mutation('SELECT tools_access.hub_binding_create(%s,%s,%s,%s,%s,%s,%s,%s) AS binding_id',
            (requester, operation, str(UUID(actor_id)), issuer, subject, owner_id, tenant_id, expiry), operation, changed=False)
        if len(rows) != 1 or not rows[0].get('binding_id'):
            raise AccessMutationUncertain(operation)
        return {'status': 'success', 'binding_id': str(rows[0]['binding_id']), 'version': 1,
                'operation_id': operation}

    async def revoke_hub_binding(self, requester, binding_id, expected_version):
        if type(expected_version) is not int or expected_version < 1:
            raise ValueError('Expected binding version required')
        operation = current_access_operation.get() or str(uuid4())
        await self._mutation('SELECT tools_access.hub_binding_revoke(%s,%s,%s,%s) AS changed',
            (requester, operation, str(UUID(binding_id)), expected_version), operation)
        return {'status': 'success', 'binding_id': binding_id, 'version': expected_version+1,
                'revoked': True, 'operation_id': operation}

    async def list_hub_bindings(self, requester, actor_id, *, cursor=None, limit=50):
        if type(limit) is not int or not 1 <= limit <= 100:
            raise ValueError('Invalid binding page limit')
        actor_id = str(UUID(actor_id))
        info = await self._reader(requester)
        if 'admin' not in info['permissions']:
            raise ValueError('Current admin required')
        binding = (requester, info['version'], 'hub-bindings', actor_id, limit)
        after = self.cursors.resolve(cursor, binding) if cursor is not None else None
        rows = await self._run('SELECT * FROM tools_access.hub_binding_list(%s,%s,%s,%s)',
                                (requester, actor_id, after, limit))
        fresh = await self._reader(requester)
        if fresh['version'] != info['version'] or 'admin' not in fresh['permissions']:
            raise ValueError('Admin changed during read')
        public = [{key: str(value) if isinstance(value, (datetime, UUID)) else value
                   for key, value in row.items()} for row in rows]
        cursor = self.cursors.issue(binding, rows[-1]['id']) if len(rows) == limit else None
        return {'status': 'success', 'bindings': public, 'count': len(public),
                'next_cursor': cursor, 'page_complete': True}
