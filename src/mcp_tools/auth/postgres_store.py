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
from .token_store import TokenStoreUnavailable

# Retenir les tâches jusqu'à leur terminaison, même pendant l'arrêt d'un appel.
_ACTIVE: set[asyncio.Task] = set()


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
        except Exception:
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
        operation = str(uuid4())
        rows = await self._run('SELECT tools_access.credential_create(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) AS changed',
            (requester, operation, current.token_hash, current.actor_id, tenant_id, service_id,
             client_name, list(current.permissions), list(current.tool_ids), current.expires_at))
        self._changed(rows)
        # Le brut n'est publié qu'après l'ACK confirmé de COMMIT par _run.
        return {'status': 'success', 'token': raw, 'token_prefix': current.token_hash[:12],
                'operation_id': operation, **current.public_view()}

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
        operation = str(uuid4())
        rows = await self._run('SELECT tools_access.credential_update(%s,%s,%s,%s,%s,%s,%s) AS changed',
            (requester, operation, current.token_hash, expected_version, proposed.client_name,
             list(proposed.permissions), list(proposed.tool_ids)))
        self._changed(rows)
        return {'status': 'success', 'operation_id': operation, 'version': expected_version+1}

    async def revoke(self, requester, reference, expected_version):
        current = await self._target(requester, reference)
        if type(expected_version) is not int or expected_version != current.version:
            raise ValueError('Access version conflict; refresh before retrying')
        operation = str(uuid4())
        rows = await self._run('SELECT tools_access.credential_revoke(%s,%s,%s,%s) AS changed',
            (requester, operation, current.token_hash, expected_version))
        self._changed(rows)
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
