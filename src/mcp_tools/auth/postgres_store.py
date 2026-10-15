"""Backend async des routines #31, sans cache d'autorité ni retry d'écriture."""
from __future__ import annotations

import asyncio
import hashlib
import time
from datetime import datetime, timezone
from uuid import UUID

from .postgres_contract import authenticate_row
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
                    connect_timeout=2, row_factory=dict_row,
                    options='-c statement_timeout=2000 -c lock_timeout=1000 -c idle_in_transaction_session_timeout=3000')

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
        return {'status': 'ok', 'calls': public, 'count': len(public),
                'next_cursor': continuation, 'page_complete': True}

    async def admit(self, *, call_id, bearer, tool, trace_id, operation_id=None):
        # UUIDs fournis avant toute écriture ; aucun renouvellement si incertitude.
        ids = tuple(str(UUID(str(value))) if value is not None else None
                    for value in (call_id, trace_id, operation_id))
        binding = hashlib.sha256(bearer.encode()).hexdigest()
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
