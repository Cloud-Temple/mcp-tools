"""Backend async des routines #31, sans cache d'autorité ni retry d'écriture."""
from __future__ import annotations

import asyncio
import hashlib
import time
from datetime import datetime, timezone
from uuid import UUID

from .postgres_contract import authenticate_row
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

    def __init__(self, credentials, *, ca_file, role, database, timeout=5.0):
        if not 2 <= timeout <= 5:
            raise ValueError('Access operation budget must be between 2 and 5 seconds')
        self.credentials = credentials
        self.ca_file = ca_file
        self.role = role
        self.database = database
        self.timeout = timeout

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
        rows = await self._run('SELECT * FROM tools_access.credential_get(%s)', (binding,))
        if len(rows) > 1:
            raise TokenStoreUnavailable('Access credential multiplicity invalid')
        return authenticate_row(rows[0] if rows else None, binding, datetime.now(timezone.utc))

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
