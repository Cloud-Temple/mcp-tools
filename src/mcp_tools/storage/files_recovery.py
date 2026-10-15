"""Maintenance-only retirement ACK and physical recovery on a restored target.

No restoration, DDL, TTL reset or physical DELETE is reachable from files MCP.
GC wiring requires the reviewed physical domain lease and inventory provider.
"""
from datetime import datetime, timedelta, timezone

from .files_credentials import StorageUnavailable
from .files_postgres import Catalog
from .files_recovery_s3 import RecoveryBlobs


class FileRecovery:
    def __init__(self, settings, *, app_role):
        if (not settings.files_recovery_enabled
                or settings.files_pg_role != settings.files_recovery_maintenance_role
                or app_role in (settings.files_pg_role, settings.files_pg_owner)):
            raise StorageUnavailable('Separate recovery maintenance identity required')
        self.settings, self.app_role = settings, app_role
        self.catalog, self.blobs = Catalog(settings), RecoveryBlobs(settings)

    def connection(self):
        return self.catalog.connection(maintenance_app_role=self.app_role)

    async def acknowledge(self, *, batch=100):
        if type(batch) is not int or not 1 <= batch <= 1000:
            raise StorageUnavailable('Bounded recovery batch required')
        # A fresh current Vault connection and a known canonical COMMIT establish
        # an ACK after the logical retirement. No mutation of refs/TTL is needed.
        async with self.connection() as c:
            async with self.catalog.transaction(c):
                rows = await (await c.execute('''SELECT generation FROM blob_retirements
                    WHERE retired_ack_at IS NULL ORDER BY retired_at,generation LIMIT %s
                    FOR UPDATE SKIP LOCKED''', (batch,))).fetchall()
        ack = datetime.now(timezone.utc)
        async with self.connection() as c:
            async with self.catalog.transaction(c):
                changed = await (await c.execute('''UPDATE blob_retirements
                    SET retired_ack_at=%s,recover_until=GREATEST(recover_until,%s)
                    WHERE generation=ANY(%s::uuid[]) AND retired_ack_at IS NULL RETURNING generation''',
                    (ack, ack + timedelta(days=self.settings.files_recovery_days),
                     [row['generation'] for row in rows]))).fetchall()
        return {'acknowledged': len(changed), 'recovery_days_minimum': self.settings.files_recovery_days}

    async def reference(self, *, path, version_id):
        async with self.connection() as c:
            async with self.catalog.transaction(c):
                await c.execute('SET TRANSACTION READ ONLY')
                rows = await (await c.execute('''SELECT id,operation,path,pin,manifest,created_at
                    FROM generations WHERE path=%s AND pin->>'version_id'=%s LIMIT 2''',
                    (path, version_id))).fetchall()
                if len(rows) != 1:
                    raise StorageUnavailable('Exact owned restored generation required')
                row = rows[0]
                self.blobs.checked(row['pin'])
                return row

    async def recover(self, *, path, version_id):
        before = await self.reference(path=path, version_id=version_id)
        content = await self.blobs.read(before['pin'])
        after = await self.reference(path=path, version_id=version_id)
        if before != after:
            raise StorageUnavailable('Restored generation changed during recovery')
        return content
