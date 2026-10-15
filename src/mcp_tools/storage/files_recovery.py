"""Maintenance-only retirement ACK and physical recovery on a restored target.

No restoration, DDL, TTL reset or physical DELETE is reachable from files MCP.
GC wiring requires the reviewed physical domain lease and inventory provider.
"""
from datetime import datetime, timedelta, timezone
import json
import re
from uuid import UUID

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


    @staticmethod
    async def referenced(c, pin):
        # One SQL snapshot for both live roots and admitted open intentions.
        # Otherwise an intent could close/publish between two separate root reads.
        roots = await (await c.execute("""SELECT jsonb_build_array(jsonb_build_object(
                'generation',g.id::text,'path',g.path,'pin',g.pin)) sources
            FROM generations g JOIN refs r ON r.path=g.path
            LEFT JOIN blob_retirements retired ON retired.generation=g.id
            WHERE NOT r.deleted AND (g.id=r.generation OR retired.generation IS NULL)
            UNION ALL SELECT o.intent->'sources' sources FROM operations o
            WHERE NOT o.closed AND o.phase<>'BARRIER_OBSERVED' LIMIT 10001""")).fetchall()
        if len(roots) > 10000:
            return True  # Incomplete graph never proves absence of dependencies.
        pending = []
        for root in roots:
            if (not isinstance(root['sources'], list)
                    or len(pending) + len(root['sources']) > 10000):
                return True
            pending.extend(root['sources'])
        seen = set()
        examined = 0
        while pending:
            examined += 1
            if examined > 10000:
                return True
            entry = pending.pop()
            if (not isinstance(entry, dict) or not isinstance(entry.get('path'), str)
                    or not isinstance(entry.get('pin'), dict)):
                return True
            try:
                generation = UUID(str(entry['generation']))
            except (KeyError, ValueError, TypeError, AttributeError):
                return True
            row = await (await c.execute('SELECT id,path,pin,manifest FROM generations WHERE id=%s',
                                         (generation,))).fetchone()
            if (row is None or row['path'] != entry['path'] or row['pin'] != entry['pin']
                    or not isinstance(row['manifest'], list)
                    or any(not isinstance(row['pin'].get(field), str) or not row['pin'][field]
                           for field in ('key', 'version_id', 'sha256'))
                    or row['pin']['version_id'] == 'null'
                    or not re.fullmatch('[a-f0-9]{64}', row['pin']['sha256'])
                    or type(row['pin'].get('size')) is not int or row['pin']['size'] < 0):
                return True
            if (row['pin'].get('key'), row['pin'].get('version_id')) == (pin['key'], pin['version_id']):
                return True
            if generation not in seen:
                seen.add(generation)
                # Retired intermediate generations still carry immutable provenance.
                if len(pending) + len(row['manifest']) > 10000:
                    return True
                pending.extend(row['manifest'])
        return False

    async def collect(self, control, *, now, batch=100):
        if (now.tzinfo is None or now.utcoffset() is None or type(batch) is not int
                or not 1 <= batch <= 1000):
            raise StorageUnavailable('Aware clock and bounded collection required')
        result = {'deleted': 0, 'protected': 0, 'inspection_required': False}
        with control.registry.locked():
            try:
                if control.pending():
                    return {**result, 'domain_protected': True}
                if control.identity['system_id'] != self.settings.files_pg_system_identifier:
                    raise StorageUnavailable('Recovery physical domain differs from SQL profile')
                async with self.connection() as c:
                    rows = await (await c.execute("""SELECT generation,pin,retired_ack_at FROM blob_retirements
                        WHERE retired_ack_at IS NOT NULL AND recover_until<=%s AND delete_state<>'deleted'
                        ORDER BY recover_until,generation LIMIT %s""", (now, batch))).fetchall()
                for candidate in rows:
                    if control.protected(candidate['retired_ack_at']):
                        result['protected'] += 1
                        continue
                    pin = self.blobs.checked(candidate['pin'])
                    async with self.connection() as c:
                        async with self.catalog.transaction(c):
                            await c.execute("""SELECT pg_advisory_xact_lock(hashtextextended(
                                'files-recovery:' || jsonb_build_array(%s::text,%s::text)::text,0))""",
                                (pin['key'], pin['version_id']))
                            row = await self.catalog.one(c, 'SELECT * FROM blob_retirements WHERE generation=%s FOR UPDATE',
                                                         (candidate['generation'],))
                            if not row or row['pin'] != pin:
                                raise StorageUnavailable('Retirement pin changed')
                            state = row['delete_state']
                            if state == 'deleted':
                                continue
                            if (row['retired_ack_at'] != candidate['retired_ack_at'] or row['recover_until'] > now
                                    or await self.referenced(c, pin)):
                                result['protected'] += 1
                                continue
                            if state == 'retained':
                                await c.execute("UPDATE blob_retirements SET delete_state='delete_armed' "
                                                "WHERE generation=%s", (candidate['generation'],))
                            elif state != 'delete_armed':
                                raise StorageUnavailable('Unknown retirement state')
                    # Arm COMMIT is known. A previous arm is observation-only.
                    if state == 'delete_armed':
                        if not await self.blobs.absence(pin):
                            result['inspection_required'] = True
                            break
                    else:
                        await self.blobs.delete_once(pin)
                    async with self.connection() as c:
                        async with self.catalog.transaction(c):
                            changed = await (await c.execute("""UPDATE blob_retirements
                                SET delete_state='deleted',delete_ack_at=clock_timestamp()
                                WHERE generation=%s AND delete_state='delete_armed' AND pin=%s::jsonb
                                RETURNING generation""", (candidate['generation'], json.dumps(pin)))).fetchall()
                            if len(changed) != 1:
                                raise StorageUnavailable('Physical delete ACK not committed')
                    result['deleted'] += 1
                return result
            finally:
                await self.blobs.drain()
