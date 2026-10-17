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


    def mission_scope(self, tenant_id, mission_id, root_agent_id, batch):
        if (not getattr(self.settings, 'files_mission_dependencies_enabled', False)
                or type(batch) is not int or not 1 <= batch <= 1000
                or not all(isinstance(v, str) and v for v in (tenant_id, mission_id, root_agent_id))
                or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}', tenant_id)
                or not re.fullmatch(r'mis_[A-Za-z0-9_-]+', mission_id)
                or not re.fullmatch(r'ag_[A-Za-z0-9_-]+', root_agent_id)):
            raise StorageUnavailable('Exact Mission scope and bounded batch required')

    async def dependencies(self, *, tenant_id, mission_id, root_agent_id, batch=1000):
        """#846 inventory of one exact Mission scope, read-only, no physical key or content."""
        self.mission_scope(tenant_id, mission_id, root_agent_id, batch)
        async with self.connection() as c, self.catalog.transaction(c):
            await c.execute('SET TRANSACTION READ ONLY')
            rows = await (await c.execute('''SELECT d.call_id,d.activity_operation_id,d.generation,d.path,
                    d.pin->>'version_id' version_id,d.pin->>'sha256' sha256,d.served_revision,d.state,
                    d.revision,d.acquired_at,d.retired_at,
                    EXISTS(SELECT 1 FROM refs r WHERE r.path=d.path AND NOT r.deleted)
                      AND NOT EXISTS(SELECT 1 FROM blob_retirements b WHERE b.generation=d.generation) visible
                    FROM mission_file_dependencies d
                    WHERE d.tenant_id=%s AND d.mission_id=%s AND d.root_agent_id=%s
                ORDER BY d.call_id,d.generation LIMIT %s''',
                (tenant_id, mission_id, root_agent_id, batch + 1))).fetchall()
        complete = len(rows) <= batch
        return {'category': 'tools_file_dependency', 'complete': complete,
                'active': sum(r['state'] == 'active' for r in rows[:batch]),
                'rows': [{k: (str(v) if isinstance(v, UUID) else v.isoformat() if hasattr(v, 'isoformat') else v)
                          for k, v in r.items()} for r in rows[:batch]]}

    async def retire_dependencies(self, *, tenant_id, mission_id, root_agent_id, batch=1000):
        """#846: retire only the exact Mission scope; another Mission keeps its rows."""
        self.mission_scope(tenant_id, mission_id, root_agent_id, batch)
        async with self.connection() as c, self.catalog.transaction(c):
            rows = await (await c.execute('''UPDATE mission_file_dependencies
                SET state='retired',retired_at=clock_timestamp(),revision=revision+1
                WHERE (call_id,generation) IN (SELECT call_id,generation FROM mission_file_dependencies
                  WHERE tenant_id=%s AND mission_id=%s AND root_agent_id=%s AND state='active'
                  ORDER BY call_id,generation LIMIT %s FOR UPDATE)
                RETURNING call_id,generation,revision''',
                (tenant_id, mission_id, root_agent_id, batch))).fetchall()
        # Returned only after a known COMMIT; a full batch says nothing about completeness.
        return {'retired': len(rows), 'complete': len(rows) < batch,
                'rows': [{'call_id': str(r['call_id']), 'generation': str(r['generation']),
                          'revision': r['revision']} for r in rows]}

    @staticmethod
    async def referenced(c, pin, *, dependencies=False):
        # One SQL snapshot for both live roots and admitted open intentions.
        # Otherwise an intent could close/publish between two separate root reads.
        # #846: an active Mission dependency is a root of its exact generation.
        extra = ("""UNION ALL SELECT jsonb_build_array(jsonb_build_object(
                'generation',g.id::text,'path',g.path,'pin',g.pin)) sources
            FROM mission_file_dependencies d JOIN generations g ON g.id=d.generation
            WHERE d.state='active'
            """ if dependencies else "")
        roots = await (await c.execute("""SELECT jsonb_build_array(jsonb_build_object(
                'generation',g.id::text,'path',g.path,'pin',g.pin)) sources
            FROM generations g JOIN refs r ON r.path=g.path
            LEFT JOIN blob_retirements retired ON retired.generation=g.id
            WHERE NOT r.deleted AND (g.id=r.generation OR retired.generation IS NULL)
            UNION ALL SELECT o.intent->'sources' sources FROM operations o
            WHERE NOT o.closed """ + extra + "LIMIT 10001")).fetchall()
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
                                    or await self.referenced(c, pin, dependencies=getattr(
                                        self.settings, 'files_mission_dependencies_enabled', False))):
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
