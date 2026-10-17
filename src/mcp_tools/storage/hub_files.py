"""Lecture #843 d'une publication Files exacte ; aucune commande MCP ni mutation."""

import base64
from uuid import UUID

from .files_service import get_files_service, public_ref


async def published(files, call_id, operation_id, claims=None):
    """Une seule source exacte : publication 843 OU dépendance #846, sinon None."""
    dependencies = claims is not None and getattr(
        getattr(files, 's', None), 'files_mission_dependencies_enabled', False)
    if operation_id is None and not dependencies:
        return None
    found = []
    async with files.catalog.connection() as connection:
        if operation_id is not None:
            row = await files.catalog.one(connection, """
                SELECT o.path,o.expected_revision+1 AS revision,g.id AS generation,g.pin
                FROM operations o JOIN generations g ON g.operation=o.id AND g.id=o.generation
                WHERE o.id=%s AND o.origin_call_id=%s AND o.intent->>'operation' IN ('write','concat')
                AND EXISTS(SELECT 1 FROM receipts r WHERE r.operation=o.id AND r.kind='publication')
                """, (operation_id, call_id))
            if row is not None:
                found.append(row)
        if dependencies:
            # Lecture seule B : dépendance locale exacte sous le scope des claims,
            # génération et pin servis, encore visibles (ni ref supprimée ni retrait 845).
            row = await files.catalog.one(connection, """
                SELECT d.path,d.served_revision AS revision,g.id AS generation,g.pin,count(*) OVER () AS matches
                FROM mission_file_dependencies d
                JOIN generations g ON g.id=d.generation AND g.path=d.path AND g.pin=d.pin
                WHERE d.call_id=%s::uuid AND d.activity_operation_id IS NOT DISTINCT FROM %s::uuid
                AND d.state='active' AND d.tenant_id=%s AND d.mission_id=%s AND d.root_agent_id=%s
                AND generation_visible(g.id) ORDER BY g.id LIMIT 1
                """, (call_id, operation_id, claims['tenant_id'], claims['mission_id'], claims['root_agent_id']))
            if row is not None:
                row = dict(row)
                found += [row] * min(row.pop('matches'), 2)
    # Zéro, deux dépendances (diff) ou deux sources : aucun choix arbitraire.
    return found[0] if len(found) == 1 else None


async def read_hub_files(calls, body, cfg, check, *, files_factory=None, claims=None):
    """Les calls ont déjà été filtrés par l'autorité SQL31, pas par des paths UI."""
    files = (files_factory or get_files_service)()
    result = []
    for call_id in body['call_ids']:
        row = await published(files, call_id, calls[call_id], claims)
        if row is None:
            result.append({'call_id': call_id, 'reference_state': 'unavailable'})
            continue
        item = {'call_id': call_id, 'reference_state': 'available',
                **public_ref({**row, 'deleted': False})}
        # public_ref ne restitue jamais la physical_key ni les credentials S3.
        if body.get('content'):
            offset, limit = body['offset'], min(body['limit'], cfg.hub_files_page_bytes)
            data = await files.blobs.get_hub(row['pin'], check)  # taille/hash/version vérifiés chez Tools
            if offset > len(data):
                raise ValueError('Invalid content range')
            part = data[offset:offset+limit]
            item.update(content_base64=base64.b64encode(part).decode('ascii'), encoding='base64',
                        offset=offset, returned_bytes=len(part), next_offset=offset+len(part),
                        end=offset+len(part) == len(data))
            if await published(files, call_id, calls[call_id], claims) != row:
                raise ValueError('File publication changed')
        result.append(item)
    return {'files': result, 'count': len(result), 'page_complete': True}


def validate_request(body, claims):
    if (set(body) - {'mission_id', 'root_agent_id', 'call_ids', 'content', 'offset', 'limit'}
            or body.get('mission_id') != claims['mission_id']
            or body.get('root_agent_id') != claims['root_agent_id']
            or not isinstance(body.get('call_ids'), list) or not 1 <= len(body['call_ids']) <= 64):
        raise ValueError('Invalid file request')
    ids = body['call_ids']
    if any(not isinstance(value, str) or str(UUID(value)) != value for value in ids) or len(set(ids)) != len(ids):
        raise ValueError('Invalid file references')
    if body.get('content') is True:
        if (len(ids) != 1 or type(body.get('offset')) is not int or body['offset'] < 0
                or type(body.get('limit')) is not int or not 1 <= body['limit'] <= 30000):
            raise ValueError('Invalid file range')
    elif set(body) & {'content', 'offset', 'limit'}:
        raise ValueError('Unexpected file fields')
