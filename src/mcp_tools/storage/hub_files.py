"""Lecture #843 d'une publication Files exacte ; aucune commande MCP ni mutation."""

import base64
from uuid import UUID

from .files_service import get_files_service, public_ref


async def published(files, call_id, operation_id):
    if operation_id is None:
        return None
    async with files.catalog.connection() as connection:
        return await files.catalog.one(connection, """
            SELECT o.path,o.expected_revision+1 AS revision,g.id AS generation,g.pin
            FROM operations o JOIN generations g ON g.operation=o.id AND g.id=o.generation
            WHERE o.id=%s AND o.origin_call_id=%s AND o.intent->>'operation' IN ('write','concat')
            AND EXISTS(SELECT 1 FROM receipts r WHERE r.operation=o.id AND r.kind='publication')
            """, (operation_id, call_id))


async def read_hub_files(calls, body, cfg, *, files_factory=None):
    """Les calls ont déjà été filtrés par l'autorité SQL31, pas par des paths UI."""
    files = (files_factory or get_files_service)()
    result = []
    for call_id in body['call_ids']:
        row = await published(files, call_id, calls[call_id])
        if row is None:
            result.append({'call_id': call_id, 'reference_state': 'unavailable'})
            continue
        item = {'call_id': call_id, 'reference_state': 'available',
                **public_ref({**row, 'deleted': False})}
        # public_ref ne restitue jamais la physical_key ni les credentials S3.
        if body.get('content'):
            offset, limit = body['offset'], min(body['limit'], cfg.hub_files_page_bytes)
            data = await files.blobs.get(row['pin'])  # taille/hash/version vérifiés chez Tools
            if offset > len(data):
                raise ValueError('Invalid content range')
            part = data[offset:offset+limit]
            item.update(content_base64=base64.b64encode(part).decode('ascii'), encoding='base64',
                        offset=offset, returned_bytes=len(part), next_offset=offset+len(part),
                        end=offset+len(part) == len(data))
            if await published(files, call_id, calls[call_id]) != row:
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
