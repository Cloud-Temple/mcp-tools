"""Surfaces HTTP du profil accès PG, sans magasin S3 ni journal de secours."""
import json
from urllib.parse import parse_qs

from ..auth.access_runtime import get_access_store
from ..auth.context import current_token_info
from ..auth.postgres_store import AccessMutationUncertain


async def handle_postgres_admin(scope, receive, send, mcp):
    from .api import (_send_json, _read_body, _handle_health,
                      _handle_tools_list, _handle_tools_run)
    path, method = scope.get('path', ''), scope.get('method', 'GET')
    auth = dict(scope.get('headers', [])).get(b'authorization', b'').decode('latin-1')
    store = get_access_store()
    info = await store.authenticate(auth[7:]) if auth.startswith('Bearer ') else None
    if info is None:
        return await _send_json(send, {'status': 'error', 'message': 'Current access required'}, 401)
    requester = info['credential_binding'].partition(':')[2]
    context = current_token_info.set(info)
    try:
        query = parse_qs(scope.get('query_string', b'').decode(), keep_blank_values=True)
        if any(len(values) != 1 for values in query.values()):
            raise ValueError('Duplicate page parameter')
        limit = int(query.get('limit', ['50'])[0])
        cursor = query.get('cursor', [None])[0]
        if path == '/admin/api/me' and method == 'GET':
            return await _send_json(send, {'status': 'ok', 'access_backend': 'postgres',
                'is_admin': 'admin' in info['permissions'],
                **{k: v for k, v in info.items() if k != 'credential_binding'}})
        if path == '/admin/api/health' and method == 'GET':
            return await _handle_health(send, mcp)
        if path == '/admin/api/tools' and method == 'GET':
            return await _handle_tools_list(send, mcp, info)
        if path == '/admin/api/tools/run' and method == 'POST':
            return await _handle_tools_run(receive, send, mcp, info)
        if path == '/admin/api/activity' and method == 'GET':
            return await _send_json(send, await store.activity_page(requester, cursor=cursor, limit=limit))
        if 'admin' not in info['permissions']:
            return await _send_json(send, {'status': 'error', 'message': 'Current admin required'}, 403)
        if path in ('/admin/api/logs', '/admin/api/audit') and method == 'GET':
            return await _send_json(send, await store.activity_page(requester, cursor=cursor, limit=limit))
        if path == '/admin/api/tokens' and method == 'GET':
            return await _send_json(send, await store.list_credentials(requester, cursor=cursor, limit=limit))
        if path == '/admin/api/hub-bindings' and method == 'GET':
            return await _send_json(send, await store.list_hub_bindings(requester,
                query.get('actor_id', [''])[0], cursor=cursor, limit=limit))
        data = None
        if method in ('POST', 'PUT'):
            data = json.loads(await _read_body(receive))
            if not isinstance(data, dict):
                raise ValueError('Access object required')
        if path == '/admin/api/hub-bindings' and method == 'POST':
            if set(data) != {'actor_id', 'issuer', 'subject', 'owner_id', 'tenant_id', 'expires_at'}:
                raise ValueError('Exact binding fields required')
            result = await store.create_hub_binding(requester, **data)
        elif path.startswith('/admin/api/hub-bindings/') and method == 'DELETE':
            result = await store.revoke_hub_binding(requester, path.rsplit('/', 1)[-1],
                int(query.get('expected_version', [''])[0]))
        elif path == '/admin/api/tokens' and method == 'POST':
            allowed = {'client_name', 'tenant_id', 'service_id', 'actor_id', 'permissions', 'tool_ids', 'expires_days'}
            if set(data)-allowed:
                raise ValueError('Unsupported access field')
            result = await store.create(requester, client_name=data.get('client_name'),
                tenant_id=data.get('tenant_id'), service_id=data.get('service_id'),
                actor_id=data.get('actor_id'), permissions=data.get('permissions', ['access']),
                tool_ids=data.get('tool_ids', []), expires_days=data.get('expires_days', 90))
        elif path.startswith('/admin/api/tokens/') and path != '/admin/api/tokens/purge':
            reference = path.rsplit('/', 1)[-1]
            if method == 'GET':
                result = await store.info(requester, reference)
            elif method == 'PUT':
                if set(data)-{'expected_version', 'client_name', 'permissions', 'tool_ids'}:
                    raise ValueError('Unsupported access field')
                result = await store.update(requester, reference, data.get('expected_version'),
                    client_name=data.get('client_name'), permissions=data.get('permissions'), tool_ids=data.get('tool_ids'))
            elif method == 'DELETE':
                result = await store.revoke(requester, reference, int(query.get('expected_version', [''])[0]))
            else:
                return await _send_json(send, {'status': 'error', 'message': 'Method not allowed'}, 405)
        elif path == '/admin/api/tokens/purge':
            return await _send_json(send, {'status': 'error', 'message': 'Use the maintenance operator'}, 403)
        else:
            return await _send_json(send, {'status': 'error', 'message': 'Unknown route'}, 404)
        return await _send_json(send, result)
    except AccessMutationUncertain as error:
        return await _send_json(send, {'status': 'uncertain', 'operation_id': error.operation_id,
            'message': 'Access mutation not confirmed; inspect without replay'}, 503)
    except (ValueError, TypeError):
        return await _send_json(send, {'status': 'error', 'message': 'Invalid access request or stale version'}, 400)
    finally:
        current_token_info.reset(context)
