"""Destinataire #31 optionnel : ES256 épinglé + contrôle live, jamais un bearer Tools."""
from __future__ import annotations

import asyncio
from contextvars import ContextVar
from datetime import datetime, timezone
import hashlib
import json
import re
import ssl
import time
from urllib.parse import urlsplit
from uuid import UUID

import httpx2
import jwt
from jwt.algorithms import ECAlgorithm

from .token_store import TokenStoreUnavailable

PATH = '/internal/hub/tools-activity'
FILES_PATH = '/internal/hub/tools-files'
PURPOSE = 'hub-tools-activity-v1'
current_hub_context = ContextVar('tools_hub_context', default=None)


def strict_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError('Duplicate JSON field')
        value[key] = item
    return value


def validate_claims(token, keys, cfg, body, permission):
    header = jwt.get_unverified_header(token)
    if header.get('alg') != 'ES256' or not isinstance(header.get('kid'), str) or header.get('crit'):
        raise ValueError('Delegation refused')
    matching = [k for k in keys if isinstance(k, dict) and k.get('kid') == header['kid']
                and k.get('kty') == 'EC' and k.get('crv') == 'P-256' and 'd' not in k
                and k.get('use', 'sig') == 'sig' and k.get('alg', 'ES256') == 'ES256']
    if len(matching) != 1:
        raise ValueError('Delegation refused')
    c = jwt.decode(token, ECAlgorithm.from_jwk(json.dumps(matching[0])), algorithms=['ES256'],
        issuer=cfg.hub_activity_issuer, audience=cfg.hub_activity_audience,
        options={'strict_aud': True, 'require': ['iss', 'aud', 'sub', 'jti', 'iat', 'nbf', 'exp']})
    if (any(type(c.get(k)) is not int for k in ('iat', 'nbf', 'exp'))
            or not 0 < c['exp']-c['iat'] <= 30 or c['nbf'] != c['iat']
            or c.get('purpose') != PURPOSE or c.get('permissions') != [permission]
            or c.get('owner_id') != cfg.hub_activity_owner
            or not all(isinstance(c.get(k), str) and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}', c[k])
                       for k in ('sub', 'jti', 'tenant_id', 'owner_id'))
            or not re.fullmatch(r'mis_[A-Za-z0-9_-]+', c.get('mission_id', ''))
            or not re.fullmatch(r'ag_[A-Za-z0-9_-]+', c.get('root_agent_id', ''))
            or c.get('resources') != [c['mission_id']]
            or c.get('request_sha256') != hashlib.sha256(body).hexdigest()):
        raise ValueError('Delegation refused')
    return c


async def bounded_json(client, method, url, maximum, **kwargs):
    async with client.stream(method, url, **kwargs) as reply:
        raw = bytearray()
        async for chunk in reply.aiter_bytes():
            raw.extend(chunk)
            if len(raw) > maximum:
                raise TokenStoreUnavailable('Delegation unavailable')
        if reply.status_code in {401, 403}:
            raise ValueError('Delegation refused')
        if reply.status_code != 200:
            raise TokenStoreUnavailable('Delegation unavailable')
        return json.loads(raw, object_pairs_hook=strict_object)


class Delegation:
    def __init__(self, client, token, claims, cfg):
        self.client, self.token, self.claims, self.cfg = client, token, claims, cfg
        self.consumed = False

    async def active(self):
        async with asyncio.timeout(self.cfg.hub_activity_timeout_seconds):
            if time.time() >= self.claims['exp']:
                raise ValueError('Delegation expired')
            answer = await bounded_json(self.client, 'POST', self.cfg.hub_activity_check_url, 1024,
                headers={'Authorization': 'Bearer ' + self.token}, json={})
            if answer != {'active': True} or time.time() >= self.claims['exp']:
                raise ValueError('Delegation revoked or expired')


def check_expiry(claims, confirmed):
    now = datetime.now(timezone.utc)
    if (time.time() >= claims['exp'] or confirmed['binding_expires_at'] <= now
            or (confirmed['credential_expires_at'] is not None
                and confirmed['credential_expires_at'] <= now)):
        raise ValueError('Local access expired before response')


async def response(send, status, code, **body):
    raw = json.dumps({'status': 'ok' if status == 200 else 'error', 'code': code, **body}).encode()
    await send({'type': 'http.response.start', 'status': status, 'headers': [
        (b'content-type', b'application/json'), (b'cache-control', b'no-store'),
        (b'vary', b'Authorization, X-Tools-Activity-Context'),
        (b'content-length', str(len(raw)).encode())]})
    await send({'type': 'http.response.body', 'body': raw})


class HubActivityMiddleware:
    def __init__(self, app, cfg, *, client_factory=httpx2.AsyncClient, store_factory=None):
        self.app, self.cfg, self.client_factory = app, cfg, client_factory
        if store_factory is None:
            from .access_runtime import get_access_store
            store_factory = get_access_store
        self.store_factory = store_factory
        self.slots = asyncio.Semaphore(cfg.hub_activity_max_inflight)

    async def __call__(self, scope, receive, send):
        if scope.get('type') != 'http':
            return await self.app(scope, receive, send)
        path = scope.get('path')
        headers = [(k.lower(), v) for k, v in scope.get('headers', [])]
        tokens = [v.decode('latin-1') for k, v in headers if k == b'x-tools-activity-context']
        if path not in {PATH, FILES_PATH} and not tokens:
            return await self.app(scope, receive, send)
        if not self.cfg.hub_activity_enabled:
            return await response(send, 404 if path in {PATH, FILES_PATH} else 403, 'DELEGATION_DISABLED')
        if path not in {PATH, FILES_PATH, '/mcp'} or scope.get('method') != 'POST' or scope.get('query_string'):
            return await response(send, 400, 'INVALID_DELEGATION_REQUEST')
        if len(tokens) != 1 or not 1 <= len(tokens[0]) <= 16384:
            return await response(send, 403, 'DELEGATION_REFUSED')
        if self.slots.locked():
            return await response(send, 503, 'DELEGATION_UNAVAILABLE')
        async with self.slots:
            return await self.handle(scope, receive, send, tokens[0], path in {PATH, FILES_PATH})

    async def handle(self, scope, receive, send, token, batch):
        cfg = self.cfg
        started = False
        async def tracked_send(message):
            nonlocal started
            if message['type'] == 'http.response.start':
                started = True
            await send(message)
        # Les erreurs ne publient ni JWT, ni corps, ni diagnostics transport/SQL.
        try:
            async with asyncio.timeout(cfg.hub_activity_timeout_seconds):
                urls = [urlsplit(u) for u in (cfg.hub_activity_jwks_url, cfg.hub_activity_check_url)]
                if (cfg.access_backend != 'postgres' or not all((cfg.hub_activity_issuer,
                        cfg.hub_activity_audience, cfg.hub_activity_owner, cfg.hub_activity_ca_file))
                        or any(u.scheme != 'https' or not u.hostname or u.username or u.password
                               or u.fragment or u.query for u in urls)):
                    raise TokenStoreUnavailable('Delegation configuration unavailable')
                raw = bytearray()
                while True:
                    message = await receive()
                    if message['type'] == 'http.disconnect':
                        return
                    raw.extend(message.get('body', b''))
                    if len(raw) > (16384 if batch else cfg.hub_activity_max_body_bytes):
                        return await response(send, 413, 'BODY_TOO_LARGE')
                    if not message.get('more_body'):
                        break
                body = json.loads(raw, object_pairs_hook=strict_object)
                if not isinstance(body, dict):
                    raise ValueError('Invalid request')
                trust = ssl.create_default_context(cafile=cfg.hub_activity_ca_file)
            async with self.client_factory(verify=trust, trust_env=False, follow_redirects=False,
                                          timeout=cfg.hub_activity_timeout_seconds) as client:
                async with asyncio.timeout(cfg.hub_activity_timeout_seconds):
                    jwks = await bounded_json(client, 'GET', cfg.hub_activity_jwks_url, 65536)
                    keys = jwks.get('keys')
                    if not isinstance(keys, list) or len(keys) > 64:
                        raise ValueError('Delegation keys invalid')
                    permission = ('tools.files.read' if scope.get('path') == FILES_PATH else
                                  'tools.activity.read' if batch else 'tools.activity.context')
                    claims = validate_claims(token, keys, cfg, raw, permission)
                    delegation = Delegation(client, token, claims, cfg)
                if batch:
                    async with asyncio.timeout(cfg.hub_activity_timeout_seconds):
                        return await self.batch(scope, send, body, delegation)
                if (body.get('jsonrpc') != '2.0' or body.get('method') != 'tools/call'
                        or not isinstance(body.get('params'), dict)
                        or body['params'].get('name') != claims.get('tool_id')
                        or not isinstance(claims.get('tool_id'), str)
                        or not re.fullmatch(r'[a-z][a-z0-9_]{0,63}', claims['tool_id'])):
                    raise ValueError('Context does not match tool call')
                claims['call_id'] = str(UUID(claims['call_id']))
                context = current_hub_context.set(delegation)
                served = False
                async def replay():
                    nonlocal served
                    if not served:
                        served = True
                        return {'type': 'http.request', 'body': bytes(raw), 'more_body': False}
                    return await receive()
                try:
                    # Le tool peut dépasser exp après admission : aucune nouvelle
                    # utilisation de la délégation pour sa clôture historique.
                    return await self.app(scope, replay, tracked_send)
                finally:
                    current_hub_context.reset(context)
        except (ValueError, KeyError, TypeError, jwt.InvalidTokenError):
            if started:
                raise
            return await response(send, 403, 'DELEGATION_REFUSED')
        except Exception:
            if started:
                raise
            return await response(send, 503, 'DELEGATION_UNAVAILABLE')

    async def batch(self, scope, send, body, delegation):
        c = delegation.claims
        file_read = scope.get('path') == FILES_PATH
        if not file_read and (set(body)-{'mission_id', 'root_agent_id', 'limit', 'cursor'}
                or body.get('mission_id') != c['mission_id']
                or body.get('root_agent_id') != c['root_agent_id']
                or type(body.get('limit')) is not int or not 1 <= body['limit'] <= 100):
            raise ValueError('Invalid batch')
        auth = [v.decode('latin-1') for k, v in scope.get('headers', []) if k.lower() == b'authorization']
        if len(auth) != 1 or not auth[0].startswith('Bearer '):
            raise ValueError('Local access required')
        store = self.store_factory()
        info = await store.authenticate(auth[0][7:])
        if info is None:
            raise ValueError('Local access refused')
        if file_read:
            from ..storage.hub_files import validate_request
            validate_request(body, c)
            if info['permissions'] != ['hub_read'] or 'files' not in info['tool_ids']:
                raise ValueError('Local hub read required')
        requester = info['credential_binding'].partition(':')[2]
        await delegation.active()
        binding = await store.hub_binding(requester, c)
        if file_read:
            from ..storage.hub_files import read_hub_files
            calls = await store.hub_file_calls(requester, c, body['call_ids'])

            async def check():
                await delegation.active()
                confirmed = await store.confirm_hub_access(requester, info, binding, c)
                check_expiry(c, confirmed)

            page = await read_hub_files(calls, body, self.cfg, check)
        else:
            page = await store.hub_activity_page(requester, info, binding, c,
                                                  cursor=body.get('cursor'), limit=body['limit'])
        await delegation.active()
        # Dernière décision locale unique, cohérente et versionnée : aucun autre
        # await d'autorité ne sépare sa lecture du credential et du mapping.
        confirmed = await store.confirm_hub_access(requester, info, binding, c)
        check_expiry(c, confirmed)
        return await response(send, 200, 'TOOLS_FILES' if file_read else 'TOOLS_ACTIVITY', **page)
