"""Contrat destinataire Tools avec émetteur ES256 contrôlé, sans service Mission."""
import asyncio
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import sys
import time
from types import SimpleNamespace
from uuid import uuid4

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import ec
from jwt.algorithms import ECAlgorithm

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from src.mcp_tools.auth import access_runtime as runtime, hub_activity as hub
from src.mcp_tools.auth.context import current_token_info


def cfg():
    return SimpleNamespace(access_backend='postgres', hub_activity_enabled=True, hub_tools_enabled=False,
        hub_activity_issuer='https://mission.test', hub_activity_audience='tools-instance-1',
        hub_activity_owner='mission-owner', hub_activity_jwks_url='https://mission.test/jwks',
        hub_activity_check_url='https://mission.test/internal/hub/delegation-check',
        hub_activity_ca_file='public-test-ca', hub_activity_timeout_seconds=2,
        hub_activity_max_inflight=2, hub_activity_max_body_bytes=16384)


def issuer(body, permission='tools.activity.read', **changes):
    key = ec.generate_private_key(ec.SECP256R1())
    jwk = json.loads(ECAlgorithm.to_jwk(key.public_key()))
    jwk['kid'] = 'controlled-1'
    now = int(time.time())
    claims = dict(iss=cfg().hub_activity_issuer, aud=cfg().hub_activity_audience, sub='external-agent',
        jti='jti-'+str(uuid4()), iat=now, nbf=now, exp=now+30,
        purpose=hub.PURPOSE, permissions=[permission], owner_id='mission-owner', tenant_id='tenant',
        mission_id='mis_1', root_agent_id='ag_root', resources=['mis_1'],
        request_sha256=hashlib.sha256(body).hexdigest(), tool_id='files', call_id=str(uuid4()))
    claims.update(changes)
    token = jwt.encode(claims, key, algorithm='ES256', headers={'kid': jwk['kid']})
    return token, [jwk], claims


@pytest.mark.parametrize('changes', [
    {'iss': 'https://other.test'}, {'aud': 'agent-instance'}, {'permissions': ['agent.read']},
    {'purpose': 'hub-agent-reports-v1'}, {'owner_id': 'other-owner'}, {'exp': int(time.time())-1},
    {'exp': int(time.time())+90}, {'resources': ['mis_other']}, {'request_sha256': '0'*64},
    {'tenant_id': ''}, {'nbf': int(time.time())-1}, {'iat': True},
])
def test_signature_and_claims_refuse_wrong_capability(changes):
    body = b'{"mission_id":"mis_1"}'
    token, keys, _ = issuer(body, **changes)
    with pytest.raises((ValueError, jwt.InvalidTokenError)):
        hub.validate_claims(token, keys, cfg(), body, 'tools.activity.read')


def test_signature_refuses_duplicate_or_wrong_keys_and_changed_body():
    body = b'{}'
    token, keys, _ = issuer(body)
    assert hub.validate_claims(token, keys, cfg(), body, 'tools.activity.read')['sub'] == 'external-agent'
    for candidates, payload in ((keys+keys, body), ([], body), (keys, b'{ }')):
        with pytest.raises(ValueError):
            hub.validate_claims(token, candidates, cfg(), payload, 'tools.activity.read')
    with pytest.raises(ValueError):
        json.loads('{"limit":1,"limit":100}', object_pairs_hook=hub.strict_object)


class Store:
    def __init__(self):
        self.info = dict(actor_id=str(uuid4()), tenant_id='tenant', service_id='tools', version=1,
            permissions=['access'], tool_ids=['files'], credential_binding='tools-token-v1:'+'a'*64)
        self.binding = dict(id=str(uuid4()), version=1,
            expires_at=datetime.now(timezone.utc)+timedelta(hours=1), revoked_at=None)
        self.reads = 0
        self.change = None
        self.admissions = []
        self.terminals = []

    async def authenticate(self, token):
        return dict(self.info) if token == 'local-opaque' else None

    async def authenticate_binding(self, binding):
        return None if self.change == 'opaque' and self.reads else dict(self.info)

    async def hub_binding(self, requester, claims):
        if claims['tenant_id'] != self.info['tenant_id'] or self.change == 'mapping':
            raise ValueError('Binding refused')
        return dict(self.binding)

    async def confirm_hub_access(self, requester, info, binding, claims):
        if (self.change in {'opaque', 'mapping'} or self.info['version'] != info['version']
                or self.binding != binding or claims['tenant_id'] != self.info['tenant_id']):
            raise ValueError('Final local access changed')
        return dict(credential_version=self.info['version'], binding_id=binding['id'],
            binding_version=binding['version'], credential_expires_at=None,
            binding_expires_at=binding['expires_at'])

    async def hub_activity_page(self, *args, **kwargs):
        self.reads += 1
        if hasattr(self, 'on_read'):
            self.on_read()
        if self.change == 'mapping-after':
            self.change = 'mapping'
        return {'calls': [{'call_id': 'SAFE-METADATA'}], 'count': 1, 'next_cursor': None, 'page_complete': True}

    async def admit_mission(self, **kwargs):
        self.admissions.append({**kwargs, 'claims': dict(kwargs['claims'])})
        return True

    async def finish(self, call, outcome):
        self.terminals.append(outcome)
        return True


class Reply:
    status_code = 200
    def __init__(self, value): self.value = value
    async def __aenter__(self): return self
    async def __aexit__(self, *args): pass
    async def aiter_bytes(self): yield json.dumps(self.value).encode()


class Client:
    def __init__(self, keys, live=None):
        self.keys, self.live = keys, list(live or [True, True])
        self.urls = []
    async def __aenter__(self): return self
    async def __aexit__(self, *args): pass
    def stream(self, method, url, **kwargs):
        self.urls.append((method, url))
        return Reply({'keys': self.keys} if method == 'GET' else {'active': self.live.pop(0)})


def test_batch_local_intersection_and_second_live_check(monkeypatch):
    monkeypatch.setattr(hub.ssl, 'create_default_context', lambda **kwargs: object())
    async def scenario(change=None, live=None, tenant='tenant', opaque='local-opaque'):
        body = json.dumps({'mission_id': 'mis_1', 'root_agent_id': 'ag_root', 'limit': 10}).encode()
        token, keys, _ = issuer(body, tenant_id=tenant)
        client, store, sent = Client(keys, live), Store(), []
        store.change = change
        async def app(*args): raise AssertionError('Dedicated route must not execute a tool')
        async def receive(): return {'type': 'http.request', 'body': body, 'more_body': False}
        async def send(value): sent.append(value)
        middleware = hub.HubActivityMiddleware(app, cfg(), client_factory=lambda **kwargs: client,
                                               store_factory=lambda: store)
        await middleware({'type': 'http', 'path': hub.PATH, 'method': 'POST', 'query_string': b'',
            'headers': [(b'authorization', ('Bearer '+opaque).encode()),
                        (b'x-tools-activity-context', token.encode())]}, receive, send)
        data = json.loads(sent[1]['body'])
        assert token not in sent[1]['body'].decode() and 'a'*64 not in sent[1]['body'].decode()
        return sent[0]['status'], data, store, client
    status, data, store, client = asyncio.run(scenario())
    assert status == 200 and data['calls'] == [{'call_id': 'SAFE-METADATA'}] and store.reads == 1
    assert client.urls == [('GET', cfg().hub_activity_jwks_url), ('POST', cfg().hub_activity_check_url),
                           ('POST', cfg().hub_activity_check_url)]
    for changes in ({'change': 'opaque'}, {'change': 'mapping-after'}, {'live': [True, False]},
                    {'tenant': 'other-tenant'}, {'opaque': 'not-local'}):
        status, data, _, _ = asyncio.run(scenario(**changes))
        assert status == 403 and 'calls' not in data


@pytest.mark.parametrize('expired_before', [False, True])
def test_context_checked_only_at_admission_not_after_long_effect(monkeypatch, expired_before):
    store, effects = Store(), []
    monkeypatch.setattr(runtime, 'get_settings', lambda: cfg())
    monkeypatch.setattr(runtime, 'get_access_store', lambda: store)
    claims = dict(tool_id='files', call_id=str(uuid4()), exp=int(time.time())+30,
        mission_id='mis_1', root_agent_id='ag_root', request_sha256='b'*64)
    client = Client([])
    delegation = hub.Delegation(client, 'signed-context', claims, cfg())
    if expired_before:
        claims['exp'] = 0
    async def effect():
        effects.append(True)
        claims['exp'] = 0  # expiration au cours de l'effet, sans nouvelle délégation
        return {'status': 'ok'}
    async def scenario():
        token = current_token_info.set(store.info)
        context = hub.current_hub_context.set(delegation)
        try:
            if expired_before:
                with pytest.raises(ValueError):
                    await runtime.run_durable_tool('files', effect, (), {})
            else:
                result = await runtime.run_durable_tool('files', effect, (), {})
                assert result['activity_call_id'] == claims['call_id']
        finally:
            hub.current_hub_context.reset(context)
            current_token_info.reset(token)
    asyncio.run(scenario())
    assert effects == ([] if expired_before else [True])
    assert len(store.admissions) == (0 if expired_before else 1)
    assert store.terminals == ([] if expired_before else ['completed'])
    assert len(client.urls) == (0 if expired_before else 1)


def test_disabled_hub_is_optional_and_refuses_context_without_network():
    async def scenario():
        calls, sent = [], []
        settings = cfg()
        settings.hub_activity_enabled = False
        async def app(*args): calls.append(True)
        async def send(value): sent.append(value)
        middleware = hub.HubActivityMiddleware(app, settings,
            client_factory=lambda **kwargs: pytest.fail('No network when disabled'))
        await middleware({'type': 'http', 'path': '/mcp', 'headers': []}, None, send)
        assert calls == [True]
        await middleware({'type': 'http', 'path': '/mcp',
            'headers': [(b'x-tools-activity-context', b'not-a-bearer')]}, None, send)
        assert sent[0]['status'] == 403 and calls == [True]
    asyncio.run(scenario())


def test_batch_expiry_during_read_returns_zero_data(monkeypatch):
    monkeypatch.setattr(hub.ssl, 'create_default_context', lambda **kwargs: object())
    body = json.dumps({'mission_id': 'mis_1', 'root_agent_id': 'ag_root', 'limit': 10}).encode()
    token, keys, claims = issuer(body)
    clock = [claims['iat']+.1]
    monkeypatch.setattr(hub.time, 'time', lambda: clock[0])
    store, client, sent = Store(), Client(keys), []
    def expire(): clock[0] = claims['exp']
    store.on_read = expire
    async def scenario():
        async def receive(): return {'type': 'http.request', 'body': body}
        async def send(value): sent.append(value)
        middleware = hub.HubActivityMiddleware(None, cfg(), client_factory=lambda **kwargs: client,
                                               store_factory=lambda: store)
        await middleware({'type': 'http', 'path': hub.PATH, 'method': 'POST', 'headers': [
            (b'authorization', b'Bearer local-opaque'), (b'x-tools-activity-context', token.encode())]}, receive, send)
    asyncio.run(scenario())
    assert store.reads == 1 and sent[0]['status'] == 403
    assert 'calls' not in json.loads(sent[1]['body'])


@pytest.mark.parametrize('revoked', [False, True])
def test_signed_context_through_middleware_needs_current_opaque_before_effect(monkeypatch, revoked):
    from src.mcp_tools.auth.middleware import AuthMiddleware
    from src.mcp_tools.auth import middleware as auth
    monkeypatch.setattr(hub.ssl, 'create_default_context', lambda **kwargs: object())
    store, sent, effects = Store(), [], []
    body = json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': 'tools/call',
                       'params': {'name': 'files', 'arguments': {'operation': 'read'}}}).encode()
    token, keys, claims = issuer(body, 'tools.activity.context')
    client = Client(keys)
    monkeypatch.setattr(auth, 'get_settings', cfg)
    monkeypatch.setattr(runtime, 'get_settings', cfg)
    monkeypatch.setattr(runtime, 'get_access_store', lambda: store)
    if revoked:
        async def refused(binding): return None
        store.authenticate_binding = refused
    async def effect():
        effects.append(True)
        return {'status': 'ok'}
    async def endpoint(scope, receive, send):
        assert (await receive())['body'] == body
        try:
            result = await runtime.run_durable_tool('files', effect, (), {})
        except ValueError:
            result = {'status': 'error'}
        await hub.response(send, 200, 'TEST_TOOL', result=result)
    async def scenario():
        async def receive(): return {'type': 'http.request', 'body': body, 'more_body': False}
        async def send(value): sent.append(value)
        middleware = hub.HubActivityMiddleware(AuthMiddleware(endpoint), cfg(),
            client_factory=lambda **kwargs: client, store_factory=lambda: store)
        await middleware({'type': 'http', 'path': '/mcp', 'method': 'POST', 'headers': [
            (b'authorization', b'Bearer local-opaque'), (b'x-tools-activity-context', token.encode())]}, receive, send)
    asyncio.run(scenario())
    assert effects == ([] if revoked else [True])
    assert store.admissions[0]['call_id'] == claims['call_id']
    assert store.admissions[0]['claims']['request_sha256'] == hashlib.sha256(body).hexdigest()
    assert hub.current_hub_context.get() is None and current_token_info.get() is None


@pytest.mark.parametrize('change', ['opaque', 'mapping', 'rights'])
def test_local_revocation_during_last_live_wait_returns_zero_batch(monkeypatch, change):
    monkeypatch.setattr(hub.ssl, 'create_default_context', lambda **kwargs: object())
    body = json.dumps({'mission_id': 'mis_1', 'root_agent_id': 'ag_root', 'limit': 10}).encode()
    token, keys, _ = issuer(body)
    store, sent = Store(), []
    async def scenario():
        entered, release = asyncio.Event(), asyncio.Event()
        class GatedReply(Reply):
            async def aiter_bytes(self):
                entered.set()
                await release.wait()
                yield b'{"active":true}'
        class GatedClient(Client):
            posts = 0
            def stream(self, method, url, **kwargs):
                if method == 'POST':
                    self.posts += 1
                    if self.posts == 2:
                        return GatedReply(None)
                return super().stream(method, url, **kwargs)
        client = GatedClient(keys)
        async def receive(): return {'type': 'http.request', 'body': body}
        async def send(value): sent.append(value)
        middleware = hub.HubActivityMiddleware(None, cfg(), client_factory=lambda **kwargs: client,
                                               store_factory=lambda: store)
        pending = asyncio.create_task(middleware({'type': 'http', 'path': hub.PATH, 'method': 'POST',
            'headers': [(b'authorization', b'Bearer local-opaque'),
                        (b'x-tools-activity-context', token.encode())]}, receive, send))
        await entered.wait()
        assert store.reads == 1
        if change == 'rights':
            store.info['tool_ids'] = []
            store.info['version'] += 1
        else:
            store.change = change
        release.set()
        await pending
    asyncio.run(scenario())
    assert sent[0]['status'] == 403 and 'calls' not in json.loads(sent[1]['body'])


def test_rights_change_during_final_local_validation_never_returns_old_page(monkeypatch):
    monkeypatch.setattr(hub.ssl, 'create_default_context', lambda **kwargs: object())
    body = json.dumps({'mission_id': 'mis_1', 'root_agent_id': 'ag_root', 'limit': 10}).encode()
    token, keys, _ = issuer(body)
    sent = []
    async def scenario():
        entered, release = asyncio.Event(), asyncio.Event()
        class ConcurrentStore(Store):
            mapping_reads = 0
            async def hub_binding(self, requester, claims):
                self.mapping_reads += 1
                if self.mapping_reads == 3:  # ancien credential puis dernier mapping séparés
                    entered.set()
                    await release.wait()
                return await super().hub_binding(requester, claims)
            async def confirm_hub_access(self, requester, info, binding, claims):
                entered.set()
                await release.wait()  # l'unique décision versionnée a lieu après l'attente
                return await super().confirm_hub_access(requester, info, binding, claims)
        store, client = ConcurrentStore(), Client(keys)
        async def receive(): return {'type': 'http.request', 'body': body}
        async def send(value): sent.append(value)
        middleware = hub.HubActivityMiddleware(None, cfg(), client_factory=lambda **kwargs: client,
                                               store_factory=lambda: store)
        pending = asyncio.create_task(middleware({'type': 'http', 'path': hub.PATH, 'method': 'POST',
            'headers': [(b'authorization', b'Bearer local-opaque'),
                        (b'x-tools-activity-context', token.encode())]}, receive, send))
        await asyncio.wait_for(entered.wait(), 1)
        store.info['tool_ids'] = []
        store.info['version'] += 1
        release.set()
        await pending
    asyncio.run(scenario())
    assert sent[0]['status'] == 403 and 'calls' not in json.loads(sent[1]['body'])


@pytest.mark.parametrize('changed', [None, 'credential_version', 'binding_version', 'binding_id'])
def test_store_confirmation_is_one_versioned_sql_decision(changed):
    from src.mcp_tools.auth.postgres_store import PostgresAccessStore
    info, local = Store().info, Store().binding
    claims = dict(iss='https://issuer.test', sub='reader', owner_id='owner', tenant_id='tenant')
    decision = dict(credential_version=info['version'], binding_id=local['id'],
        binding_version=local['version'], credential_expires_at=None, binding_expires_at=local['expires_at'])
    if changed:
        decision[changed] = str(uuid4()) if changed == 'binding_id' else 2
    class SQLStore(PostgresAccessStore):
        async def _run(self, query, params):
            self.calls.append((query, params))
            return [decision]
        async def authenticate_binding(self, *args): raise AssertionError('No split credential read')
        async def hub_binding(self, *args): raise AssertionError('No split mapping read')
    store = SQLStore(None, ca_file='ca', role='app', database='access')
    store.calls = []
    if changed:
        with pytest.raises(ValueError):
            asyncio.run(store.confirm_hub_access('a'*64, info, local, claims))
    else:
        assert asyncio.run(store.confirm_hub_access('a'*64, info, local, claims)) == decision
    assert len(store.calls) == 1 and 'hub_access_confirm' in store.calls[0][0]
    assert store.calls[0][1] == ('a'*64, info['version'], local['id'], local['version'],
                                  claims['iss'], claims['sub'], claims['owner_id'], claims['tenant_id'])
