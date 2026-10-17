"""Preuve Mission `mission-retention-v1` pour l'owner tools, copiée de Vault 7a8a1c0.

Source : mcp-vault `src/mcp_vault/storage/retention_proof.py`. Différences : owner
`tools`, réglages `access_retention_*`, JWKS lu par un GET borné (pas de cache
partagé dans Tools). La preuve sert à l'inspection ; l'autorité SQL reste celle
du rôle de maintenance.
"""
import hashlib
import json
from datetime import datetime, timedelta, timezone
from time import monotonic
from urllib.parse import urlsplit
from uuid import UUID

import httpx
import jwt
from jwt.algorithms import ECAlgorithm

OWNER = 'tools'
IDENTITY = frozenset({'owner', 'tenant_id', 'mission_id', 'root_agent_id', 'claim_id', 'claim_revision',
                      'terminal_at', 'retain_until', 'manifest_sha256'})


def endpoint(settings):
    issuer, jwks = settings.access_retention_issuer, settings.access_retention_jwks_url
    for value in (issuer, jwks):
        url = urlsplit(value)
        if url.scheme != 'https' or not url.hostname or url.username or url.password or url.query or url.fragment:
            raise ValueError('Explicit HTTPS retention authority required')
    a, b = urlsplit(issuer), urlsplit(jwks)
    if ((a.hostname, a.port or 443) != (b.hostname, b.port or 443) or not settings.access_retention_audience
            or len(settings.access_retention_audience.encode()) > 256):
        raise ValueError('Retention issuer/JWKS origin refused')
    return issuer.rstrip('/') + '/internal/retention/claim-check'


def decode(settings, keys, token, *, now=None):
    endpoint(settings)
    if not isinstance(token, str) or not token or len(token) > 16384:
        raise ValueError('Retention proof refused')
    try:
        header = jwt.get_unverified_header(token)
        if header.get('alg') != 'ES256' or not isinstance(header.get('kid'), str):
            raise ValueError()
        matching = [k for k in keys if isinstance(k, dict) and k.get('kid') == header['kid']
                    and k.get('kty') == 'EC' and k.get('crv') == 'P-256' and 'd' not in k]
        if len(matching) != 1:
            raise ValueError()
        body = jwt.decode(token, ECAlgorithm.from_jwk(json.dumps(matching[0])), algorithms=['ES256'],
                          audience=settings.access_retention_audience, issuer=settings.access_retention_issuer,
                          options={'strict_aud': True, 'verify_exp': False, 'verify_iat': False, 'verify_nbf': False})
        if (set(body) != IDENTITY | {'iss', 'aud', 'sub', 'purpose', 'iat', 'nbf', 'exp', 'jti'}
                or body['sub'] != 'mission-retention-maintenance' or body['purpose'] != 'mission-retention-v1'
                or body['owner'] != OWNER
                or type(body['claim_revision']) is not int or body['claim_revision'] < 1
                or any(not isinstance(body[k], str) or not body[k] or len(body[k].encode()) > 256
                       for k in ('tenant_id', 'mission_id'))
                or not isinstance(body['root_agent_id'], str) or len(body['root_agent_id'].encode()) > 256
                or str(UUID(body['claim_id'])) != body['claim_id']
                or any(type(body[k]) is not int for k in ('iat', 'nbf', 'exp'))
                or body['nbf'] != body['iat'] or not 1 <= body['exp'] - body['iat'] <= 30):
            raise ValueError()
        for key, length in (('manifest_sha256', 64), ('jti', 32)):
            if (not isinstance(body[key], str) or len(body[key]) != length
                    or any(c not in '0123456789abcdef' for c in body[key])):
                raise ValueError()
        ended, until = (datetime.fromisoformat(body[k]) for k in ('terminal_at', 'retain_until'))
        stamp = now or datetime.now(timezone.utc)
        if (stamp.utcoffset() is None or ended.utcoffset() is None or until.utcoffset() is None
                or ended > stamp or until < ended + timedelta(days=365)
                or not body['iat'] <= stamp.timestamp() < body['exp']):
            raise ValueError()
        result = {k: body[k] for k in IDENTITY}
        result.update(terminal_at=ended.astimezone(timezone.utc).isoformat(),
                      retain_until=until.astimezone(timezone.utc).isoformat())
        return result, datetime.fromtimestamp(body['exp'], timezone.utc)
    except (ValueError, TypeError, KeyError, AttributeError, jwt.InvalidTokenError):
        raise ValueError('Retention proof refused') from None


def _bounded(client, method, url, deadline, limit, **kwargs):
    with client.stream(method, url, **kwargs) as response:
        raw = bytearray()
        for block in response.iter_bytes():
            if len(raw) + len(block) > limit or monotonic() >= deadline:
                raise ValueError('Retention callback refused')
            raw.extend(block)
        return response.status_code, bytes(raw)


def live(settings, token):
    """Décodage, callback claim-check, nouveau décodage. Échec : ValueError, jamais un effet."""
    deadline = monotonic() + settings.access_retention_callback_seconds
    url = endpoint(settings)
    try:
        with httpx.Client(timeout=settings.access_retention_callback_seconds, follow_redirects=False) as client:
            status, raw = _bounded(client, 'GET', settings.access_retention_jwks_url, deadline, 65536)
            keys = json.loads(raw).get('keys') if status == 200 else None
            if not isinstance(keys, list):
                raise ValueError('Retention JWKS unavailable')
            identity, expires = decode(settings, keys, token)
            status, raw = _bounded(client, 'POST', url, deadline, 4096, headers={'Authorization': 'Bearer ' + token})
            if status != 200 or json.loads(raw) != {'active': True}:
                raise ValueError('Retention claim unavailable')
        fresh, fresh_expires = decode(settings, keys, token)
    except ValueError:
        raise
    except Exception:
        raise ValueError('Retention authority unavailable') from None
    if fresh != identity or fresh_expires != expires or monotonic() >= deadline:
        raise ValueError('Retention claim changed')
    return identity, expires


def canonical_identity(identity):
    return json.dumps(identity, sort_keys=True, separators=(',', ':'))


def fingerprint(identity):
    return hashlib.sha256(canonical_identity(identity).encode()).hexdigest()
