"""Contrats d'identité/TTL avant raccord PG ; aucune persistance attestée."""

import json
from datetime import datetime, timezone
from uuid import uuid4

import pytest

from mcp_tools.auth.postgres_contract import Credential, authenticate_row, validate_transition
from mcp_tools.auth.token_store import TokenStoreUnavailable

NOW = datetime(2026, 10, 15, 12, tzinfo=timezone.utc)
HASH = "a"*64


def row(**changes):
    return {"token_hash": HASH, "actor_id": str(uuid4()), "tenant_id": "tenant-a", "service_id": "tools-local",
            "client_name": "reader", "permissions": ["access"], "tool_ids": ["files"],
            "created_at": "2026-10-15T00:00:00Z", "expires_at": "2026-10-16T00:00:00Z",
            "revoked_at": None, "version": 1, **changes}


def test_authentication_preserves_existing_binding_and_separates_public_metadata():
    source = row()
    info = authenticate_row(source, HASH, NOW)
    assert info["credential_binding"] == "tools-token-v1:"+HASH
    assert info["actor_id"] == source["actor_id"]
    public = Credential.from_row(source).public_view()
    assert HASH not in json.dumps(public)
    assert not {"token", "raw_token", "token_hash", "password"} & public.keys()


@pytest.mark.parametrize("change", [{"revoked_at": "2026-10-15T01:00:00Z"}, {"expires_at": "2026-10-15T12:00:00Z"}])
def test_revoked_or_exactly_expired_credential_never_authenticates(change):
    assert authenticate_row(row(**change), HASH, NOW) is None


@pytest.mark.parametrize("change", [
    {"permissions": "admin"}, {"permissions": ["access", "unknown"]}, {"tool_ids": "files"},
    {"tool_ids": ["files", "files"]}, {"actor_id": "forged"}, {"version": True},
    {"tenant_id": "bad\ntenant"}, {"created_at": "secret-CANARY-invalid-time"},
    {"token_hash": "b"*64}, {"raw_token": "CANARY"},
])
def test_corruption_is_unavailable_not_an_authenticated_or_missing_credential(change):
    with pytest.raises(TokenStoreUnavailable) as error:
        authenticate_row(row(**change), HASH, NOW)
    assert "CANARY" not in str(error.value)


def test_confirmed_absence_is_distinct_from_corrupt_entry():
    assert authenticate_row(None, HASH, NOW) is None
    with pytest.raises(TokenStoreUnavailable):
        authenticate_row({}, HASH, NOW)


@pytest.mark.parametrize("change", [
    {"actor_id": str(uuid4())}, {"tenant_id": "other"}, {"service_id": "other"},
    {"expires_at": "2026-10-17T00:00:00Z"}, {"created_at": "2026-10-15T01:00:00Z"},
    {"token_hash": "b"*64}, {"version": 1},
])
def test_update_cannot_replace_identity_or_extend_the_old_security_ttl(change):
    original = row()
    with pytest.raises(TokenStoreUnavailable, match="transition invalid"):
        validate_transition(Credential.from_row(original), Credential.from_row({**original, "version": 2, **change}))


def test_client_rename_does_not_replace_actor_and_revocation_is_monotonic():
    original = row()
    renamed = {**original, "client_name": "renamed", "version": 2}
    validate_transition(Credential.from_row(original), Credential.from_row(renamed))
    revoked = {**renamed, "revoked_at": "2026-10-15T10:00:00Z", "version": 3}
    validate_transition(Credential.from_row(renamed), Credential.from_row(revoked))
    with pytest.raises(TokenStoreUnavailable, match="transition invalid"):
        validate_transition(Credential.from_row(revoked), Credential.from_row({**revoked, "revoked_at": None, "version": 4}))
