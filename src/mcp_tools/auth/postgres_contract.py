"""Contrat pur des accès PG #31 ; pas de cache, réseau ou seconde autorité."""

import hmac
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from uuid import UUID

from .token_store import TokenStoreUnavailable

_HASH = re.compile(r"[0-9a-f]{64}\Z")
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z")
_TOOL = re.compile(r"[a-z][a-z0-9_]{0,63}\Z")


def utc(value):
    try:
        if isinstance(value, str) and len(value) <= 64:
            value = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if not isinstance(value, datetime) or value.utcoffset() != timezone.utc.utcoffset(value):
            raise ValueError()
        return value
    except (ValueError, TypeError, OverflowError):
        raise TokenStoreUnavailable("Access timestamp invalid") from None


def _strings(value, *, permissions=False):
    if (not isinstance(value, list) or not all(isinstance(v, str) for v in value)
            or len(value) != len(set(value))
            or (not set(value) <= {"access", "admin", "hub_read"} if permissions else any(not _TOOL.fullmatch(v) for v in value))
            or (permissions and "hub_read" in value and value != ["hub_read"])):
        raise TokenStoreUnavailable("Access scopes invalid")
    return tuple(value)


@dataclass(frozen=True)
class Credential:
    token_hash: str
    actor_id: str
    tenant_id: str
    service_id: str
    client_name: str
    permissions: tuple[str, ...]
    tool_ids: tuple[str, ...]
    created_at: datetime
    expires_at: datetime | None
    revoked_at: datetime | None
    version: int

    @classmethod
    def from_row(cls, row):
        try:
            if not isinstance(row, dict) or {"token", "raw_token", "password", "secret", "data"} & row.keys():
                raise ValueError()
            token_hash = row["token_hash"]
            if not isinstance(token_hash, str) or not _HASH.fullmatch(token_hash):
                raise ValueError()
            actor = str(UUID(str(row["actor_id"])))
            if any(not isinstance(row[k], str) or not _ID.fullmatch(row[k]) for k in ("tenant_id", "service_id", "client_name")):
                raise ValueError()
            version = row["version"]
            if type(version) is not int or version < 1:
                raise ValueError()
            created = utc(row["created_at"])
            expires = utc(row["expires_at"]) if row["expires_at"] is not None else None
            revoked = utc(row["revoked_at"]) if row["revoked_at"] is not None else None
            if (expires is not None and expires <= created) or (revoked is not None and revoked < created):
                raise ValueError()
            return cls(token_hash, actor, row["tenant_id"], row["service_id"], row["client_name"],
                       _strings(row["permissions"], permissions=True), _strings(row["tool_ids"]),
                       created, expires, revoked, version)
        except (ValueError, TypeError, KeyError, AttributeError):
            raise TokenStoreUnavailable("Access metadata invalid") from None

    def public_view(self):
        """Métadonnées seules ; pas de hash complet, credential ou champs libres."""
        return {"actor_id": self.actor_id, "tenant_id": self.tenant_id, "service_id": self.service_id,
                "client_name": self.client_name, "permissions": list(self.permissions), "tool_ids": list(self.tool_ids),
                "created_at": self.created_at.isoformat(),
                "expires_at": self.expires_at.isoformat() if self.expires_at else None,
                "revoked": self.revoked_at is not None, "version": self.version}


def authenticate_row(row, expected_hash, now):
    """None = absence confirmée de la requête PG, jamais défaut de connexion."""
    if row is None:
        return None
    current = Credential.from_row(row)
    if not isinstance(expected_hash, str) or not _HASH.fullmatch(expected_hash):
        raise TokenStoreUnavailable("Access binding invalid")
    if not hmac.compare_digest(current.token_hash, expected_hash):
        raise TokenStoreUnavailable("Access binding mismatch")
    now = utc(now)
    if current.revoked_at is not None or (current.expires_at is not None and current.expires_at <= now):
        return None
    return {**current.public_view(), "credential_binding": "tools-token-v1:"+current.token_hash}


def validate_transition(before, after):
    """L'usage/rename/update ne renouvellent pas l'identité ni l'ancien TTL."""
    immutable = ("token_hash", "actor_id", "tenant_id", "service_id", "created_at", "expires_at")
    if (any(getattr(before, k) != getattr(after, k) for k in immutable)
            or after.version != before.version+1
            or (before.revoked_at is not None and after.revoked_at != before.revoked_at)):
        raise TokenStoreUnavailable("Access transition invalid")
