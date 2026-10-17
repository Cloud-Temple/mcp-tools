"""Copie figée du validateur Mission, pour le test croisé du reçu Tools #846.

Source : Cloud-Temple/mcp-mission, révision 9ded160c (PR #914),
`src/mcp_mission/storage/retention_coordination.py` lignes 113-166
(`validate_owner_receipt`), `_canonical` et `_digest` à l'identique.
`RetentionClaim.identity()` vient de `src/mcp_mission/auth/retention_proof.py`
(lignes 56-63), réduite aux champs ; la normalisation `instant()` est remplacée
par des dates déjà en UTC ISO. La branche Vault est hors sujet ici.
Ne pas « corriger » cette copie : elle doit refléter le contrat livré.
"""
import json
from dataclasses import dataclass
from uuid import UUID

OWNERS = frozenset({"mission", "agent", "teleport", "vault", "tools"})
REMOTE_OWNERS = OWNERS - {"mission"}


@dataclass(frozen=True)
class RetentionClaim:
    owner: str
    tenant_id: str
    mission_id: str
    root_agent_id: str
    claim_id: str
    claim_revision: int
    terminal_at: str
    retain_until: str
    manifest_sha256: str

    def identity(self):
        return {"owner": self.owner, "tenant_id": self.tenant_id, "mission_id": self.mission_id,
                "root_agent_id": self.root_agent_id, "claim_id": self.claim_id,
                "claim_revision": self.claim_revision, "terminal_at": self.terminal_at,
                "retain_until": self.retain_until, "manifest_sha256": self.manifest_sha256}


def _canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(",", ":"), allow_nan=False)


def _digest(value):
    return isinstance(value, str) and len(value) == 64 and all(c in "0123456789abcdef" for c in value)


def _validate_vault_references(refs, claim):
    raise AssertionError("hors sujet pour le reçu Tools")


def validate_owner_receipt(value, claim):
    expected = set(claim.identity()) | {"state", "inventory_complete", "operation_id", "receipt_sha256",
                                        "references", "contracts"}
    if (not isinstance(value, dict) or set(value) != expected or claim.owner not in REMOTE_OWNERS
            or any(value.get(key) != actual for key, actual in claim.identity().items())
            or value["state"] != "retired_confirmed" or value["inventory_complete"] is not True
            or not _digest(value["receipt_sha256"])):
        raise ValueError("confirmed scoped retention receipt required")
    try:
        if str(UUID(value["operation_id"])) != value["operation_id"]:
            raise ValueError()
    except (ValueError, TypeError, AttributeError):
        raise ValueError("retention operation receipt required") from None
    refs = value["references"]
    if not isinstance(refs, list) or len(refs) > 1000:
        raise ValueError("bounded retention references required")
    seen = set()
    for ref in refs:
        if (not isinstance(ref, dict) or set(ref) != {"kind", "id", "revision", "root_agent_id"}
                or any(not isinstance(ref[key], str) or not ref[key] or len(ref[key].encode()) > 256
                       for key in ("kind", "id"))
                or type(ref["revision"]) is not int or ref["revision"] < 0
                or not isinstance(ref["root_agent_id"], str) or len(ref["root_agent_id"].encode()) > 256):
            raise ValueError("retention reference refused")
        if ref['root_agent_id'] and ref['root_agent_id'] != claim.root_agent_id:
            raise ValueError("retention root refused")
        identity = (ref["kind"], ref["id"], ref["revision"], ref["root_agent_id"])
        if identity in seen:
            raise ValueError("duplicate retention reference")
        seen.add(identity)
    if claim.owner == "vault":
        _validate_vault_references(refs, claim)
    if claim.owner == "teleport":
        allowed = {"teleport_task", "teleport_observation", "teleport_mission_tombstone",
                   "teleport_intent_anchor", "teleport_segment_anchor"}
        tombstone = {"kind": "teleport_mission_tombstone", "id": claim.mission_id,
                     "revision": claim.claim_revision, "root_agent_id": claim.root_agent_id}
        if (any(ref["kind"] not in allowed for ref in refs)
                or [ref for ref in refs if ref["kind"] == "teleport_mission_tombstone"] != [tombstone]):
            raise ValueError("complete Teleport owner retirement receipt required")
    required = {"agent": {"events389": "v1", "access391": "v1", "costs390": "v1", "recovery845": "v1"},
                "teleport": {"audit366": "v1", "holds846": "v1"}, "vault": {"audit179": "v1", "holds846": "v1"},
                "tools": {"activity31": "v1", "files843": "v1", "recovery845": "v1", "holds846": "v1"}}
    if value["contracts"] != required[claim.owner]:
        raise ValueError("retention owner contract incomplete")
    if len(_canonical(value).encode()) > 262144:
        raise ValueError("retention receipt too large")
    return value
