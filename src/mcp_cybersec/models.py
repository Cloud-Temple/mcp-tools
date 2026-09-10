# -*- coding: utf-8 -*-
"""Modèles minimaux et validation défensive des campagnes cybersec."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
import uuid
from datetime import datetime, timezone
from typing import Any
from urllib.parse import unquote, urlsplit


class ValidationError(ValueError):
    """Entrée hors contrat, refusée avant toute action réseau."""


_IDENTIFIER = re.compile(r"^[a-z][a-z0-9_-]{1,62}$")
_HOSTNAME = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9-]{2,63}$",
    re.IGNORECASE,
)
_SAFE_RELATIVE_PATH = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,511}$")

CAMPAIGN_STATES = {"prepared", "approved", "running", "completed", "partial", "failed", "cancelled", "expired"}
JOB_STATES = {"queued", "running", "completed", "partial", "failed", "interrupted"}
PROFILE_TEST_CLASSES = {
    "recon",
    "active_standard",
    "active_extended",
}


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def iso_now() -> str:
    return utcnow().isoformat()


def parse_utc(value: str, field: str) -> datetime:
    if not isinstance(value, str):
        raise ValidationError(f"{field} doit être une date ISO 8601 UTC.")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValidationError(f"{field} est invalide.") from exc
    if parsed.tzinfo is None:
        raise ValidationError(f"{field} doit inclure son fuseau horaire.")
    return parsed.astimezone(timezone.utc)


def require_identifier(value: str, label: str) -> str:
    if not isinstance(value, str) or not _IDENTIFIER.fullmatch(value):
        raise ValidationError(
            f"{label} invalide : utiliser 2 à 63 caractères minuscules, chiffres, _ ou -."
        )
    return value


def validate_relative_path(path: str) -> str:
    if not isinstance(path, str) or not _SAFE_RELATIVE_PATH.fullmatch(path):
        raise ValidationError("Chemin de fichier de travail invalide.")
    if path.startswith("/") or "//" in path or any(part in {".", ".."} for part in path.split("/")):
        raise ValidationError("Le chemin doit rester relatif à l'espace de travail de campagne.")
    return path


def normalize_host(host: str) -> str:
    if not isinstance(host, str):
        raise ValidationError("La cible doit être une chaîne.")
    candidate = host.strip().rstrip(".").lower()
    if not candidate:
        raise ValidationError("Cible vide.")
    try:
        return str(ipaddress.ip_address(candidate))
    except ValueError:
        pass
    try:
        candidate = candidate.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ValidationError("Nom de domaine invalide.") from exc
    if not _HOSTNAME.fullmatch(candidate):
        raise ValidationError("Nom de domaine invalide ou non qualifié.")
    return candidate


def normalize_url(value: str) -> str:
    if not isinstance(value, str):
        raise ValidationError("URL invalide.")
    parsed = urlsplit(value.strip())
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValidationError("Seules les URL HTTP et HTTPS absolues sont autorisées.")
    if parsed.username or parsed.password:
        raise ValidationError("Les identifiants dans une URL sont interdits.")
    host = normalize_host(parsed.hostname)
    try:
        explicit_port = parsed.port
    except ValueError as exc:
        raise ValidationError("Port URL invalide.") from exc
    if explicit_port is not None and not 1 <= explicit_port <= 65535:
        raise ValidationError("Port URL invalide.")
    port = f":{explicit_port}" if explicit_port else ""
    path = parsed.path or "/"
    decoded_path = path
    for _ in range(3):
        decoded_path = unquote(decoded_path)
    if "\\" in decoded_path or any(part in {".", ".."} for part in decoded_path.split("/")):
        raise ValidationError("Les segments de chemin URL ambigus ou traversants sont interdits.")
    return f"{parsed.scheme}://{host}{port}{path}" + (f"?{parsed.query}" if parsed.query else "")


def normalize_ip_or_cidr(value: str, *, cidr: bool = False, allow_non_global: bool = False) -> str:
    try:
        if cidr:
            network = ipaddress.ip_network(value, strict=False)
            if not network.is_global and not allow_non_global:
                raise ValidationError("Les réseaux privés, loopback et réservés sont hors MVP.")
            return str(network)
        address = ipaddress.ip_address(value)
        if not address.is_global and not allow_non_global:
            raise ValidationError("Les IP privées, loopback, link-local et réservées sont hors MVP.")
        return str(address)
    except ValueError as exc:
        raise ValidationError("Adresse IP ou CIDR invalide.") from exc


def canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def sha256_json(value: Any) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def _string_list(value: Any, field: str, maximum: int = 256) -> list[str]:
    if value is None:
        return []
    if not isinstance(value, list) or len(value) > maximum or not all(isinstance(item, str) for item in value):
        raise ValidationError(f"{field} doit être une liste de texte bornée.")
    return value


def _normalized_targets(raw_targets: Any, maximum: int, *, allow_non_global: bool = False) -> dict:
    if not isinstance(raw_targets, dict):
        raise ValidationError("targets est obligatoire.")
    domains = sorted({normalize_host(item) for item in _string_list(raw_targets.get("domains"), "targets.domains", maximum)})
    ips = sorted({normalize_ip_or_cidr(item, allow_non_global=allow_non_global) for item in _string_list(raw_targets.get("ips"), "targets.ips", maximum)})
    cidrs = sorted({normalize_ip_or_cidr(item, cidr=True, allow_non_global=allow_non_global) for item in _string_list(raw_targets.get("cidrs"), "targets.cidrs", maximum)})
    urls = sorted({normalize_url(item) for item in _string_list(raw_targets.get("urls"), "targets.urls", maximum)})
    raw_ports = raw_targets.get("ports", [])
    if not isinstance(raw_ports, list) or len(raw_ports) > maximum:
        raise ValidationError("targets.ports doit être une liste bornée.")
    ports: list[int] = []
    for port in raw_ports:
        if not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65535:
            raise ValidationError("Chaque port autorisé doit être un entier entre 1 et 65535.")
        ports.append(port)
    all_tcp = raw_targets.get("all_tcp", False)
    if not isinstance(all_tcp, bool):
        raise ValidationError("targets.all_tcp doit être un booléen.")
    result = {
        "domains": domains,
        "ips": ips,
        "cidrs": cidrs,
        "urls": urls,
        "ports": sorted(set(ports)),
        "all_tcp": all_tcp,
    }
    if not any(result[key] for key in ("domains", "ips", "cidrs", "urls")):
        raise ValidationError("Le mandat doit contenir au moins une cible.")
    return result


def _normalise_exclusions(raw: Any, maximum: int, *, allow_non_global: bool = False) -> dict:
    if raw is None:
        return {"domains": [], "ips": [], "cidrs": [], "urls": []}
    if not isinstance(raw, dict):
        raise ValidationError("exclusions doit être un objet.")
    return {
        "domains": sorted({normalize_host(item) for item in _string_list(raw.get("domains"), "exclusions.domains", maximum)}),
        "ips": sorted({normalize_ip_or_cidr(item, allow_non_global=allow_non_global) for item in _string_list(raw.get("ips"), "exclusions.ips", maximum)}),
        "cidrs": sorted({normalize_ip_or_cidr(item, cidr=True, allow_non_global=allow_non_global) for item in _string_list(raw.get("cidrs"), "exclusions.cidrs", maximum)}),
        "urls": sorted({normalize_url(item) for item in _string_list(raw.get("urls"), "exclusions.urls", maximum)}),
    }


def build_campaign_manifest(
    raw_manifest: dict,
    *,
    tenant_id: str,
    requested_by: str,
    max_targets: int,
    allow_lab_targets: bool = False,
) -> dict:
    """Construit un mandat préparé, sans jamais accepter un tenant appelant."""
    if not isinstance(raw_manifest, dict):
        raise ValidationError("Le mandat doit être un objet JSON.")
    tenant_id = require_identifier(tenant_id, "tenant_id")
    required_text = ("mandate_ref", "client", "owner", "source_address", "emergency_contact")
    output: dict[str, Any] = {}
    for field in required_text:
        value = raw_manifest.get(field)
        if not isinstance(value, str) or not value.strip() or len(value.strip()) > 256:
            raise ValidationError(f"{field} est obligatoire et doit rester borné.")
        output[field] = value.strip()

    window = raw_manifest.get("window")
    if not isinstance(window, dict):
        raise ValidationError("window est obligatoire.")
    starts_at = parse_utc(window.get("starts_at"), "window.starts_at")
    ends_at = parse_utc(window.get("ends_at"), "window.ends_at")
    if ends_at <= starts_at:
        raise ValidationError("La fin de fenêtre doit être postérieure au début.")

    classes = _string_list(raw_manifest.get("allowed_test_classes"), "allowed_test_classes", 8)
    if not classes or not set(classes).issubset(PROFILE_TEST_CLASSES):
        raise ValidationError("allowed_test_classes doit contenir des profils recon, active_standard ou active_extended.")

    rate_limit = raw_manifest.get("rate_limit", 10)
    concurrency = raw_manifest.get("concurrency", 2)
    if not isinstance(rate_limit, int) or isinstance(rate_limit, bool) or not 1 <= rate_limit <= 1000:
        raise ValidationError("rate_limit doit être compris entre 1 et 1000.")
    if not isinstance(concurrency, int) or isinstance(concurrency, bool) or not 1 <= concurrency <= 64:
        raise ValidationError("concurrency doit être compris entre 1 et 64.")

    laboratory = raw_manifest.get("laboratory", False)
    if not isinstance(laboratory, bool):
        raise ValidationError("laboratory doit être un booléen.")
    if laboratory and not allow_lab_targets:
        raise ValidationError("Le mode laboratoire n'est disponible que dans la recette locale explicitement activée.")
    campaign_id = raw_manifest.get("campaign_id") or f"camp_{uuid.uuid4().hex[:16]}"
    campaign_id = require_identifier(campaign_id, "campaign_id")
    now = iso_now()
    manifest = {
        "schema_version": 1,
        "campaign_id": campaign_id,
        "tenant_id": tenant_id,
        "requested_by": requested_by[:128],
        "requested_at": now,
        "status": "prepared",
        "approval": None,
        "mandate": output,
        "laboratory": laboratory,
        "targets": _normalized_targets(raw_manifest.get("targets"), max_targets, allow_non_global=laboratory and allow_lab_targets),
        "exclusions": _normalise_exclusions(raw_manifest.get("exclusions"), max_targets, allow_non_global=laboratory and allow_lab_targets),
        "window": {"starts_at": starts_at.isoformat(), "ends_at": ends_at.isoformat()},
        "allowed_test_classes": sorted(set(classes)),
        "rate_limit": rate_limit,
        "concurrency": concurrency,
        "evidence_refs": [],
    }
    # La valeur approuvée ne dépend d'aucune sortie cible ni d'une valeur
    # calculée par un scanner : seulement du manifeste humainement relu.
    manifest["manifest_hash"] = sha256_json({
        key: manifest[key]
        for key in ("campaign_id", "tenant_id", "mandate", "laboratory", "targets", "exclusions", "window", "allowed_test_classes", "rate_limit", "concurrency")
    })
    return manifest


def redact_text(value: str, limit: int = 100_000) -> str:
    """Réduit les secrets usuels sans transformer une sortie en instruction."""
    if not isinstance(value, str):
        return ""
    redacted = re.sub(r"(?im)^(authorization|proxy-authorization|cookie|set-cookie)\s*:\s*.*$", r"\1: [REDACTED]", value)
    redacted = re.sub(r"(?i)(\"?(?:password|passwd|secret|token|api[_-]?key)\"?\s*[:=]\s*)[^\s,}\]]+", r"\1[REDACTED]", redacted)
    if len(redacted) > limit:
        return redacted[:limit] + f"\n[TRONQUÉ à {limit} caractères]"
    return redacted
