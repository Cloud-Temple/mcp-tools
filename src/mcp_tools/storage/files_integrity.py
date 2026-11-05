"""Contrat d'intégrité texte commun aux entrées Files S3 et catalogue."""
import base64
import binascii
import hashlib
import re

MAX_VERIFIED_BYTES = 5_000_000
MAX_BASE64_CHARS = 4 * ((MAX_VERIFIED_BYTES + 2) // 3)


def decode_write_content(operation, content, content_base64, expected_sha256):
    """Transport alternatif : aucun décodage JSON ou accès stockage."""
    if content_base64 is None:
        return content, None
    code = None
    if operation != "write":
        code = "checksum_write_only"
    elif content is not None:
        code = "ambiguous_content"
    elif expected_sha256 is None:
        code = "expected_sha256_required"
    elif not isinstance(content_base64, str) or len(content_base64) > MAX_BASE64_CHARS:
        code = "invalid_content_base64"
    else:
        try:
            raw = base64.b64decode(content_base64, validate=True)
            if len(raw) > MAX_VERIFIED_BYTES or base64.b64encode(raw).decode("ascii") != content_base64:
                code = "invalid_content_base64"
            else:
                return raw.decode("utf-8"), None
        except (ValueError, binascii.Error, UnicodeError):
            code = "invalid_content_base64"
    return None, {"status": "error", "code": code, "effect_state": "not_published",
                  "message": "Transport de preuve texte refusé avant publication."}


def validate_write_checksum(operation, content, expected_sha256):
    """Aucun accès stockage ; les réponses ne reprennent jamais le contenu."""
    if expected_sha256 is None:
        return None  # contrat historique, sans attestation de correspondance
    code = None
    if operation != "write":
        code = "checksum_write_only"
    elif not isinstance(expected_sha256, str) or not re.fullmatch(r"[0-9a-fA-F]{64}", expected_sha256):
        code = "invalid_expected_sha256"
    elif not isinstance(content, str) or len(content) > MAX_VERIFIED_BYTES:
        code = "invalid_verified_content"
    else:
        try:
            body = content.encode("utf-8")
        except UnicodeEncodeError:
            code = "invalid_verified_content"
        else:
            if len(body) > MAX_VERIFIED_BYTES:
                code = "invalid_verified_content"
            elif hashlib.sha256(body).hexdigest() != expected_sha256.lower():
                code = "content_checksum_mismatch"
    if code:
        return {"status": "error", "code": code, "effect_state": "not_published",
                "message": "Contrat d'intégrité write refusé avant publication."}
    return None
