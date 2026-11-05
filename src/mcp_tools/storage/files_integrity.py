"""Contrat d'intégrité texte commun aux entrées Files S3 et catalogue."""
import hashlib
import re


def validate_write_checksum(operation, content, expected_sha256):
    """Aucun accès stockage ; les réponses ne reprennent jamais le contenu."""
    if expected_sha256 is None:
        return None  # contrat historique, sans attestation de correspondance
    code = None
    if operation != "write":
        code = "checksum_write_only"
    elif not isinstance(expected_sha256, str) or not re.fullmatch(r"[0-9a-fA-F]{64}", expected_sha256):
        code = "invalid_expected_sha256"
    elif not isinstance(content, str) or not content or len(content) > 5_000_000:
        code = "invalid_verified_content"
    else:
        try:
            body = content.encode("utf-8")
        except UnicodeEncodeError:
            code = "invalid_verified_content"
        else:
            if len(body) > 5_000_000:
                code = "invalid_verified_content"
            elif hashlib.sha256(body).hexdigest() != expected_sha256.lower():
                code = "content_checksum_mismatch"
    if code:
        return {"status": "error", "code": code, "effect_state": "not_published",
                "message": "Contrat d'intégrité write refusé avant publication."}
    return None
