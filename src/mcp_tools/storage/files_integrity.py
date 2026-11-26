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


def validate_write_checksum(operation, content, expected_sha256, *, encoded=False):
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
                "message": _checksum_message(code, content, encoded)}
    return None


# Le refus dit au modèle comment reprendre, sans donner l'empreinte réelle :
# recopiée, elle ferait passer n'importe quel contenu (#68).
_DIGEST_FROM_TOOL = (" Si elle vient d'un outil, ne pas la retirer : content diffère de la source "
                     "et ne doit pas être publié comme sa copie.")
_CHECKSUM_PROBLEMS = {
    "content_checksum_mismatch": "le SHA-256 des octets UTF-8 du contenu ne correspond pas à expected_sha256.",
    "invalid_expected_sha256": "expected_sha256 doit contenir 64 caractères hexadécimaux.",
}


def _checksum_message(code, content, encoded):
    problem = _CHECKSUM_PROBLEMS.get(code)
    if problem is None:
        return "Contrat d'intégrité write refusé avant publication."
    message = "Rien n'a été écrit : " + problem
    if encoded or not content:
        # content_base64 et le texte vide exigent une empreinte : la retirer ne suffit pas.
        return (message + " Ce transport exige l'empreinte rendue par l'outil qui a produit le contenu ;"
                " ne jamais la calculer.")
    if code == "invalid_expected_sha256":
        # Le format seul est en cause : rien ne dit que content diffère de la source.
        tail = " Si elle vient d'un outil, reprendre sa valeur intégrale auprès de l'outil producteur."
    else:
        tail = _DIGEST_FROM_TOOL
    return (message + " Si cette empreinte ne vient pas d'une réponse d'outil, relancer l'écriture "
            "sans expected_sha256." + tail)
