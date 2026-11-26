"""Contrat d'intégrité texte commun aux entrées Files S3 et catalogue."""
import base64
import binascii
import hashlib
import json
import re

MAX_VERIFIED_BYTES = 5_000_000
MAX_BASE64_CHARS = 4 * ((MAX_VERIFIED_BYTES + 2) // 3)


def serialize_json_content(value):
    """Texte écrit pour un objet ou une liste JSON passé dans content.

    Déterministe : UTF-8 sans échappement ASCII, indentation de 2 espaces,
    ordre des clés reçu, aucun retour à la ligne final. NaN et Infinity sont
    refusés, car ils ne sont pas du JSON standard.
    """
    return json.dumps(value, ensure_ascii=False, indent=2, allow_nan=False)


def normalize_write_content(operation, content):
    """Ramène content à un texte avant tout contrôle d'intégrité ou stockage.

    Un texte reste tel quel, octet pour octet. Un objet ou une liste JSON est
    sérialisé par serialize_json_content ; empreinte, taille et expected_sha256
    portent ensuite sur ce texte. None garde le refus « content requis » du
    handler. Les autres types sont refusés sans rien publier. Hors write,
    content n'est pas utilisé : une valeur non texte y est ignorée, comme une
    chaîne l'était déjà.
    """
    if content is None or isinstance(content, str):
        return content, None
    if operation != "write":
        return None, None
    if isinstance(content, (dict, list)):
        try:
            return serialize_json_content(content), None
        except (TypeError, ValueError, RecursionError):
            return None, _content_error(
                "invalid_content_json",
                "Rien n'a été écrit : l'objet ou la liste passé dans content n'est pas du JSON "
                "standard (NaN, Infinity ou valeur non sérialisable). Passer le texte à écrire "
                "comme chaîne.")
    return None, _content_error(
        "invalid_content_type",
        f"Rien n'a été écrit : content doit être une chaîne de caractères ; reçu {_json_type(content)}. "
        "Pour écrire un nombre ou un booléen, le passer comme texte, par exemple \"42\".")


def _json_type(value):
    if isinstance(value, bool):
        return "un booléen"
    if isinstance(value, (int, float)):
        return "un nombre"
    if isinstance(value, (bytes, bytearray)):
        return "des octets"
    return f"le type {type(value).__name__}"


def _content_error(code, message):
    return {"status": "error", "code": code, "effect_state": "not_published", "message": message}


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


def validate_write_checksum(operation, content, expected_sha256, *, encoded=False, serialized=False):
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
                "message": _checksum_message(code, content, encoded, serialized)}
    return None


# Le refus dit au modèle comment reprendre, sans donner l'empreinte réelle :
# recopiée, elle ferait passer n'importe quel contenu (#68).
_DIGEST_FROM_TOOL = (" Si elle vient d'un outil, ne pas la retirer : content diffère de la source "
                     "et ne doit pas être publié comme sa copie.")
_CHECKSUM_PROBLEMS = {
    "content_checksum_mismatch": "le SHA-256 des octets UTF-8 du contenu ne correspond pas à expected_sha256.",
    "invalid_expected_sha256": "expected_sha256 doit contenir 64 caractères hexadécimaux.",
}


def _checksum_message(code, content, encoded, serialized=False):
    problem = _CHECKSUM_PROBLEMS.get(code)
    if problem is None:
        return "Contrat d'intégrité write refusé avant publication."
    message = "Rien n'a été écrit : " + problem
    if serialized and code == "content_checksum_mismatch":
        # L'empreinte d'une source porte sur ses octets, pas sur notre sérialisation.
        message += (" content a été reçu comme objet ou liste JSON et sérialisé avec une indentation"
                    " de 2 espaces ; pour écrire les octets exacts de la source, passer son texte"
                    " intégral comme chaîne.")
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
