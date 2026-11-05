"""Encodage mécanique d'une preuve locale, sans fabriquer son empreinte attendue."""
import base64
import re

MAX_SOURCE_BYTES = 5_000_000  # contrat public Files vérifié


def encode_content_file(path, expected_sha256, *, content=None, content_base64=None):
    if content is not None or content_base64 is not None:
        raise ValueError("content-file exclut content et content-base64")
    if not isinstance(expected_sha256, str) or not re.fullmatch(r"[0-9a-fA-F]{64}", expected_sha256):
        raise ValueError("content-file exige expected-sha256 natif (64 hex)")
    with open(path, "rb") as source:
        body = source.read(MAX_SOURCE_BYTES + 1)
    if len(body) > MAX_SOURCE_BYTES:
        raise ValueError("content-file dépasse 5000000 octets")
    return base64.b64encode(body).decode("ascii")
