"""Paramètres de texte libre que le SDK MCP ne doit pas décoder.

Le SDK MCP 2.2 applique `json.loads` à toute chaîne destinée à un paramètre
dont l'annotation n'est pas exactement `str` (`func_metadata.pre_parse_json`).
Avec `Optional[str]`, la chaîne `'{"a": 1}'` devient un dict, refusé ensuite
comme « Input should be a valid string », et la chaîne `'null'` devient `None`
sans message. Un texte libre peut légitimement avoir cette forme.

Ces annotations gardent `str` comme type de base : le SDK ne décode plus la
chaîne, qui arrive intacte. Le validateur accepte `None` comme avant et le
schéma publié reste `anyOf [string, null]`, identique à l'ancien
`Optional[str]`.
"""
from typing import Annotated, Any

from pydantic import WithJsonSchema, WrapValidator

_SCHEMA = {"anyOf": [{"type": "string"}, {"type": "null"}]}


def _text_or_none(value: Any, handler):
    # Hors None, la validation str habituelle s'applique : un objet, une liste
    # ou un nombre envoyés comme tels restent refusés.
    return None if value is None else handler(value)


def _unchanged(value: Any, handler):
    # Le handler de l'outil choisit le traitement de chaque type (files.content).
    return value


RawText = Annotated[str, WrapValidator(_text_or_none), WithJsonSchema(_SCHEMA)]
"""Texte libre facultatif, transmis tel quel ; refuse les types non texte."""

RawValue = Annotated[str, WrapValidator(_unchanged), WithJsonSchema(_SCHEMA)]
"""Valeur transmise sans conversion au handler, qui doit en vérifier le type."""
