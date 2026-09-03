# -*- coding: utf-8 -*-
"""Contexte d'identité et contrôle d'accès du service cybersec."""

from contextvars import ContextVar
from typing import Optional


current_token_info: ContextVar[Optional[dict]] = ContextVar(
    "cybersec_current_token_info", default=None
)


class AuthorizationError(ValueError):
    """Erreur d'autorisation exprimable sans exposer d'information sensible."""


def is_admin(token_info: Optional[dict] = None) -> bool:
    token_info = token_info if token_info is not None else current_token_info.get()
    return bool(token_info and "admin" in token_info.get("permissions", []))


def require_token() -> dict:
    token_info = current_token_info.get()
    if token_info is None:
        raise AuthorizationError("Authentification requise.")
    return token_info


def require_tool_access(tool_name: str) -> dict:
    """Applique access + allow-list tool_ids, fail-closed pour les missions."""
    token_info = require_token()
    if is_admin(token_info):
        return token_info
    if "access" not in token_info.get("permissions", []):
        raise AuthorizationError(
            f"Accès refusé : permission access requise pour {tool_name}."
        )
    tool_ids = token_info.get("tool_ids", [])
    if not tool_ids or tool_name not in tool_ids:
        raise AuthorizationError(f"Accès refusé à l'outil {tool_name}.")
    if not token_info.get("tenant_id"):
        raise AuthorizationError("Jeton de mission invalide : tenant_id absent.")
    return token_info


def require_admin() -> dict:
    token_info = require_token()
    if not is_admin(token_info):
        raise AuthorizationError("Permission administrateur humaine requise.")
    return token_info


def tenant_for(token_info: Optional[dict] = None) -> str:
    token_info = token_info if token_info is not None else require_token()
    if is_admin(token_info):
        # L'admin peut relire plusieurs tenants, mais aucune opération de
        # campagne ne dérive d'un tenant libre : elle s'appuie toujours sur
        # le tenant inscrit dans l'objet S3 déjà chargé.
        return "*"
    tenant_id = str(token_info.get("tenant_id", ""))
    if not tenant_id:
        raise AuthorizationError("Jeton de mission invalide : tenant_id absent.")
    return tenant_id


def may_access_tenant(token_info: dict, tenant_id: str) -> bool:
    return is_admin(token_info) or token_info.get("tenant_id") == tenant_id
