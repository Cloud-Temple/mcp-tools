# -*- coding: utf-8 -*-
"""
Outil: token — Gestion des tokens d'authentification MCP.

Permet de créer, lister, inspecter et révoquer des tokens clients.
Chaque token restreint l'accès à un sous-ensemble d'outils via tool_ids.

⚠️  Toutes les opérations nécessitent les permissions admin.

Opérations :
  - create  : Génère un nouveau token (affiché une seule fois)
  - list    : Liste tous les tokens (sans valeur brute)
  - info    : Détails d'un token par client_name
  - revoke  : Supprime un token par client_name

Stockage :
  - S3 Dell ECS sous le préfixe _tokens/
  - Cache mémoire avec TTL de 5 minutes
  - SHA-256 hash du token comme clé S3 (token brut jamais persisté)
"""

from typing import Annotated, Optional, List

from pydantic import Field
from mcp.server.fastmcp import FastMCP, Context
from ..auth.context import check_tool_access, current_token_info


ALLOWED_OPERATIONS = ("create", "list", "info", "revoke")


def register(mcp: FastMCP) -> None:
    @mcp.tool()
    async def token(
        operation: Annotated[str, Field(description="Opération : create (nouveau token), list (tous les tokens), info (détails), revoke (supprimer)")],
        client_name: Annotated[Optional[str], Field(default=None, description="Nom du client associé au token (requis pour create, info, revoke)")] = None,
        permissions: Annotated[Optional[List[str]], Field(default=None, description="Permissions du token (ex: ['access', 'admin']). Défaut: ['access']")] = None,
        tool_ids: Annotated[Optional[List[str]], Field(default=None, description="Liste des IDs d'outils autorisés (ex: ['shell', 'http', 'calc']). Vide = tous les outils")] = None,
        expires_days: Annotated[int, Field(default=90, description="Durée de validité en jours (0 = jamais d'expiration)")] = 90,
        email: Annotated[Optional[str], Field(default=None, description="Email du propriétaire du token (optionnel, pour traçabilité)")] = None,
        ctx: Optional[Context] = None,
    ) -> dict:
        """Gestion des tokens d'authentification MCP (admin uniquement). Opérations : create, list, info, revoke. Chaque token restreint l'accès aux outils via tool_ids."""
        try:
            check_tool_access("token")

            # Vérifier que l'appelant est admin
            token_info = current_token_info.get()
            if not token_info or "admin" not in token_info.get("permissions", []):
                return {
                    "status": "error",
                    "message": "Seuls les administrateurs peuvent gérer les tokens.",
                }

            # Validation opération
            if operation not in ALLOWED_OPERATIONS:
                return {
                    "status": "error",
                    "message": f"Opération '{operation}' non supportée. Valides : {', '.join(ALLOWED_OPERATIONS)}",
                }

            # Import du store
            from ..auth.token_store import get_token_store
            store = get_token_store()

            # --- CREATE ---
            if operation == "create":
                if not client_name:
                    return {"status": "error", "message": "Le paramètre 'client_name' est requis pour create."}

                perms = permissions or ["access"]
                tools = tool_ids or []

                if expires_days < 0:
                    return {"status": "error", "message": "expires_days doit être >= 0 (0 = jamais)."}

                created_by = token_info.get("client_name", "admin")
                return store.create(
                    client_name=client_name,
                    permissions=perms,
                    tool_ids=tools,
                    expires_days=expires_days,
                    created_by=created_by,
                    email=email or "",
                )

            # --- LIST ---
            elif operation == "list":
                return store.list_tokens()

            # --- INFO ---
            elif operation == "info":
                if not client_name:
                    return {"status": "error", "message": "Le paramètre 'client_name' est requis pour info."}
                return store.info(client_name)

            # --- REVOKE ---
            elif operation == "revoke":
                if not client_name:
                    return {"status": "error", "message": "Le paramètre 'client_name' est requis pour revoke."}
                return store.revoke(client_name)

        except Exception as e:
            return {"status": "error", "message": str(e)}
