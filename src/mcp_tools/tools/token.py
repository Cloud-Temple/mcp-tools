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


ALLOWED_OPERATIONS = ("create", "list", "info", "revoke", "update")

# Liste complète des outils MCP disponibles (pour résoudre "all")
ALL_TOOL_IDS = [
    "shell", "network", "http", "ssh", "files",
    "perplexity_search", "perplexity_doc",
    "system_health", "system_about",
    "date", "calc", "token",
]


def register(mcp: FastMCP) -> None:
    @mcp.tool()
    async def token(
        operation: Annotated[str, Field(description="Opération : create (nouveau token), list (tous les tokens), info (détails), revoke (supprimer), update (modifier permissions/tool_ids/email)")],
        client_name: Annotated[Optional[str], Field(default=None, description="Nom du client associé au token (requis pour create, info, revoke, update)")] = None,
        permissions: Annotated[Optional[List[str]], Field(default=None, description="Permissions du token (ex: ['access', 'admin']). Défaut: ['access']")] = None,
        tool_ids: Annotated[Optional[List[str]], Field(default=None, description="Liste des IDs d'outils autorisés (ex: ['shell', 'http', 'calc']). ['all'] = tous les 12 outils. Vide = aucun accès (fail-closed pour non-admin)")] = None,
        expires_days: Annotated[int, Field(default=90, description="Durée de validité en jours (0 = jamais d'expiration)")] = 90,
        email: Annotated[Optional[str], Field(default=None, description="Email du propriétaire du token (optionnel, pour traçabilité)")] = None,
        ctx: Optional[Context] = None,
    ) -> dict:
        """Gestion des tokens d'authentification MCP (admin uniquement). Opérations : create, list, info, revoke, update. Chaque token restreint l'accès aux outils via tool_ids. Passez tool_ids=['all'] pour autoriser tous les outils."""
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

            # Résoudre le mot-clé "all" dans tool_ids
            # ["all"] → liste complète des 12 outils
            if tool_ids and len(tool_ids) == 1 and tool_ids[0].lower() == "all":
                tool_ids = list(ALL_TOOL_IDS)

            # Import du store
            from ..auth.token_store import get_token_store
            store = get_token_store()

            # --- CREATE ---
            if operation == "create":
                if not client_name:
                    return {"status": "error", "message": "Le paramètre 'client_name' est requis pour create."}

                perms = permissions or ["access"]
                tools = tool_ids if tool_ids is not None else []

                if expires_days < 0:
                    return {"status": "error", "message": "expires_days doit être >= 0 (0 = jamais)."}

                # Avertir si token non-admin avec tool_ids vide (sera bloqué par fail-closed)
                if "admin" not in perms and not tools:
                    return {
                        "status": "error",
                        "message": "⚠️ Fail-closed : un token non-admin avec tool_ids vide sera bloqué. "
                                   "Spécifiez les outils autorisés (ex: tool_ids=['shell','http','calc']) "
                                   "ou utilisez tool_ids=['all'] pour tous les outils.",
                    }

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

            # --- UPDATE ---
            elif operation == "update":
                if not client_name:
                    return {"status": "error", "message": "Le paramètre 'client_name' est requis pour update."}
                return store.update(
                    client_name=client_name,
                    permissions=permissions,
                    tool_ids=tool_ids,
                    email=email,
                )

            # --- REVOKE ---
            elif operation == "revoke":
                if not client_name:
                    return {"status": "error", "message": "Le paramètre 'client_name' est requis pour revoke."}
                return store.revoke(client_name)

            return {"status": "error", "message": f"Opération '{operation}' non implémentée."}

        except Exception as e:
            return {"status": "error", "message": str(e)}
