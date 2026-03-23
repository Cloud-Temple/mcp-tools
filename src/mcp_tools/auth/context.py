# -*- coding: utf-8 -*-
"""
Helpers d'authentification basés sur contextvars pour MCP Tools.
Vérifie les accès aux outils via permissions (access/admin) et la liste `tool_ids`.
"""

from contextvars import ContextVar
from typing import Optional

# --- Context variables injectées par le middleware ---
current_token_info: ContextVar[Optional[dict]] = ContextVar("current_token_info", default=None)

def check_tool_access(tool_name: str) -> None:
    """
    Vérifie que le token courant a accès à l'outil spécifié.
    Lève une exception ValueError si l'accès est refusé, 
    ce qui sera retourné proprement par FastMCP.

    Args:
        tool_name: Le nom de l'outil (ex: "ssh", "network")
    """
    token_info = current_token_info.get()

    if token_info is None:
        raise ValueError("Authentification requise pour appeler cet outil")

    permissions = token_info.get("permissions", [])

    # Si admin, on autorise tout
    if "admin" in permissions:
        return

    # Vérifie la permission "access" (requise pour appeler des outils)
    if "access" not in permissions:
        raise ValueError(
            f"Accès refusé : permission 'access' requise pour appeler l'outil '{tool_name}'"
        )

    # Vérifie si l'outil est dans la liste autorisée
    tool_ids = token_info.get("tool_ids", [])
    
    # Si tool_ids est vide ou absent → accès à TOUS les outils (convention Cloud Temple)
    # Seuls les tokens avec une liste tool_ids explicite sont restreints.
    if tool_ids and tool_name not in tool_ids:
        raise ValueError(f"Accès refusé à l'outil '{tool_name}' (non présent dans tool_ids)")
