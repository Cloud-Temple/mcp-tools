# -*- coding: utf-8 -*-
"""
Shell interactif — Couche 3 : interface interactive avec autocomplétion.

Utilise prompt_toolkit pour l'autocomplétion et l'historique,
et Rich pour l'affichage coloré.
"""

import json
import asyncio
from prompt_toolkit import PromptSession
from prompt_toolkit.completion import WordCompleter
from prompt_toolkit.history import FileHistory
from pathlib import Path

from .client import MCPClient
from .display import (
    console, show_error, show_success, show_warning,
    show_health_result, show_about_result, show_json,
    show_token_create_result, show_token_list_result, show_token_revoke_result,
)


# =============================================================================
# Commandes disponibles dans le shell (pour autocomplétion)
# =============================================================================

SHELL_COMMANDS = {
    "help":    "Afficher l'aide",
    "health":  "Vérifier l'état de santé",
    "about":   "Informations sur le service",
    "token":   "Gestion tokens (create/list/revoke). Ex: token list, token create mon-agent --email a@b.com",
    "quit":    "Quitter le shell",
    "exit":    "Quitter le shell",
    # Ajouter vos commandes métier ici :
    # "mon-outil": "Description courte",
}


# =============================================================================
# Handlers de commandes
# =============================================================================

async def cmd_health(client: MCPClient, state: dict, args: str = "",
                      json_output: bool = False):
    """Health check."""
    result = await client.call_tool("system_health", {})
    if json_output:
        show_json(result)
    elif result.get("status") in ("ok", "healthy"):
        show_health_result(result)
    else:
        show_error(result.get("message", "Erreur"))


async def cmd_about(client: MCPClient, state: dict, args: str = "",
                     json_output: bool = False):
    """Informations sur le service."""
    result = await client.call_tool("system_about", {})
    if json_output:
        show_json(result)
    elif result.get("status") == "ok":
        show_about_result(result)
    else:
        show_error(result.get("message", "Erreur"))


def cmd_help():
    """Affiche l'aide du shell."""
    from rich.table import Table

    table = Table(title="🐚 Commandes disponibles", show_header=True)
    table.add_column("Commande", style="cyan bold", min_width=20)
    table.add_column("Description", style="white")

    for cmd, desc in SHELL_COMMANDS.items():
        table.add_row(cmd, desc)

    table.add_row("", "")
    table.add_row("[dim]--json[/dim]", "[dim]Ajouter après une commande pour la sortie JSON[/dim]")

    console.print(table)


# =============================================================================
# Handler token (gestion des tokens d'accès)
# =============================================================================

async def cmd_token(client: MCPClient, state: dict, args: str = "",
                     json_output: bool = False):
    """Gestion des tokens : create/list/revoke."""
    parts = args.strip().split(None, 1)
    sub = parts[0].lower() if parts else ""
    sub_args = parts[1] if len(parts) > 1 else ""

    if sub == "list":
        result = await client.call_tool("token", {"operation": "list"})
        if json_output:
            show_json(result)
        elif result.get("status") == "ok":
            show_token_list_result(result)
        else:
            show_error(result.get("message", "Erreur"))

    elif sub == "create":
        # Parser: token create NOM [--email EMAIL] [--permissions PERMS]
        create_parts = sub_args.split()
        if not create_parts:
            show_warning("Usage: token create NOM [--email EMAIL] [--permissions read,write]")
            return
        name = create_parts[0]
        email = ""
        permissions = "read,write"
        i = 1
        while i < len(create_parts):
            if create_parts[i] == "--email" and i + 1 < len(create_parts):
                email = create_parts[i + 1]
                i += 2
            elif create_parts[i] == "--permissions" and i + 1 < len(create_parts):
                permissions = create_parts[i + 1]
                i += 2
            else:
                i += 1

        result = await client.call_tool("token", {
            "operation": "create",
            "client_name": name,
            "permissions": permissions,
            "email": email,
        })
        if json_output:
            show_json(result)
        elif result.get("status") in ("ok", "created"):
            show_token_create_result(result)
        else:
            show_error(result.get("message", "Erreur"))

    elif sub == "revoke":
        if not sub_args.strip():
            show_warning("Usage: token revoke HASH_PREFIX")
            return
        result = await client.call_tool("token", {
            "operation": "revoke",
            "client_name": sub_args.strip(),
        })
        if json_output:
            show_json(result)
        elif result.get("status") == "ok":
            show_token_revoke_result(result)
        else:
            show_error(result.get("message", "Erreur"))

    else:
        show_warning("Usage: token <create|list|revoke> [args]")


# =============================================================================
# Ajouter vos handlers métier ici
# =============================================================================
# Exemple :
#
# async def cmd_mon_outil(client: MCPClient, state: dict, args: str = "",
#                          json_output: bool = False):
#     """Mon outil."""
#     if not args.strip():
#         show_warning("Usage: mon-outil <param>")
#         return
#     result = await client.call_tool("mon_outil", {
#         "resource_id": state.get("current_resource", ""),
#         "param": args.strip(),
#     })
#     if json_output:
#         show_json(result)
#     elif result.get("status") == "ok":
#         show_mon_outil_result(result)
#     else:
#         show_error(result.get("message", "Erreur"))


# =============================================================================
# Boucle principale du shell
# =============================================================================

async def run_shell(url: str, token: str):
    """Lance le shell interactif."""

    client = MCPClient(url, token)
    state = {}  # État du shell (ressource courante, préférences, etc.)

    # Autocomplétion
    completer = WordCompleter(
        list(SHELL_COMMANDS.keys()) + ["--json"],
        ignore_case=True,
    )

    # Historique persistant
    history_path = Path.home() / ".mcp_shell_history"
    session = PromptSession(
        history=FileHistory(str(history_path)),
        completer=completer,
    )

    console.print(f"\n[bold cyan]🐚 Shell MCP[/bold cyan] — connecté à [green]{url}[/green]")
    console.print("[dim]Tapez 'help' pour l'aide, 'quit' pour quitter.[/dim]\n")

    while True:
        try:
            # Prompt avec contexte
            prompt_text = "mcp> "
            if state.get("current_resource"):
                prompt_text = f"mcp [{state['current_resource']}]> "

            user_input = await session.prompt_async(prompt_text)

            if not user_input.strip():
                continue

            # Parser la commande
            parts = user_input.strip().split(None, 1)
            command = parts[0].lower()
            args = parts[1] if len(parts) > 1 else ""

            # Détecter --json
            json_output = "--json" in args
            if json_output:
                args = args.replace("--json", "").strip()

            # Dispatch
            if command in ("quit", "exit"):
                console.print("[dim]Au revoir 👋[/dim]")
                break

            elif command == "help":
                cmd_help()

            elif command == "health":
                await cmd_health(client, state, args, json_output)

            elif command == "about":
                await cmd_about(client, state, args, json_output)

            elif command == "token":
                await cmd_token(client, state, args, json_output)

            # Ajouter vos commandes métier ici :
            # elif command == "mon-outil":
            #     await cmd_mon_outil(client, state, args, json_output)

            else:
                show_warning(f"Commande inconnue: '{command}'. Tapez 'help'.")

        except KeyboardInterrupt:
            console.print("\n[dim]Ctrl+C — tapez 'quit' pour quitter[/dim]")
        except EOFError:
            console.print("[dim]Au revoir 👋[/dim]")
            break
        except Exception as e:
            show_error(f"Erreur: {e}")
