# -*- coding: utf-8 -*-
"""
Shell interactif — MCP Tools.
"""

import asyncio
from prompt_toolkit import PromptSession
from prompt_toolkit.completion import WordCompleter
from prompt_toolkit.history import FileHistory
from pathlib import Path

from .client import MCPClient
from .display import (
    console, show_error, show_warning, show_json,
    show_health_result, show_about_result,
    show_shell_result, show_ping_result,
    show_http_result, show_perplexity_result,
)


SHELL_COMMANDS = {
    "help":      "Afficher l'aide",
    "health":    "Vérifier l'état de santé",
    "about":     "Informations sur le service",
    "run":       "run <commande> — Exécuter une commande shell",
    "ping":      "ping <host> [op] — Diagnostic réseau (ping/nslookup/dig/traceroute)",
    "http":      "http <url> [method] — Requête HTTP",
    "search":    "search <query> — Recherche Perplexity AI",
    "quit":      "Quitter le shell",
}


async def cmd_health(client, state, args="", json_output=False):
    # Health check via REST /health (pas d'auth nécessaire)
    result = await client.call_rest("GET", "/health")
    if json_output:
        show_json(result)
    elif result.get("status") == "ok":
        show_health_result(result)
    else:
        show_error(result.get("message", "Erreur"))


async def cmd_about(client, state, args="", json_output=False):
    result = await client.call_tool("system_about", {})
    if json_output:
        show_json(result)
    elif result.get("status") == "ok":
        show_about_result(result)
    else:
        show_error(result.get("message", "Erreur"))


async def cmd_run(client, state, args="", json_output=False):
    if not args.strip():
        show_warning("Usage: run <commande>")
        return
    result = await client.call_tool("shell", {"command": args.strip()})
    if json_output:
        show_json(result)
    else:
        show_shell_result(result)


async def cmd_ping(client, state, args="", json_output=False):
    parts = args.strip().split()
    if not parts:
        show_warning("Usage: ping <host> [ping|nslookup|dig|traceroute]")
        return
    host = parts[0]
    op = parts[1] if len(parts) > 1 else "ping"
    result = await client.call_tool("ping", {"host": host, "operation": op})
    if json_output:
        show_json(result)
    else:
        show_ping_result(result)


async def cmd_http(client, state, args="", json_output=False):
    parts = args.strip().split()
    if not parts:
        show_warning("Usage: http <url> [GET|POST|PUT|DELETE]")
        return
    url = parts[0]
    method = parts[1].upper() if len(parts) > 1 else "GET"
    result = await client.call_tool("http", {"url": url, "method": method})
    if json_output:
        show_json(result)
    else:
        show_http_result(result)


async def cmd_search(client, state, args="", json_output=False):
    if not args.strip():
        show_warning("Usage: search <query>")
        return
    result = await client.call_tool("perplexity_search", {
        "query": args.strip(), "detail_level": "normal"
    })
    if json_output:
        show_json(result)
    elif result.get("status") == "success":
        show_perplexity_result(result)
    else:
        show_error(result.get("message", "Erreur"))


def cmd_help():
    from rich.table import Table
    table = Table(title="🐚 Commandes disponibles", show_header=True)
    table.add_column("Commande", style="cyan bold", min_width=20)
    table.add_column("Description", style="white")
    for cmd, desc in SHELL_COMMANDS.items():
        table.add_row(cmd, desc)
    table.add_row("", "")
    table.add_row("[dim]--json[/dim]", "[dim]Ajouter pour la sortie JSON[/dim]")
    console.print(table)


async def run_shell(url: str, token: str):
    client = MCPClient(url, token)
    state = {}

    completer = WordCompleter(
        list(SHELL_COMMANDS.keys()) + ["--json"],
        ignore_case=True,
    )

    history_path = Path.home() / ".mcp_tools_shell_history"
    session = PromptSession(
        history=FileHistory(str(history_path)),
        completer=completer,
    )

    console.print(f"\n[bold cyan]🐚 MCP Tools Shell[/bold cyan] — connecté à [green]{url}[/green]")
    console.print("[dim]Tapez 'help' pour l'aide, 'quit' pour quitter.[/dim]\n")

    while True:
        try:
            user_input = await session.prompt_async("mcp-tools> ")
            if not user_input.strip():
                continue

            parts = user_input.strip().split(None, 1)
            command = parts[0].lower()
            args = parts[1] if len(parts) > 1 else ""

            json_output = "--json" in args
            if json_output:
                args = args.replace("--json", "").strip()

            if command == "quit":
                console.print("[dim]Au revoir 👋[/dim]")
                break
            elif command == "help":
                cmd_help()
            elif command == "health":
                await cmd_health(client, state, args, json_output)
            elif command == "about":
                await cmd_about(client, state, args, json_output)
            elif command == "run":
                await cmd_run(client, state, args, json_output)
            elif command == "ping":
                await cmd_ping(client, state, args, json_output)
            elif command == "http":
                await cmd_http(client, state, args, json_output)
            elif command == "search":
                await cmd_search(client, state, args, json_output)
            else:
                show_warning(f"Commande inconnue: '{command}'. Tapez 'help'.")

        except KeyboardInterrupt:
            console.print("\n[dim]Ctrl+C — tapez 'quit' pour quitter[/dim]")
        except EOFError:
            console.print("[dim]Au revoir 👋[/dim]")
            break
        except Exception as e:
            show_error(f"Erreur: {e}")
