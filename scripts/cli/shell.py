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
    show_shell_result, show_network_result,
    show_http_result, show_perplexity_result,
    show_date_result, show_calc_result, show_doc_result,
    show_ssh_result, show_files_result,
)


SHELL_COMMANDS = {
    "help":       "Afficher l'aide",
    "health":     "Vérifier l'état de santé",
    "about":      "Informations sur le service",
    "run":        "run <commande> — Exécuter une commande shell en sandbox",
    "network":    "network <op> <host> [args] — ping, dig, nslookup, traceroute",
    "http":       "http <url> [GET|POST|PUT|DELETE] — Requête HTTP",
    "search":     "search <query> — Recherche Perplexity AI",
    "date":       "date <op> [date] [--tz X] — now, today, parse, add, diff, format...",
    "calc":       "calc <expression> — Calcul math (math.sqrt, statistics.mean...)",
    "doc":        "doc <query> [context] — Documentation technique via Perplexity",
    "ssh":        "ssh <op> <host> <user> [options] — exec, status, upload, download",
    "files":      "files <op> [options] — list, read, write, delete, info, diff (S3)",
    "quit":       "Quitter le shell",
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


NETWORK_OPS = ("ping", "dig", "nslookup", "traceroute")


async def cmd_network(client, state, args="", json_output=False):
    parts = args.strip().split()
    if len(parts) < 2 or parts[0] not in NETWORK_OPS:
        show_warning("Usage: network <op> <host> [args...]")
        show_warning("")
        show_warning("  network ping google.com           — ping avec 4 paquets")
        show_warning("  network ping 8.8.8.8 -c 2        — ping 2 paquets")
        show_warning("  network dig google.com MX +short  — requête DNS MX")
        show_warning("  network nslookup google.com -type=mx")
        show_warning("  network traceroute 8.8.8.8 -m 10")
        return
    op = parts[0]
    host = parts[1]
    extra = " ".join(parts[2:]) if len(parts) > 2 else ""
    params = {"host": host, "operation": op}
    if extra:
        params["extra_args"] = extra
    result = await client.call_tool("network", params)
    if json_output:
        show_json(result)
    else:
        show_network_result(result)


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


DATE_OPS = ("now", "today", "parse", "format", "add", "diff", "week_number", "day_of_week")


async def cmd_date(client, state, args="", json_output=False):
    parts = args.strip().split()
    if not parts or parts[0] not in DATE_OPS:
        show_warning("Usage: date <op> [date] [options...]")
        show_warning("")
        show_warning("  date now                          — date/heure actuelle (UTC)")
        show_warning("  date now --tz Europe/Paris        — avec fuseau horaire")
        show_warning("  date today                        — date du jour")
        show_warning("  date parse 06/03/2026             — parser une date")
        show_warning("  date add 2026-03-06 --days 10     — ajouter des jours")
        show_warning("  date diff 2026-01-01 2026-03-06   — différence entre 2 dates")
        show_warning("  date week_number 2026-03-06       — numéro de semaine")
        show_warning("  date day_of_week 2026-03-06       — jour de la semaine")
        return
    op = parts[0]
    params = {"operation": op}
    # Parser les arguments positionnels et options
    positional = []
    i = 1
    while i < len(parts):
        if parts[i].startswith("--") and i + 1 < len(parts):
            key = parts[i][2:]
            val = parts[i + 1]
            if key in ("days", "hours", "minutes"):
                params[key] = int(val)
            else:
                params[key] = val
            i += 2
        else:
            positional.append(parts[i])
            i += 1
    if positional:
        params["date"] = positional[0]
    if len(positional) > 1:
        params["date2"] = positional[1]
    result = await client.call_tool("date", params)
    if json_output:
        show_json(result)
    else:
        show_date_result(result)


async def cmd_calc(client, state, args="", json_output=False):
    if not args.strip():
        show_warning("Usage: calc <expression>")
        show_warning("")
        show_warning("  calc 2 + 3 * 4")
        show_warning("  calc math.sqrt(144)")
        show_warning("  calc statistics.mean([10, 20, 30])")
        return
    result = await client.call_tool("calc", {"expr": args.strip()})
    if json_output:
        show_json(result)
    else:
        show_calc_result(result)


async def cmd_doc(client, state, args="", json_output=False):
    if not args.strip():
        show_warning("Usage: doc <query> [context]")
        show_warning("")
        show_warning('  doc Python asyncio')
        show_warning('  doc FastAPI middleware et dépendances')
        return
    # Le premier "mot" ou groupe entre guillemets est la query
    # Tout le reste est le context (simplifié)
    params = {"query": args.strip()}
    result = await client.call_tool("perplexity_doc", params)
    if json_output:
        show_json(result)
    elif result.get("status") == "success":
        show_doc_result(result)
    else:
        show_error(result.get("message", "Erreur"))


SSH_OPS = ("exec", "status", "upload", "download")


async def cmd_ssh(client, state, args="", json_output=False):
    parts = args.strip().split()
    if len(parts) < 3 or parts[0] not in SSH_OPS:
        show_warning("Usage: ssh <op> <host> <user> [options...]")
        show_warning("")
        show_warning("  ssh exec myserver.com root --password pass --command 'uptime'")
        show_warning("  ssh status myserver.com admin --password pass")
        show_warning("  ssh download myserver.com deploy --password pass --remote-path /var/log/app.log")
        show_warning("  ssh upload myserver.com deploy --password pass --remote-path /tmp/cfg --content 'key=val'")
        return
    op = parts[0]
    host = parts[1]
    username = parts[2]
    params = {"operation": op, "host": host, "username": username}
    # Parser les options --key value
    i = 3
    while i < len(parts):
        if parts[i].startswith("--") and i + 1 < len(parts):
            key = parts[i][2:].replace("-", "_")
            val = parts[i + 1]
            if key == "port":
                params[key] = int(val)
            elif key == "timeout":
                params[key] = int(val)
            elif key == "sudo":
                params[key] = val.lower() in ("true", "1", "yes")
            elif key == "auth_type":
                params[key] = val
            else:
                params[key] = val
            i += 2
        else:
            i += 1
    # Déduire auth_type si non spécifié
    if "auth_type" not in params:
        if "private_key" in params:
            params["auth_type"] = "key"
        elif "password" in params:
            params["auth_type"] = "password"
    result = await client.call_tool("ssh", params)
    if json_output:
        show_json(result)
    else:
        show_ssh_result(result)


FILES_OPS = ("list", "read", "write", "delete", "info", "diff")


async def cmd_files(client, state, args="", json_output=False):
    parts = args.strip().split()
    if not parts or parts[0] not in FILES_OPS:
        show_warning("Usage: files <op> [options...]")
        show_warning("")
        show_warning("  files list --prefix data/")
        show_warning("  files read --path config/app.json")
        show_warning("  files write --path test.txt --content 'hello'")
        show_warning("  files info --path config/app.json")
        show_warning("  files diff --path v1.json --path2 v2.json")
        show_warning("  files delete --path old.json")
        return
    op = parts[0]
    params = {"operation": op}
    i = 1
    while i < len(parts):
        if parts[i].startswith("--") and i + 1 < len(parts):
            key = parts[i][2:].replace("-", "_")
            val = parts[i + 1]
            if key in ("max_keys", "timeout"):
                params[key] = int(val)
            else:
                params[key] = val
            i += 2
        else:
            i += 1
    result = await client.call_tool("files", params)
    if json_output:
        show_json(result)
    else:
        show_files_result(result)


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
            elif command in ("network", "ping"):
                await cmd_network(client, state, args, json_output)
            elif command == "http":
                await cmd_http(client, state, args, json_output)
            elif command == "search":
                await cmd_search(client, state, args, json_output)
            elif command == "date":
                await cmd_date(client, state, args, json_output)
            elif command == "calc":
                await cmd_calc(client, state, args, json_output)
            elif command == "doc":
                await cmd_doc(client, state, args, json_output)
            elif command == "ssh":
                await cmd_ssh(client, state, args, json_output)
            elif command == "files":
                await cmd_files(client, state, args, json_output)
            else:
                show_warning(f"Commande inconnue: '{command}'. Tapez 'help'.")

        except KeyboardInterrupt:
            console.print("\n[dim]Ctrl+C — tapez 'quit' pour quitter[/dim]")
        except EOFError:
            console.print("[dim]Au revoir 👋[/dim]")
            break
        except Exception as e:
            show_error(f"Erreur: {e}")
