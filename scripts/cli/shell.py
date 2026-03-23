# -*- coding: utf-8 -*-
"""
Shell interactif — MCP Tools.

Chaque commande du shell correspond à un outil MCP et expose ses paramètres
via des options --key value. Les commandes sont alignées avec l'API MCP.
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
    show_ssh_result, show_files_result, show_token_result,
)


SHELL_COMMANDS = {
    "help":       "Afficher l'aide",
    "health":     "Vérifier l'état de santé",
    "about":      "Informations sur le service",
    "run":        "run <commande> [--shell bash|sh|python3|node] [--network] [--timeout N] — Exécuter en sandbox",
    "network":    "network <op> <host> [args] [--timeout N] — ping, dig, nslookup, traceroute",
    "http":       "http <url> [METHOD] [--header 'K: V'] [--data JSON] [--body TXT] [--auth-type T --auth-value V] [--no-ssl] [--timeout N]",
    "search":     "search <query> [--detail brief|normal|detailed] [--model M] — Perplexity AI",
    "date":       "date <op> [date] [--tz X] [--days N] [--hours N] [--minutes N] [--format F] [--date2 D]",
    "calc":       "calc <expression> — Calcul math (math.sqrt, statistics.mean...)",
    "doc":        "doc <query> [--context C] [--model M] — Documentation technique via Perplexity",
    "ssh":        "ssh <op> <host> <user> [--password P] [--key K] [--command C] [--port N] [--remote-path P] [--content C] [--sudo] [--timeout N]",
    "files":      "files <op> [--path P] [--path2 P] [--content C] [--prefix P] [--version-id V] [--max-keys N] [--bucket B] [--endpoint E] [--access-key A] [--secret-key S] [--region R] [--timeout N]",
    "token":      "token <op> [name] [--tools T] [--permissions P] [--expires N] [--email E]",
    "quit":       "Quitter le shell",
}


# =============================================================================
# Helpers pour parser les options --key value dans les args du shell
# =============================================================================

def _parse_options(args_str: str, positional_count: int = 0,
                   int_keys: tuple = (), float_keys: tuple = (),
                   bool_flags: tuple = ()):
    """
    Parse une chaîne d'arguments en positionnels + options --key value.

    Retourne (positionals: list[str], options: dict).
    Les bool_flags sont des options sans valeur (--network, --sudo, --no-ssl).
    """
    parts = args_str.strip().split()
    positionals = []
    options = {}
    i = 0
    while i < len(parts):
        if parts[i].startswith("--"):
            key = parts[i][2:].replace("-", "_")
            # Bool flag (pas de valeur après)
            if key in bool_flags:
                options[key] = True
                i += 1
            elif i + 1 < len(parts):
                val = parts[i + 1]
                if key in int_keys:
                    try:
                        options[key] = int(val)
                    except ValueError:
                        options[key] = val
                elif key in float_keys:
                    try:
                        options[key] = float(val)
                    except ValueError:
                        options[key] = val
                else:
                    options[key] = val
                i += 2
            else:
                i += 1
        else:
            positionals.append(parts[i])
            i += 1
    return positionals, options


# =============================================================================
# Commandes système
# =============================================================================

async def cmd_health(client, state, args="", json_output=False):
    """MCP tool: system_health — Pas de paramètres."""
    result = await client.call_rest("GET", "/health")
    if json_output:
        show_json(result)
    elif result.get("status") in ("ok", "healthy"):
        show_health_result(result)
    else:
        show_error(result.get("message", "Erreur"))


async def cmd_about(client, state, args="", json_output=False):
    """MCP tool: system_about — Pas de paramètres."""
    result = await client.call_tool("system_about", {})
    if json_output:
        show_json(result)
    elif result.get("status") == "ok":
        show_about_result(result)
    else:
        show_error(result.get("message", "Erreur"))


# =============================================================================
# Tool: shell
# MCP params: command, shell, cwd, timeout, network
# =============================================================================

async def cmd_run(client, state, args="", json_output=False):
    """Exécuter une commande dans un conteneur sandbox isolé.

    Usage: run <commande> [--shell bash|sh|python3|node] [--cwd DIR] [--timeout N] [--network]

    Exemples :
      run echo hello
      run "import numpy; print(numpy.__version__)" --shell python3
      run "pip install cowsay" --network
      run "curl -s https://httpbin.org/ip" --network --timeout 15
    """
    if not args.strip():
        show_warning("Usage: run <commande> [--shell bash|sh|python3|node] [--cwd DIR] [--timeout N] [--network]")
        show_warning("")
        show_warning("  run echo hello")
        show_warning('  run "import numpy; print(numpy.__version__)" --shell python3')
        show_warning('  run "pip install cowsay" --network')
        show_warning('  run "curl -s https://httpbin.org/ip" --network --timeout 15')
        return

    # Séparer les options de la commande
    # Stratégie : extraire les options connues, le reste = commande
    raw_parts = args.strip().split()
    command_parts = []
    params = {}
    i = 0
    while i < len(raw_parts):
        if raw_parts[i] == "--shell" and i + 1 < len(raw_parts):
            params["shell"] = raw_parts[i + 1]
            i += 2
        elif raw_parts[i] == "--cwd" and i + 1 < len(raw_parts):
            params["cwd"] = raw_parts[i + 1]
            i += 2
        elif raw_parts[i] == "--timeout" and i + 1 < len(raw_parts):
            try:
                params["timeout"] = int(raw_parts[i + 1])
            except ValueError:
                pass
            i += 2
        elif raw_parts[i] == "--network":
            params["network"] = True
            i += 1
        else:
            command_parts.append(raw_parts[i])
            i += 1

    command = " ".join(command_parts)
    if not command:
        show_warning("Commande vide. Usage: run <commande> [options]")
        return

    params["command"] = command
    result = await client.call_tool("shell", params)
    if json_output:
        show_json(result)
    else:
        show_shell_result(result)


# =============================================================================
# Tool: network
# MCP params: host, operation, extra_args, count, timeout
# =============================================================================

NETWORK_OPS = ("ping", "dig", "nslookup", "traceroute")


async def cmd_network(client, state, args="", json_output=False):
    """Diagnostic réseau en sandbox Docker.

    Usage: network <op> <host> [extra_args] [--count N] [--timeout N]

    Exemples :
      network ping google.com
      network ping 8.8.8.8 -c 2
      network ping google.com --count 2
      network dig google.com MX +short
      network nslookup google.com -type=mx
      network traceroute 8.8.8.8 -m 10
      network traceroute 8.8.8.8 --timeout 20
    """
    parts = args.strip().split()
    if len(parts) < 2 or parts[0] not in NETWORK_OPS:
        show_warning("Usage: network <op> <host> [extra_args] [--count N] [--timeout N]")
        show_warning("")
        show_warning("  network ping google.com               — ping avec 4 paquets")
        show_warning("  network ping google.com --count 2     — ping 2 paquets")
        show_warning("  network ping 8.8.8.8 -c 2            — extra_args passés à ping")
        show_warning("  network dig google.com MX +short      — requête DNS MX")
        show_warning("  network nslookup google.com -type=mx")
        show_warning("  network traceroute 8.8.8.8 -m 10")
        show_warning("  network traceroute 8.8.8.8 --timeout 20")
        return
    op = parts[0]
    host = parts[1]
    params = {"host": host, "operation": op}

    # Extraire --count et --timeout du reste, le reste = extra_args
    extra_parts = []
    i = 2
    while i < len(parts):
        if parts[i] == "--count" and i + 1 < len(parts):
            try:
                params["count"] = int(parts[i + 1])
            except ValueError:
                pass
            i += 2
        elif parts[i] == "--timeout" and i + 1 < len(parts):
            try:
                params["timeout"] = int(parts[i + 1])
            except ValueError:
                pass
            i += 2
        else:
            extra_parts.append(parts[i])
            i += 1

    if extra_parts:
        params["extra_args"] = " ".join(extra_parts)

    result = await client.call_tool("network", params)
    if json_output:
        show_json(result)
    else:
        show_network_result(result)


# =============================================================================
# Tool: http
# MCP params: url, method, headers, body, json_body, auth_type, auth_value,
#             timeout, verify_ssl
# =============================================================================

async def cmd_http(client, state, args="", json_output=False):
    """Client HTTP/REST en sandbox Docker.

    Usage: http <url> [METHOD] [--header 'K: V'] [--data JSON] [--body TXT]
                      [--auth-type T] [--auth-value V] [--timeout N] [--no-ssl]

    Exemples :
      http https://httpbin.org/get
      http https://httpbin.org/post POST
      http https://httpbin.org/post POST --data '{"key":"value"}'
      http https://httpbin.org/post POST --body "texte brut"
      http https://httpbin.org/headers GET --header "X-Custom: test"
      http https://api.example.com GET --auth-type bearer --auth-value "mytoken"
      http https://self-signed.example.com GET --no-ssl
    """
    import json as json_module

    parts = args.strip().split()
    if not parts:
        show_warning("Usage: http <url> [METHOD] [--header 'K: V'] [--data JSON] [--body TXT] [--auth-type T] [--auth-value V] [--timeout N] [--no-ssl]")
        show_warning("")
        show_warning("  http https://httpbin.org/get")
        show_warning("  http https://httpbin.org/post POST --data '{\"key\":\"value\"}'")
        show_warning("  http https://httpbin.org/headers GET --header \"X-Custom: test\"")
        show_warning("  http https://api.example.com GET --auth-type bearer --auth-value \"mytoken\"")
        show_warning("  http https://self-signed.example.com GET --no-ssl")
        return

    url = parts[0]
    params = {"url": url, "method": "GET"}

    # Deuxième argument positionnel = méthode HTTP (si pas un flag --)
    i = 1
    if i < len(parts) and not parts[i].startswith("--"):
        params["method"] = parts[i].upper()
        i += 1

    # Parser les options
    while i < len(parts):
        if parts[i] == "--header" and i + 1 < len(parts):
            header_str = parts[i + 1]
            if ":" in header_str:
                key, val = header_str.split(":", 1)
                headers = params.get("headers", {})
                headers[key.strip()] = val.strip()
                params["headers"] = headers
            i += 2
        elif parts[i] == "--data" and i + 1 < len(parts):
            try:
                params["json_body"] = json_module.loads(parts[i + 1])
            except json_module.JSONDecodeError:
                show_error(f"JSON invalide: {parts[i + 1]}")
                return
            i += 2
        elif parts[i] == "--body" and i + 1 < len(parts):
            params["body"] = parts[i + 1]
            i += 2
        elif parts[i] == "--auth-type" and i + 1 < len(parts):
            params["auth_type"] = parts[i + 1]
            i += 2
        elif parts[i] == "--auth-value" and i + 1 < len(parts):
            params["auth_value"] = parts[i + 1]
            i += 2
        elif parts[i] == "--timeout" and i + 1 < len(parts):
            try:
                params["timeout"] = int(parts[i + 1])
            except ValueError:
                pass
            i += 2
        elif parts[i] == "--no-ssl":
            params["verify_ssl"] = False
            i += 1
        else:
            i += 1

    result = await client.call_tool("http", params)
    if json_output:
        show_json(result)
    else:
        show_http_result(result)


# =============================================================================
# Tool: perplexity_search
# MCP params: query, detail_level, model
# =============================================================================

async def cmd_search(client, state, args="", json_output=False):
    """Recherche internet via Perplexity AI.

    Usage: search <query> [--detail brief|normal|detailed] [--model M]

    Exemples :
      search Qu'est-ce que MCP ?
      search "architecture microservices" --detail detailed
      search "Python asyncio" --model sonar-pro
    """
    if not args.strip():
        show_warning("Usage: search <query> [--detail brief|normal|detailed] [--model M]")
        show_warning("")
        show_warning("  search Qu'est-ce que MCP ?")
        show_warning('  search "architecture microservices" --detail detailed')
        show_warning('  search "Python asyncio" --model sonar-pro')
        return

    # Extraire --detail et --model du reste
    raw_parts = args.strip().split()
    query_parts = []
    params = {"detail_level": "normal"}
    i = 0
    while i < len(raw_parts):
        if raw_parts[i] == "--detail" and i + 1 < len(raw_parts):
            params["detail_level"] = raw_parts[i + 1]
            i += 2
        elif raw_parts[i] == "--model" and i + 1 < len(raw_parts):
            params["model"] = raw_parts[i + 1]
            i += 2
        else:
            query_parts.append(raw_parts[i])
            i += 1

    params["query"] = " ".join(query_parts)
    result = await client.call_tool("perplexity_search", params)
    if json_output:
        show_json(result)
    elif result.get("status") == "success":
        show_perplexity_result(result)
    else:
        show_error(result.get("message", "Erreur"))


# =============================================================================
# Tool: date
# MCP params: operation, date, date2, days, hours, minutes, format, tz
# =============================================================================

DATE_OPS = ("now", "today", "parse", "format", "add", "diff", "week_number", "day_of_week")


async def cmd_date(client, state, args="", json_output=False):
    """Manipulation de dates/heures.

    Usage: date <op> [date] [--date2 D] [--tz TZ] [--days N] [--hours N] [--minutes N] [--format F]

    Exemples :
      date now
      date now --tz Europe/Paris
      date today
      date parse 06/03/2026
      date format 2026-03-06 --format %d/%m/%Y
      date add 2026-03-06 --days 10
      date add 2026-03-06 --days 1.5 --hours 3
      date diff 2026-01-01 --date2 2026-03-06
      date diff 2026-01-01 2026-03-06
      date week_number 2026-03-06
      date day_of_week 2026-03-06
    """
    parts = args.strip().split()
    if not parts or parts[0] not in DATE_OPS:
        show_warning("Usage: date <op> [date] [--date2 D] [--tz TZ] [--days N] [--hours N] [--minutes N] [--format F]")
        show_warning("")
        show_warning("  date now                          — date/heure actuelle (UTC)")
        show_warning("  date now --tz Europe/Paris        — avec fuseau horaire")
        show_warning("  date today                        — date du jour")
        show_warning("  date parse 06/03/2026             — parser une date")
        show_warning("  date add 2026-03-06 --days 10     — ajouter des jours")
        show_warning("  date add 2026-03-06 --days 1.5 --hours 3")
        show_warning("  date diff 2026-01-01 --date2 2026-03-06")
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
                try:
                    params[key] = float(val)
                except ValueError:
                    params[key] = val
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


# =============================================================================
# Tool: calc
# MCP params: expr
# =============================================================================

async def cmd_calc(client, state, args="", json_output=False):
    """Calculs mathématiques dans une sandbox Python Docker.

    Usage: calc <expression>

    Exemples :
      calc 2 + 3 * 4
      calc math.sqrt(144)
      calc statistics.mean([10, 20, 30])
    """
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


# =============================================================================
# Tool: perplexity_doc
# MCP params: query, context, model
# =============================================================================

async def cmd_doc(client, state, args="", json_output=False):
    """Documentation technique via Perplexity AI.

    Usage: doc <query> [--context C] [--model M]

    Exemples :
      doc Python asyncio
      doc FastAPI --context "middleware et dépendances"
      doc React hooks --model sonar-pro
    """
    if not args.strip():
        show_warning("Usage: doc <query> [--context C] [--model M]")
        show_warning("")
        show_warning("  doc Python asyncio")
        show_warning('  doc FastAPI --context "middleware et dépendances"')
        show_warning("  doc React hooks --model sonar-pro")
        return

    # Extraire --context et --model du reste
    raw_parts = args.strip().split()
    query_parts = []
    params = {}
    i = 0
    while i < len(raw_parts):
        if raw_parts[i] == "--context" and i + 1 < len(raw_parts):
            params["context"] = raw_parts[i + 1]
            i += 2
        elif raw_parts[i] == "--model" and i + 1 < len(raw_parts):
            params["model"] = raw_parts[i + 1]
            i += 2
        else:
            query_parts.append(raw_parts[i])
            i += 1

    params["query"] = " ".join(query_parts)
    result = await client.call_tool("perplexity_doc", params)
    if json_output:
        show_json(result)
    elif result.get("status") == "success":
        show_doc_result(result)
    else:
        show_error(result.get("message", "Erreur"))


# =============================================================================
# Tool: ssh
# MCP params: host, username, operation, auth_type, password, private_key,
#             command, sudo, port, remote_path, content, timeout
# =============================================================================

SSH_OPS = ("exec", "status", "upload", "download")


async def cmd_ssh(client, state, args="", json_output=False):
    """Exécuter des commandes ou transférer des fichiers via SSH.

    Usage: ssh <op> <host> <user> [--password P] [--key K] [--command C]
                                   [--port N] [--remote-path P] [--content C]
                                   [--sudo] [--timeout N]

    Exemples :
      ssh exec myserver.com root --password pass --command 'uptime'
      ssh status myserver.com admin --password pass
      ssh download myserver.com deploy --password pass --remote-path /var/log/app.log
      ssh upload myserver.com deploy --password pass --remote-path /tmp/cfg --content 'key=val'
      ssh exec myserver.com deploy --password pass --command 'systemctl restart app' --sudo
    """
    parts = args.strip().split()
    if len(parts) < 3 or parts[0] not in SSH_OPS:
        show_warning("Usage: ssh <op> <host> <user> [--password P] [--key K] [--command C] [--port N] [--remote-path P] [--content C] [--sudo] [--timeout N]")
        show_warning("")
        show_warning("  ssh exec myserver.com root --password pass --command 'uptime'")
        show_warning("  ssh status myserver.com admin --password pass")
        show_warning("  ssh download myserver.com deploy --password pass --remote-path /var/log/app.log")
        show_warning("  ssh upload myserver.com deploy --password pass --remote-path /tmp/cfg --content 'key=val'")
        show_warning("  ssh exec myserver.com deploy --password pass --command 'systemctl restart app' --sudo")
        return
    op = parts[0]
    host = parts[1]
    username = parts[2]
    params = {"operation": op, "host": host, "username": username}
    # Parser les options --key value
    i = 3
    while i < len(parts):
        if parts[i] == "--sudo":
            params["sudo"] = True
            i += 1
        elif parts[i].startswith("--") and i + 1 < len(parts):
            key = parts[i][2:].replace("-", "_")
            val = parts[i + 1]
            if key == "port":
                try:
                    params[key] = int(val)
                except ValueError:
                    params[key] = val
            elif key == "timeout":
                try:
                    params[key] = int(val)
                except ValueError:
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


# =============================================================================
# Tool: files (S3)
# MCP params: operation, path, content, path2, prefix, version_id, max_keys,
#             endpoint, access_key, secret_key, bucket, region, timeout
# =============================================================================

FILES_OPS = ("list", "read", "write", "delete", "info", "diff", "versions", "enable_versioning")


async def cmd_files(client, state, args="", json_output=False):
    """Opérations fichiers sur S3 Dell ECS.

    Usage: files <op> [--path P] [--path2 P] [--content C] [--prefix P]
                      [--version-id V] [--max-keys N] [--bucket B]
                      [--endpoint E] [--access-key A] [--secret-key S]
                      [--region R] [--timeout N]

    Opérations : list, read, write, delete, info, diff, versions, enable_versioning

    Exemples :
      files list --prefix data/
      files read --path config/app.json
      files read --path config/app.json --version-id v123456
      files write --path test.txt --content 'hello'
      files info --path config/app.json
      files diff --path v1.json --path2 v2.json
      files versions --path config/app.json
      files enable_versioning
      files delete --path old.json
    """
    parts = args.strip().split()
    if not parts or parts[0] not in FILES_OPS:
        show_warning("Usage: files <op> [--path P] [--path2 P] [--content C] [--prefix P] [--version-id V] [--max-keys N] [--bucket B] [--endpoint E] [--access-key A] [--secret-key S] [--region R] [--timeout N]")
        show_warning("")
        show_warning("  Opérations : list, read, write, delete, info, diff, versions, enable_versioning")
        show_warning("")
        show_warning("  files list --prefix data/")
        show_warning("  files read --path config/app.json")
        show_warning("  files read --path config/app.json --version-id v123456")
        show_warning("  files write --path test.txt --content 'hello'")
        show_warning("  files info --path config/app.json")
        show_warning("  files diff --path v1.json --path2 v2.json")
        show_warning("  files versions --path config/app.json")
        show_warning("  files enable_versioning")
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
                try:
                    params[key] = int(val)
                except ValueError:
                    params[key] = val
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


# =============================================================================
# Tool: token
# MCP params: operation, client_name, permissions, tool_ids, expires_days, email
# =============================================================================

TOKEN_OPS = ("create", "list", "info", "update", "revoke")


async def cmd_token(client, state, args="", json_output=False):
    """Gestion des tokens d'authentification MCP (admin uniquement).

    Usage: token <op> [name] [--tools T] [--permissions P] [--expires N] [--email E]

    Exemples :
      token create agent-prod --tools shell,date,calc --expires 90
      token create cline-dev --tools all --expires 365
      token create admin-user --permissions access,admin
      token list
      token info agent-prod
      token update agent-prod --tools all
      token update agent-prod --tools shell,http,date --email new@ct.com
      token revoke agent-prod
    """
    parts = args.strip().split()
    if not parts or parts[0] not in TOKEN_OPS:
        show_warning("Usage: token <op> [name] [--tools T] [--permissions P] [--expires N] [--email E]")
        show_warning("")
        show_warning("  Opérations : create, list, info, update, revoke")
        show_warning("  'all' dans --tools = les 12 outils (résolu côté serveur)")
        show_warning("")
        show_warning("  token create agent-prod --tools shell,date,calc --expires 90")
        show_warning("  token create cline-dev --tools all --expires 365")
        show_warning("  token create admin-user --permissions access,admin")
        show_warning("  token list")
        show_warning("  token info agent-prod")
        show_warning("  token update agent-prod --tools all")
        show_warning("  token update agent-prod --tools shell,http,date --email new@ct.com")
        show_warning("  token revoke agent-prod")
        return
    op = parts[0]
    params = {"operation": op}
    # Parser les options --key value
    i = 1
    positional = []
    while i < len(parts):
        if parts[i].startswith("--") and i + 1 < len(parts):
            key = parts[i][2:].replace("-", "_")
            val = parts[i + 1]
            if key == "expires" or key == "expires_days":
                try:
                    params["expires_days"] = int(val)
                except ValueError:
                    params["expires_days"] = val
            elif key == "tools":
                params["tool_ids"] = [t.strip() for t in val.split(",") if t.strip()]
            elif key == "permissions":
                params["permissions"] = [p.strip() for p in val.split(",") if p.strip()]
            elif key == "email":
                params["email"] = val
            else:
                params[key] = val
            i += 2
        else:
            positional.append(parts[i])
            i += 1
    # Le premier argument positionnel après l'op est le client_name
    if positional:
        params["client_name"] = positional[0]
    result = await client.call_tool("token", params)
    if json_output:
        show_json(result)
    else:
        show_token_result(result)


# =============================================================================
# Commande help
# =============================================================================

def cmd_help():
    from rich.table import Table
    table = Table(title="🐚 Commandes disponibles", show_header=True)
    table.add_column("Commande", style="cyan bold", min_width=12)
    table.add_column("Description / Usage", style="white")
    for cmd, desc in SHELL_COMMANDS.items():
        table.add_row(cmd, desc)
    table.add_row("", "")
    table.add_row("[dim]--json[/dim]", "[dim]Ajouter à la fin de n'importe quelle commande pour la sortie JSON brute[/dim]")
    console.print(table)


# =============================================================================
# Boucle principale du shell
# =============================================================================

async def run_shell(url: str, token: str):
    client = MCPClient(url, token)
    state = {}

    completer = WordCompleter(
        list(SHELL_COMMANDS.keys()) + list(NETWORK_OPS) + list(DATE_OPS)
        + list(FILES_OPS) + list(SSH_OPS) + list(TOKEN_OPS)
        + ["--json", "--shell", "--network", "--timeout", "--count",
           "--detail", "--model", "--context", "--header", "--data",
           "--body", "--auth-type", "--auth-value", "--no-ssl",
           "--password", "--key", "--command", "--port", "--remote-path",
           "--content", "--sudo", "--path", "--path2", "--prefix",
           "--version-id", "--max-keys", "--bucket", "--endpoint",
           "--access-key", "--secret-key", "--region",
           "--tools", "--permissions", "--expires", "--email",
           "--tz", "--days", "--hours", "--minutes", "--format", "--date2",
           "--cwd"],
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
                # Alias: "ping google.com" → "network ping google.com"
                if command == "ping":
                    args = f"ping {args}"
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
            elif command == "token":
                await cmd_token(client, state, args, json_output)
            else:
                show_warning(f"Commande inconnue: '{command}'. Tapez 'help'.")

        except KeyboardInterrupt:
            console.print("\n[dim]Ctrl+C — tapez 'quit' pour quitter[/dim]")
        except EOFError:
            console.print("[dim]Au revoir 👋[/dim]")
            break
        except Exception as e:
            show_error(f"Erreur: {e}")
