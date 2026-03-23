# -*- coding: utf-8 -*-
"""
CLI Click — MCP Tools : commandes scriptables.

Usage :
    python scripts/mcp_cli.py health
    python scripts/mcp_cli.py about
    python scripts/mcp_cli.py run-shell "echo hello"
    python scripts/mcp_cli.py network ping google.com
    python scripts/mcp_cli.py http https://httpbin.org/get
    python scripts/mcp_cli.py search "Qu'est-ce que MCP ?"
    python scripts/mcp_cli.py shell
"""

import asyncio
import click
from . import BASE_URL, TOKEN
from .client import MCPClient
from .display import (
    console, show_error, show_success, show_json,
    show_health_result, show_about_result,
    show_shell_result, show_network_result,
    show_http_result, show_perplexity_result,
    show_date_result, show_calc_result, show_doc_result,
    show_ssh_result, show_files_result, show_token_result,
)


@click.group()
@click.option("--url", "-u", envvar=["MCP_URL"], default=BASE_URL, help="URL du serveur MCP")
@click.option("--token", "-t", envvar=["MCP_TOKEN"], default=TOKEN, help="Token d'authentification")
@click.pass_context
def cli(ctx, url, token):
    """🔧 CLI pour MCP Tools — Boîte à outils pour agents IA."""
    ctx.ensure_object(dict)
    ctx.obj["url"] = url
    ctx.obj["token"] = token


# =============================================================================
# Commandes système
# =============================================================================

@cli.command("health")
@click.option("--json", "-j", "output_json", is_flag=True, help="Sortie JSON brute")
@click.pass_context
def health_cmd(ctx, output_json):
    """❤️  Vérifier l'état de santé du service (pas d'auth requise)."""
    async def _run():
        client = MCPClient(ctx.obj["url"], ctx.obj["token"])
        # Health check via REST /health (pas d'auth nécessaire)
        result = await client.call_rest("GET", "/health")
        if output_json:
            show_json(result)
        elif result.get("status") in ("ok", "healthy"):
            show_health_result(result)
        else:
            show_error(result.get("message", "Service indisponible"))
    asyncio.run(_run())


@cli.command("about")
@click.option("--json", "-j", "output_json", is_flag=True, help="Sortie JSON brute")
@click.pass_context
def about_cmd(ctx, output_json):
    """ℹ️  Informations sur le service MCP Tools."""
    async def _run():
        client = MCPClient(ctx.obj["url"], ctx.obj["token"])
        result = await client.call_tool("system_about", {})
        if output_json:
            show_json(result)
        elif result.get("status") == "ok":
            show_about_result(result)
        else:
            show_error(result.get("message", "Erreur"))
    asyncio.run(_run())


# =============================================================================
# Outil shell
# =============================================================================

@cli.command("run-shell")
@click.argument("command")
@click.option("--cwd", default=None, help="Répertoire de travail")
@click.option("--timeout", default=30, type=int, help="Timeout en secondes (max 30)")
@click.option("--json", "-j", "output_json", is_flag=True, help="Sortie JSON brute")
@click.pass_context
def run_shell_cmd(ctx, command, cwd, timeout, output_json):
    """🖥️  Exécuter une commande shell."""
    async def _run():
        client = MCPClient(ctx.obj["url"], ctx.obj["token"])
        params = {"command": command, "timeout": timeout}
        if cwd:
            params["cwd"] = cwd
        result = await client.call_tool("shell", params)
        if output_json:
            show_json(result)
        else:
            show_shell_result(result)
    asyncio.run(_run())


# =============================================================================
# Outil network (groupe de sous-commandes)
# =============================================================================

@cli.group("network")
@click.pass_context
def network_group(ctx):
    """📡 Diagnostic réseau en sandbox Docker (IPs privées RFC 1918 interdites).

    Sous-commandes : ping, traceroute, dig, nslookup.

    \b
    Exemples :
      network ping google.com
      network ping 8.8.8.8 -c 2
      network dig google.com
      network traceroute 8.8.8.8
      network nslookup google.com
    """
    pass


def _run_network(ctx, host: str, operation: str, extra_args: str = "", timeout: int = 15, output_json: bool = False):
    """Helper partagé pour toutes les sous-commandes network."""
    async def _run():
        client = MCPClient(ctx.obj["url"], ctx.obj["token"])
        params = {"host": host, "operation": operation, "timeout": timeout}
        if extra_args:
            params["extra_args"] = extra_args
        result = await client.call_tool("network", params)
        if output_json:
            show_json(result)
        else:
            show_network_result(result)
    asyncio.run(_run())


@network_group.command("ping", context_settings=dict(ignore_unknown_options=True, allow_extra_args=True))
@click.argument("host")
@click.argument("extra", nargs=-1, type=click.UNPROCESSED)
@click.option("--timeout", default=15, type=int, help="Timeout en secondes (max 30)")
@click.option("--json", "-j", "output_json", is_flag=True, help="Sortie JSON brute")
@click.pass_context
def network_ping(ctx, host, extra, timeout, output_json):
    """🏓 Tester la connectivité (ICMP). Arguments passés directement à ping.

    \b
    Exemples :
      network ping google.com
      network ping 8.8.8.8 -c 2
      network ping cloudflare.com -c 1 -W 3
    """
    _run_network(ctx, host, "ping", extra_args=" ".join(extra), timeout=timeout, output_json=output_json)


@network_group.command("traceroute", context_settings=dict(ignore_unknown_options=True, allow_extra_args=True))
@click.argument("host")
@click.argument("extra", nargs=-1, type=click.UNPROCESSED)
@click.option("--timeout", default=15, type=int, help="Timeout en secondes (max 30)")
@click.option("--json", "-j", "output_json", is_flag=True, help="Sortie JSON brute")
@click.pass_context
def network_traceroute(ctx, host, extra, timeout, output_json):
    """🗺️  Tracer le chemin réseau vers un host. Arguments passés directement.

    \b
    Exemples :
      network traceroute google.com
      network traceroute 8.8.8.8 -m 10
    """
    _run_network(ctx, host, "traceroute", extra_args=" ".join(extra), timeout=timeout, output_json=output_json)


@network_group.command("dig", context_settings=dict(ignore_unknown_options=True, allow_extra_args=True))
@click.argument("host")
@click.argument("extra", nargs=-1, type=click.UNPROCESSED)
@click.option("--timeout", default=15, type=int, help="Timeout en secondes (max 30)")
@click.option("--json", "-j", "output_json", is_flag=True, help="Sortie JSON brute")
@click.pass_context
def network_dig(ctx, host, extra, timeout, output_json):
    """🔎 Requête DNS détaillée. Arguments passés après le host.

    \b
    Exemples :
      network dig google.com
      network dig google.com MX
      network dig google.com MX +short
      network dig google.com ANY +noall +answer
    """
    _run_network(ctx, host, "dig", extra_args=" ".join(extra), timeout=timeout, output_json=output_json)


@network_group.command("nslookup", context_settings=dict(ignore_unknown_options=True, allow_extra_args=True))
@click.argument("host")
@click.argument("extra", nargs=-1, type=click.UNPROCESSED)
@click.option("--timeout", default=15, type=int, help="Timeout en secondes (max 30)")
@click.option("--json", "-j", "output_json", is_flag=True, help="Sortie JSON brute")
@click.pass_context
def network_nslookup(ctx, host, extra, timeout, output_json):
    """📋 Résolution DNS. Arguments passés directement à nslookup.

    \b
    Exemples :
      network nslookup google.com
      network nslookup -type=mx google.com
      network nslookup -type=ns example.com
    """
    _run_network(ctx, host, "nslookup", extra_args=" ".join(extra), timeout=timeout, output_json=output_json)


# =============================================================================
# Outil http
# =============================================================================

@cli.command("http")
@click.argument("url")
@click.option("--method", "-m", default="GET", help="Méthode HTTP")
@click.option("--data", "-d", default=None, help="Body JSON (string)")
@click.option("--timeout", default=30, type=int, help="Timeout en secondes")
@click.option("--no-ssl", is_flag=True, help="Désactiver la vérification SSL")
@click.option("--json", "-j", "output_json", is_flag=True, help="Sortie JSON brute")
@click.pass_context
def http_cmd(ctx, url, method, data, timeout, no_ssl, output_json):
    """🌐 Effectuer une requête HTTP."""
    import json as json_module
    async def _run():
        client = MCPClient(ctx.obj["url"], ctx.obj["token"])
        params = {
            "url": url, "method": method,
            "timeout": timeout, "verify_ssl": not no_ssl
        }
        if data:
            try:
                params["json_body"] = json_module.loads(data)
            except json_module.JSONDecodeError:
                show_error(f"Body JSON invalide: {data}")
                return
        result = await client.call_tool("http", params)
        if output_json:
            show_json(result)
        else:
            show_http_result(result)
    asyncio.run(_run())


# =============================================================================
# Outil perplexity
# =============================================================================

@cli.command("search")
@click.argument("query")
@click.option("--detail", "-d", default="normal",
              type=click.Choice(["brief", "normal", "detailed"]),
              help="Niveau de détail")
@click.option("--json", "-j", "output_json", is_flag=True, help="Sortie JSON brute")
@click.pass_context
def search_cmd(ctx, query, detail, output_json):
    """🔍 Recherche internet via Perplexity AI."""
    async def _run():
        client = MCPClient(ctx.obj["url"], ctx.obj["token"])
        result = await client.call_tool("perplexity_search", {
            "query": query, "detail_level": detail
        })
        if output_json:
            show_json(result)
        elif result.get("status") == "success":
            show_perplexity_result(result)
        else:
            show_error(result.get("message", "Erreur"))
    asyncio.run(_run())


# =============================================================================
# Outil date
# =============================================================================

@cli.command("date")
@click.argument("operation")
@click.argument("date", default="")
@click.option("--date2", default=None, help="Deuxième date (pour diff)")
@click.option("--tz", default=None, help="Fuseau horaire (ex: Europe/Paris)")
@click.option("--days", default=None, type=int, help="Jours à ajouter (pour add)")
@click.option("--hours", default=None, type=int, help="Heures à ajouter (pour add)")
@click.option("--minutes", default=None, type=int, help="Minutes à ajouter (pour add)")
@click.option("--format", "fmt", default=None, help="Format strftime (pour format)")
@click.option("--json", "-j", "output_json", is_flag=True, help="Sortie JSON brute")
@click.pass_context
def date_cmd(ctx, operation, date, date2, tz, days, hours, minutes, fmt, output_json):
    """🗓️  Manipulation de dates/heures.

    \b
    Opérations : now, today, parse, format, add, diff, week_number, day_of_week
    Exemples :
      date now
      date now --tz Europe/Paris
      date today
      date parse 06/03/2026
      date format 2026-03-06 --format "%d/%m/%Y"
      date add 2026-03-06 --days 10
      date diff 2026-01-01 --date2 2026-03-06
      date week_number 2026-03-06
      date day_of_week 2026-03-06
    """
    async def _run():
        client = MCPClient(ctx.obj["url"], ctx.obj["token"])
        params = {"operation": operation}
        if date:
            params["date"] = date
        if date2:
            params["date2"] = date2
        if tz:
            params["tz"] = tz
        if days is not None:
            params["days"] = days
        if hours is not None:
            params["hours"] = hours
        if minutes is not None:
            params["minutes"] = minutes
        if fmt:
            params["format"] = fmt
        result = await client.call_tool("date", params)
        if output_json:
            show_json(result)
        else:
            show_date_result(result)
    asyncio.run(_run())


# =============================================================================
# Outil calc
# =============================================================================

@cli.command("calc")
@click.argument("expr")
@click.option("--json", "-j", "output_json", is_flag=True, help="Sortie JSON brute")
@click.pass_context
def calc_cmd(ctx, expr, output_json):
    """🧮 Calculs mathématiques (sandbox Python Docker).

    \b
    Modules math et statistics pré-importés.
    Exemples :
      calc "2 + 3 * 4"
      calc "(3 + 5) * (2 - 1)"
      calc "math.sqrt(144)"
      calc "statistics.mean([10, 20, 30])"
      calc "round(math.pi, 4)"
    """
    async def _run():
        client = MCPClient(ctx.obj["url"], ctx.obj["token"])
        result = await client.call_tool("calc", {"expr": expr})
        if output_json:
            show_json(result)
        else:
            show_calc_result(result)
    asyncio.run(_run())


# =============================================================================
# Outil perplexity_doc
# =============================================================================

@cli.command("doc")
@click.argument("query")
@click.option("--context", "-c", "ctx_str", default=None, help="Aspect spécifique à approfondir")
@click.option("--json", "-j", "output_json", is_flag=True, help="Sortie JSON brute")
@click.pass_context
def doc_cmd(ctx, query, ctx_str, output_json):
    """📚 Documentation technique via Perplexity AI.

    \b
    Exemples :
      doc "Python asyncio"
      doc "FastAPI" --context "middleware et dépendances"
      doc "PostgreSQL" --context "index GIN et recherche full-text"
    """
    async def _run():
        client = MCPClient(ctx.obj["url"], ctx.obj["token"])
        params = {"query": query}
        if ctx_str:
            params["context"] = ctx_str
        result = await client.call_tool("perplexity_doc", params)
        if output_json:
            show_json(result)
        elif result.get("status") == "success":
            show_doc_result(result)
        else:
            show_error(result.get("message", "Erreur"))
    asyncio.run(_run())


# =============================================================================
# Outil ssh
# =============================================================================

@cli.command("ssh")
@click.argument("host")
@click.argument("username")
@click.option("--operation", "-o", default="exec", type=click.Choice(["exec", "status", "upload", "download"]), help="Opération SSH")
@click.option("--command", "-c", "cmd", default=None, help="Commande à exécuter (pour exec)")
@click.option("--password", "-p", default=None, help="Mot de passe SSH")
@click.option("--key", "-k", "private_key", default=None, help="Chemin vers la clé privée (le contenu sera lu)")
@click.option("--port", default=22, type=int, help="Port SSH")
@click.option("--remote-path", "-r", default=None, help="Chemin distant (upload/download)")
@click.option("--content", default=None, help="Contenu à uploader (pour upload)")
@click.option("--sudo", is_flag=True, help="Exécuter avec sudo")
@click.option("--timeout", default=30, type=int, help="Timeout en secondes (max 60)")
@click.option("--json", "-j", "output_json", is_flag=True, help="Sortie JSON brute")
@click.pass_context
def ssh_cmd(ctx, host, username, operation, cmd, password, private_key, port, remote_path, content, sudo, timeout, output_json):
    """🔑 Exécuter des commandes ou transférer des fichiers via SSH (sandbox Docker).

    \b
    Exemples :
      ssh myserver.com root -c "uptime" -p "password"
      ssh myserver.com admin -o status -p "password"
      ssh myserver.com deploy -o exec -c "ls -la /app" -k ~/.ssh/id_rsa
      ssh myserver.com deploy -o upload -r /tmp/config.txt --content "key=value" -p "pass"
      ssh myserver.com deploy -o download -r /var/log/app.log -p "pass"
    """
    async def _run():
        client = MCPClient(ctx.obj["url"], ctx.obj["token"])
        params = {
            "host": host, "username": username,
            "operation": operation, "port": port,
            "timeout": timeout, "sudo": sudo,
        }
        # Auth
        if private_key:
            import os
            key_path = os.path.expanduser(private_key)
            if os.path.isfile(key_path):
                with open(key_path, "r") as f:
                    params["private_key"] = f.read()
                params["auth_type"] = "key"
            else:
                show_error(f"Fichier clé non trouvé : {key_path}")
                return
        elif password:
            params["password"] = password
            params["auth_type"] = "password"
        else:
            show_error("Spécifiez --password ou --key pour l'authentification SSH.")
            return
        if cmd:
            params["command"] = cmd
        if remote_path:
            params["remote_path"] = remote_path
        if content:
            params["content"] = content
        result = await client.call_tool("ssh", params)
        if output_json:
            show_json(result)
        else:
            show_ssh_result(result)
    asyncio.run(_run())


# =============================================================================
# Outil files (S3)
# =============================================================================

@cli.command("files")
@click.argument("operation", type=click.Choice(["list", "read", "write", "delete", "info", "diff"]))
@click.option("--path", "-p", "s3_path", default=None, help="Clé S3 de l'objet")
@click.option("--path2", default=None, help="2ème clé S3 (pour diff)")
@click.option("--content", "-c", default=None, help="Contenu à écrire (pour write)")
@click.option("--prefix", default=None, help="Préfixe pour lister (pour list)")
@click.option("--max-keys", default=100, type=int, help="Nombre max d'objets (pour list)")
@click.option("--endpoint", default=None, help="Endpoint S3 (override config)")
@click.option("--bucket", "-b", default=None, help="Bucket S3 (override config)")
@click.option("--timeout", default=30, type=int, help="Timeout en secondes (max 60)")
@click.option("--json", "-j", "output_json", is_flag=True, help="Sortie JSON brute")
@click.pass_context
def files_cmd(ctx, operation, s3_path, path2, content, prefix, max_keys, endpoint, bucket, timeout, output_json):
    """📁 Opérations fichiers sur S3 Dell ECS (sandbox Docker).

    \b
    Exemples :
      files list --prefix "data/"
      files read -p "config/app.json"
      files write -p "config/app.json" -c '{"key": "value"}'
      files info -p "config/app.json"
      files diff -p "config/v1.json" --path2 "config/v2.json"
      files delete -p "config/old.json"
    """
    async def _run():
        client = MCPClient(ctx.obj["url"], ctx.obj["token"])
        params = {"operation": operation, "timeout": timeout, "max_keys": max_keys}
        if s3_path:
            params["path"] = s3_path
        if path2:
            params["path2"] = path2
        if content:
            params["content"] = content
        if prefix:
            params["prefix"] = prefix
        if endpoint:
            params["endpoint"] = endpoint
        if bucket:
            params["bucket"] = bucket
        result = await client.call_tool("files", params)
        if output_json:
            show_json(result)
        else:
            show_files_result(result)
    asyncio.run(_run())


# =============================================================================
# Outil token (gestion des tokens)
# =============================================================================

@cli.group("token")
@click.pass_context
def token_group(ctx):
    """🔑 Gestion des tokens d'authentification MCP (admin uniquement).

    \b
    Sous-commandes : create, list, info, revoke.
    Chaque token restreint l'accès aux outils via tool_ids.
    """
    pass


@token_group.command("create")
@click.argument("name")
@click.option("--tools", "-t", "tool_ids_str", default="", help="Outils autorisés (séparés par virgule). Vide = tous.")
@click.option("--permissions", "-p", default="access", help="Permissions : access, admin (séparées par virgule)")
@click.option("--expires", "-e", default=90, type=int, help="Expiration en jours (0 = jamais)")
@click.option("--email", default="", help="Email du propriétaire (optionnel, traçabilité)")
@click.option("--json", "-j", "output_json", is_flag=True, help="Sortie JSON brute")
@click.pass_context
def token_create(ctx, name, tool_ids_str, permissions, expires, email, output_json):
    """Créer un nouveau token.

    \b
    Exemples :
      token create agent-prod --tools shell,date,calc --expires 90
      token create cline-dev --tools shell,http,network,date,calc --expires 365
      token create admin-user --permissions access,admin
      token create ct-user --email user@cloud-temple.com --expires 180
    """
    async def _run():
        client = MCPClient(ctx.obj["url"], ctx.obj["token"])
        tools = [t.strip() for t in tool_ids_str.split(",") if t.strip()] if tool_ids_str else []
        perms = [p.strip() for p in permissions.split(",") if p.strip()]
        params = {
            "operation": "create",
            "client_name": name,
            "tool_ids": tools,
            "permissions": perms,
            "expires_days": expires,
        }
        if email:
            params["email"] = email
        result = await client.call_tool("token", params)
        if output_json:
            show_json(result)
        else:
            show_token_result(result)
    asyncio.run(_run())


@token_group.command("list")
@click.option("--json", "-j", "output_json", is_flag=True, help="Sortie JSON brute")
@click.pass_context
def token_list(ctx, output_json):
    """Lister tous les tokens."""
    async def _run():
        client = MCPClient(ctx.obj["url"], ctx.obj["token"])
        result = await client.call_tool("token", {"operation": "list"})
        if output_json:
            show_json(result)
        else:
            show_token_result(result)
    asyncio.run(_run())


@token_group.command("info")
@click.argument("name")
@click.option("--json", "-j", "output_json", is_flag=True, help="Sortie JSON brute")
@click.pass_context
def token_info(ctx, name, output_json):
    """Détails d'un token par nom client."""
    async def _run():
        client = MCPClient(ctx.obj["url"], ctx.obj["token"])
        result = await client.call_tool("token", {"operation": "info", "client_name": name})
        if output_json:
            show_json(result)
        else:
            show_token_result(result)
    asyncio.run(_run())


@token_group.command("revoke")
@click.argument("name")
@click.option("--json", "-j", "output_json", is_flag=True, help="Sortie JSON brute")
@click.pass_context
def token_revoke(ctx, name, output_json):
    """Révoquer (supprimer) un token par nom client."""
    async def _run():
        client = MCPClient(ctx.obj["url"], ctx.obj["token"])
        result = await client.call_tool("token", {"operation": "revoke", "client_name": name})
        if output_json:
            show_json(result)
        else:
            show_token_result(result)
    asyncio.run(_run())


# =============================================================================
# Shell interactif
# =============================================================================

@cli.command("shell")
@click.pass_context
def shell_cmd(ctx):
    """🐚 Lancer le shell interactif."""
    from .shell import run_shell
    asyncio.run(run_shell(ctx.obj["url"], ctx.obj["token"]))
