# -*- coding: utf-8 -*-
"""
CLI Click — MCP Tools : commandes scriptables.

Usage :
    python scripts/mcp_cli.py health
    python scripts/mcp_cli.py about
    python scripts/mcp_cli.py run-shell "echo hello"
    python scripts/mcp_cli.py ping google.com
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
    show_shell_result, show_ping_result,
    show_http_result, show_perplexity_result,
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
        elif result.get("status") == "ok":
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
# Outil ping
# =============================================================================

@cli.command("ping")
@click.argument("host")
@click.option("--op", default="ping", type=click.Choice(["ping", "traceroute", "nslookup", "dig"]),
              help="Opération réseau")
@click.option("--count", "-c", default=4, type=int, help="Nombre de paquets (ping)")
@click.option("--json", "-j", "output_json", is_flag=True, help="Sortie JSON brute")
@click.pass_context
def ping_cmd(ctx, host, op, count, output_json):
    """📡 Diagnostic réseau (ping, nslookup, dig, traceroute)."""
    async def _run():
        client = MCPClient(ctx.obj["url"], ctx.obj["token"])
        result = await client.call_tool("ping", {
            "host": host, "operation": op, "count": count
        })
        if output_json:
            show_json(result)
        else:
            show_ping_result(result)
    asyncio.run(_run())


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
# Shell interactif
# =============================================================================

@cli.command("shell")
@click.pass_context
def shell_cmd(ctx):
    """🐚 Lancer le shell interactif."""
    from .shell import run_shell
    asyncio.run(run_shell(ctx.obj["url"], ctx.obj["token"]))
