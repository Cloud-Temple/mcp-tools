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
# Shell interactif
# =============================================================================

@cli.command("shell")
@click.pass_context
def shell_cmd(ctx):
    """🐚 Lancer le shell interactif."""
    from .shell import run_shell
    asyncio.run(run_shell(ctx.obj["url"], ctx.obj["token"]))
