# -*- coding: utf-8 -*-
"""
CLI Click — MCP Tools : commandes scriptables.

Chaque commande Click correspond à un outil MCP et expose TOUS ses paramètres.
Les options reprennent exactement les noms et types des paramètres MCP.

Usage :
    python scripts/mcp_cli.py --help
    python scripts/mcp_cli.py health
    python scripts/mcp_cli.py about
    python scripts/mcp_cli.py run-shell "echo hello"
    python scripts/mcp_cli.py run-shell "import numpy; print(numpy.__version__)" --shell python3
    python scripts/mcp_cli.py run-shell "pip install cowsay" --network
    python scripts/mcp_cli.py network ping google.com
    python scripts/mcp_cli.py network ping 8.8.8.8 -c 2
    python scripts/mcp_cli.py http https://httpbin.org/get
    python scripts/mcp_cli.py http https://api.example.com -m POST --data '{"key":"val"}'
    python scripts/mcp_cli.py http https://api.example.com --auth-type bearer --auth-value "token123"
    python scripts/mcp_cli.py search "Qu'est-ce que MCP ?"
    python scripts/mcp_cli.py search "IA générative" --model "sonar-pro"
    python scripts/mcp_cli.py date now --tz Europe/Paris
    python scripts/mcp_cli.py calc "math.sqrt(144)"
    python scripts/mcp_cli.py doc "FastAPI" --context "middleware"
    python scripts/mcp_cli.py ssh myserver.com root -c "uptime" -p "password"
    python scripts/mcp_cli.py files list --prefix "data/"
    python scripts/mcp_cli.py files versions -p "config/app.json"
    python scripts/mcp_cli.py token create agent-prod --tools shell,date,calc
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
# MCP params: command, shell, cwd, timeout, network
# =============================================================================

@cli.command("run-shell")
@click.argument("command")
@click.option("--shell", "shell_name", default="bash",
              type=click.Choice(["bash", "sh", "python3", "node"]),
              help="Shell à utiliser (défaut: bash)")
@click.option("--cwd", default=None, help="Répertoire de travail (ignoré en mode sandbox)")
@click.option("--timeout", default=30, type=int, help="Timeout en secondes (max selon config serveur)")
@click.option("--network", is_flag=True, default=False,
              help="⚠️ ÉLÉVATION DE PRIVILÈGE : active l'accès réseau (pip install, curl, wget)")
@click.option("--json", "-j", "output_json", is_flag=True, help="Sortie JSON brute")
@click.pass_context
def run_shell_cmd(ctx, command, shell_name, cwd, timeout, network, output_json):
    """🖥️  Exécuter une commande dans un conteneur sandbox isolé.

    \b
    Shells disponibles : bash, sh, python3, node.
    Packages Python pré-installés : numpy, pandas, requests, scipy, etc.
    Par défaut : aucun accès réseau (--network=none).

    \b
    Exemples :
      run-shell "echo hello"
      run-shell "ls -la /tmp"
      run-shell "import numpy; print(numpy.__version__)" --shell python3
      run-shell "console.log(1+2)" --shell node
      run-shell "pip install cowsay && python3 -c 'import cowsay; cowsay.cow(\"hello\")'" --network
      run-shell "curl -s https://httpbin.org/ip" --network
    """
    async def _run():
        client = MCPClient(ctx.obj["url"], ctx.obj["token"])
        params = {"command": command, "shell": shell_name, "timeout": timeout}
        if cwd:
            params["cwd"] = cwd
        if network:
            params["network"] = True
        result = await client.call_tool("shell", params)
        if output_json:
            show_json(result)
        else:
            show_shell_result(result)
    asyncio.run(_run())


# =============================================================================
# Outil network (groupe de sous-commandes)
# MCP params: host, operation, extra_args, count, timeout
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
      network ping google.com --count 2
      network dig google.com
      network dig google.com MX +short
      network traceroute 8.8.8.8
      network nslookup google.com
      network nslookup -type=mx google.com
    """
    pass


def _run_network(ctx, host: str, operation: str, extra_args: str = "",
                 count: int = 4, timeout: int = 15, output_json: bool = False):
    """Helper partagé pour toutes les sous-commandes network."""
    async def _run():
        client = MCPClient(ctx.obj["url"], ctx.obj["token"])
        params = {"host": host, "operation": operation, "timeout": timeout}
        if extra_args:
            params["extra_args"] = extra_args
        if operation == "ping" and not extra_args:
            # count n'est utilisé que pour ping et seulement si extra_args est vide
            params["count"] = count
        result = await client.call_tool("network", params)
        if output_json:
            show_json(result)
        else:
            show_network_result(result)
    asyncio.run(_run())


@network_group.command("ping", context_settings=dict(ignore_unknown_options=True, allow_extra_args=True))
@click.argument("host")
@click.argument("extra", nargs=-1, type=click.UNPROCESSED)
@click.option("--count", default=4, type=int, help="Nombre de pings (1-10, utilisé si pas d'args extra)")
@click.option("--timeout", default=15, type=int, help="Timeout en secondes (max 30)")
@click.option("--json", "-j", "output_json", is_flag=True, help="Sortie JSON brute")
@click.pass_context
def network_ping(ctx, host, extra, count, timeout, output_json):
    """🏓 Tester la connectivité (ICMP). Arguments passés directement à ping.

    \b
    Exemples :
      network ping google.com
      network ping google.com --count 2
      network ping 8.8.8.8 -c 2
      network ping cloudflare.com -c 1 -W 3
    """
    _run_network(ctx, host, "ping", extra_args=" ".join(extra),
                 count=count, timeout=timeout, output_json=output_json)


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
# MCP params: url, method, headers, body, json_body, auth_type, auth_value,
#             timeout, verify_ssl
# =============================================================================

@cli.command("http")
@click.argument("url")
@click.option("--method", "-m", default="GET",
              type=click.Choice(["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD"], case_sensitive=False),
              help="Méthode HTTP (défaut: GET)")
@click.option("--header", "-H", "headers_list", multiple=True,
              help="Header HTTP (répétable). Format: 'Clé: Valeur'. Ex: -H 'Content-Type: text/plain'")
@click.option("--body", "-b", "body_text", default=None,
              help="Corps de la requête en texte brut")
@click.option("--data", "-d", default=None,
              help="Corps de la requête en JSON (string). Prioritaire sur --body")
@click.option("--auth-type", default=None,
              type=click.Choice(["basic", "bearer", "api_key"], case_sensitive=False),
              help="Type d'authentification")
@click.option("--auth-value", default=None,
              help="Valeur d'authentification (ex: 'user:pass' pour basic, token pour bearer)")
@click.option("--timeout", default=30, type=int, help="Timeout en secondes")
@click.option("--no-ssl", is_flag=True, help="Désactiver la vérification SSL")
@click.option("--json", "-j", "output_json", is_flag=True, help="Sortie JSON brute")
@click.pass_context
def http_cmd(ctx, url, method, headers_list, body_text, data, auth_type, auth_value, timeout, no_ssl, output_json):
    """🌐 Client HTTP/REST en sandbox Docker (anti-SSRF, IPs privées bloquées).

    \b
    Méthodes : GET, POST, PUT, DELETE, PATCH, HEAD.
    Auth : basic, bearer, api_key.

    \b
    Exemples :
      http https://httpbin.org/get
      http https://httpbin.org/post -m POST -d '{"key": "value"}'
      http https://httpbin.org/post -m POST --body "texte brut"
      http https://httpbin.org/headers -H "X-Custom: test" -H "Accept: text/plain"
      http https://api.example.com --auth-type bearer --auth-value "mon-token"
      http https://api.example.com --auth-type basic --auth-value "user:password"
      http https://self-signed.example.com --no-ssl
    """
    import json as json_module
    async def _run():
        client = MCPClient(ctx.obj["url"], ctx.obj["token"])
        params = {
            "url": url, "method": method.upper(),
            "timeout": timeout, "verify_ssl": not no_ssl
        }
        # Headers (-H répétable)
        if headers_list:
            headers_dict = {}
            for h in headers_list:
                if ":" in h:
                    key, val = h.split(":", 1)
                    headers_dict[key.strip()] = val.strip()
                else:
                    show_error(f"Header invalide (format 'Clé: Valeur'): {h}")
                    return
            params["headers"] = headers_dict
        # Body JSON (--data) prioritaire sur body texte (--body)
        if data:
            try:
                params["json_body"] = json_module.loads(data)
            except json_module.JSONDecodeError:
                show_error(f"Body JSON invalide: {data}")
                return
        elif body_text:
            params["body"] = body_text
        # Auth
        if auth_type:
            params["auth_type"] = auth_type
        if auth_value:
            params["auth_value"] = auth_value
        result = await client.call_tool("http", params)
        if output_json:
            show_json(result)
        else:
            show_http_result(result)
    asyncio.run(_run())


# =============================================================================
# Outil perplexity_search
# MCP params: query, detail_level, model
# =============================================================================

@cli.command("search")
@click.argument("query")
@click.option("--detail", "-d", default="normal",
              type=click.Choice(["brief", "normal", "detailed"]),
              help="Niveau de détail (défaut: normal)")
@click.option("--model", default=None,
              help="Modèle Perplexity à utiliser (optionnel, défaut selon config serveur)")
@click.option("--json", "-j", "output_json", is_flag=True, help="Sortie JSON brute")
@click.pass_context
def search_cmd(ctx, query, detail, model, output_json):
    """🔍 Recherche internet via Perplexity AI.

    \b
    Niveaux : brief (2-3 phrases), normal (complet), detailed (en profondeur).
    Retourne du Markdown avec citations.

    \b
    Exemples :
      search "Qu'est-ce que le protocole MCP ?"
      search "dernières actualités IA" --detail brief
      search "architecture microservices" --detail detailed
      search "Python asyncio" --model "sonar-pro"
    """
    async def _run():
        client = MCPClient(ctx.obj["url"], ctx.obj["token"])
        params = {"query": query, "detail_level": detail}
        if model:
            params["model"] = model
        result = await client.call_tool("perplexity_search", params)
        if output_json:
            show_json(result)
        elif result.get("status") == "success":
            show_perplexity_result(result)
        else:
            show_error(result.get("message", "Erreur"))
    asyncio.run(_run())


# =============================================================================
# Outil perplexity_doc
# MCP params: query, context, model
# =============================================================================

@cli.command("doc")
@click.argument("query")
@click.option("--context", "-c", "ctx_str", default=None,
              help="Aspect spécifique à approfondir")
@click.option("--model", default=None,
              help="Modèle Perplexity à utiliser (optionnel, défaut selon config serveur)")
@click.option("--json", "-j", "output_json", is_flag=True, help="Sortie JSON brute")
@click.pass_context
def doc_cmd(ctx, query, ctx_str, model, output_json):
    """📚 Documentation technique via Perplexity AI.

    \b
    Retourne syntaxe, exemples de code et bonnes pratiques.

    \b
    Exemples :
      doc "Python asyncio"
      doc "FastAPI" --context "middleware et dépendances"
      doc "PostgreSQL" --context "index GIN et recherche full-text"
      doc "React hooks" --model "sonar-pro"
    """
    async def _run():
        client = MCPClient(ctx.obj["url"], ctx.obj["token"])
        params = {"query": query}
        if ctx_str:
            params["context"] = ctx_str
        if model:
            params["model"] = model
        result = await client.call_tool("perplexity_doc", params)
        if output_json:
            show_json(result)
        elif result.get("status") == "success":
            show_doc_result(result)
        else:
            show_error(result.get("message", "Erreur"))
    asyncio.run(_run())


# =============================================================================
# Outil date
# MCP params: operation, date, date2, days, hours, minutes, format, tz
# Note: days/hours/minutes sont float côté MCP
# =============================================================================

@cli.command("date")
@click.argument("operation")
@click.argument("date", default="")
@click.option("--date2", default=None, help="Deuxième date (pour diff)")
@click.option("--tz", default=None, help="Fuseau horaire IANA (ex: Europe/Paris, America/New_York)")
@click.option("--days", default=None, type=float, help="Jours à ajouter (pour add, accepte décimaux)")
@click.option("--hours", default=None, type=float, help="Heures à ajouter (pour add, accepte décimaux)")
@click.option("--minutes", default=None, type=float, help="Minutes à ajouter (pour add, accepte décimaux)")
@click.option("--format", "fmt", default=None, help="Format strftime (pour format, ex: '%%d/%%m/%%Y %%H:%%M')")
@click.option("--json", "-j", "output_json", is_flag=True, help="Sortie JSON brute")
@click.pass_context
def date_cmd(ctx, operation, date, date2, tz, days, hours, minutes, fmt, output_json):
    """🗓️  Manipulation de dates/heures. Dates en ISO 8601.

    \b
    Opérations : now, today, parse, format, add, diff, week_number, day_of_week

    \b
    Exemples :
      date now
      date now --tz Europe/Paris
      date today
      date parse 06/03/2026
      date format 2026-03-06 --format "%d/%m/%Y"
      date add 2026-03-06 --days 10
      date add 2026-03-06 --days 1.5 --hours 3
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
# MCP params: expr
# =============================================================================

@cli.command("calc")
@click.argument("expr")
@click.option("--json", "-j", "output_json", is_flag=True, help="Sortie JSON brute")
@click.pass_context
def calc_cmd(ctx, expr, output_json):
    """🧮 Calculs mathématiques dans une sandbox Python Docker isolée.

    \b
    Modules math et statistics pré-importés.

    \b
    Exemples :
      calc "2 + 3 * 4"
      calc "(3 + 5) * (2 - 1)"
      calc "math.sqrt(144)"
      calc "math.pi * 2"
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
# Outil ssh
# MCP params: host, username, operation, auth_type, password, private_key,
#             command, sudo, port, remote_path, content, timeout
# =============================================================================

@cli.command("ssh")
@click.argument("host")
@click.argument("username")
@click.option("--operation", "-o", default="exec",
              type=click.Choice(["exec", "status", "upload", "download"]),
              help="Opération SSH (défaut: exec)")
@click.option("--command", "-c", "cmd", default=None,
              help="Commande à exécuter (requis pour exec)")
@click.option("--password", "-p", default=None,
              help="Mot de passe SSH")
@click.option("--key", "-k", "private_key", default=None,
              help="Chemin vers la clé privée (le contenu sera lu)")
@click.option("--port", default=22, type=int,
              help="Port SSH (1-65535, défaut: 22)")
@click.option("--remote-path", "-r", default=None,
              help="Chemin distant (requis pour upload/download)")
@click.option("--content", default=None,
              help="Contenu à uploader (requis pour upload, max 1 MB)")
@click.option("--sudo", is_flag=True,
              help="Exécuter avec sudo")
@click.option("--timeout", default=30, type=int,
              help="Timeout en secondes (max 60)")
@click.option("--json", "-j", "output_json", is_flag=True, help="Sortie JSON brute")
@click.pass_context
def ssh_cmd(ctx, host, username, operation, cmd, password, private_key, port, remote_path, content, sudo, timeout, output_json):
    """🔑 Exécuter des commandes ou transférer des fichiers via SSH en sandbox Docker.

    \b
    Opérations : exec (commande), status (test connexion),
                 upload (envoyer fichier), download (récupérer fichier).
    Auth : password ou key (clé privée). Pas de blocage RFC 1918 (SSH interne légitime).

    \b
    Exemples :
      ssh myserver.com root -c "uptime" -p "password"
      ssh myserver.com admin -o status -p "password"
      ssh myserver.com deploy -o exec -c "ls -la /app" -k ~/.ssh/id_rsa
      ssh myserver.com deploy -o upload -r /tmp/config.txt --content "key=value" -p "pass"
      ssh myserver.com deploy -o download -r /var/log/app.log -p "pass"
      ssh myserver.com deploy -c "systemctl restart app" -p "pass" --sudo
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
# MCP params: operation, path, content, path2, prefix, version_id, max_keys,
#             endpoint, access_key, secret_key, bucket, region, timeout
# =============================================================================

@cli.command("files")
@click.argument("operation", type=click.Choice([
    "list", "read", "write", "delete", "info", "diff", "versions", "enable_versioning"
]))
@click.option("--path", "-p", "s3_path", default=None,
              help="Clé S3 de l'objet (requis pour read, write, delete, info, diff, versions)")
@click.option("--path2", default=None,
              help="2ème clé S3 (pour diff)")
@click.option("--content", "-c", default=None,
              help="Contenu à écrire (pour write, max 5 MB)")
@click.option("--prefix", default=None,
              help="Préfixe pour filtrer le listing (pour list)")
@click.option("--version-id", default=None,
              help="ID de version S3 pour lire une version spécifique")
@click.option("--max-keys", default=100, type=int,
              help="Nombre max d'objets retournés par list (1-1000, défaut: 100)")
@click.option("--endpoint", default=None,
              help="Endpoint S3 (override config serveur)")
@click.option("--access-key", default=None,
              help="Access key S3 (override config serveur)")
@click.option("--secret-key", default=None,
              help="Secret key S3 (override config serveur)")
@click.option("--bucket", "-b", default=None,
              help="Bucket S3 (override config serveur)")
@click.option("--region", default=None,
              help="Région S3 (override config serveur)")
@click.option("--timeout", default=30, type=int,
              help="Timeout en secondes (max 60)")
@click.option("--json", "-j", "output_json", is_flag=True, help="Sortie JSON brute")
@click.pass_context
def files_cmd(ctx, operation, s3_path, path2, content, prefix, version_id,
              max_keys, endpoint, access_key, secret_key, bucket, region, timeout, output_json):
    """📁 Opérations fichiers sur S3 Dell ECS en sandbox Docker.

    \b
    Opérations :
      list               — Lister les objets (avec --prefix optionnel)
      read               — Lire le contenu d'un objet
      write              — Écrire du contenu dans un objet
      delete             — Supprimer un objet
      info               — Métadonnées d'un objet (HEAD)
      diff               — Comparer 2 objets S3
      versions           — Lister les versions d'un objet (versioning S3)
      enable_versioning  — Activer le versioning sur le bucket

    \b
    Config hybride SigV2/SigV4 pour Dell ECS Cloud Temple.

    \b
    Exemples :
      files list --prefix "data/"
      files read -p "config/app.json"
      files read -p "config/app.json" --version-id "v123456"
      files write -p "config/app.json" -c '{"key": "value"}'
      files info -p "config/app.json"
      files diff -p "config/v1.json" --path2 "config/v2.json"
      files versions -p "config/app.json"
      files enable_versioning
      files delete -p "config/old.json"
      files list --endpoint "https://s3.custom.com" --bucket "my-bucket" --access-key "AK" --secret-key "SK"
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
        if version_id:
            params["version_id"] = version_id
        if endpoint:
            params["endpoint"] = endpoint
        if access_key:
            params["access_key"] = access_key
        if secret_key:
            params["secret_key"] = secret_key
        if bucket:
            params["bucket"] = bucket
        if region:
            params["region"] = region
        result = await client.call_tool("files", params)
        if output_json:
            show_json(result)
        else:
            show_files_result(result)
    asyncio.run(_run())


# =============================================================================
# Outil token (gestion des tokens)
# MCP params: operation, client_name, permissions, tool_ids, expires_days, email
# =============================================================================

@cli.group("token")
@click.pass_context
def token_group(ctx):
    """🔑 Gestion des tokens d'authentification MCP (admin uniquement).

    \b
    Sous-commandes : create, list, info, update, revoke.
    Chaque token restreint l'accès aux outils via tool_ids.
    Utilisez --tools all pour autoriser tous les 12 outils.
    """
    pass


@token_group.command("create")
@click.argument("name")
@click.option("--tools", "-t", "tool_ids_str", default="",
              help="Outils autorisés (virgule). 'all' = tous les 12 outils. Requis pour non-admin (fail-closed).")
@click.option("--permissions", "-p", default="access",
              help="Permissions : access, admin (séparées par virgule). Défaut: access.")
@click.option("--expires", "-e", default=90, type=int,
              help="Expiration en jours (0 = jamais). Défaut: 90.")
@click.option("--email", default="",
              help="Email du propriétaire (optionnel, pour traçabilité)")
@click.option("--json", "-j", "output_json", is_flag=True, help="Sortie JSON brute")
@click.pass_context
def token_create(ctx, name, tool_ids_str, permissions, expires, email, output_json):
    """Créer un nouveau token.

    \b
    ⚠️ Le token en clair ne sera affiché qu'UNE SEULE FOIS. Sauvegardez-le !
    ⚠️ Fail-closed : un token non-admin DOIT avoir des tool_ids. Utilisez --tools all
       pour autoriser tous les outils, ou listez-les explicitement.

    \b
    Outils disponibles (12) :
      shell, network, http, ssh, files, perplexity_search,
      perplexity_doc, system_health, system_about, date, calc, token

    \b
    Exemples :
      token create agent-prod --tools shell,date,calc --expires 90
      token create cline-dev --tools all --expires 365
      token create admin-user --permissions access,admin
      token create ct-user --tools all --email user@cloud-temple.com --expires 180
      token create readonly --tools system_health,system_about --expires 30
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
    """Lister tous les tokens (métadonnées seulement, jamais en clair)."""
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


@token_group.command("update")
@click.argument("name")
@click.option("--tools", "-t", "tool_ids_str", default=None,
              help="Nouveaux outils autorisés (virgule). 'all' = tous les 12 outils. Remplace la liste existante.")
@click.option("--permissions", "-p", default=None,
              help="Nouvelles permissions (access, admin). Remplace les permissions existantes.")
@click.option("--email", default=None,
              help="Nouvel email du propriétaire")
@click.option("--json", "-j", "output_json", is_flag=True, help="Sortie JSON brute")
@click.pass_context
def token_update(ctx, name, tool_ids_str, permissions, email, output_json):
    """Mettre à jour un token existant (tool_ids, permissions, email).

    \b
    Seuls les champs fournis sont modifiés. Le token brut n'est pas changé.
    ⚠️ --tools remplace TOUTE la liste tool_ids existante.

    \b
    Outils disponibles (12) :
      shell, network, http, ssh, files, perplexity_search,
      perplexity_doc, system_health, system_about, date, calc, token

    \b
    Exemples :
      token update agent-prod --tools all
      token update agent-prod --tools shell,http,date,calc
      token update agent-prod --permissions access,admin
      token update agent-prod --email new@cloud-temple.com
      token update agent-prod --tools all --email admin@cloud-temple.com
    """
    async def _run():
        client = MCPClient(ctx.obj["url"], ctx.obj["token"])
        params = {
            "operation": "update",
            "client_name": name,
        }
        if tool_ids_str is not None:
            params["tool_ids"] = [t.strip() for t in tool_ids_str.split(",") if t.strip()]
        if permissions is not None:
            params["permissions"] = [p.strip() for p in permissions.split(",") if p.strip()]
        if email is not None:
            params["email"] = email
        result = await client.call_tool("token", params)
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
