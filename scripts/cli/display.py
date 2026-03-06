# -*- coding: utf-8 -*-
"""
Fonctions d'affichage Rich — MCP Tools.
"""

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.syntax import Syntax
from rich.markdown import Markdown

console = Console()


# =============================================================================
# Utilitaires communs
# =============================================================================

def show_error(msg: str):
    console.print(f"[red]❌ {msg}[/red]")

def show_success(msg: str):
    console.print(f"[green]✅ {msg}[/green]")

def show_warning(msg: str):
    console.print(f"[yellow]⚠️  {msg}[/yellow]")

def show_json(data: dict):
    import json
    console.print(Syntax(json.dumps(data, indent=2, ensure_ascii=False), "json"))


# =============================================================================
# Affichage system_health
# =============================================================================

def show_health_result(result: dict):
    status = result.get("status", "?")
    name = result.get("service_name") or result.get("service", "?")
    version = result.get("version", "")
    icon = "✅" if status == "ok" else "❌"
    info = f"{icon} [bold]{name}[/bold] — Status: [green]{status}[/green]"
    if version:
        info += f" — v{version}"
    console.print(Panel.fit(
        info,
        border_style="green" if status == "ok" else "red",
    ))


# =============================================================================
# Affichage system_about
# =============================================================================

def show_about_result(result: dict):
    name = result.get("service_name", "?")
    version = result.get("version", "?")
    py_version = result.get("python_version", "?")
    tools_count = result.get("tools_count", 0)
    tools = result.get("tools", [])

    console.print(Panel.fit(
        f"[bold]Service :[/bold] [cyan]{name}[/cyan]\n"
        f"[bold]Version :[/bold] [green]{version}[/green]\n"
        f"[bold]Python  :[/bold] {py_version}\n"
        f"[bold]Outils  :[/bold] {tools_count}",
        title="ℹ️  À propos",
        border_style="blue",
    ))

    if tools:
        table = Table(title=f"🔧 Outils MCP ({tools_count})", show_header=True)
        table.add_column("Nom", style="cyan bold", min_width=20)
        table.add_column("Description", style="dim")
        for t in tools:
            table.add_row(t.get("name", "?"), t.get("description", ""))
        console.print(table)


# =============================================================================
# Affichage outil shell
# =============================================================================

def show_shell_result(result: dict):
    status = result.get("status", "?")
    stdout = result.get("stdout", "")
    stderr = result.get("stderr", "")
    rc = result.get("returncode", "?")

    icon = "✅" if status == "success" else "❌"
    console.print(f"\n{icon} [bold]Résultat[/bold] (exit code: {rc})")
    if stdout.strip():
        console.print(Panel(stdout.rstrip(), title="stdout", border_style="green"))
    if stderr.strip():
        console.print(Panel(stderr.rstrip(), title="stderr", border_style="red"))
    if result.get("message"):
        console.print(f"[yellow]{result['message']}[/yellow]")


# =============================================================================
# Affichage outil date
# =============================================================================

def show_date_result(result: dict):
    status = result.get("status", "?")
    operation = result.get("operation", "?")

    icon = "✅" if status == "success" else "❌"
    console.print(f"\n{icon} [bold]date {operation}[/bold]")

    if status == "error":
        console.print(f"[red]{result.get('message', 'Erreur')}[/red]")
        return

    # Afficher les champs pertinents selon l'opération
    fields = [
        ("datetime", "🕐 Datetime"),
        ("date", "📅 Date"),
        ("result", "📋 Résultat"),
        ("diff_days", "📏 Différence (jours)"),
        ("diff_human", "📏 Différence"),
        ("week_number", "📅 Semaine"),
        ("day_number", "📅 Jour (numéro)"),
        ("day_name_en", "📅 Jour (EN)"),
        ("day_name_fr", "📅 Jour (FR)"),
        ("tz", "🌍 Fuseau"),
    ]
    for key, label in fields:
        if key in result:
            console.print(f"  {label} : [cyan]{result[key]}[/cyan]")


# =============================================================================
# Affichage outil calc
# =============================================================================

def show_calc_result(result: dict):
    status = result.get("status", "?")
    expr = result.get("expr", "?")

    icon = "✅" if status == "success" else "❌"
    console.print(f"\n{icon} [bold]calc[/bold]")

    if status == "error":
        console.print(f"  Expression : [dim]{expr}[/dim]")
        console.print(f"  [red]{result.get('message', 'Erreur')}[/red]")
        return

    r = result.get("result", "?")
    console.print(f"  Expression : [dim]{expr}[/dim]")
    console.print(f"  Résultat   : [bold green]{r}[/bold green]")
    if result.get("type"):
        console.print(f"  Type       : [dim]{result['type']}[/dim]")


# =============================================================================
# Affichage outil perplexity_doc
# =============================================================================

def show_doc_result(result: dict):
    status = result.get("status", "?")
    query = result.get("query", "?")
    context = result.get("context", "")
    content = result.get("content", "")
    citations = result.get("citations", [])

    icon = "✅" if status == "success" else "❌"
    title = f"Perplexity Doc — {query}"
    if context:
        title += f" ({context})"
    console.print(f"\n{icon} [bold]{title}[/bold]")

    if status == "error":
        console.print(f"[red]{result.get('message', 'Erreur')}[/red]")
        return

    if content:
        console.print(Markdown(content))

    if citations:
        console.print(f"\n[dim]📎 {len(citations)} citations :[/dim]")
        for i, c in enumerate(citations[:5], 1):
            console.print(f"  [dim][{i}] {c}[/dim]")
        if len(citations) > 5:
            console.print(f"  [dim]... et {len(citations)-5} autres[/dim]")


# =============================================================================
# Affichage outil network
# =============================================================================

def show_network_result(result: dict):
    status = result.get("status", "?")
    operation = result.get("operation", "?")
    host = result.get("host", "?")
    stdout = result.get("stdout", "")
    stderr = result.get("stderr", "")

    icon = "✅" if status == "success" else "❌"
    sandbox_tag = " [dim](sandbox)[/dim]" if result.get("sandbox") else ""
    console.print(f"\n{icon} [bold]{operation}[/bold] → {host}{sandbox_tag}")
    if stdout.strip():
        console.print(stdout)
    if stderr.strip():
        console.print(f"[red]{stderr}[/red]")
    if result.get("message"):
        console.print(f"[yellow]{result['message']}[/yellow]")


# =============================================================================
# Affichage outil http
# =============================================================================

def show_http_result(result: dict):
    status = result.get("status", "?")
    code = result.get("status_code", "?")
    text = result.get("text", "")

    icon = "✅" if status == "success" else "❌"
    console.print(f"\n{icon} [bold]HTTP {code}[/bold]")

    headers = result.get("headers", {})
    if headers:
        ct = headers.get("content-type", "")
        console.print(f"[dim]Content-Type: {ct}[/dim]")

    if text.strip():
        if len(text) > 2000:
            text = text[:2000] + "\n... [TRUNCATED]"
        console.print(Panel(text.rstrip(), title="Response body", border_style="cyan"))

    if result.get("message"):
        console.print(f"[yellow]{result['message']}[/yellow]")


# =============================================================================
# Affichage outil ssh
# =============================================================================

def show_ssh_result(result: dict):
    status = result.get("status", "?")
    operation = result.get("operation", "?")
    host = result.get("host", "?")
    port = result.get("port", 22)
    username = result.get("username", "?")

    icon = "✅" if status == "success" else "❌"
    sandbox_tag = " [dim](sandbox)[/dim]" if result.get("sandbox") else ""
    console.print(f"\n{icon} [bold]ssh {operation}[/bold] → {username}@{host}:{port}{sandbox_tag}")

    if status == "error":
        console.print(f"[red]{result.get('message', 'Erreur')}[/red]")
        if result.get("stderr"):
            console.print(Panel(result["stderr"].rstrip(), title="stderr", border_style="red"))
        return

    if operation == "status":
        console.print(f"  [green]{result.get('message', 'Connexion réussie')}[/green]")
    elif operation == "exec":
        stdout = result.get("stdout", "")
        if stdout.strip():
            console.print(Panel(stdout.rstrip(), title="stdout", border_style="green"))
    elif operation == "upload":
        console.print(f"  [green]{result.get('message', 'Upload réussi')}[/green]")
        if result.get("remote_path"):
            console.print(f"  📁 Remote : [cyan]{result['remote_path']}[/cyan]")
    elif operation == "download":
        content = result.get("content", "")
        if content.strip():
            console.print(Panel(content.rstrip(), title="contenu téléchargé", border_style="green"))

    if result.get("stderr"):
        console.print(Panel(result["stderr"].rstrip(), title="stderr", border_style="yellow"))


# =============================================================================
# Affichage outil files (S3)
# =============================================================================

def show_files_result(result: dict):
    status = result.get("status", "?")
    operation = result.get("operation", "?")
    bucket = result.get("bucket", "?")

    icon = "✅" if status == "success" else "❌"
    sandbox_tag = " [dim](sandbox)[/dim]" if result.get("sandbox") else ""
    console.print(f"\n{icon} [bold]files {operation}[/bold] — bucket:{bucket}{sandbox_tag}")

    if status == "error":
        console.print(f"[red]{result.get('message', 'Erreur')}[/red]")
        return

    if operation == "list":
        count = result.get("count", 0)
        console.print(f"  📋 {count} objet(s)")
        if result.get("prefix"):
            console.print(f"  🔍 Préfixe : [cyan]{result['prefix']}[/cyan]")
        objects = result.get("objects", [])
        if objects:
            table = Table(show_header=True)
            table.add_column("Clé", style="cyan")
            table.add_column("Taille", style="green", justify="right")
            table.add_column("Modifié", style="dim")
            for obj in objects[:50]:
                size = obj.get("size", 0)
                size_str = f"{size:,}" if size < 1_000_000 else f"{size/1_000_000:.1f} MB"
                table.add_row(obj.get("key", "?"), size_str, obj.get("last_modified", "?")[:19])
            if len(objects) > 50:
                table.add_row(f"... +{len(objects)-50} objets", "", "")
            console.print(table)

    elif operation == "read":
        path = result.get("path", "?")
        size = result.get("size", 0)
        console.print(f"  📄 [cyan]{path}[/cyan] ({size} octets)")
        content = result.get("content", "")
        if content.strip():
            if len(content) > 2000:
                content = content[:2000] + "\n... [TRONQUÉ]"
            console.print(Panel(content.rstrip(), title=path, border_style="cyan"))

    elif operation == "write":
        console.print(f"  [green]{result.get('message', 'Fichier écrit')}[/green]")

    elif operation == "delete":
        console.print(f"  [green]{result.get('message', 'Fichier supprimé')}[/green]")

    elif operation == "info":
        path = result.get("path", "?")
        console.print(f"  📄 [cyan]{path}[/cyan]")
        console.print(f"  Taille       : [green]{result.get('size', '?')}[/green] octets")
        console.print(f"  Content-Type : [dim]{result.get('content_type', '?')}[/dim]")
        console.print(f"  Modifié      : [dim]{result.get('last_modified', '?')[:19]}[/dim]")
        console.print(f"  ETag         : [dim]{result.get('etag', '?')}[/dim]")

    elif operation == "diff":
        path1 = result.get("path", "?")
        path2 = result.get("path2", "?")
        identical = result.get("identical", False)
        console.print(f"  📄 [cyan]{path1}[/cyan] vs [cyan]{path2}[/cyan]")
        if identical:
            console.print(f"  [green]Fichiers identiques[/green]")
        else:
            diff_text = result.get("diff", "")
            if diff_text:
                console.print(Syntax(diff_text, "diff"))


# =============================================================================
# Affichage outil perplexity
# =============================================================================

def show_perplexity_result(result: dict):
    status = result.get("status", "?")
    content = result.get("content", "")
    citations = result.get("citations", [])

    icon = "✅" if status == "success" else "❌"
    console.print(f"\n{icon} [bold]Perplexity Search[/bold]")

    if content:
        console.print(Markdown(content))

    if citations:
        console.print(f"\n[dim]📎 {len(citations)} citations :[/dim]")
        for i, c in enumerate(citations[:5], 1):
            console.print(f"  [dim][{i}] {c}[/dim]")
        if len(citations) > 5:
            console.print(f"  [dim]... et {len(citations)-5} autres[/dim]")

    if result.get("message"):
        console.print(f"[yellow]{result['message']}[/yellow]")
