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
# Affichage outil ping
# =============================================================================

def show_ping_result(result: dict):
    status = result.get("status", "?")
    stdout = result.get("stdout", "")
    stderr = result.get("stderr", "")

    icon = "✅" if status == "success" else "❌"
    console.print(f"\n{icon} [bold]Résultat ping[/bold]")
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
