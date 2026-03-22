# -*- coding: utf-8 -*-
"""
Fonctions d'affichage Rich partagées entre CLI Click et Shell interactif.

Chaque outil MCP devrait avoir sa propre fonction show_xxx_result() ici.
Ces fonctions sont importées dans commands.py ET shell.py (DRY).
"""

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.syntax import Syntax

console = Console()


# =============================================================================
# Utilitaires communs
# =============================================================================

def show_error(msg: str):
    """Affiche un message d'erreur."""
    console.print(f"[red]❌ {msg}[/red]")


def show_success(msg: str):
    """Affiche un message de succès."""
    console.print(f"[green]✅ {msg}[/green]")


def show_warning(msg: str):
    """Affiche un avertissement."""
    console.print(f"[yellow]⚠️  {msg}[/yellow]")


def show_json(data: dict):
    """Affiche un dict en JSON coloré."""
    import json
    console.print(Syntax(
        json.dumps(data, indent=2, ensure_ascii=False), "json"
    ))


# =============================================================================
# Affichage des outils système
# =============================================================================

def show_health_result(result: dict):
    """Affiche le résultat de system_health."""
    status = result.get("status", "?")
    service_name = result.get("service_name", "?")
    services = result.get("services", {})

    icon = "✅" if status in ("ok", "healthy") else "❌"
    color = "green" if status == "ok" else "red"

    table = Table(title=f"{icon} {service_name} — Health Check", show_header=True)
    table.add_column("Service", style="cyan bold")
    table.add_column("Statut", style=color)
    table.add_column("Détails", style="dim")

    for name, info in services.items():
        s = info.get("status", "?")
        s_icon = "✅" if s == "ok" else "❌"
        details = info.get("message", info.get("uptime", ""))
        table.add_row(name, f"{s_icon} {s}", str(details))

    console.print(table)


def show_about_result(result: dict):
    """Affiche le résultat de system_about."""
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
        table.add_column("Nom", style="cyan bold")
        table.add_column("Description", style="dim", max_width=60)
        for t in tools:
            table.add_row(t.get("name", "?"), t.get("description", ""))
        console.print(table)


# =============================================================================
# Affichage des tokens
# =============================================================================

def show_token_create_result(result: dict):
    """Affiche le résultat de token create (token brut affiché une seule fois)."""
    raw = result.get("raw_token", "?")
    name = result.get("client_name", "?")
    perms = ", ".join(result.get("permissions", []))
    email = result.get("email", "")
    expires = result.get("expires_at", "jamais")

    console.print(Panel.fit(
        f"[bold]Client  :[/bold] [cyan]{name}[/cyan]\n"
        f"[bold]Email   :[/bold] {email or '[dim]—[/dim]'}\n"
        f"[bold]Perms   :[/bold] {perms}\n"
        f"[bold]Expire  :[/bold] {expires or 'jamais'}\n"
        f"\n[bold yellow]⚠️  Token (affiché UNE SEULE FOIS) :[/bold yellow]\n"
        f"[green bold]{raw}[/green bold]",
        title="🔑 Token créé",
        border_style="green",
    ))


def show_token_list_result(result: dict):
    """Affiche la liste des tokens."""
    tokens = result.get("tokens", [])

    table = Table(title=f"🔑 Tokens ({len(tokens)})", show_header=True)
    table.add_column("Client", style="cyan bold")
    table.add_column("Email", style="dim")
    table.add_column("Permissions", style="green")
    table.add_column("Hash", style="dim")
    table.add_column("Expire", style="dim")
    table.add_column("Statut", style="white")

    for t in tokens:
        status = "[red]révoqué[/red]" if t.get("revoked") else "[green]actif[/green]"
        perms = ", ".join(t.get("permissions", []))
        email = t.get("email", "")
        expires = t.get("expires_at", "—") or "—"
        table.add_row(
            t.get("client_name", "?"),
            email or "—",
            perms,
            t.get("hash_prefix", "?") + "…",
            expires[:10] if expires != "—" else "—",
            status,
        )

    console.print(table)


def show_token_revoke_result(result: dict):
    """Affiche le résultat de token revoke."""
    msg = result.get("message", "Token révoqué")
    show_success(msg)
