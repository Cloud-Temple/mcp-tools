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
    # `--json` est un contrat machine : Rich/Syntax peut replier une longue
    # chaîne à la largeur du terminal et rendre le flux invalide pour jq ou un
    # autre programme. L'écrire brut préserve exactement le JSON MCP.
    print(json.dumps(data, indent=2, ensure_ascii=False, default=str))


# =============================================================================
# Affichage activité corrélée
# =============================================================================

_ACTIVITY_STATE = {
    "succeeded": ("✅", "terminé"),
    "tool_failed": ("❌", "échec outil"),
    "remote_result_uncertain": ("⚠️", "résultat distant incertain"),
    "response_missing": ("❌", "réponse MCP absente"),
    "response_delivery_failed": ("❌", "émission ASGI échouée"),
    "response_terminal_unobserved": ("⚠️", "réponse terminale non observée"),
    "response_incomplete": ("⚠️", "réponse incomplète"),
    "client_cancelled": ("⚠️", "client annulé"),
    "cancelled": ("⚠️", "annulé"),
    "transport_failed": ("❌", "transport en échec"),
    "transport_completed": ("✅", "transport terminé"),
    "incomplete": ("⚠️", "incomplet"),
}


def _activity_label(state: str) -> tuple[str, str]:
    return _ACTIVITY_STATE.get(state or "", ("•", state or "inconnu"))


def _format_activity_duration(duration_ms) -> str:
    if not isinstance(duration_ms, (int, float)):
        return "—"
    if duration_ms < 1000:
        return f"{round(duration_ms)} ms"
    return f"{duration_ms / 1000:.1f} s"


def show_activity_result(result: dict, details: bool = False, include_protocol: bool = False):
    """Affiche les appels corrélés ; le JSON brut reste disponible avec --json."""
    if result.get("status") != "ok":
        show_error(result.get("message", "Impossible de lire l'activité"))
        return

    stats = result.get("stats", {}) if isinstance(result.get("stats"), dict) else {}
    all_calls = result.get("calls", []) if isinstance(result.get("calls"), list) else []
    calls = all_calls if include_protocol else [call for call in all_calls if call.get("kind") == "tool_call"]
    title = f"📋 Activité corrélée — {len(calls)} appel(s)"
    if not include_protocol and len(calls) != len(all_calls):
        title += f" (tools sur {len(all_calls)} traces)"
    if stats:
        title += f" · buffer {stats.get('stored_events', '?')}/{stats.get('max_events', '?')}"
    table = Table(title=title, show_header=True)
    table.add_column("Heure", style="dim", no_wrap=True)
    table.add_column("Verdict", no_wrap=True)
    table.add_column("Tool", style="cyan")
    table.add_column("Acteur / call", overflow="fold")
    table.add_column("Trace", style="dim", overflow="fold")
    table.add_column("Durée", justify="right", no_wrap=True)
    table.add_column("Transport", style="dim", overflow="fold")

    for call in calls:
        icon, label = _activity_label(str(call.get("terminal_state", "")))
        if call.get("terminal_state") == "succeeded" and not call.get("mcp_terminal_required"):
            label = "terminé — réponse HTTP émise"
        if call.get("timeline_complete") is False:
            label += " · trace partielle"
        started = str(call.get("started_at", ""))
        time_value = started[11:19] if len(started) >= 19 else started
        actor = str(call.get("actor", "—"))
        call_id = str(call.get("call_id", ""))
        actor_call = actor if not call_id else f"{actor}\n{call_id}"
        duration_value = _format_activity_duration(call.get("duration_ms"))
        table.add_row(
            time_value,
            f"{icon} {label}",
            str(call.get("tool", call.get("rpc_method", "—"))),
            actor_call,
            str(call.get("trace_id", "—")),
            duration_value,
            str(call.get("transport_state", "—")),
        )
    console.print(table)

    if not calls:
        console.print("[dim]Aucun appel d'outil dans cette fenêtre. Utilisez --all pour voir les échanges de protocole.[/dim]")

    if stats.get("evicted_capacity") or stats.get("evicted_age"):
        show_warning(
            "Historique local tronqué : "
            f"capacité={stats.get('evicted_capacity', 0)}, âge={stats.get('evicted_age', 0)}."
        )

    if details:
        import json
        for call in calls:
            icon, label = _activity_label(str(call.get("terminal_state", "")))
            if call.get("timeline_complete") is False:
                label += " · trace partielle"
            lines = []
            for event in call.get("events", []):
                timestamp = str(event.get("timestamp", ""))
                moment = timestamp[11:23] if len(timestamp) >= 23 else timestamp
                line = f"{event.get('sequence', '?'):>5} {moment}  {event.get('event', '?')}"
                if event.get("details"):
                    line += "  " + json.dumps(event["details"], ensure_ascii=False, default=str)
                lines.append(line)
            console.print(Panel(
                "\n".join(lines) or "Aucune étape conservée.",
                title=f"{icon} {label} · {call.get('trace_id', '?')}",
                border_style="green" if call.get("terminal_state") == "succeeded" else "yellow",
            ))


# =============================================================================
# Affichage system_health
# =============================================================================

def show_health_result(result: dict):
    status = result.get("status", "?")
    name = result.get("service_name") or result.get("service", "?")
    version = result.get("version", "")
    icon = "✅" if status in ("ok", "healthy") else "❌"
    info = f"{icon} [bold]{name}[/bold] — Status: [green]{status}[/green]"
    if version:
        info += f" — v{version}"
    console.print(Panel.fit(
        info,
        border_style="green" if status in ("ok", "healthy") else "red",
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

    elif operation == "versions":
        path = result.get("path", "?")
        versions = result.get("versions", [])
        count = result.get("count", len(versions))
        console.print(f"  📄 [cyan]{path}[/cyan] — {count} version(s)")
        if versions:
            table = Table(show_header=True)
            table.add_column("Version ID", style="cyan")
            table.add_column("Taille", style="green", justify="right")
            table.add_column("Modifié", style="dim")
            table.add_column("Latest", style="yellow")
            for v in versions[:50]:
                size = v.get("size", 0)
                size_str = f"{size:,}" if size < 1_000_000 else f"{size/1_000_000:.1f} MB"
                is_latest = "✅" if v.get("is_latest") else ""
                table.add_row(
                    v.get("version_id", "?")[:20],
                    size_str,
                    str(v.get("last_modified", "?"))[:19],
                    is_latest,
                )
            if len(versions) > 50:
                table.add_row(f"... +{len(versions)-50} versions", "", "", "")
            console.print(table)

    elif operation == "enable_versioning":
        console.print(f"  [green]{result.get('message', 'Versioning activé')}[/green]")


# =============================================================================
# Affichage outil token
# =============================================================================

def show_token_result(result: dict):
    status = result.get("status", "?")
    operation = result.get("operation", "")

    icon = "✅" if status == "success" else "❌"

    if status == "error":
        console.print(f"\n{icon} [bold]token[/bold]")
        console.print(f"[red]{result.get('message', 'Erreur')}[/red]")
        return

    # --- CREATE ---
    if "token" in result:
        raw_token = result.get("token", "")
        client_name = result.get("client_name", "?")
        console.print(f"\n{icon} [bold]Token créé pour '{client_name}'[/bold]")
        console.print(Panel.fit(
            f"[bold yellow]{raw_token}[/bold yellow]",
            title="⚠️  TOKEN (sauvegardez-le maintenant !)",
            border_style="yellow",
        ))
        console.print(f"  Client      : [cyan]{client_name}[/cyan]")
        email = result.get("email", "")
        if email:
            console.print(f"  Email       : [cyan]{email}[/cyan]")
        console.print(f"  Permissions : [green]{', '.join(result.get('permissions', []))}[/green]")
        tool_ids = result.get("tool_ids", [])
        if tool_ids:
            console.print(f"  Outils      : [cyan]{', '.join(tool_ids)}[/cyan]")
        else:
            console.print(f"  Outils      : [dim](tous — aucune restriction tool_ids)[/dim]")
        console.print(f"  Expire      : {result.get('expires_at', 'jamais')}")
        console.print(f"  Hash        : [dim]{result.get('token_hash', '?')}[/dim]")
        return

    # --- LIST ---
    tokens = result.get("tokens")
    if tokens is not None:
        count = result.get("count", 0)
        console.print(f"\n{icon} [bold]{count} token(s)[/bold]")
        if tokens:
            table = Table(show_header=True)
            table.add_column("Client", style="cyan bold", min_width=15)
            table.add_column("Email", style="dim")
            table.add_column("Permissions", style="green")
            table.add_column("Outils (tool_ids)", style="white")
            table.add_column("Expire", style="dim")
            table.add_column("Créé par", style="dim")
            for t in tokens:
                tool_str = ", ".join(t.get("tool_ids", [])) or "(tous)"
                exp = t.get("expires_at", "jamais") or "jamais"
                if t.get("expired"):
                    exp = f"[red]{exp[:10]} (EXPIRÉ)[/red]"
                elif exp != "jamais":
                    exp = exp[:10]
                table.add_row(
                    t.get("client_name", "?"),
                    t.get("email", "") or "",
                    ", ".join(t.get("permissions", [])),
                    tool_str,
                    exp,
                    t.get("created_by", "?"),
                )
            console.print(table)
        return

    # --- INFO ---
    if "client_name" in result:
        cn = result.get("client_name", "?")
        console.print(f"\n{icon} [bold]Token : {cn}[/bold]")
        email = result.get("email", "")
        if email:
            console.print(f"  Email       : [cyan]{email}[/cyan]")
        console.print(f"  Permissions : [green]{', '.join(result.get('permissions', []))}[/green]")
        tool_ids = result.get("tool_ids", [])
        if tool_ids:
            console.print(f"  Outils      : [cyan]{', '.join(tool_ids)}[/cyan]")
        else:
            console.print(f"  Outils      : [dim](tous)[/dim]")
        console.print(f"  Créé le     : {result.get('created_at', '?')[:19]}")
        exp = result.get("expires_at") or "jamais"
        if result.get("expired"):
            console.print(f"  Expire      : [red]{exp[:19]} (EXPIRÉ)[/red]")
        else:
            console.print(f"  Expire      : {exp[:19] if exp != 'jamais' else exp}")
        console.print(f"  Créé par    : {result.get('created_by', '?')}")
        console.print(f"  Hash        : [dim]{result.get('token_hash_prefix', '?')}[/dim]")
        return

    # --- REVOKE / generic ---
    if result.get("message"):
        console.print(f"\n{icon} [bold]token[/bold] — {result['message']}")


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
