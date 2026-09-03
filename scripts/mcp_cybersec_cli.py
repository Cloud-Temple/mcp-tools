#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""CLI Click de mcp-cybersec v0.7.0.

Chaque commande correspond à une opération MCP ; elle ne contourne jamais le
service, le mandat, le tenant ou les contrôles S3. La sortie JSON est pensée
pour GPT, jq et les pipelines opérateurs.
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
from pathlib import Path

import click


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

try:
    from dotenv import load_dotenv
    load_dotenv(ROOT / ".env")
except Exception:
    pass

from scripts.cli.client import MCPClient


def _print(value: dict) -> None:
    click.echo(json.dumps(value, ensure_ascii=False, indent=2, default=str))


def _call(ctx: click.Context, tool: str, arguments: dict) -> None:
    result = asyncio.run(MCPClient(ctx.obj["url"], ctx.obj["token"]).call_tool(tool, arguments))
    _print(result)
    if result.get("status") in {"error", "failed"}:
        ctx.exit(1)


def _load_json(path: str) -> dict:
    try:
        value = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise click.ClickException(f"JSON invalide : {exc}") from exc
    if not isinstance(value, dict):
        raise click.ClickException("Le fichier JSON doit contenir un objet.")
    return value


def _json_list(value: str | None, label: str) -> list:
    if not value:
        return []
    try:
        parsed = json.loads(value)
    except json.JSONDecodeError as exc:
        raise click.ClickException(f"{label} doit être un tableau JSON.") from exc
    if not isinstance(parsed, list):
        raise click.ClickException(f"{label} doit être un tableau JSON.")
    return parsed


@click.group(context_settings={"help_option_names": ["-h", "--help"]})
@click.option("--url", envvar="CYBERSEC_MCP_URL", default="http://localhost:8081", show_default=True, help="URL WAF du service cybersec")
@click.option("--token", envvar=["CYBERSEC_MCP_TOKEN", "CYBERSEC_ADMIN_BOOTSTRAP_KEY"], default="", help="Bearer cybersec")
@click.pass_context
def cli(ctx: click.Context, url: str, token: str) -> None:
    """Pilote mcp-cybersec sans aucune voie de contournement locale."""
    ctx.ensure_object(dict)
    ctx.obj.update(url=url.rstrip("/"), token=token)


@cli.command("health")
@click.pass_context
def health(ctx: click.Context) -> None:
    """Vérifie /health sans authentification."""
    result = asyncio.run(MCPClient(ctx.obj["url"], ctx.obj["token"]).call_rest("GET", "/health"))
    _print(result)
    if result.get("status") not in {"healthy", "ok"}:
        ctx.exit(1)


@cli.command("about")
@click.pass_context
def about(ctx: click.Context) -> None:
    """Affiche le catalogue et les limites de sécurité."""
    _call(ctx, "system_about", {})


@cli.command("activity")
@click.option("--limit", type=click.IntRange(1, 1000), default=100, show_default=True)
@click.option("--trace-id")
@click.option("--call-id")
@click.pass_context
def activity(ctx: click.Context, limit: int, trace_id: str | None, call_id: str | None) -> None:
    """Consulte le journal corrélé (administrateur requis)."""
    _call(ctx, "system_activity", {"limit": limit, "trace_id": trace_id, "call_id": call_id})


@cli.group("campaign")
def campaign_group() -> None:
    """Créer, approuver, suivre, arrêter et restituer les campagnes."""


@campaign_group.command("create")
@click.option("--manifest", "manifest_path", required=True, type=click.Path(exists=True, dir_okay=False, path_type=str))
@click.pass_context
def campaign_create(ctx: click.Context, manifest_path: str) -> None:
    _call(ctx, "campaign", {"operation": "create", "manifest": _load_json(manifest_path)})


@campaign_group.command("list")
@click.option("--tenant-id", help="Filtre réservé à l'administrateur")
@click.pass_context
def campaign_list(ctx: click.Context, tenant_id: str | None) -> None:
    _call(ctx, "campaign", {"operation": "list", "tenant_id": tenant_id})


@campaign_group.command("get")
@click.argument("campaign_id")
@click.option("--tenant-id", help="Requis pour un admin multi-tenant")
@click.pass_context
def campaign_get(ctx: click.Context, campaign_id: str, tenant_id: str | None) -> None:
    _call(ctx, "campaign", {"operation": "get", "campaign_id": campaign_id, "tenant_id": tenant_id})


@campaign_group.command("status")
@click.argument("campaign_id")
@click.option("--tenant-id")
@click.pass_context
def campaign_status(ctx: click.Context, campaign_id: str, tenant_id: str | None) -> None:
    _call(ctx, "campaign", {"operation": "status", "campaign_id": campaign_id, "tenant_id": tenant_id})


@campaign_group.command("approve")
@click.argument("campaign_id")
@click.option("--tenant-id", required=True, help="Tenant de la campagne à figer")
@click.pass_context
def campaign_approve(ctx: click.Context, campaign_id: str, tenant_id: str) -> None:
    _call(ctx, "campaign", {"operation": "approve", "campaign_id": campaign_id, "tenant_id": tenant_id})


@campaign_group.command("cancel")
@click.argument("campaign_id")
@click.option("--tenant-id")
@click.option("--reason", default="")
@click.pass_context
def campaign_cancel(ctx: click.Context, campaign_id: str, tenant_id: str | None, reason: str) -> None:
    _call(ctx, "campaign", {"operation": "cancel", "campaign_id": campaign_id, "tenant_id": tenant_id, "reason": reason})


@campaign_group.command("results")
@click.argument("campaign_id")
@click.option("--tenant-id")
@click.pass_context
def campaign_results(ctx: click.Context, campaign_id: str, tenant_id: str | None) -> None:
    _call(ctx, "campaign", {"operation": "results", "campaign_id": campaign_id, "tenant_id": tenant_id})


@cli.group("scope")
def scope_group() -> None:
    """Lire et vérifier le périmètre approuvé."""


@scope_group.command("show")
@click.argument("campaign_id")
@click.option("--tenant-id")
@click.pass_context
def scope_show(ctx: click.Context, campaign_id: str, tenant_id: str | None) -> None:
    _call(ctx, "scope", {"operation": "show", "campaign_id": campaign_id, "tenant_id": tenant_id})


@scope_group.command("resolve")
@click.argument("campaign_id")
@click.argument("target")
@click.pass_context
def scope_resolve(ctx: click.Context, campaign_id: str, target: str) -> None:
    _call(ctx, "scope", {"operation": "resolve", "campaign_id": campaign_id, "target": target})


@scope_group.command("check")
@click.argument("campaign_id")
@click.argument("target")
@click.pass_context
def scope_check(ctx: click.Context, campaign_id: str, target: str) -> None:
    _call(ctx, "scope", {"operation": "check", "campaign_id": campaign_id, "target": target})


@cli.command("network")
@click.argument("campaign_id")
@click.argument("operation", type=click.Choice(["dns", "reverse_dns", "ping", "traceroute", "tcp", "tls"]))
@click.argument("target")
@click.option("--port", type=click.IntRange(1, 65535), default=443)
@click.option("--timeout", type=click.IntRange(1, 120), default=15)
@click.option("--count", type=click.IntRange(1, 5), default=2)
@click.option("--max-hops", type=click.IntRange(1, 30), default=10)
@click.pass_context
def network(ctx: click.Context, campaign_id: str, operation: str, target: str, port: int, timeout: int, count: int, max_hops: int) -> None:
    _call(ctx, "network", {"campaign_id": campaign_id, "operation": operation, "target": target, "port": port, "timeout": timeout, "count": count, "max_hops": max_hops})


@cli.command("http")
@click.argument("campaign_id")
@click.argument("url")
@click.option("--method", type=click.Choice(["GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE"], case_sensitive=False), default="GET")
@click.option("--headers", default="{}", help="Objet JSON de headers non sensibles")
@click.option("--body")
@click.option("--no-follow", is_flag=True, default=False)
@click.option("--timeout", type=click.IntRange(1, 300), default=30)
@click.pass_context
def http(ctx: click.Context, campaign_id: str, url: str, method: str, headers: str, body: str | None, no_follow: bool, timeout: int) -> None:
    try:
        parsed_headers = json.loads(headers)
    except json.JSONDecodeError as exc:
        raise click.ClickException("--headers doit être un objet JSON.") from exc
    if not isinstance(parsed_headers, dict):
        raise click.ClickException("--headers doit être un objet JSON.")
    _call(ctx, "http", {"campaign_id": campaign_id, "url": url, "method": method, "headers": parsed_headers, "body": body, "follow_redirects": not no_follow, "timeout": timeout})


@cli.command("nmap")
@click.argument("campaign_id")
@click.argument("target")
@click.option("--idempotency-key", required=True)
@click.option("--profile", type=click.Choice(["quick", "top-ports", "full-tcp", "service", "safe-scripts"]), default="quick")
@click.option("--ports", help="Tableau JSON, sous-ensemble du mandat, ex. [80,443]")
@click.option("--discovery-only", is_flag=True)
@click.option("--service-detection", is_flag=True)
@click.option("--safe-scripts", is_flag=True)
@click.option("--timing", type=click.IntRange(0, 4), default=3)
@click.option("--max-rate", type=click.IntRange(1, 10000), default=100)
@click.option("--timeout", type=click.IntRange(5, 14400), default=600)
@click.pass_context
def nmap(ctx: click.Context, campaign_id: str, target: str, idempotency_key: str, profile: str, ports: str | None, discovery_only: bool, service_detection: bool, safe_scripts: bool, timing: int, max_rate: int, timeout: int) -> None:
    _call(ctx, "nmap", {"campaign_id": campaign_id, "target": target, "idempotency_key": idempotency_key, "profile": profile, "ports": _json_list(ports, "ports") if ports else None, "discovery_only": discovery_only, "service_detection": service_detection, "safe_scripts": safe_scripts, "timing": timing, "max_rate": max_rate, "timeout": timeout})


@cli.command("nuclei")
@click.argument("campaign_id")
@click.argument("target")
@click.option("--idempotency-key", required=True)
@click.option("--profile", type=click.Choice(["recon", "active_standard", "active_extended"]), default="recon")
@click.option("--template-ids", help="Tableau JSON d'IDs versionnés")
@click.option("--tags", help="Tableau JSON de tags autorisés")
@click.option("--severities", help="Tableau JSON de sévérités")
@click.option("--rate-limit", type=click.IntRange(1, 1000), default=10)
@click.option("--concurrency", type=click.IntRange(1, 64), default=2)
@click.option("--timeout", type=click.IntRange(5, 14400), default=600)
@click.pass_context
def nuclei(ctx: click.Context, campaign_id: str, target: str, idempotency_key: str, profile: str, template_ids: str | None, tags: str | None, severities: str | None, rate_limit: int, concurrency: int, timeout: int) -> None:
    _call(ctx, "nuclei", {"campaign_id": campaign_id, "target": target, "idempotency_key": idempotency_key, "profile": profile, "template_ids": _json_list(template_ids, "template_ids") if template_ids else None, "tags": _json_list(tags, "tags") if tags else None, "severities": _json_list(severities, "severities") if severities else None, "rate_limit": rate_limit, "concurrency": concurrency, "timeout": timeout})


@cli.command("shell")
@click.argument("campaign_id")
@click.argument("command")
@click.option("--shell", "shell_name", type=click.Choice(["bash", "sh", "python3"]), default="bash")
@click.option("--input-paths", help="Tableau JSON des fichiers workspace à copier")
@click.option("--output-paths", help="Tableau JSON des résultats à remonter")
@click.option("--timeout", type=click.IntRange(5, 1800), default=120)
@click.pass_context
def shell(ctx: click.Context, campaign_id: str, command: str, shell_name: str, input_paths: str | None, output_paths: str | None, timeout: int) -> None:
    _call(ctx, "shell", {"campaign_id": campaign_id, "command": command, "shell_name": shell_name, "input_paths": _json_list(input_paths, "input_paths") if input_paths else None, "output_paths": _json_list(output_paths, "output_paths") if output_paths else None, "timeout": timeout})


@cli.group("files")
def files_group() -> None:
    """Manipule exclusivement le workspace S3 de la campagne."""


def _files(ctx, operation: str, campaign_id: str, **kwargs) -> None:
    _call(ctx, "files", {"campaign_id": campaign_id, "operation": operation, **kwargs})


@files_group.command("list")
@click.argument("campaign_id")
@click.option("--prefix", default="")
@click.pass_context
def files_list(ctx: click.Context, campaign_id: str, prefix: str) -> None: _files(ctx, "list", campaign_id, prefix=prefix)


@files_group.command("read")
@click.argument("campaign_id")
@click.argument("path")
@click.pass_context
def files_read(ctx: click.Context, campaign_id: str, path: str) -> None: _files(ctx, "read", campaign_id, path=path)


@files_group.command("write")
@click.argument("campaign_id")
@click.argument("path")
@click.option("--content", required=True)
@click.pass_context
def files_write(ctx: click.Context, campaign_id: str, path: str, content: str) -> None: _files(ctx, "write", campaign_id, path=path, content=content)


@files_group.command("info")
@click.argument("campaign_id")
@click.argument("path")
@click.pass_context
def files_info(ctx: click.Context, campaign_id: str, path: str) -> None: _files(ctx, "info", campaign_id, path=path)


@files_group.command("diff")
@click.argument("campaign_id")
@click.argument("path")
@click.argument("other_path")
@click.pass_context
def files_diff(ctx: click.Context, campaign_id: str, path: str, other_path: str) -> None: _files(ctx, "diff", campaign_id, path=path, other_path=other_path)


@files_group.command("versions")
@click.argument("campaign_id")
@click.argument("path")
@click.pass_context
def files_versions(ctx: click.Context, campaign_id: str, path: str) -> None: _files(ctx, "versions", campaign_id, path=path)


@cli.group("evidence")
def evidence_group() -> None:
    """Consulte et exporte les preuves de la campagne."""


@evidence_group.command("list")
@click.argument("campaign_id")
@click.option("--job-id")
@click.pass_context
def evidence_list(ctx: click.Context, campaign_id: str, job_id: str | None) -> None: _call(ctx, "evidence", {"campaign_id": campaign_id, "operation": "list", "job_id": job_id})


@evidence_group.command("read")
@click.argument("campaign_id")
@click.argument("evidence_ref")
@click.pass_context
def evidence_read(ctx: click.Context, campaign_id: str, evidence_ref: str) -> None: _call(ctx, "evidence", {"campaign_id": campaign_id, "operation": "read", "evidence_ref": evidence_ref})


@evidence_group.command("export")
@click.argument("campaign_id")
@click.pass_context
def evidence_export(ctx: click.Context, campaign_id: str) -> None: _call(ctx, "evidence", {"campaign_id": campaign_id, "operation": "export"})


@cli.group("token")
def token_group() -> None:
    """Gère les tokens cybersec (administrateur uniquement)."""


@token_group.command("create")
@click.argument("client_name")
@click.option("--tenant-id")
@click.option("--tool-ids", required=True, help="Tableau JSON des outils autorisés")
@click.option("--permissions", default='["access"]', help="Tableau JSON des permissions")
@click.option("--expires-days", type=click.IntRange(1, 3650), default=90)
@click.pass_context
def token_create(ctx: click.Context, client_name: str, tenant_id: str | None, tool_ids: str, permissions: str, expires_days: int) -> None:
    _call(ctx, "token", {"operation": "create", "client_name": client_name, "tenant_id": tenant_id, "tool_ids": _json_list(tool_ids, "tool_ids"), "permissions": _json_list(permissions, "permissions"), "expires_days": expires_days})


@token_group.command("list")
@click.pass_context
def token_list(ctx: click.Context) -> None: _call(ctx, "token", {"operation": "list"})


@token_group.command("info")
@click.argument("client_name")
@click.pass_context
def token_info(ctx: click.Context, client_name: str) -> None: _call(ctx, "token", {"operation": "info", "client_name": client_name})


@token_group.command("revoke")
@click.argument("client_name")
@click.pass_context
def token_revoke(ctx: click.Context, client_name: str) -> None: _call(ctx, "token", {"operation": "revoke", "client_name": client_name})


if __name__ == "__main__":
    cli()
