# -*- coding: utf-8 -*-
"""Catalogue MCP distinct de mcp-tools pour les campagnes cybersec."""

from __future__ import annotations

import platform
from pathlib import Path
from typing import Annotated, Optional

from mcp.server.mcpserver import MCPServer
from pydantic import Field

from .identity import AuthorizationError, current_token_info, require_admin, require_tool_access
from .models import ValidationError
from .services import CybersecServices
from .storage import ObjectNotFound


CYBERSEC_TOOL_IDS = {
    "campaign", "scope", "network", "http", "nmap", "nuclei", "evidence", "shell", "files", "token",
    "system_health", "system_about", "system_activity",
}


def _services() -> CybersecServices:
    # Import tardif pour que tools/list et le health statique restent
    # disponibles même si le bucket de production est temporairement absent.
    from .server import get_services
    return get_services()


def _token() -> dict:
    value = current_token_info.get()
    if value is None:
        raise AuthorizationError("Authentification requise.")
    return value


async def _safe(action):
    try:
        return await action()
    except (AuthorizationError, ValidationError, ObjectNotFound, ValueError) as exc:
        return {"status": "error", "message": str(exc), "traffic_emitted": False}
    except Exception as exc:
        # Ne jamais rendre les exceptions de stockage, Docker ou SDK à un agent
        # si elles peuvent transporter un endpoint ou une valeur sensible.
        return {"status": "error", "message": f"Erreur interne contrôlée : {type(exc).__name__}.", "traffic_emitted": False}


def register_all_tools(mcp: MCPServer) -> None:
    """Enregistre le catalogue cyber ; aucun import du catalogue mcp-tools."""
    from src.mcp_tools.observability import traced_tool

    @mcp.tool()
    @traced_tool("campaign")
    async def campaign(
        operation: Annotated[str, Field(description="create, get, list, status, approve, cancel ou results")],
        campaign_id: Annotated[Optional[str], Field(default=None, description="Identifiant de campagne")]=None,
        manifest: Annotated[Optional[dict], Field(default=None, description="Mandat préparé : cibles, fenêtre, profils, limites et contacts")]=None,
        tenant_id: Annotated[Optional[str], Field(default=None, description="Tenant administratif uniquement ; ignoré/refusé pour une mission")]=None,
        reason: Annotated[str, Field(default="", description="Motif borné pour l'annulation")]= "",
    ) -> dict:
        """Gère une campagne sous mandat. L'approbation reste réservée à un administrateur humain."""
        async def action():
            require_tool_access("campaign")
            service = _services()
            token = _token()
            if operation == "create":
                if manifest is None:
                    raise ValidationError("manifest est requis pour campaign create.")
                result = await service.campaigns.create(manifest, token)
                return {"status": "success", "campaign": result, "traffic_emitted": False}
            if operation == "list":
                result = await service.campaigns.list(token, admin_tenant_id=tenant_id)
                return {"status": "success", "campaigns": result, "traffic_emitted": False}
            if not campaign_id:
                raise ValidationError("campaign_id est requis.")
            if operation in {"get", "status"}:
                result = await service.campaigns.get(campaign_id, token, admin_tenant_id=tenant_id)
                return {"status": "success", "campaign": result, "traffic_emitted": False}
            if operation == "approve":
                result = await service.campaigns.approve(campaign_id, token, admin_tenant_id=tenant_id or "")
                return {"status": "success", "campaign": result, "traffic_emitted": False}
            if operation == "cancel":
                result = await service.campaigns.cancel(campaign_id, token, admin_tenant_id=tenant_id, reason=reason)
                stopped = await service.jobs.cancel_campaign(result)
                return {"status": "success", "campaign": result, "jobs_stop_requested": stopped, "traffic_emitted": False}
            if operation == "results":
                result = await service.campaigns.get(campaign_id, token, admin_tenant_id=tenant_id)
                return {"status": "success", **(await service.jobs.results(result)), "traffic_emitted": False}
            raise ValidationError("Opération campaign invalide.")
        return await _safe(action)

    @mcp.tool()
    @traced_tool("scope")
    async def scope(
        operation: Annotated[str, Field(description="show, resolve ou check")],
        campaign_id: Annotated[str, Field(description="Campagne concernée")],
        target: Annotated[Optional[str], Field(default=None, description="Domaine, IP ou URL à contrôler")]=None,
        tenant_id: Annotated[Optional[str], Field(default=None, description="Tenant administratif uniquement")]=None,
    ) -> dict:
        """Explique le périmètre et refuse une cible avant l'émission de trafic."""
        async def action():
            require_tool_access("scope")
            service = _services()
            token = _token()
            if operation == "show":
                campaign_value = await service.campaigns.get(campaign_id, token, admin_tenant_id=tenant_id)
                return {"status": "success", "campaign_id": campaign_id, "targets": campaign_value["targets"], "exclusions": campaign_value["exclusions"], "window": campaign_value["window"], "allowed_test_classes": campaign_value["allowed_test_classes"], "campaign_status": campaign_value["status"], "traffic_emitted": False}
            if operation not in {"resolve", "check"} or not target:
                raise ValidationError("scope resolve/check exige target.")
            # Résoudre est traité comme une sonde recon : aucune requête DNS
            # n'est faite pour une campagne uniquement prepared.
            decision = await service.scope.check(campaign_id, target, token, required_test_class="recon", admin_tenant_id=tenant_id)
            return {"status": "success", "operation": operation, **decision, "traffic_emitted": operation == "resolve"}
        return await _safe(action)

    @mcp.tool()
    @traced_tool("network")
    async def network(
        campaign_id: Annotated[str, Field(description="Campagne approuvée")],
        target: Annotated[str, Field(description="Domaine ou IP explicitement mandaté")],
        operation: Annotated[str, Field(description="dns, reverse_dns, ping, traceroute, tcp ou tls")],
        port: Annotated[int, Field(default=443, description="Port TCP/TLS")]=443,
        timeout: Annotated[int, Field(default=15, description="Timeout de sonde, maximum 120 secondes")]=15,
        count: Annotated[int, Field(default=2, description="Paquets ping, 1 à 5")]=2,
        max_hops: Annotated[int, Field(default=10, description="Sauts traceroute, 1 à 30")]=10,
    ) -> dict:
        """Exécute une sonde réseau contrôlée par mandat et conserve une preuve expurgée."""
        async def action():
            require_tool_access("network")
            return await _services().network.run(campaign_id=campaign_id, target=target, token_info=_token(), operation=operation, port=port, timeout=timeout, count=count, max_hops=max_hops)
        return await _safe(action)

    @mcp.tool()
    @traced_tool("http")
    async def http(
        campaign_id: Annotated[str, Field(description="Campagne approuvée")],
        url: Annotated[str, Field(description="URL HTTP(S) explicitement dans le périmètre")],
        method: Annotated[str, Field(default="GET", description="GET, HEAD, OPTIONS, POST, PUT, PATCH ou DELETE selon le profil")]= "GET",
        headers: Annotated[Optional[dict[str, str]], Field(default=None, description="Headers non sensibles ; Authorization/Cookie/Host sont hors MVP")]=None,
        body: Annotated[Optional[str], Field(default=None, description="Corps non destructif, maximum 1 Mio")]=None,
        follow_redirects: Annotated[bool, Field(default=True, description="Revalider chaque redirection dans le mandat")]=True,
        timeout: Annotated[int, Field(default=30, description="Timeout HTTP, maximum 300 secondes")]=30,
    ) -> dict:
        """Effectue une requête HTTP mandatée, IP épinglée à chaque saut et sans auth cible."""
        async def action():
            require_tool_access("http")
            return await _services().http.request(campaign_id=campaign_id, url=url, token_info=_token(), method=method, headers=headers, body=body, follow_redirects=follow_redirects, timeout=timeout)
        return await _safe(action)

    @mcp.tool()
    @traced_tool("nmap")
    async def nmap(
        campaign_id: Annotated[str, Field(description="Campagne approuvée")],
        target: Annotated[str, Field(description="Domaine ou IP exactement mandaté")],
        idempotency_key: Annotated[str, Field(description="Clé stable de lancement ; même clé => même job")],
        profile: Annotated[str, Field(default="quick", description="quick, top-ports, full-tcp, service ou safe-scripts")]= "quick",
        ports: Annotated[Optional[list[int]], Field(default=None, description="Sous-ensemble des ports explicitement autorisés")]=None,
        discovery_only: Annotated[bool, Field(default=False, description="N'effectuer que la découverte d'hôte")]=False,
        service_detection: Annotated[bool, Field(default=False, description="Activer la détection de service/version légère")]=False,
        safe_scripts: Annotated[bool, Field(default=False, description="Activer exclusivement le groupe NSE safe")]=False,
        timing: Annotated[int, Field(default=3, description="Timing nmap 0 à 4")]=3,
        max_rate: Annotated[int, Field(default=100, description="Débit maximal de paquets")]=100,
        timeout: Annotated[int, Field(default=600, description="Timeout de job")]=600,
    ) -> dict:
        """Lance un job nmap asynchrone dans une image fixe ; jamais une commande libre."""
        async def action():
            require_tool_access("nmap")
            return await _services().jobs.start_nmap(campaign_id=campaign_id, target=target, idempotency_key=idempotency_key, token_info=_token(), profile=profile, ports=ports, discovery_only=discovery_only, service_detection=service_detection, safe_scripts=safe_scripts, timing=timing, max_rate=max_rate, timeout=timeout)
        return await _safe(action)

    @mcp.tool()
    @traced_tool("nuclei")
    async def nuclei(
        campaign_id: Annotated[str, Field(description="Campagne approuvée")],
        target: Annotated[str, Field(description="URL HTTP(S) exactement mandatée")],
        idempotency_key: Annotated[str, Field(description="Clé stable de lancement ; même clé => même job")],
        profile: Annotated[str, Field(default="recon", description="recon, active_standard ou active_extended")]= "recon",
        template_ids: Annotated[Optional[list[str]], Field(default=None, description="IDs issus du catalogue nuclei versionné uniquement")]=None,
        tags: Annotated[Optional[list[str]], Field(default=None, description="Tags issus du catalogue sélectionné")]=None,
        severities: Annotated[Optional[list[str]], Field(default=None, description="info, low, medium, high ou critical")]=None,
        rate_limit: Annotated[int, Field(default=10, description="Requêtes nuclei par seconde, bornées par mandat")]=10,
        concurrency: Annotated[int, Field(default=2, description="Concurrence nuclei, bornée par mandat")]=2,
        timeout: Annotated[int, Field(default=600, description="Timeout de job")]=600,
    ) -> dict:
        """Lance un job nuclei asynchrone avec templates locaux épinglés, jamais téléchargés à l'exécution."""
        async def action():
            require_tool_access("nuclei")
            return await _services().jobs.start_nuclei(campaign_id=campaign_id, target=target, idempotency_key=idempotency_key, token_info=_token(), profile=profile, template_ids=template_ids, tags=tags, severities=severities, rate_limit=rate_limit, concurrency=concurrency, timeout=timeout)
        return await _safe(action)

    @mcp.tool()
    @traced_tool("shell")
    async def shell(
        campaign_id: Annotated[str, Field(description="Campagne du workspace S3")],
        command: Annotated[str, Field(description="Commande libre dans le seul conteneur sans réseau")],
        shell_name: Annotated[str, Field(default="bash", description="bash, sh ou python3")]= "bash",
        input_paths: Annotated[Optional[list[str]], Field(default=None, description="Fichiers du workspace à copier dans la sandbox")]=None,
        output_paths: Annotated[Optional[list[str]], Field(default=None, description="Fichiers de sortie à remettre dans le workspace")]=None,
        timeout: Annotated[int, Field(default=120, description="Timeout du shell hors réseau")]=120,
    ) -> dict:
        """Traite les artefacts S3 dans une sandbox sans réseau ni accès Docker/hôte/secrets."""
        async def action():
            require_tool_access("shell")
            return await _services().shell.run(campaign_id=campaign_id, token_info=_token(), command=command, shell=shell_name, input_paths=input_paths, output_paths=output_paths, timeout=timeout)
        return await _safe(action)

    @mcp.tool()
    @traced_tool("files")
    async def files(
        campaign_id: Annotated[str, Field(description="Campagne du workspace S3")],
        operation: Annotated[str, Field(description="list, read, write, info, diff ou versions ; delete est indisponible")],
        path: Annotated[Optional[str], Field(default=None, description="Chemin relatif au workspace de campagne")]=None,
        content: Annotated[Optional[str], Field(default=None, description="Contenu texte pour write")]=None,
        other_path: Annotated[Optional[str], Field(default=None, description="Second chemin pour diff")]=None,
        prefix: Annotated[str, Field(default="", description="Préfixe relatif pour list")]= "",
    ) -> dict:
        """Lit ou écrit uniquement le workspace S3 de la campagne ; bucket et clés internes restent inaccessibles."""
        async def action():
            require_tool_access("files")
            return await _services().files.run(campaign_id=campaign_id, token_info=_token(), operation=operation, path=path, content=content, other_path=other_path, prefix=prefix)
        return await _safe(action)

    @mcp.tool()
    @traced_tool("evidence")
    async def evidence(
        campaign_id: Annotated[str, Field(description="Campagne concernée")],
        operation: Annotated[str, Field(description="list, read ou export")],
        evidence_ref: Annotated[Optional[str], Field(default=None, description="Référence retournée par un outil ou un job")]=None,
        job_id: Annotated[Optional[str], Field(default=None, description="Filtre optionnel de liste")]=None,
    ) -> dict:
        """Consulte les preuves expurgées et produit un export dans le workspace de la campagne."""
        async def action():
            require_tool_access("evidence")
            return await _services().evidence.run(campaign_id=campaign_id, token_info=_token(), operation=operation, evidence_ref=evidence_ref, job_id=job_id)
        return await _safe(action)

    @mcp.tool()
    @traced_tool("token")
    async def token(
        operation: Annotated[str, Field(description="create, list, info ou revoke ; admin uniquement")],
        client_name: Annotated[Optional[str], Field(default=None, description="Nom du client token")]=None,
        tenant_id: Annotated[Optional[str], Field(default=None, description="Tenant obligatoire pour un jeton mission")]=None,
        tool_ids: Annotated[Optional[list[str]], Field(default=None, description="Allow-list des outils autorisés")]=None,
        permissions: Annotated[Optional[list[str]], Field(default=None, description="access ou admin")]=None,
        expires_days: Annotated[int, Field(default=90, description="Durée de vie du token")]=90,
    ) -> dict:
        """Gère les jetons cybersec persistés sous hash S3 ; la valeur brute n'apparaît qu'à create."""
        async def action():
            require_tool_access("token")
            require_admin()
            store = _services().tokens
            if operation == "create":
                if not client_name:
                    raise ValidationError("client_name est requis.")
                selected = tool_ids or []
                unknown = set(selected) - CYBERSEC_TOOL_IDS
                if unknown:
                    raise ValidationError("tool_ids contient un outil cybersec inconnu.")
                return await store.create(client_name=client_name, tenant_id=tenant_id, tool_ids=selected, permissions=permissions, expires_days=expires_days)
            if operation == "list":
                return {"status": "success", "tokens": await store.list()}
            if operation == "info":
                if not client_name:
                    raise ValidationError("client_name est requis.")
                result = await store.info(client_name)
                return {"status": "success", "token": result} if result else {"status": "error", "message": "Token introuvable."}
            if operation == "revoke":
                if not client_name:
                    raise ValidationError("client_name est requis.")
                return {"status": "success", "revoked": await store.revoke(client_name, _token().get("client_name", "admin"))}
            raise ValidationError("Opération token invalide.")
        return await _safe(action)

    @mcp.tool()
    @traced_tool("system_health")
    async def system_health() -> dict:
        """État du service cybersec, sans exposer les secrets ou le détail S3."""
        async def action():
            require_tool_access("system_health")
            settings = _services().settings
            version = _version()
            return {"status": "ok", "service_name": settings.cybersec_mcp_server_name, "version": version, "storage": "s3-configured" if settings.cybersec_s3_endpoint_url else "s3-unconfigured", "scanners": {"nmap": settings.cybersec_nmap_version, "nuclei": settings.cybersec_nuclei_version, "templates_revision": settings.cybersec_nuclei_templates_revision}}
        return await _safe(action)

    @mcp.tool()
    @traced_tool("system_about")
    async def system_about() -> dict:
        """Catalogue cybersec, versions des moteurs et limites fondamentales."""
        async def action():
            require_tool_access("system_about")
            tools = []
            for registered in await mcp.list_tools():
                tools.append({"name": registered.name, "description": (registered.description or "").split("\n")[0]})
            settings = _services().settings
            return {"status": "ok", "service_name": settings.cybersec_mcp_server_name, "version": _version(), "python_version": platform.python_version(), "tools": tools, "tools_count": len(tools), "limits": {"network_shell": False, "ssh": False, "arbitrary_s3": False, "dynamic_templates": False, "authenticated_scans": False}}
        return await _safe(action)

    @mcp.tool()
    @traced_tool("system_activity")
    async def system_activity(
        limit: Annotated[int, Field(default=100, description="Nombre de traces, 1 à 1000")]=100,
        trace_id: Annotated[Optional[str], Field(default=None, description="Trace précise")]=None,
        call_id: Annotated[Optional[str], Field(default=None, description="Call agent précis")]=None,
    ) -> dict:
        """Restitue le journal corrélé sans payload, secrets ni preuves brutes ; admin uniquement."""
        async def action():
            require_tool_access("system_activity")
            require_admin()
            from src.mcp_tools.observability import get_activity_snapshot, activity_stats
            snapshot = get_activity_snapshot(limit=max(1, min(limit, 1000)), trace_id=trace_id, call_id=call_id)
            return {"status": "ok", "events": snapshot["events"], "calls": snapshot["calls"], "stats": activity_stats()}
        return await _safe(action)


def _version() -> str:
    version_file = Path(__file__).resolve().parents[2] / "VERSION"
    try:
        return version_file.read_text().strip()
    except OSError:
        return "dev"
