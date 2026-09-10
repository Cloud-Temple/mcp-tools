# -*- coding: utf-8 -*-
"""Normalisation prudente des sorties nmap/nuclei en constats, pas en verdicts."""

from __future__ import annotations

import json
import xml.etree.ElementTree as ET
from datetime import datetime, timezone


def _base(*, campaign_id: str, job_id: str, engine: str, evidence_ref: str) -> dict:
    return {
        "schema_version": 1,
        "campaign_id": campaign_id,
        "job_id": job_id,
        "engine": engine,
        "observed_at": datetime.now(timezone.utc).isoformat(),
        "evidence_ref": evidence_ref,
        "status": "detected_to_confirm",
        "confidence": "scanner",
    }


def parse_nmap_findings(raw_xml: bytes, *, campaign_id: str, job_id: str, evidence_ref: str, version: str) -> list[dict]:
    """Expose les services observés comme éléments à confirmer, jamais comme CVE."""
    try:
        root = ET.fromstring(raw_xml)
    except ET.ParseError:
        return []
    findings: list[dict] = []
    for host in root.findall("host"):
        address = next((node.get("addr") for node in host.findall("address") if node.get("addr")), None)
        for port in host.findall("./ports/port"):
            state = port.find("state")
            if state is None or state.get("state") != "open":
                continue
            service = port.find("service")
            name = service.get("name", "unknown") if service is not None else "unknown"
            product = service.get("product", "") if service is not None else ""
            finding = _base(campaign_id=campaign_id, job_id=job_id, engine="nmap", evidence_ref=evidence_ref)
            finding.update({
                "rule_id": "nmap.open-service",
                "engine_version": version,
                "asset": address,
                "port": int(port.get("portid", "0")),
                "protocol": port.get("protocol", "tcp"),
                "severity_source": "info",
                "severity": "info",
                "cwe": None,
                "title": f"Service ouvert observé : {name}",
                "impact": "Inventaire technique à vérifier ; ce résultat seul n'est pas une vulnérabilité.",
                "recommendation": "Valider l'exposition attendue et appliquer le durcissement adapté.",
                "evidence_minimal": {"service": name, "product": product[:128]},
            })
            findings.append(finding)
    return findings


def parse_nuclei_findings(raw_jsonl: bytes, *, campaign_id: str, job_id: str, evidence_ref: str, version: str) -> list[dict]:
    """Ne propage que les champs utiles ; la sortie cible reste une donnée non fiable."""
    findings: list[dict] = []
    for line in raw_jsonl.decode("utf-8", errors="replace").splitlines():
        try:
            data = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(data, dict):
            continue
        info = data.get("info") if isinstance(data.get("info"), dict) else {}
        classification = info.get("classification") if isinstance(info.get("classification"), dict) else {}
        severity = str(info.get("severity", "unknown")).lower()
        finding = _base(campaign_id=campaign_id, job_id=job_id, engine="nuclei", evidence_ref=evidence_ref)
        finding.update({
            "rule_id": str(data.get("template-id", "unknown"))[:160],
            "template": str(data.get("template-id", "unknown"))[:160],
            "engine_version": version,
            "asset": str(data.get("host", data.get("matched-at", "")))[:512],
            "url": str(data.get("matched-at", ""))[:512],
            "severity_source": severity,
            "severity": severity if severity in {"info", "low", "medium", "high", "critical"} else "unknown",
            "cwe": classification.get("cwe-id") or classification.get("cwe"),
            "title": str(info.get("name", data.get("template-id", "Nuclei finding")))[:256],
            "impact": "Alerte automatique à confirmer ; aucune exploitation n'est déduite automatiquement.",
            "recommendation": "Reproduire de manière non destructive, puis qualifier avec le propriétaire de l'actif.",
            "evidence_minimal": {
                "matcher": str(data.get("matcher-name", ""))[:128],
                "type": str(data.get("type", ""))[:64],
            },
        })
        findings.append(finding)
    return findings
