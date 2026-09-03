# -*- coding: utf-8 -*-
"""Assemblage injectable des composants cybersec, sans dépendance externe additionnelle."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from .auth import CybersecTokenStore
from .campaigns import CampaignService
from .config import CybersecSettings, get_settings
from .jobs import ScanJobManager
from .probes import HttpService, NetworkService
from .scope import ScopeGuard
from .storage import CybersecRepository, build_repository
from .workspace import EvidenceService, FilesService, ShellService


@dataclass
class CybersecServices:
    settings: CybersecSettings
    repository: CybersecRepository
    campaigns: CampaignService
    scope: ScopeGuard
    jobs: ScanJobManager
    network: NetworkService
    http: HttpService
    shell: ShellService
    files: FilesService
    evidence: EvidenceService
    tokens: CybersecTokenStore


def build_services(
    settings: Optional[CybersecSettings] = None,
    repository: Optional[CybersecRepository] = None,
) -> CybersecServices:
    settings = settings or get_settings()
    repository = repository or build_repository(settings)
    campaigns = CampaignService(repository, settings)
    scope = ScopeGuard(campaigns, settings=settings)
    return CybersecServices(
        settings=settings,
        repository=repository,
        campaigns=campaigns,
        scope=scope,
        jobs=ScanJobManager(repository, campaigns, scope, settings),
        network=NetworkService(repository, campaigns, scope, settings),
        http=HttpService(repository, campaigns, scope, settings),
        shell=ShellService(repository, campaigns, settings),
        files=FilesService(repository, campaigns, settings),
        evidence=EvidenceService(repository, campaigns, settings),
        tokens=CybersecTokenStore(repository),
    )
