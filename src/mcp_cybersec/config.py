# -*- coding: utf-8 -*-
"""Configuration propre au service ``mcp-cybersec``.

Les variables commencent toutes par ``CYBERSEC_`` : le service ne réutilise ni
le bucket, ni les identités, ni les secrets de ``mcp-tools``. En production,
elles sont injectées par Vault (ou son agent) dans l'environnement du
conteneur ; aucun secret n'est lu depuis le dépôt.
"""

from functools import lru_cache

from pydantic import Field
from pydantic_settings import BaseSettings


class CybersecSettings(BaseSettings):
    """Configuration du second service MCP, strictement séparée du premier."""

    # Transport MCP
    cybersec_mcp_server_name: str = "mcp-cybersec"
    cybersec_mcp_server_host: str = "0.0.0.0"
    cybersec_mcp_server_port: int = 8051
    cybersec_admin_bootstrap_key: str = "change_me_in_production"

    # S3 dédié. Le mode mémoire n'est accepté que par les tests unitaires qui
    # injectent directement MemoryObjectStore ; le runtime reste S3 par défaut.
    cybersec_s3_endpoint_url: str = ""
    cybersec_s3_access_key_id: str = ""
    cybersec_s3_secret_access_key: str = ""
    cybersec_s3_bucket_name: str = "mcp-cybersec"
    cybersec_s3_region_name: str = "fr1"
    cybersec_s3_prefix: str = "mcp-cybersec"

    # Vault ne fournit jamais sa valeur à un outil : l'agent Vault peut
    # injecter les variables CYBERSEC_S3_* avant le démarrage. Ces références
    # servent à rendre ce contrat visible et documentable au runtime.
    cybersec_vault_enabled: bool = True
    cybersec_vault_secret_reference: str = "kv/data/mcp-cybersec/runtime"

    # Limites de campagne et arrêt d'urgence.
    cybersec_max_targets_per_campaign: int = Field(default=256, ge=1, le=4096)
    cybersec_max_ports_per_scan: int = Field(default=1024, ge=1, le=65535)
    cybersec_max_http_redirects: int = Field(default=5, ge=0, le=10)
    cybersec_job_cancel_poll_seconds: float = Field(default=2.0, ge=0.2, le=10.0)
    cybersec_max_job_timeout: int = Field(default=3600, ge=5, le=14400)
    cybersec_max_output_chars: int = Field(default=100_000, ge=1_000, le=2_000_000)

    # Images fixes : l'agent ne peut ni les choisir ni modifier leur commande.
    # Les Dockerfiles associés portent aussi un label de provenance et version.
    cybersec_network_image: str = "mcp-cybersec-network:0.7.0"
    cybersec_shell_image: str = "mcp-cybersec-shell:0.7.0"
    cybersec_nmap_image: str = "mcp-cybersec-nmap:0.7.0"
    cybersec_nuclei_image: str = "mcp-cybersec-nuclei:0.7.0"
    cybersec_scanner_network: str = "mcp-cybersec-scan-network"
    cybersec_nmap_version: str = "7.98"
    cybersec_nuclei_version: str = "3.7.1"
    cybersec_nuclei_templates_revision: str = "v10.4.2"

    # Ressources et isolation des conteneurs éphémères.
    cybersec_scanner_memory: str = "512m"
    cybersec_scanner_cpus: str = "1.0"
    cybersec_scanner_pids_limit: int = Field(default=64, ge=8, le=512)
    cybersec_shell_memory: str = "256m"
    cybersec_shell_cpus: str = "0.5"
    cybersec_shell_pids_limit: int = Field(default=32, ge=8, le=128)
    cybersec_shell_timeout: int = Field(default=120, ge=5, le=1800)
    cybersec_shell_max_artifact_bytes: int = Field(default=20_000_000, ge=1_024, le=200_000_000)

    # Exclusivement pour la recette locale déclarée. Cette bascule reste false
    # en production : elle n'ouvre pas un scan interne général, seulement les
    # CIDR de laboratoire explicitement configurés et approuvés dans le mandat.
    cybersec_lab_mode: bool = False
    cybersec_lab_allowed_cidrs: str = ""

    model_config = {
        "env_file": ".env",
        "env_file_encoding": "utf-8",
        "extra": "ignore",
    }


@lru_cache()
def get_settings() -> CybersecSettings:
    return CybersecSettings()
