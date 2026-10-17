# -*- coding: utf-8 -*-
"""
Configuration du MCP Tools via pydantic-settings.

Variables d'environnement chargées depuis .env.
"""

from functools import lru_cache
from typing import Literal
from pydantic import Field, model_validator
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """Configuration MCP Tools."""

    @model_validator(mode="after")
    def validate_file_recovery(self):
        if self.files_recovery_enabled and (
                self.files_metadata_backend != "postgres"
                or not self.files_recovery_maintenance_role
                or self.files_recovery_maintenance_role == self.files_pg_owner):
            raise ValueError("File recovery requires PostgreSQL and a separate maintenance role")
        if self.files_mission_dependencies_enabled and not self.files_recovery_enabled:
            raise ValueError("Mission file dependencies require the file recovery extension")
        return self

    # --- Serveur MCP ---
    mcp_server_name: str = "mcp-tools"
    mcp_server_host: str = "0.0.0.0"
    mcp_server_port: int = 8050
    mcp_server_debug: bool = False
    technical_log_directory: str = ""

    # --- Auth ---
    admin_bootstrap_key: str = "change_me_in_production"

    # --- Autorité accès/activité PG explicite #31 (aucun fallback S3) ---
    access_backend: Literal["s3", "postgres"] = "s3"
    access_pg_database: str = "tools"
    access_pg_role: str = "tools_access_app"
    access_pg_owner: str = "tools_access_owner"
    access_pg_hosts: str = ""
    access_pg_ca_file: str = ""
    access_operation_timeout: float = Field(default=5, ge=2, le=5)
    access_cursor_ttl_seconds: int = Field(default=60, ge=1, le=300)
    access_cursor_capacity: int = Field(default=1024, ge=1, le=10000)
    access_vault_url: str = ""
    access_vault_id: str = ""
    access_vault_path: str = "connection"
    access_vault_token_file: str = ""
    access_vault_ca_file: str = ""

    # Destinataire hub facultatif, séparé du bearer opaque Tools.
    hub_activity_enabled: bool = False
    hub_activity_issuer: str = ""
    hub_activity_audience: str = ""
    hub_activity_owner: str = ""
    hub_activity_jwks_url: str = ""
    hub_activity_check_url: str = ""
    hub_activity_ca_file: str = ""
    hub_activity_timeout_seconds: float = Field(default=10, ge=2, le=30)
    hub_activity_max_inflight: int = Field(default=16, ge=1, le=64)
    hub_activity_max_body_bytes: int = Field(default=8388608, ge=16384, le=16777216)
    hub_files_page_bytes: int = Field(default=30000, ge=1, le=30000)

    # --- S3 (tokens MCP uniquement) ---
    s3_endpoint_url: str = ""
    s3_access_key_id: str = ""
    s3_secret_access_key: str = ""
    s3_bucket_name: str = "mcp-tools"
    s3_region_name: str = "fr1"

    # --- Magasin de tokens : comportement en panne ---
    # Le magasin échoue en FERMÉ. Ces trois réglages bornent ce qu'il accepte
    # de servir quand S3 devient injoignable.
    #
    #   cache_ttl    : au-delà, le cache est rechargé. 0 interdit de servir
    #                  depuis le cache, y compris pendant une panne, et
    #                  l'emporte sur fail_open.
    #   stale_grace  : durée pendant laquelle un cache déjà périmé reste servi
    #                  malgré la panne, avant refus.
    #   fail_mode    : fail_open lève la fenêtre ci-dessus, au prix explicite
    #                  de révocations ignorées tant que la panne dure.
    token_store_cache_ttl: int = 300
    token_store_stale_grace: int = 300
    token_store_fail_mode: str = "fail_close"

    # --- Autorité fichiers (aucune bascule/fallback implicite) ---
    files_metadata_backend: str = "s3"
    files_credentials_mode: str = "direct"
    files_pg_service: str = "tools-app"
    files_pg_database: str = "tools"
    files_pg_role: str = "tools_files_app"
    files_pg_owner: str = "tools_files_owner"
    files_pg_schema: str = "tools_files"
    files_pg_ca_file: str = ""
    files_pg_system_identifier: str = ""
    files_pg_timeline: int = Field(default=1, ge=1)
    files_connect_timeout: int = Field(default=2, ge=1, le=10)
    files_durability: str = "local"
    files_quorum: int = Field(default=1, ge=1, le=16)
    files_replication_roster: str = "[]"
    files_recovery_enabled: bool = False
    files_recovery_days: int = Field(default=30, ge=30, le=36500)
    files_recovery_maintenance_role: str = ""
    # #846 : fermé par défaut, projection PG17 capturée requise avant activation.
    files_mission_dependencies_enabled: bool = False
    files_s3_prefix: str = "files-generations/"
    files_s3_data_signature: str = "s3"  # Dell ECS s3 ; autre provider s3v4 explicite
    files_vault_url: str = ""
    files_vault_id: str = ""
    files_vault_path: str = ""
    files_vault_token_file: str = ""
    files_vault_ca_file: str = ""

    # --- Perplexity ---
    perplexity_api_key: str = ""
    perplexity_model: str = "sonar-reasoning-pro"
    perplexity_api_url: str = "https://api.perplexity.ai"
    perplexity_timeout: int = 600  # Timeout dédié Perplexity (sonar-reasoning-pro prend 60-120s en detailed)

    # --- Limites globales ---
    tool_max_output_chars: int = 50_000
    tool_max_concurrent: int = 20
    tool_default_timeout: int = 600
    tool_max_timeout: int = 600

    # --- Observabilité ---
    # Buffer local borné : il sert au diagnostic temps réel. La conservation
    # durable reste volontairement découplée du chemin d'exécution.
    activity_max_events: int = Field(default=5_000, ge=100, le=100_000)
    activity_max_age_seconds: int = Field(default=86_400, ge=60, le=31_536_000)

    # --- Sandbox Docker (tool shell) ---
    sandbox_image: str = "mcp-tools-sandbox"
    sandbox_memory: str = "256m"
    sandbox_cpus: str = "0.5"
    sandbox_pids_limit: int = 10
    sandbox_tmpfs_size: str = "32m"
    sandbox_max_timeout: int = 30
    sandbox_dns: str = "8.8.8.8,8.8.4.4"  # DNS pour les sandbox réseau (séparés par virgule)
    sandbox_enabled: bool = True  # False = exécution locale (dev sans Docker)

    # --- Email (optionnel, Phase 2) ---
    smtp_host: str = ""
    smtp_port: int = 587
    smtp_user: str = ""
    smtp_password: str = ""

    model_config = {"env_file": ".env", "env_file_encoding": "utf-8", "extra": "ignore"}


@lru_cache()
def get_settings() -> Settings:
    """Singleton Settings (cached)."""
    return Settings()
