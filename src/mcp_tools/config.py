# -*- coding: utf-8 -*-
"""
Configuration du MCP Tools via pydantic-settings.

Variables d'environnement chargées depuis .env.
"""

from functools import lru_cache
from typing import Optional
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """Configuration MCP Tools."""

    # --- Serveur MCP ---
    mcp_server_name: str = "mcp-tools"
    mcp_server_host: str = "0.0.0.0"
    mcp_server_port: int = 8050
    mcp_server_debug: bool = False

    # --- Auth ---
    admin_bootstrap_key: str = "change_me_in_production"

    # --- S3 (tokens MCP uniquement) ---
    s3_endpoint_url: str = ""
    s3_access_key_id: str = ""
    s3_secret_access_key: str = ""
    s3_bucket_name: str = "mcp-tools"
    s3_region_name: str = "fr1"

    # --- Perplexity ---
    perplexity_api_key: str = ""
    perplexity_model: str = "sonar-reasoning-pro"
    perplexity_api_url: str = "https://api.perplexity.ai"

    # --- Limites globales ---
    tool_max_output_chars: int = 50_000
    tool_max_concurrent: int = 20
    tool_default_timeout: int = 60
    tool_max_timeout: int = 600

    # --- Sandbox Docker (tool shell) ---
    sandbox_image: str = "mcp-tools-sandbox"
    sandbox_memory: str = "256m"
    sandbox_cpus: str = "0.5"
    sandbox_pids_limit: int = 10
    sandbox_tmpfs_size: str = "32m"
    sandbox_max_timeout: int = 30
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
