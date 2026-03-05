# Changelog

All notable changes to MCP Tools will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [0.1.0] — 2026-03-05

### Fixed (5 mars 2026 — session CLI)
- **CLI : chargement automatique du `.env`** — `scripts/cli/__init__.py` utilise `python-dotenv` pour charger le `.env` du projet (token, config). Plus besoin d'exporter `MCP_TOKEN` manuellement
- **CLI : `health` sans auth** — Les commandes `health` (CLI Click et shell interactif) utilisent un appel REST `/health` au lieu du protocole MCP → pas d'auth requise
- **CLI : erreurs d'auth lisibles** — Le client MCP extrait les vraies sous-exceptions des `ExceptionGroup` (MCP SDK TaskGroup) et traduit les erreurs 401/403 en messages clairs
- **CLI : affichage health** — `show_health_result()` gère les deux formats (REST `service` et MCP `service_name`)

### Added

- **Serveur MCP** avec FastMCP (Streamable HTTP) sur port 8050
- **WAF Caddy + Coraza** (OWASP CRS, rate limiting, security headers) sur port 8082
- **HealthCheckMiddleware** ASGI — `/health` retourne `{"status":"ok","service":"mcp-tools","version":"0.1.0","transport":"streamable-http"}`
- **AuthMiddleware** — Bearer token avec support `tool_ids` pour restriction d'accès par outil
- **LoggingMiddleware** — Logs des requêtes HTTP sur stderr

#### Outils MCP (6)
- `shell` — Exécution de commandes bash (async, timeout, cwd)
- `ping` — Diagnostic réseau (ping, traceroute, nslookup, dig)
- `http` — Client HTTP/REST async (GET, POST, PUT, DELETE, PATCH, HEAD)
- `perplexity_search` — Recherche internet via Perplexity AI (brief/normal/detailed)
- `system_health` — Santé du service
- `system_about` — Métadonnées et liste des outils

#### CLI (3 couches)
- **CLI Click** (`scripts/mcp_cli.py`) — 7 commandes : health, about, run-shell, ping, http, search, shell
- **Shell interactif** — Autocomplétion, historique, commandes : run, ping, http, search
- **Affichage Rich** — Panels, tables, Markdown pour chaque outil

#### Infrastructure
- `Dockerfile` — Python 3.11-slim, binaires réseau (ping, dig, traceroute, git), utilisateur non-root
- `docker-compose.yml` — WAF + MCP service, réseau Docker isolé
- `scripts/test_service.py` — Script de recette E2E (18 tests, auto docker build/start/stop)
- `.env.example` — Template de configuration
- `.gitignore` — Protège .env, chantier/, memory-bank/

### Architecture
- Pattern starter-kit Cloud Temple respecté (PYTHONPATH=/app, ENTRYPOINT python -m)
- Tous les outils utilisent `try/except` → jamais d'exception levée (retour `{"status":"error"}`)
- Rate limit WAF calibré : 300 events/min pour /mcp, 500 events/min global
