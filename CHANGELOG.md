# Changelog

All notable changes to MCP Tools will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [0.1.2] — 2026-03-05

### Changed
- **Tool `perplexity_search`** — Timeout depuis config (`settings.tool_default_timeout`), plus de hardcode. Nouveau param `model` optionnel (défaut : config `PERPLEXITY_MODEL`). Modèle effectif retourné dans la réponse
- **Tools `system_health` et `system_about`** — Ajout `check_tool_access()` + pattern `try/except` pour cohérence avec tous les autres tools. Description `system_about` améliorée
- **Tool `http` réécrit — Sandbox Docker + anti-SSRF** — Les requêtes HTTP sont désormais exécutées via `curl` dans un conteneur Docker éphémère (`--network=bridge`, `--read-only`, `--cap-drop=ALL`, `--user=sandbox`). Protection anti-SSRF complète :
  - Résolution DNS côté serveur avant exécution
  - Blocage RFC 1918 (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16), loopback (127.0.0.0/8), link-local (169.254.0.0/16 — metadata cloud), IPv6 privé
  - Validation du schéma URL (http/https uniquement)
- **Sémantique du status HTTP** — `status: "success"` = réponse reçue (même 404/500), `status: "error"` = erreur de transport uniquement (timeout, DNS, connexion, SSRF)
- **Nouveau param `body`** — Body texte brut en plus de `json_body` (JSON)
- **Nouveau param `auth_type` / `auth_value`** — Helpers d'authentification : `basic` (user:pass), `bearer` (token), `api_key` (X-API-Key)
- **Timeout depuis config** — Plus aucun hardcode, utilise `settings.tool_max_timeout`
- **Fallback local** — `SANDBOX_ENABLED=false` utilise httpx avec la même validation anti-SSRF
- **Tests E2E** — 10 tests http (GET, sandbox, POST JSON, POST body, 404=success, méthode invalide, SSRF ×3, auth bearer)

## [0.1.1] — 2026-03-05

### Changed
- **`ping` → `network`** — L'ancien tool `ping` est remplacé par `network`. Exécution dans un conteneur Docker sandbox éphémère avec réseau (`--network=bridge`, `--cap-add=NET_RAW`, `--read-only`). Opérations : ping, traceroute, nslookup, dig
- **Blocage RFC 1918** — Les IPs privées (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16), loopback, link-local sont interdites dans le tool `network` pour empêcher le scan interne
- **Validation du host** — Regex stricte + `subprocess_exec` (pas de shell) pour bloquer les injections de commandes
- **sandbox/Dockerfile** — Ajout des outils réseau (iputils, bind-tools, traceroute) à l'image Alpine
- **CLI sous-commandes** — `network ping <host> [-c N]`, `network dig <host> [MX +short]`, `network nslookup <host> [-type=mx]`, `network traceroute <host> [-m N]`. Tous les arguments sont passés directement à la commande (via `extra_args`)
- **Shell interactif** — Syntaxe `network <op> <host> [args...]` avec aide contextuelle et exemples
- **Tool MCP `extra_args`** — Nouveau paramètre `extra_args` (string) passé tel quel à la commande réseau. Backward compat : `count` fonctionne toujours pour les anciens appelants
- **Tests E2E** — 10 tests network (ping, nslookup, dig, traceroute, sandbox, RFC 1918 ×3, injection, opération invalide)

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
