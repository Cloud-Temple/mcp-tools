# 🔧 MCP Tools

> **Bibliothèque d'outils exécutables pour agents IA** — Serveur MCP Cloud Temple
>
> [English version](README.EN.md)

MCP Tools est un serveur MCP passif qui expose des **outils** (shell, réseau, HTTP, recherche IA…) aux agents autonomes via le protocole **Streamable HTTP**. C'est la « boîte à outils » de l'écosystème Cloud Temple.

## Démarrage rapide

### 1. Configuration

```bash
cp .env.example .env
# Éditer .env avec vos credentials S3, Perplexity, etc.
```

### 2. Lancement (Docker Compose)

```bash
docker compose build
docker compose up -d

# Vérification
curl http://localhost:8082/health
# → {"status":"ok","service":"mcp-tools","version":"0.1.0","transport":"streamable-http"}
```

### 3. CLI

```bash
# Créer le venv Python
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# Health check (pas d'auth requise)
python scripts/mcp_cli.py health

# Infos service
python scripts/mcp_cli.py about

# Exécuter une commande shell
python scripts/mcp_cli.py run-shell "hostname && uptime"

# Diagnostic réseau
python scripts/mcp_cli.py network ping google.com
python scripts/mcp_cli.py network dig google.com MX +short
python scripts/mcp_cli.py network nslookup google.com -type=mx

# Requête HTTP
python scripts/mcp_cli.py http https://httpbin.org/get

# Dates et heures
python scripts/mcp_cli.py date now --tz Europe/Paris
python scripts/mcp_cli.py date add 2026-03-06 --days 10
python scripts/mcp_cli.py date diff 2026-01-01 --date2 2026-03-06
python scripts/mcp_cli.py date day_of_week 2026-03-06

# Calculs mathématiques
python scripts/mcp_cli.py calc "2 + 3 * 4"
python scripts/mcp_cli.py calc "math.sqrt(144) + statistics.mean([10,20,30])"

# Recherche IA (Perplexity)
python scripts/mcp_cli.py search "Qu'est-ce que le protocole MCP ?"

# Documentation technique (Perplexity)
python scripts/mcp_cli.py doc "Python asyncio"
python scripts/mcp_cli.py doc "FastAPI" --context "middleware et dépendances"

# Gestion des tokens (admin)
python scripts/mcp_cli.py token create agent-prod --tools shell,date,calc --expires 90
python scripts/mcp_cli.py token list
python scripts/mcp_cli.py token info agent-prod
python scripts/mcp_cli.py token revoke agent-prod

# Shell interactif
python scripts/mcp_cli.py shell
```

### 4. Recette E2E

```bash
# Tous les tests (build + start + test + stop)
python scripts/test_service.py

# Test spécifique
python scripts/test_service.py --test shell
python scripts/test_service.py --test files
python scripts/test_service.py --test token

# Serveur déjà lancé
python scripts/test_service.py --no-docker

# Verbose (réponses complètes)
python scripts/test_service.py --test shell -v
```

### 5. Développement local (sans Docker)

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
PYTHONPATH=src python -m mcp_tools
```

## Architecture

```
Internet/LAN → :8082 (WAF Caddy+Coraza) → mcp-tools:8050 (interne)
```

### Pile ASGI

```
HealthCheckMiddleware → AuthMiddleware → LoggingMiddleware → FastMCP streamable_http_app
```

### 3 couches (pattern Cloud Temple)

| Couche           | Fichier                      | Rôle                       |
| ---------------- | ---------------------------- | -------------------------- |
| Outils MCP       | `src/mcp_tools/server.py`    | API MCP (Streamable HTTP)  |
| CLI Click        | `scripts/cli/commands.py`    | Interface scriptable       |
| Shell interactif | `scripts/cli/shell.py`       | Interface interactive      |
| Affichage        | `scripts/cli/display.py`     | Rich partagé (couches 2+3) |

### Outils disponibles (12/27 — Phase 1)

| Outil              | Description                                          |
| ------------------ | ---------------------------------------------------- |
| `shell`            | Sandbox Docker isolée (bash, sh, python3, node, openssl) — sans réseau |
| `network`          | Diagnostic réseau en sandbox Docker (ping, traceroute, nslookup, dig) — IPs privées RFC 1918 interdites |
| `http`             | Client HTTP/REST en sandbox Docker (anti-SSRF, auth basic/bearer/api_key) — IPs privées bloquées |
| `ssh`              | Exécution de commandes et transfert de fichiers via SSH en sandbox Docker (exec, status, upload, download) — auth password/key |
| `files`            | Opérations fichiers sur S3 Dell ECS en sandbox Docker (list, read, write, delete, info, diff, versions, enable_versioning) — config hybride SigV2/SigV4, versioning S3 |
| `perplexity_search`| Recherche internet via Perplexity AI                 |
| `perplexity_doc`   | Documentation technique d'une technologie/librairie/API via Perplexity AI |
| `date`             | Manipulation de dates/heures (now, today, diff, add, format, parse, week_number, day_of_week) — fuseaux horaires |
| `calc`             | Calculs mathématiques en sandbox Python Docker (expressions, math, statistics) — sans réseau |
| `token`            | Gestion des tokens d'authentification MCP (create, list, info, revoke) — admin uniquement, isolation par tool_ids |
| `system_health`    | Santé du service                                     |
| `system_about`     | Métadonnées et liste des outils                      |

### Sécurité

- **WAF Caddy + Coraza** : OWASP CRS, headers de sécurité, rate limiting
- **Auth Bearer token** : Chaque requête /mcp est authentifiée
- **`tool_ids`** : Le token peut restreindre l'accès à un sous-ensemble d'outils
- **Sandbox Docker** : Chaque commande shell/network/http dans un conteneur éphémère isolé (--cap-drop=ALL, --read-only, non-root)
- **Anti-SSRF** : Résolution DNS + blocage RFC 1918 / loopback / metadata cloud pour les tools `http` et `network`
- **Utilisateur non-root** dans Docker
- **Timeouts et limites** sur tous les outils
- **Kill automatique** des conteneurs sandbox en cas de timeout

## Variables d'environnement

### Serveur (.env)

| Variable               | Description                     | Défaut                     |
| ---------------------- | ------------------------------- | -------------------------- |
| `WAF_PORT`             | Port WAF exposé                 | `8082`                     |
| `MCP_SERVER_NAME`      | Nom du service                  | `mcp-tools`                |
| `MCP_SERVER_PORT`      | Port interne MCP                | `8050`                     |
| `ADMIN_BOOTSTRAP_KEY`  | Token admin (⚠️ changer !)     | `change_me_in_production`  |
| `S3_ENDPOINT_URL`      | Endpoint S3                     |                            |
| `S3_ACCESS_KEY_ID`     | Clé d'accès S3                  |                            |
| `S3_SECRET_ACCESS_KEY` | Secret S3                       |                            |
| `S3_BUCKET_NAME`       | Bucket S3                       | `mcp-tools`                |
| `PERPLEXITY_API_KEY`   | Clé API Perplexity              |                            |
| `PERPLEXITY_MODEL`     | Modèle Perplexity               | `sonar-reasoning-pro`      |

### Client CLI

| Variable    | Description        | Défaut                    |
| ----------- | ------------------ | ------------------------- |
| `MCP_URL`   | URL du serveur     | `http://localhost:8082`   |
| `MCP_TOKEN` | Token d'auth       | (vide)                    |

## Structure des fichiers

```
mcp-tools/
├── src/mcp_tools/
│   ├── server.py              # Serveur MCP + HealthCheck + bannière
│   ├── config.py              # Configuration pydantic-settings (sandbox, etc.)
│   ├── auth/                  # Middleware auth + Token Store S3
│   └── tools/                 # Outils MCP (shell, network, http, perplexity)
├── sandbox/
│   └── Dockerfile             # Image Alpine sandbox (python3, node, openssl…)
├── scripts/
│   ├── mcp_cli.py             # Point d'entrée CLI
│   ├── test_service.py        # Recette E2E (--test NOM pour cibler)
│   └── cli/                   # CLI Click + Shell + Display
├── waf/                       # WAF Caddy + Coraza
├── Dockerfile                 # Python 3.11 + docker CLI statique
├── docker-compose.yml         # sandbox + mcp-tools + waf + docker.sock
├── .env.example
└── VERSION
```

## Roadmap

- **Phase 1** (actuel) : shell, network, http, ssh, files, perplexity_search, perplexity_doc, date, calc — ✅
- **Phase 1** (à faire) : docker, generate, mcp_call
- **Phase 2** : git, s3, db, host_audit, ssh_diagnostics, sqlite, script_executor, email_send, pdf, doc_scraper
- **Phase 3** : imap, perplexity_api, perplexity_deprecated

## Licence

Apache 2.0 — Cloud Temple
