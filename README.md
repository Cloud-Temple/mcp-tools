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
# → {"status":"healthy","service":"mcp-tools","version":"0.1.9","transport":"streamable-http"}

# Console d'administration
open http://localhost:8082/admin
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

# SSH (exécution distante)
python scripts/mcp_cli.py ssh exec myserver.com --user admin --password secret "uptime"
python scripts/mcp_cli.py ssh status myserver.com --user admin --password secret

# Fichiers S3
python scripts/mcp_cli.py files list --prefix logs/
python scripts/mcp_cli.py files read config/app.yaml
python scripts/mcp_cli.py files write test.txt --content "Hello World"

# Gestion des tokens (admin)
python scripts/mcp_cli.py token create agent-prod --tools shell,date,calc --expires 90
python scripts/mcp_cli.py token create ct-user --email user@cloud-temple.com --expires 180
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

# Test spécifique (14 catégories)
python scripts/test_service.py --test shell
python scripts/test_service.py --test network
python scripts/test_service.py --test http
python scripts/test_service.py --test ssh
python scripts/test_service.py --test files
python scripts/test_service.py --test token
python scripts/test_service.py --test admin
python scripts/test_service.py --test waf
python scripts/test_service.py --test date
python scripts/test_service.py --test calc

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
AdminMiddleware → HealthCheckMiddleware → AuthMiddleware → LoggingMiddleware → FastMCP streamable_http_app
```

### 3 couches (pattern Cloud Temple)

| Couche           | Fichier                   | Rôle                       |
| ---------------- | ------------------------- | -------------------------- |
| Outils MCP       | `src/mcp_tools/server.py` | API MCP (Streamable HTTP)  |
| CLI Click        | `scripts/cli/commands.py` | Interface scriptable       |
| Shell interactif | `scripts/cli/shell.py`    | Interface interactive      |
| Affichage        | `scripts/cli/display.py`  | Rich partagé (couches 2+3) |

### Outils disponibles (12/27 — Phase 1)

> **Tous les paramètres** de chaque outil sont documentés avec des descriptions détaillées via le protocole MCP. Les clients compatibles (Cline, Claude Desktop…) affichent automatiquement ces descriptions.

| Outil               | Description                                                                                                                                                            |
| ------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `shell`             | Sandbox Docker isolée (bash, sh, python3, node) — sans réseau par défaut, `network=true` pour pip install. Python packages pré-installés : numpy, pandas, requests, beautifulsoup4, scipy, matplotlib… |
| `network`           | Diagnostic réseau en sandbox Docker (ping, traceroute, nslookup, dig) — IPs privées RFC 1918 interdites                                                                |
| `http`              | Client HTTP/REST en sandbox Docker (anti-SSRF, auth basic/bearer/api_key) — IPs privées bloquées                                                                       |
| `ssh`               | Exécution de commandes et transfert de fichiers via SSH en sandbox Docker (exec, status, upload, download) — auth password/key                                         |
| `files`             | Opérations fichiers sur S3 Dell ECS en sandbox Docker (list, read, write, delete, info, diff, versions, enable_versioning) — config hybride SigV2/SigV4, versioning S3 |
| `perplexity_search` | Recherche internet via Perplexity AI                                                                                                                                   |
| `perplexity_doc`    | Documentation technique d'une technologie/librairie/API via Perplexity AI                                                                                              |
| `date`              | Manipulation de dates/heures (now, today, diff, add, format, parse, week_number, day_of_week) — fuseaux horaires                                                       |
| `calc`              | Calculs mathématiques en sandbox Python Docker (expressions, math, statistics) — sans réseau                                                                           |
| `token`             | Gestion des tokens d'authentification MCP (create, list, info, revoke) — admin uniquement, isolation par tool_ids, email propriétaire                                  |
| `system_health`     | Santé du service                                                                                                                                                       |
| `system_about`      | Métadonnées et liste des outils                                                                                                                                        |

### Console d'administration (`/admin`)

Une interface web d'administration est disponible sur `/admin` :

```
http://localhost:8082/admin
```

**4 vues** : Dashboard (état serveur), Tools (exécution interactive avec formulaires dynamiques), Tokens (CRUD), Activité (logs temps réel).

Authentification admin requise (ADMIN_BOOTSTRAP_KEY ou token S3 avec permission admin). Design Cloud Temple (dark theme). Same-origin uniquement (pas de CORS cross-origin).

### Sécurité

- **Audit de sécurité** : Rapport complet dans `DESIGN/mcp-tools/SECURITY_AUDIT.md` — architecture qualifiée "niveau Entreprise"
- **WAF Caddy + Coraza** : OWASP CRS en mode blocage (`SecRuleEngine On`), headers de sécurité, rate limiting (1000 req/min MCP) — 6 tests E2E (`--test waf`)
- **Auth Bearer token** : Chaque requête /mcp est authentifiée. Permissions `access` (appel d'outils) ou `admin` (tout)
- **`tool_ids`** : Le token peut restreindre l'accès à un sous-ensemble d'outils (whitelisting par outil)
- **Sandbox Docker** : Chaque commande shell/network/http dans un conteneur éphémère isolé (--cap-drop=ALL, --read-only, non-root)
- **Token Manager S3** : Tokens stockés en S3 Dell ECS (`_tokens/{sha256}.json`), cache mémoire TTL 5min, isolation par `tool_ids`
- **Admin same-origin** : Console `/admin` sans CORS cross-origin, auth admin obligatoire sur l'API
- **Anti-SSRF** : Résolution DNS + blocage RFC 1918 / loopback / metadata cloud pour les tools `http` et `network`
- **Utilisateur non-root** dans Docker
- **Timeouts et limites** sur tous les outils
- **Kill automatique** des conteneurs sandbox en cas de timeout

## Variables d'environnement

### Serveur (.env)

| Variable               | Description                  | Défaut                    |
| ---------------------- | ---------------------------- | ------------------------- |
| `WAF_PORT`             | Port WAF exposé              | `8082`                    |
| `MCP_SERVER_NAME`      | Nom du service               | `mcp-tools`               |
| `MCP_SERVER_PORT`      | Port interne MCP             | `8050`                    |
| `ADMIN_BOOTSTRAP_KEY`  | Token admin (⚠️ changer !) | `change_me_in_production` |
| `S3_ENDPOINT_URL`      | Endpoint S3                  |                           |
| `S3_ACCESS_KEY_ID`     | Clé d'accès S3               |                           |
| `S3_SECRET_ACCESS_KEY` | Secret S3                    |                           |
| `S3_BUCKET_NAME`       | Bucket S3                    | `mcp-tools`               |
| `PERPLEXITY_API_KEY`   | Clé API Perplexity           |                           |
| `PERPLEXITY_MODEL`     | Modèle Perplexity            | `sonar-reasoning-pro`     |
| `SANDBOX_DNS`          | DNS pour sandbox réseau      | `8.8.8.8,8.8.4.4`         |

### Client CLI

| Variable    | Description    | Défaut                  |
| ----------- | -------------- | ----------------------- |
| `MCP_URL`   | URL du serveur | `http://localhost:8082` |
| `MCP_TOKEN` | Token d'auth   | (vide)                  |

## Structure des fichiers

```
mcp-tools/
├── src/mcp_tools/
│   ├── server.py              # Serveur MCP + HealthCheck + bannière
│   ├── config.py              # Configuration pydantic-settings (sandbox, etc.)
│   ├── admin/                 # Console d'administration web (/admin)
│   ├── static/                # Fichiers statiques admin (HTML, CSS, JS)
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

## Configurer dans Cline (VS Code / VSCodium)

Pour connecter MCP Tools à **Cline**, ajoutez dans votre `cline_mcp_settings.json`
(accessible via ⚙️ MCP Servers dans la sidebar Cline) :

```json
{
  "mcpServers": {
    "mcp-tools": {
      "disabled": false,
      "timeout": 60,
      "type": "streamableHttp",
      "url": "http://localhost:8082/mcp",
      "headers": {
        "Authorization": "Bearer VOTRE_TOKEN_ICI"
      }
    }
  }
}
```

| Paramètre       | Valeur                      | Description                                                   |
| --------------- | --------------------------- | ------------------------------------------------------------- |
| `type`          | `streamableHttp`            | **Obligatoire** — indique à Cline le transport MCP à utiliser |
| `url`           | `http://localhost:8082/mcp` | Endpoint Streamable HTTP (via WAF, **toujours `/mcp`**)       |
| `timeout`       | `60`                        | Timeout en secondes (recommandé pour les outils longs)        |
| `Authorization` | `Bearer VOTRE_TOKEN`        | Bootstrap key ou token S3                                     |
| `disabled`      | `false`                     | Permet de désactiver le serveur sans supprimer la config      |

Pour créer un token dédié à Cline avec des outils spécifiques :

```bash
python scripts/mcp_cli.py --token $ADMIN_BOOTSTRAP_KEY \
  token create cline-dev --tools shell,http,network,date,calc,perplexity_search --expires 365
```

> **Guide complet** : voir [`starter-kit/CLINE_SETUP.md`](starter-kit/CLINE_SETUP.md) pour les chemins des fichiers de configuration par OS, le multi-serveurs, le debug, etc.

## Roadmap

- **Phase 1** (actuel) : shell, network, http, ssh, files, perplexity_search, perplexity_doc, date, calc — ✅
- **Phase 1** (à faire) : docker, generate, mcp_call
- **Phase 2** : git, s3, db, host_audit, ssh_diagnostics, sqlite, script_executor, email_send, pdf, doc_scraper
- **Phase 3** : imap, perplexity_api, perplexity_deprecated

## Licence

Apache 2.0 — Cloud Temple
