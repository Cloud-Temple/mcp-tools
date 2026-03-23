# Architecture — MCP Tools

> **Version** : 0.1.8 | **Date** : 2026-03-12 | **Auteur** : Cloud Temple
> **Projet** : mcp-tools | **Licence** : Apache 2.0
> **Statut** : 🚧 Implémentation en cours — 12/28 tools validés (shell, network, http, ssh, files, token, perplexity_search, perplexity_doc, date, calc, system_health, system_about) + Token Manager S3 + Console Admin Web + 64 paramètres MCP

---

## 1. Vision

**MCP Tools** est un serveur MCP qui fournit une **bibliothèque de tools exécutables** pour les agents IA. C'est la **boîte à outils** de l'écosystème : SSH, HTTP, Docker, Git, recherche internet, calculs, manipulation de fichiers/PDFs, etc.

Les agents (via MCP Agent) appellent MCP Tools pour exécuter des actions concrètes. MCP Tools est un **serveur passif** — il ne prend pas de décisions, il exécute ce qu'on lui demande.

### Principes

1. **Même pattern que Live Memory** — Starter-kit (auth, CLI, shell, Docker)
2. **Token → subset de tools** — Un token autorise un sous-ensemble de tools, pas tous
3. **28 tools en 3 phases** — 13 essentiels (Phase 1), 12 enrichissement (Phase 2), 3 avancés (Phase 3)
4. **S'inspirer, pas copier** — On réécrit les tools en Python dans notre framework, en s'inspirant de Dragonfly et perplexity-mcp
5. **Timeout et limites sur tout** — Chaque tool a un timeout, une taille max d'output, des paramètres bornés

---

## 2. Architecture

```
     MCP Agent (instances d'agents)          Humain (CLI/Shell)
           │                                       │
           │  MCP Protocol (Streamable HTTP)       │
           ▼                                       ▼
┌────────────────────────────────────────────────────────┐
│                MCP Tools Server (:8050)                │
│                Python / FastMCP (starter-kit)          │
│                                                        │
│  ┌──────────────────────────────────────────────────┐  │
│  │  Auth Middleware (starter-kit standard)          │  │
│  │  • Bearer Token + permissions (access/admin)     │  │
│  │  • tool_ids dans le token (whitelist de tools)   │  │
│  └──────────────────────────────────────────────────┘  │
│                                                        │
│  ┌──────────────────────────────────────────────────┐  │
│  │  28 Outils MCP (tools/)                          │  │
│  │                                                  │  │
│  │  Infra :    ssh, shell, network, docker          │  │
│  │  Réseau :   http, ssh_diagnostics                │  │
│  │  Données :  files, sqlite, db, s3                │  │
│  │  Dev :      git, script_executor, calc, date     │  │
│  │  Docs :     pdf2text, pdf_search, office_to_pdf, │  │
│  │             doc_scraper                          │  │
│  │  Recherche: perplexity_search, perplexity_doc    │  │
│  │  Audit :   host_audit                            │  │
│  │  Comm :    email_send, imap                      │  │
│  │  Meta :    generate, mcp_call                    │  │
│  └──────────────────────────────────────────────────┘  │
│                                                        │
│  ┌──────────────────────────────────────────────────┐  │
│  │  Token Manager (S3 Dell ECS)                     │  │
│  │  _tokens/{sha256}.json — cache TTL 5min          │  │
│  │  create/list/info/revoke — admin only            │  │
│  └──────────────────────────────────────────────────┘  │
└──────────────────────────┬─────────────────────────────┘
                           │
                    S3 Dell ECS          Docker Socket
                    Bucket : mcp-tools   /var/run/docker.sock
                                              │
                                    ┌─────────┴───────────┐
                                    │  Sandbox Container  │
                                    │  (Alpine éphémère)  │
                                    │  --network=none     │
                                    │  --read-only        │
                                    │  --cap-drop=ALL     │
                                    └─────────────────────┘
```

### 2.1 Sandbox Docker (tool shell)

Le tool `shell` n'exécute **pas** les commandes dans le conteneur MCP Tools.
Chaque commande est isolée dans un **conteneur Docker éphémère** (Alpine)
lancé via `docker run --rm` avec les contraintes de sécurité suivantes :

| Contrainte            | Valeur                  | Raison                                 |
| --------------------- | ----------------------- | -------------------------------------- |
| `--network=none`      | Pas de réseau           | Empêche toute exfiltration de données  |
| `--read-only`         | Filesystem immuable     | Empêche la modification du conteneur   |
| `--cap-drop=ALL`      | Zéro capabilities Linux | Pas de privilèges noyau                |
| `--memory=256m`       | Limite mémoire          | Protection contre les OOM              |
| `--cpus=0.5`          | Limite CPU              | Protection contre les boucles infinies |
| `--pids-limit=10`     | Limite processus        | Anti fork-bomb                         |
| `--user=sandbox`      | Non-root                | Pas d'accès root                       |
| `--no-new-privileges` | Pas d'escalade          | Bloque setuid/setgid                   |
| `--tmpfs /tmp:noexec` | Temp sans exec          | Pas d'exécution depuis /tmp            |

**Image sandbox** : `mcp-tools-sandbox` (Alpine 3.20 + bash, coreutils,
grep, sed, awk, jq, bc, curl, git, openssl, gnupg, python3, node).
Buildée par `docker compose up`.

**Prérequis** : le conteneur MCP Tools monte `/var/run/docker.sock` (read-only)
pour pouvoir lancer les conteneurs sandbox. Le docker CLI est inclus dans
l'image MCP Tools (binaire statique).

**Fallback dev** : `SANDBOX_ENABLED=false` → exécution locale via subprocess
(pour le développement sans Docker).

### 2.2 Sandbox Docker réseau (tool network)

Le tool `network` utilise le **même conteneur éphémère** que `shell`, mais avec
un accès réseau (bridge) pour pouvoir exécuter ping, traceroute, dig, nslookup.

| Contrainte       | shell  | network            | Raison                             |
| ---------------- | ------ | ------------------ | ---------------------------------- |
| `--network`      | `none` | `bridge`           | Network a besoin du réseau         |
| `--cap-add`      | aucun  | `NET_RAW`          | Pour ICMP (ping)                   |
| `--read-only`    | ✅     | ✅                 | Identique                          |
| `--cap-drop=ALL` | ✅     | ✅                 | Identique (NET_RAW ajouté en plus) |
| `--user=sandbox` | ✅     | ✅                 | Identique                          |
| `--dns`          | —      | `8.8.8.8, 8.8.4.4` | DNS publics pour résolution        |

**Sécurité supplémentaire** :
- **Blocage RFC 1918** : les IPs privées (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16),
  loopback (127.0.0.0/8), link-local (169.254.0.0/16) sont **interdites** côté serveur
  avant exécution. Empêche le scan de l'infrastructure interne.
- **Validation du host** : regex stricte, seuls les caractères alphanumériques,
  points, tirets et deux-points (IPv6) sont autorisés. Bloque l'injection de commandes.
- **Commandes construites côté serveur** : le host est un paramètre, pas du code
  arbitraire. Les commandes sont passées via `subprocess_exec` (pas de shell).

### 2.3 Sandbox Docker HTTP (tool http)

Le tool `http` exécute les requêtes HTTP via **curl** dans un conteneur Docker
éphémère, avec une **protection anti-SSRF** complète :

| Contrainte         | Valeur              | Raison                                 |
| ------------------ | ------------------- | -------------------------------------- |
| `--network=bridge` | Accès réseau        | Nécessaire pour les requêtes HTTP      |
| `--read-only`      | Filesystem immuable | Empêche la modification du conteneur   |
| `--cap-drop=ALL`   | Zéro capabilities   | Pas de privilèges noyau                |
| `--memory=256m`    | Limite mémoire      | Protection contre les OOM              |
| `--cpus=0.5`       | Limite CPU          | Protection contre les boucles infinies |
| `--pids-limit=10`  | Limite processus    | Anti fork-bomb                         |
| `--user=sandbox`   | Non-root            | Pas d'accès root                       |
| `--dns=8.8.8.8`    | DNS publics         | Résolution DNS contrôlée               |

**Sécurité anti-SSRF** (avant lancement du conteneur) :
1. **Parse de l'URL** : extraction du hostname, validation du schéma (http/https uniquement)
2. **Si IP directe** → vérification RFC 1918 / loopback / link-local / metadata cloud
3. **Si hostname** → **résolution DNS côté serveur** (`socket.getaddrinfo`) puis vérification
   de toutes les IPs résolues. Bloque les hostnames pointant vers des IPs privées
4. **Blocage explicite** : 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 127.0.0.0/8,
   169.254.0.0/16 (metadata cloud AWS/GCP), 0.0.0.0/8, ::1, fe80::/10, fc00::/7

**Sémantique du status** :
- `status: "success"` = une réponse HTTP a été reçue (même 404, 500...)
- `status: "error"` = erreur de transport uniquement (timeout, DNS, connexion refusée, SSRF bloqué)

**Auth helpers** intégrés (curl) :
- `basic` → `-u user:password`
- `bearer` → `-H "Authorization: Bearer token"`
- `api_key` → `-H "X-API-Key: key"`

**Fallback dev** : `SANDBOX_ENABLED=false` → httpx local avec la même validation anti-SSRF.

### 2.4 Sandbox Docker Python (tool calc)

Le tool `calc` évalue des expressions mathématiques Python dans un conteneur
sandbox éphémère **sans réseau** :

| Contrainte         | Valeur              | Raison                                 |
| ------------------ | ------------------- | -------------------------------------- |
| `--network=none`   | Pas de réseau       | Calcul pur, pas besoin de réseau       |
| `--read-only`      | Filesystem immuable | Empêche la modification du conteneur   |
| `--cap-drop=ALL`   | Zéro capabilities   | Pas de privilèges noyau                |
| `--memory=256m`    | Limite mémoire      | Protection contre les OOM              |
| `--cpus=0.5`       | Limite CPU          | Protection contre les boucles infinies |
| `--pids-limit=10`  | Limite processus    | Anti fork-bomb                         |
| `--user=sandbox`   | Non-root            | Pas d'accès root                       |

**Fonctionnement** :
1. L'expression est wrappée dans un script Python avec `import math, statistics`
2. `eval(expr)` exécute l'expression dans le conteneur isolé
3. Le résultat est parsé (int/float/texte) et retourné
4. **Sécurité par la sandbox** : pas de safe eval AST complexe — la sandbox Docker isole complètement (pas de réseau, pas de filesystem, non-root)

**Limite** : 1000 chars max, timeout 10s + 15s marge conteneur.
**Nommage conteneurs** : `calc-{uuid}`
**Fallback dev** : `SANDBOX_ENABLED=false` → subprocess python3 local.

### 2.5 Tool date (pure Python, pas de sandbox)

Le tool `date` manipule les dates/heures via la stdlib Python (`datetime` + `zoneinfo`).
Pas de sandbox nécessaire — c'est du calcul pur sans I/O externe.

**8 opérations** : now, today, parse, format, add, diff, week_number, day_of_week.
**Parsing flexible** : ISO 8601, DD/MM/YYYY, YYYYMMDD, etc. (12 formats).
**Fuseaux horaires** : `zoneinfo.ZoneInfo` (stdlib Python 3.9+).

### Matrice sandbox comparée

| Contrainte        | shell                | network                      | http                      | calc                |
| ----------------- | -------------------- | ---------------------------- | ------------------------- | ------------------- |
| `--network`       | `none`               | `bridge`                     | `bridge`                  | `none`              |
| `--cap-add`       | aucun                | `NET_RAW`                    | aucun                     | aucun               |
| Anti-SSRF         | N/A (pas de réseau)  | RFC 1918 (IP directe)        | RFC 1918 + résolution DNS | N/A (pas de réseau) |
| Exécutable        | bash/sh/python3/node | ping/dig/nslookup/traceroute | curl                      | python3             |
| Nommage conteneur | `sandbox-{uuid}`     | `network-{uuid}`             | `http-{uuid}`             | `calc-{uuid}`       |

### Matrice de communication (mise à jour)

MCP Tools est un **serveur passif** comme Live Memory, Graph Memory et Vault :

| Appelle →              |       MCP Tools        |
| ---------------------- | :--------------------: |
| **MCP Agent**          |       ✅ (tools)       |
| **Mission Controller** |           ❌           |
| **MCP Tools**          | — (n'appelle personne) |

---

## 2.6 Console d'administration Web (`/admin`)

MCP Tools inclut une **interface web d'administration** accessible sur `/admin`,
reprenant les codes graphiques de **Cloud Temple Live Memory** (dark theme, accent teal #41a890).

### Architecture

```
AdminMiddleware (ASGI, outermost)
    │
    ├── GET /admin           → SPA HTML (admin.html)
    ├── GET /admin/static/*  → fichiers statiques (CSS, JS, images)
    └── */admin/api/*        → API REST admin (auth Bearer admin requise)
            │
            ├── GET  /admin/api/health         → état du serveur
            ├── GET  /admin/api/tools          → liste des outils + paramètres
            ├── POST /admin/api/tools/run      → exécuter un outil interactivement
            ├── GET  /admin/api/tokens         → lister les tokens S3
            ├── POST /admin/api/tokens         → créer un token
            ├── GET  /admin/api/tokens/{name}  → info d'un token
            ├── DELETE /admin/api/tokens/{name} → révoquer un token
            └── GET  /admin/api/logs           → activité récente (ring buffer 200)
```

### Pile middleware ASGI (ordre d'exécution)

```
AdminMiddleware → HealthCheckMiddleware → AuthMiddleware → LoggingMiddleware → FastMCP
```

L'AdminMiddleware intercepte toutes les routes `/admin*` **avant** l'auth MCP.
L'API admin gère sa propre authentification (Bearer token admin uniquement).

### 4 vues

| Vue          | Description                                                                                          |
| ------------ | ---------------------------------------------------------------------------------------------------- |
| **Dashboard** | État du serveur (version, Python, sandbox, S3, Perplexity), stats tokens, actions rapides           |
| **Tools**    | Grille des 12 outils avec recherche. Clic = formulaire dynamique (select pour enums, inputs typés). Exécution interactive avec résultat JSON formaté |
| **Tokens**   | Table CRUD : créer (checkboxes tool_ids), info, révoquer. Token brut affiché une seule fois         |
| **Activité** | Logs temps réel (ring buffer mémoire 200 entrées, auto-refresh 5s). Méthode, path, status, durée   |

### Fichiers

| Fichier                              | Rôle                                       |
| ------------------------------------ | ------------------------------------------ |
| `src/mcp_tools/admin/__init__.py`    | Module admin                               |
| `src/mcp_tools/admin/middleware.py`  | AdminMiddleware ASGI (static + API routing) |
| `src/mcp_tools/admin/api.py`        | REST API (7 endpoints + enum enrichment)   |
| `src/mcp_tools/static/admin.html`   | SPA HTML                                   |
| `src/mcp_tools/static/css/admin.css` | Styles (design Cloud Temple)               |
| `src/mcp_tools/static/js/*.js`      | 7 modules JS (config, api, app, dashboard, tools, tokens, logs) |
| `src/mcp_tools/static/img/`         | Logo Cloud Temple SVG                      |

### Sécurité

- **Authentification admin** : seul le `ADMIN_BOOTSTRAP_KEY` ou un token S3 avec permission `admin` donne accès
- **HTML/CSS/JS publics** : la page de login est servie sans auth (l'auth se fait côté API)
- **CORS preflight** : OPTIONS géré pour les appels AJAX cross-origin
- **Path traversal** : protection contre les `../` dans les chemins statiques

---

## 3. Auth : Token → subset de tools

### Concept `tool_ids`

Le token d'accès contient un champ `tool_ids` qui liste les tools autorisés :

```json
{
  "client_name": "agent-sre",
  "permissions": ["access"],
  "tool_ids": ["ssh", "shell", "http", "network", "docker", "files", "date", "calc", "perplexity_search"],
  "email": "sre-team@cloudtemple.fr",
  "expires_at": "2026-06-01T00:00:00Z"
}
```

Un agent `doc-writer` aurait : `["pdf2text", "pdf_search", "files", "doc_scraper", "generate", "perplexity_doc"]`

Si `tool_ids` est vide ou absent → accès à **tous** les tools (admin).

### Vérification

Chaque outil MCP vérifie que le tool est dans la whitelist du token avant exécution :

```python
@mcp.tool()
async def ssh(host: str, command: str, ...):
    check_tool_access("ssh")  # Vérifie tool_ids dans le token
    ...
```

---

## 4. Réutilisation vs développement

### Ce qu'on réutilise du starter-kit (identique à Live Memory)

| Composant        | Source                                  | Effort                                       |
| ---------------- | --------------------------------------- | -------------------------------------------- |
| Auth Middleware  | `auth/middleware.py` (starter-kit)      | Copie + ajout `tool_ids`                     |
| Token Service    | `core/tokens.py` (starter-kit)          | Copie + champ `tool_ids`                     |
| Access Control   | `auth/context.py` (starter-kit)         | Copie + `check_tool_access()`                |
| Storage S3       | `core/storage.py` (starter-kit)         | Copie directe                                |
| CLI client       | `scripts/cli/client.py` (starter-kit)   | Copie directe                                |
| CLI commands     | `scripts/cli/commands.py` (starter-kit) | Adapté (tools au lieu de spaces)             |
| Shell interactif | `scripts/cli/shell.py` (starter-kit)    | Adapté                                       |
| Display Rich     | `scripts/cli/display.py` (starter-kit)  | Copie directe                                |
| Config           | `config.py` (starter-kit)               | Adapté (ajout Perplexity, etc.)              |
| Dockerfile       | Starter-kit                             | Adapté (ajout libreoffice, ffmpeg si besoin) |

### Ce qu'on s'inspire de Dragonfly (réécriture Python propre)

| Tool            | Module Dragonfly          | Ce qu'on prend                        | Ce qu'on adapte                       |
| --------------- | ------------------------- | ------------------------------------- | ------------------------------------- |
| ssh             | `tools/_ssh_client/`      | Paramètres, auth types, SFTP          | Asyncio subprocess, intégration vault |
| shell           | `tools/_script/`          | Params (cwd, timeout, shell)          | Sandbox + forbidden_patterns          |
| http            | `tools/_http_client/`     | Auth types, retry, proxy              | httpx async, taille réponse limitée   |
| host_audit      | `tools/_host_audit/`      | Plans d'audit par service             | Output format adapté à nos personas   |
| git             | `tools/_git/`             | Opérations locales + GitHub API       | Async, pas de GitHub en v1            |
| files           | `tools/_file_editor/`     | Édition chirurgicale (search/replace) | Fichiers locaux (pas S3 scope)        |
| sqlite          | `tools/_sqlite_db/`       | CRUD, schemas                         | aiosqlite                             |
| script_executor | `tools/_script_executor/` | Sandbox Python                        | Whitelist tools adaptée               |
| date            | `tools/_date/`            | Toutes les opérations                 | Python natif (datetime, zoneinfo)     |
| calc            | `tools/_math/`            | Subset (stats, arithmétique)          | Pas besoin de SymPy complet           |
| ssh_diagnostics | `tools/_ssh_diagnostics/` | Opérations diagnostic                 | Async subprocess                      |
| email_send      | `tools/_email_send/`      | SMTP, pièces jointes                  | aiosmtplib                            |
| pdf2text        | `tools/_pdf2text/`        | Extraction par pages                  | PyPDF2 ou pdfplumber                  |
| pdf_search      | `tools/_pdf_search/`      | Recherche regex dans PDFs             | PyPDF2 + re                           |
| office_to_pdf   | `tools/_office_to_pdf/`   | Conversion via LibreOffice            | subprocess headless                   |
| doc_scraper     | `tools/_universal_doc/`   | Scraping multi-plateformes            | httpx + beautifulsoup4                |

### Ce qu'on s'inspire de perplexity-mcp (réécriture Python)

| Tool              | Source              | Ce qu'on prend             | Ce qu'on adapte                        |
| ----------------- | ------------------- | -------------------------- | -------------------------------------- |
| perplexity_search | `search`            | Prompt + detail_level      | httpx async (pas axios), pas de SQLite |
| perplexity_doc    | `get_documentation` | Prompt structuré doc/code  | ✅ httpx async — validé 3/3 tests      |

### Ce qu'on développe from scratch

| Tool         | Raison                                                                     |
| ------------ | -------------------------------------------------------------------------- |
| **network**  | Sandbox Docker réseau + blocage RFC 1918 (ping, traceroute, nslookup, dig) |
| **docker**   | Spécifique à notre infra (subprocess `docker` CLI)                         |
| **s3**       | Spécifique Cloud Temple (boto3, dual SigV2/V4)                             |
| **db**       | Client SQL universel (asyncpg, aiomysql)                                   |
| **generate** | Génération de fichiers depuis templates (Jinja2)                           |
| **mcp_call** | Appel MCP générique (SDK `streamablehttp_client`)                          |

---

## 5. Configuration (.env)

```env
# --- MCP Tools ---
MCP_SERVER_NAME=mcp-tools
MCP_SERVER_PORT=8050

# --- Auth ---
ADMIN_BOOTSTRAP_KEY=change_me_in_production

# --- S3 (tokens MCP) ---
S3_ENDPOINT_URL=https://your-endpoint.s3.fr1.cloud-temple.com
S3_ACCESS_KEY_ID=AKIA_YOUR_KEY
S3_SECRET_ACCESS_KEY=your_secret
S3_BUCKET_NAME=mcp-tools
S3_REGION_NAME=fr1

# --- Perplexity ---
PERPLEXITY_API_KEY=pplx_xxx
PERPLEXITY_MODEL=sonar-reasoning-pro

# --- Email (optionnel) ---
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=xxx
SMTP_PASSWORD=xxx
```

---

## 6. Structure fichiers

```
mcp-tools/
├── src/mcp_tools/
│   ├── __init__.py
│   ├── __main__.py
│   ├── server.py              # Outils système + create_app() + bannière
│   ├── config.py              # Config (S3, Perplexity, sandbox, limites)
│   ├── admin/                 # ✅ Console d'administration web (/admin)
│   │   ├── __init__.py
│   │   ├── middleware.py      # AdminMiddleware ASGI (static + API routing)
│   │   └── api.py             # REST API admin (7 endpoints + enum enrichment)
│   ├── static/                # ✅ Fichiers statiques admin (SPA)
│   │   ├── admin.html         # SPA HTML (login + 4 vues)
│   │   ├── css/admin.css      # Design Cloud Temple (dark theme #0f0f23)
│   │   ├── js/                # 7 modules JS (config, api, app, dashboard, tools, tokens, logs)
│   │   └── img/               # Logo Cloud Temple SVG
│   ├── auth/                  # Auth + Token Manager
│   │   ├── __init__.py
│   │   ├── middleware.py      # Bootstrap key + Token Store S3 lookup
│   │   ├── context.py         # check_tool_access() via ContextVar
│   │   └── token_store.py     # ✅ Token Store S3 + cache mémoire TTL 5min
│   └── tools/
│       ├── __init__.py        # register_all_tools(mcp)
│       ├── shell.py           # ✅ Shell sandbox Docker éphémère (--network=none)
│       ├── network.py         # ✅ Diagnostic réseau sandbox (--network=bridge, RFC 1918)
│       ├── http.py            # ✅ Client HTTP/REST
│       ├── perplexity.py      # ✅ Recherche + doc Perplexity AI (search + doc)
│       ├── ssh.py             # ✅ SSH exec/upload/download sandbox (--network=bridge, sshpass+key)
│       ├── docker.py          # 📐 Docker CLI
│       ├── files.py           # ✅ Fichiers S3 Dell ECS sandbox (--network=bridge, boto3 hybride SigV2/SigV4, versioning)
│       ├── date.py            # ✅ Date/heure/timezone (pure Python, 12 tests)
│       ├── calc.py            # ✅ Calculs math (sandbox Python Docker, 12 tests)
│       ├── token.py           # ✅ Token CRUD admin (create/list/info/revoke, 12 tests)
│       ├── generate.py        # 📐 Génération fichiers (Jinja2)
│       ├── mcp_call.py        # 📐 Appel MCP externe
│       ├── git.py             # 📐 Git local + GitHub
│       ├── s3.py              # 📐 Opérations S3
│       ├── db.py              # 📐 Client SQL (PostgreSQL/MySQL)
│       ├── host_audit.py      # 📐 Plans d'audit
│       ├── ssh_diagnostics.py # 📐 Diagnostic SSH
│       ├── sqlite.py          # 📐 SQLite local
│       ├── script_executor.py # 📐 Sandbox Python
│       ├── email_send.py      # 📐 SMTP
│       ├── pdf.py             # 📐 pdf2text + pdf_search
│       ├── office_to_pdf.py   # 📐 Conversion Office→PDF
│       ├── doc_scraper.py     # 📐 Scraping doc web
│       ├── imap.py            # 📐 Lecture emails
│       └── perplexity_ext.py  # 📐 find_apis + check_deprecated
├── sandbox/
│   └── Dockerfile             # ✅ Image Alpine sandbox (éphémère, --network=none)
├── scripts/
│   ├── test_service.py        # ✅ Recette E2E (--test NOM pour cibler)
│   └── cli/                   # CLI standard (starter-kit)
├── Dockerfile                 # ✅ Python 3.11 + docker CLI statique
├── docker-compose.yml         # ✅ sandbox + mcp-tools + waf + docker.sock
├── requirements.txt
├── .env.example
└── VERSION
```

> ✅ = implémenté et testé | 📐 = design, non implémenté

---

## 7. Roadmap

| Phase       | Tools                                                                                                                           | Nombre | Effort  |
| ----------- | ------------------------------------------------------------------------------------------------------------------------------- | ------ | ------- |
| **Phase 1** | ssh, shell, http, network, docker, files, date, calc, token, generate, mcp_call, perplexity (×2)                                 | 13     | 2-3 sem |
| **Phase 2** | git, s3, db, host_audit, ssh_diagnostics, sqlite, script_executor, email_send, pdf2text, pdf_search, office_to_pdf, doc_scraper | 12     | 2-3 sem |
| **Phase 3** | imap, perplexity_api, perplexity_deprecated                                                                                     | 3      | 1 sem   |

---

*Document créé le 5 mars 2026 — Mis à jour le 17 mars 2026 — MCP Tools v0.1.8*
