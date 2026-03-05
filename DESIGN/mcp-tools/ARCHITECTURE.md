# Architecture — MCP Tools

> **Version** : 0.1.0-draft | **Date** : 2026-03-05 | **Auteur** : Cloud Temple
> **Projet** : mcp-tools | **Licence** : Apache 2.0
> **Statut** : 📐 Design — non implémenté

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
           │  MCP Protocol (Streamable HTTP)        │
           ▼                                       ▼
┌────────────────────────────────────────────────────────┐
│                MCP Tools Server (:8050)                  │
│                Python / FastMCP (starter-kit)            │
│                                                          │
│  ┌────────────────────────────────────────────────────┐  │
│  │  Auth Middleware (starter-kit standard)             │  │
│  │  • Bearer Token + permissions (read/write/admin)    │  │
│  │  • tool_ids dans le token (whitelist de tools)      │  │
│  └────────────────────────────────────────────────────┘  │
│                                                          │
│  ┌────────────────────────────────────────────────────┐  │
│  │  28 Outils MCP (tools/)                             │  │
│  │                                                     │  │
│  │  Infra :    ssh, shell, ping, docker                │  │
│  │  Réseau :   http, ssh_diagnostics                   │  │
│  │  Données :  files, sqlite, db, s3                   │  │
│  │  Dev :      git, script_executor, calc, date        │  │
│  │  Docs :     pdf2text, pdf_search, office_to_pdf,    │  │
│  │             doc_scraper                              │  │
│  │  Recherche: perplexity_search, perplexity_doc,      │  │
│  │             perplexity_chat                          │  │
│  │  Audit :   host_audit                               │  │
│  │  Comm :    email_send, imap                          │  │
│  │  Meta :    generate, mcp_call                        │  │
│  └────────────────────────────────────────────────────┘  │
│                                                          │
│  ┌────────────────────────────────────────────────────┐  │
│  │  Token Manager (starter-kit, S3)                   │  │
│  └────────────────────────────────────────────────────┘  │
└──────────────────────────┬───────────────────────────────┘
                           │
                    S3 Dell ECS          Docker Socket
                    Bucket : mcp-tools   /var/run/docker.sock
                                              │
                                    ┌─────────┴──────────┐
                                    │  Sandbox Container  │
                                    │  (Alpine éphémère)  │
                                    │  --network=none     │
                                    │  --read-only        │
                                    │  --cap-drop=ALL     │
                                    └────────────────────┘
```

### 2.1 Sandbox Docker (tool shell)

Le tool `shell` n'exécute **pas** les commandes dans le conteneur MCP Tools.
Chaque commande est isolée dans un **conteneur Docker éphémère** (Alpine)
lancé via `docker run --rm` avec les contraintes de sécurité suivantes :

| Contrainte | Valeur | Raison |
|-----------|--------|--------|
| `--network=none` | Pas de réseau | Empêche toute exfiltration de données |
| `--read-only` | Filesystem immuable | Empêche la modification du conteneur |
| `--cap-drop=ALL` | Zéro capabilities Linux | Pas de privilèges noyau |
| `--memory=256m` | Limite mémoire | Protection contre les OOM |
| `--cpus=0.5` | Limite CPU | Protection contre les boucles infinies |
| `--pids-limit=10` | Limite processus | Anti fork-bomb |
| `--user=sandbox` | Non-root | Pas d'accès root |
| `--no-new-privileges` | Pas d'escalade | Bloque setuid/setgid |
| `--tmpfs /tmp:noexec` | Temp sans exec | Pas d'exécution depuis /tmp |

**Image sandbox** : `mcp-tools-sandbox` (Alpine 3.20 + bash, coreutils,
grep, sed, awk, jq, bc, curl, git, openssl, gnupg, python3, node).
Buildée par `docker compose up`.

**Prérequis** : le conteneur MCP Tools monte `/var/run/docker.sock` (read-only)
pour pouvoir lancer les conteneurs sandbox. Le docker CLI est inclus dans
l'image MCP Tools (binaire statique).

**Fallback dev** : `SANDBOX_ENABLED=false` → exécution locale via subprocess
(pour le développement sans Docker).

### Matrice de communication (mise à jour)

MCP Tools est un **serveur passif** comme Live Memory, Graph Memory et Vault :

| Appelle →              |       MCP Tools        |
| ---------------------- | :--------------------: |
| **MCP Agent**          |       ✅ (tools)       |
| **Mission Controller** |           ❌           |
| **MCP Tools**          | — (n'appelle personne) |

---

## 3. Auth : Token → subset de tools

### Concept `tool_ids`

Le token d'accès contient un champ `tool_ids` qui liste les tools autorisés :

```json
{
  "client_name": "agent-sre",
  "permissions": "write",
  "tool_ids": ["ssh", "shell", "http", "ping", "docker", "files", "date", "calc", "perplexity_search"],
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
| perplexity_doc    | `get_documentation` | Prompt structuré           | httpx async                            |
| perplexity_chat   | `chat_perplexity`   | Historique de conversation | Stockage S3 (pas SQLite local)         |

### Ce qu'on développe from scratch

| Tool         | Raison                                                       |
| ------------ | ------------------------------------------------------------ |
| **ping**     | Trivial (subprocess `ping`, `traceroute`, `nslookup`, `dig`) |
| **docker**   | Spécifique à notre infra (subprocess `docker` CLI)           |
| **s3**       | Spécifique Cloud Temple (boto3, dual SigV2/V4)               |
| **db**       | Client SQL universel (asyncpg, aiomysql)                     |
| **generate** | Génération de fichiers depuis templates (Jinja2)             |
| **mcp_call** | Appel MCP générique (SDK `streamablehttp_client`)            |

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
│   ├── auth/                  # Auth standard (starter-kit)
│   │   ├── __init__.py
│   │   ├── middleware.py      # + check_tool_access()
│   │   └── context.py
│   └── tools/
│       ├── __init__.py        # register_all_tools(mcp)
│       ├── shell.py           # ✅ Shell sandbox Docker éphémère
│       ├── ping.py            # ✅ Ping/traceroute/nslookup/dig
│       ├── http.py            # ✅ Client HTTP/REST
│       ├── perplexity.py      # ✅ Recherche Perplexity AI
│       ├── ssh.py             # 📐 SSH exec + SFTP
│       ├── docker.py          # 📐 Docker CLI
│       ├── files.py           # 📐 Édition fichiers
│       ├── date.py            # 📐 Date/heure/timezone
│       ├── calc.py            # 📐 Calculs/stats
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
| **Phase 1** | ssh, shell, http, ping, docker, files, date, calc, generate, mcp_call, perplexity (×3)                                          | 13     | 2-3 sem |
| **Phase 2** | git, s3, db, host_audit, ssh_diagnostics, sqlite, script_executor, email_send, pdf2text, pdf_search, office_to_pdf, doc_scraper | 12     | 2-3 sem |
| **Phase 3** | imap, perplexity_api, perplexity_deprecated                                                                                     | 3      | 1 sem   |

---

*Document créé le 5 mars 2026 — MCP Tools v0.1.0-draft*
