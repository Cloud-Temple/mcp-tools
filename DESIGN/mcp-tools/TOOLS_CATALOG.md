# Catalogue des Tools — MCP Tools

> **Version** : 0.3.0 | **Date** : 2026-03-24
> **Référence** : Voir `ARCHITECTURE.md` pour le contexte global

---

## Phase 1 — 13 tools essentiels

### Infra (4 tools)

| Tool        | Opérations                                                                                                      | Params clés                                                                                                     | Source                             |
| ----------- | --------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------- | ---------------------------------- |
| **ssh** ✅  | `exec`, `upload`, `download`, `status` — Sandbox Docker (--network=bridge, sshpass+key dans tmpfs)              | host, username, auth_type (password/key), command, sudo, timeout (60s max), remote_path, content — 10 tests     | Sandbox Docker (from scratch)      |
| **shell** ✅ | Exécution dans conteneur sandbox Docker éphémère (--network=none, --read-only, --cap-drop=ALL)                  | command, shell (bash/sh/python3/node), timeout (30s max). `cwd` ignoré en sandbox. Fallback local si `SANDBOX_ENABLED=false` | Dragonfly `shell` + sandbox Docker |
| **network** ✅ | `ping`, `traceroute`, `nslookup`, `dig` — Sandbox Docker (--network=bridge, --cap-add=NET_RAW, RFC 1918 bloqué) | host, operation, extra_args (args passés à la commande), timeout. IPs privées interdites.                       | From scratch (sandbox Docker)      |
| **docker**  | `ps`, `logs`, `exec`, `pull`, `compose_up`, `compose_down`, `stats`, `inspect`                                  | container, command, service, compose_file, tail (logs), timeout                                                 | From scratch                       |

### Réseau (1 tool)

| Tool     | Opérations                                                                                                    | Params clés                                                                                              | Source                      |
| -------- | ------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------- | --------------------------- |
| **http** ✅ | GET, POST, PUT, DELETE, PATCH, HEAD — Sandbox Docker (--network=bridge, anti-SSRF, RFC 1918 + résolution DNS) | url, method, headers, body, json_body, auth_type (basic/bearer/api_key), auth_value, timeout, verify_ssl | Sandbox curl (from scratch) |

### Données (1 tool)

| Tool      | Opérations                                        | Params clés                                                              | Source                  |
| --------- | ------------------------------------------------- | ------------------------------------------------------------------------ | ----------------------- |
| **files** ✅ | `list`, `read`, `write`, `delete`, `info`, `diff`, `versions`, `enable_versioning` — Sandbox Docker (--network=bridge, python3+boto3, S3 Dell ECS hybride SigV2/SigV4) | path, content, prefix, version_id, endpoint, access_key, secret_key, bucket, region — 11 tests + 9 tests versioning | Sandbox boto3 (from scratch) |

### Utilitaires (2 tools)

| Tool        | Opérations                                                                     | Params clés                                                                           | Source                                     |
| ----------- | ------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------- | ------------------------------------------ |
| **date** ✅ | `now`, `today`, `diff`, `add`, `format`, `parse`, `week_number`, `day_of_week` | date, operation, tz, days/hours/minutes, format                                       | Pure Python (datetime+zoneinfo) — 12 tests |
| **calc** ✅ | Expression Python dans sandbox Docker isolée (math + statistics pré-importés)  | expr (expression Python, ex: `(3+5)*2`, `math.sqrt(144)`, `statistics.mean([1,2,3])`) | Sandbox Python Docker — 12 tests           |

### Meta (2 tools)

| Tool         | Opérations                                  | Params clés                              | Source                 |
| ------------ | ------------------------------------------- | ---------------------------------------- | ---------------------- |
| **generate** | `from_template`, `markdown`, `json`, `yaml` | template, variables, format, output_path | From scratch (Jinja2)  |
| **mcp_call** | Appel MCP générique                         | mcp_name, tool_name, params              | From scratch (SDK MCP) |

### Auth (1 tool)

| Tool        | Opérations                                                                                                      | Params clés                                                                                                      | Source                        |
| ----------- | --------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------- | ----------------------------- |
| **token** ✅ | `create`, `list`, `info`, `update`, `revoke` — Admin uniquement. Tokens stockés en S3 (`_tokens/{sha256}.json`), cache mémoire TTL 5min. Chaque token restreint l'accès via `tool_ids`. `update` modifie permissions/tool_ids/email sans révoquer. `tool_ids=["all"]` résolu en 12 outils. Fail-closed §3.2 : non-admin + tool_ids vide = refusé | client_name, permissions, tool_ids (`["all"]` = tous), email (optionnel, traçabilité), expires_days. Token brut affiché une seule fois à la création — 12 tests E2E | Token Store S3 (from scratch) |

### Recherche Perplexity (3 tools)

| Tool                  | Description                              | Params clés                                                    | Source                             |
| --------------------- | ---------------------------------------- | -------------------------------------------------------------- | ---------------------------------- |
| **perplexity_search** ✅ | Recherche internet avec niveau de détail | query, detail_level (brief/normal/detailed), model (optionnel) | perplexity-mcp `search`            |
| **perplexity_doc** ✅ | Documentation d'une techno/lib/API       | query, context (optionnel), model (optionnel)                  | perplexity-mcp `get_documentation` — 3 tests |
| ~~perplexity_chat~~   | ~~Conversation continue avec historique~~ | ~~message, chat_id~~ — **Abandonné**                          | —                                  |

---

## Phase 2 — 12 tools enrichissement

### Dev (2 tools)

| Tool                | Opérations                                                                     | Params clés                                     | Source                      |
| ------------------- | ------------------------------------------------------------------------------ | ----------------------------------------------- | --------------------------- |
| **git**             | `status`, `commit`, `push`, `pull`, `diff`, `log`, `branch_create`, `checkout` | repo_dir, operation, message, branch            | Dragonfly `git`             |
| **script_executor** | Exécution Python sandboxé                                                      | script, variables, timeout (60s), allowed_tools | Dragonfly `script_executor` |

### Données (3 tools)

| Tool       | Opérations                                                | Params clés                                                                  | Source                          |
| ---------- | --------------------------------------------------------- | ---------------------------------------------------------------------------- | ------------------------------- |
| **s3**     | `list`, `get`, `put`, `delete`, `info`                    | bucket, key, local_path, prefix                                              | From scratch (boto3)            |
| **db**     | `query`, `execute`, `tables`, `describe`                  | host, port, type (postgresql/mysql), database, query, credentials_from_vault | From scratch (asyncpg/aiomysql) |
| **sqlite** | `create_db`, `query`, `execute`, `get_tables`, `describe` | db, operation, query                                                         | Dragonfly `sqlite_db`           |

### Audit (2 tools)

| Tool                | Opérations                                                                                                  | Params clés                          | Source                      |
| ------------------- | ----------------------------------------------------------------------------------------------------------- | ------------------------------------ | --------------------------- |
| **host_audit**      | `ubuntu_plan`, `nginx_plan`, `mysql_plan`, `php_plan`, `nodejs_plan`, `apache_plan`                         | operation, profile, logs_lines       | Dragonfly `host_audit`      |
| **ssh_diagnostics** | `test_connection`, `check_keepalive`, `test_network`, `check_firewall`, `check_fail2ban`, `full_diagnostic` | host, operation, user, port, timeout | Dragonfly `ssh_diagnostics` |

### Documents (4 tools)

| Tool              | Opérations                                             | Params clés                                              | Source                            |
| ----------------- | ------------------------------------------------------ | -------------------------------------------------------- | --------------------------------- |
| **pdf2text**      | Extraction texte                                       | path, pages (ex: "1-3,5"), limit                         | Dragonfly `pdf2text`              |
| **pdf_search**    | Recherche texte/regex dans PDFs                        | query, path/paths, pages, regex, case_sensitive, context | Dragonfly `pdf_search`            |
| **office_to_pdf** | Conversion Office → PDF                                | input_path, output_path, engine (auto/libreoffice)       | Dragonfly `office_to_pdf`         |
| **doc_scraper**   | `discover_docs`, `extract_page`, `search_across_sites` | base_url, url, query, sites, max_pages, depth            | Dragonfly `universal_doc_scraper` |

### Communication (1 tool)

| Tool           | Opérations                | Params clés                                                              | Source                 |
| -------------- | ------------------------- | ------------------------------------------------------------------------ | ---------------------- |
| **email_send** | `send`, `test_connection` | to, subject, body, body_type (text/html), cc, bcc, attachments, priority | Dragonfly `email_send` |

---

## Phase 3 — 3 tools avancés

| Tool                      | Description                                         | Params clés                                    | Source                                 |
| ------------------------- | --------------------------------------------------- | ---------------------------------------------- | -------------------------------------- |
| **imap**                  | Lecture emails (search, read, download attachments) | provider, operation, folder, query, message_id | Dragonfly `imap`                       |
| **perplexity_api**        | Trouver et évaluer des APIs                         | requirement, context                           | perplexity-mcp `find_apis`             |
| **perplexity_deprecated** | Vérifier du code déprécié                           | code, technology                               | perplexity-mcp `check_deprecated_code` |

---

## Contraintes globales

| Contrainte            | Valeur                    | Raison                              |
| --------------------- | ------------------------- | ----------------------------------- |
| Timeout max par tool  | 600s (10 min)             | Éviter les exécutions infinies      |
| Taille max output     | 50 000 chars              | Éviter les réponses de GB           |
| Taille max input file | 100 MB                    | Protection mémoire                  |
| Retry max (http)      | 5                         | Éviter les boucles infinies         |
| Concurrence max       | 20 exécutions simultanées | Protection CPU/mémoire du container |

---

## Mapping Persona → Tools

| Persona                | Tools autorisés (via `tool_ids` du token)                                                                               |
| ---------------------- | ----------------------------------------------------------------------------------------------------------------------- |
| **sre-operator**       | ssh, shell, http, network, docker, files, date, calc, git, s3, host_audit, ssh_diagnostics, perplexity_search, generate |
| **security-auditor**   | http, network, ssh_diagnostics, host_audit, pdf_search, doc_scraper, perplexity_search, perplexity_doc                  |
| **dba**                | ssh, db, sqlite, files, calc, date, perplexity_search, generate                                                         |
| **monitoring-analyst** | http, network, calc, date, files, perplexity_search, generate                                                           |
| **doc-writer**         | files, pdf2text, pdf_search, office_to_pdf, doc_scraper, generate, perplexity_doc, perplexity_search                    |

---

## Requirements (Phase 1)

```
mcp[cli]>=1.8.0
uvicorn>=0.32.0
pydantic>=2.0
pydantic-settings>=2.0
boto3>=1.34
httpx>=0.27
click>=8.1
prompt-toolkit>=3.0
rich>=13.0
python-dotenv>=1.0
jinja2>=3.1
```

### Requirements additionnels (Phase 2)

```
asyncpg>=0.29        # PostgreSQL
aiomysql>=0.2        # MySQL
aiosqlite>=0.19      # SQLite async
aiosmtplib>=3.0      # SMTP async
pypdf>=4.0           # PDF extraction
beautifulsoup4>=4.12 # HTML scraping
```

---

*Document créé le 5 mars 2026 — Mis à jour le 24 mars 2026 — MCP Tools v0.3.0*
