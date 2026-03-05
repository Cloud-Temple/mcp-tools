# Catalogue des Tools — MCP Tools

> **Version** : 0.1.0-draft | **Date** : 2026-03-05
> **Référence** : Voir `ARCHITECTURE.md` pour le contexte global

---

## Phase 1 — 13 tools essentiels

### Infra (4 tools)

| Tool       | Opérations                                                                                     | Params clés                                                                                                     | Source                             |
| ---------- | ---------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------- | ---------------------------------- |
| **ssh**    | `exec`, `upload`, `download`, `status`                                                         | host, username, auth_type (password/key/agent), command, sudo, timeout (60s max), remote_path, local_path       | Dragonfly `ssh_client`             |
| **shell**  | Exécution dans conteneur sandbox Docker éphémère (--network=none, --read-only, --cap-drop=ALL) | command, shell (bash/sh), timeout (30s max). `cwd` ignoré en sandbox. Fallback local si `SANDBOX_ENABLED=false` | Dragonfly `shell` + sandbox Docker |
| **network**| `ping`, `traceroute`, `nslookup`, `dig` — Sandbox Docker (--network=bridge, --cap-add=NET_RAW, RFC 1918 bloqué) | host, operation, extra_args (args passés à la commande), timeout. IPs privées interdites. | From scratch (sandbox Docker)      |
| **docker** | `ps`, `logs`, `exec`, `pull`, `compose_up`, `compose_down`, `stats`, `inspect`                 | container, command, service, compose_file, tail (logs), timeout                                                 | From scratch                       |

### Réseau (1 tool)

| Tool     | Opérations                          | Params clés                                                                                                | Source                  |
| -------- | ----------------------------------- | ---------------------------------------------------------------------------------------------------------- | ----------------------- |
| **http** | GET, POST, PUT, DELETE, PATCH, HEAD | url, method, headers, json, body, auth_type (basic/bearer/api_key), timeout (30s), max_retries, verify_ssl | Dragonfly `http_client` |

### Données (1 tool)

| Tool      | Opérations                                        | Params clés                                                              | Source                  |
| --------- | ------------------------------------------------- | ------------------------------------------------------------------------ | ----------------------- |
| **files** | `read`, `write`, `edit`, `list`, `delete`, `diff` | path, content, edits (search_replace/regex/insert/delete_lines), dry_run | Dragonfly `file_editor` |

### Utilitaires (2 tools)

| Tool     | Opérations                                                                             | Params clés                                     | Source                    |
| -------- | -------------------------------------------------------------------------------------- | ----------------------------------------------- | ------------------------- |
| **date** | `now`, `today`, `diff`, `add`, `format`, `parse`, `week_number`, `day_of_week`         | date, operation, tz, days/hours/minutes, format | Dragonfly `date`          |
| **calc** | `add`, `subtract`, `multiply`, `divide`, `mean`, `median`, `stdev`, `variance`, `eval` | operation, a, b, data, expr                     | Dragonfly `math` (subset) |

### Meta (2 tools)

| Tool         | Opérations                                  | Params clés                              | Source                 |
| ------------ | ------------------------------------------- | ---------------------------------------- | ---------------------- |
| **generate** | `from_template`, `markdown`, `json`, `yaml` | template, variables, format, output_path | From scratch (Jinja2)  |
| **mcp_call** | Appel MCP générique                         | mcp_name, tool_name, params              | From scratch (SDK MCP) |

### Recherche Perplexity (3 tools)

| Tool                  | Description                              | Params clés                                 | Source                             |
| --------------------- | ---------------------------------------- | ------------------------------------------- | ---------------------------------- |
| **perplexity_search** | Recherche internet avec niveau de détail | query, detail_level (brief/normal/detailed) | perplexity-mcp `search`            |
| **perplexity_doc**    | Documentation d'une techno/lib/API       | query, context                              | perplexity-mcp `get_documentation` |
| **perplexity_chat**   | Conversation continue avec historique    | message, chat_id (optionnel)                | perplexity-mcp `chat_perplexity`   |

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

| Persona                | Tools autorisés (via `tool_ids` du token)                                                                            |
| ---------------------- | -------------------------------------------------------------------------------------------------------------------- |
| **sre-operator**       | ssh, shell, http, network, docker, files, date, calc, git, s3, host_audit, ssh_diagnostics, perplexity_search, generate |
| **security-auditor**   | http, network, ssh_diagnostics, host_audit, pdf_search, doc_scraper, perplexity_search, perplexity_doc                  |
| **dba**                | ssh, db, sqlite, files, calc, date, perplexity_search, generate                                                         |
| **monitoring-analyst** | http, network, calc, date, files, perplexity_search, generate                                                           |
| **doc-writer**         | files, pdf2text, pdf_search, office_to_pdf, doc_scraper, generate, perplexity_doc, perplexity_chat                   |

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

*Document créé le 5 mars 2026 — MCP Tools v0.1.0-draft*
