# Changelog

All notable changes to MCP Tools will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [0.2.1] — 2026-03-23

### Security
- **Audit de sécurité complet** — Rapport d'audit rédigé (`DESIGN/mcp-tools/SECURITY_AUDIT.md`). Architecture qualifiée "niveau Entreprise" par l'auditeur. 5 vulnérabilités identifiées, 3 corrigées dans cette version
- **§3.2 Fail-Closed `tool_ids`** (`context.py`) — Un token non-admin avec `tool_ids=[]` (vide) est désormais **refusé** au lieu d'avoir accès à tous les outils. Seuls les tokens `admin` conservent l'accès universel implicite. Applique le principe de moindre privilège. ⚠️ **Breaking change** : les tokens `access` existants avec `tool_ids=[]` doivent être mis à jour avec une liste explicite d'outils, ou promus en `admin`
- **§3.3 sshpass masqué** (`ssh.py`) — Le mot de passe SSH est passé via la variable d'environnement `SSHPASS` + flag `-e` au lieu de l'argument `-p` en ligne de commande. Masque le mot de passe de `/proc/[pid]/cmdline` dans le conteneur éphémère
- **§3.4 Documentation `network=true`** (`shell.py`) — Description du paramètre `network` enrichie avec ⚠️ ÉLÉVATION DE PRIVILÈGE pour alerter les LLMs que cette option retire l'isolation réseau et `noexec` de `/tmp`

### Fixed
- **Script SSH `set -e` masquait les erreurs** (`ssh.py`) — Le `set -e` dans le script shell généré provoquait une sortie immédiate avant `EXIT=$?` en cas d'échec SSH. Le parser recevait un output vide et retournait `exit_code=0` par défaut. Suppression de `set -e` : les exit codes sont capturés explicitement
- **Tests E2E permissions obsolètes** (`test_service.py`) — Les créations de tokens de test utilisaient `["read", "write"]` (modèle v0.1.8 obsolète). Corrigé en `["access"]` (modèle v0.1.9+)
- **Test token cleanup** (`test_service.py`) — Ajout d'un nettoyage préventif des tokens résiduels de runs précédents. Assertion `count=0` remplacée par vérification ciblée du `client_name` (cohabitation avec tokens de production)

### Changed
- **Rate-limit WAF augmenté** (`waf/Caddyfile`) — MCP : 300→1000 req/min, API : 30→100 req/min, Global : 500→2000 req/min. L'ancien rate-limit bloquait les suites de tests E2E complètes (~138 tests × 4-5 req HTTP chacun). Commentaires dans le Caddyfile mis à jour
- **138 tests E2E** — Total porté à 138 tests (vs ~108 en v0.2.0). Tous passent ✅

## [0.2.0] — 2026-03-23

### Added
- **Paramètre `network` sur le tool shell** — Nouveau paramètre `network: bool = false` (65ème paramètre MCP). Quand activé (`network=true`), le conteneur sandbox passe de `--network=none` à `--network=bridge` avec DNS, permettant `pip install`, `curl`, `wget`. Contraintes adaptées : tmpfs 256m (vs 32m), pids-limit 50 (vs 10), tmpfs supplémentaires sur `~/.local` (128m) et `~/.cache` (64m) pour pip
- **14 packages Python pré-installés dans l'image sandbox** — numpy, pandas, requests, beautifulsoup4, lxml, pyyaml, scipy, matplotlib, pillow, boto3, tabulate, toml, chardet, dateutil. Utilisables sans réseau (`network=false`). Packages Alpine pré-compilés (`py3-*`) pour limiter la taille de l'image
- **Variables d'environnement sandbox** — `OPENBLAS_NUM_THREADS=1` (évite conflit OpenBLAS vs pids-limit), `OPENBLAS_MAIN_FREE=1`, `PIP_BREAK_SYSTEM_PACKAGES=1` (fix PEP 668 Alpine Python, uniquement quand `network=true`)
- **6 nouveaux tests E2E shell** — Packages pré-installés (numpy v1.25.2, pandas v2.0.3, requests v2.32.4), curl avec `network=true` (HTTP 200), pip install + import (`cowsay`), régression `network=false` (toujours isolé). Total recette : ~108 tests
- **Documentation d'audit des tests** (`DESIGN/mcp-tools/TESTS_AUDIT.md`) — Référentiel exhaustif des ~108 tests E2E organisé par catégorie (14 catégories), avec explication de chaque test, critères de succès, matrice de sécurité sandbox, et classification par niveau de risque (critique/isolation/fonctionnel)

### Changed
- **Image sandbox enrichie** (`sandbox/Dockerfile`) — Passage de 1 package pip (boto3) à 14 packages Python. Utilisation des packages Alpine natifs (`py3-numpy`, `py3-pandas`, etc.) quand disponibles pour éviter la compilation C
- **Sécurité tmpfs différenciée** — `noexec` conservé sur tmpfs `/tmp` quand `network=false` (isolation maximale), retiré quand `network=true` (pip en a besoin)
- **65 paramètres MCP** — Ajout du paramètre `network` (total : 65 paramètres documentés avec `Annotated[type, Field(description="...")]`)

## [0.1.9] — 2026-03-23

### Changed
- **Simplification des permissions : `access`/`admin`** — Les permissions `read`/`write` (jamais vérifiées, inadaptées aux tools mixtes http/ssh/files) sont remplacées par un modèle à 2 niveaux : `access` (peut appeler les outils via `tool_ids`) et `admin` (accès total + gestion tokens). `check_tool_access()` vérifie désormais la permission `access` avant d'autoriser l'appel
- **Migration forcée des tokens** — Au démarrage, `_migrate_permissions()` détecte les tokens S3 avec anciennes permissions `read`/`write` et les réécrit automatiquement avec `access`. Log : `🔄 Token Store: N token(s) migrés (read/write → access)`
- **CLI et doc alignés** — `--permissions` default `access` (CLI Click + shell), exemples mis à jour, ARCHITECTURE.md corrigé

### Added
- **Tests WAF Coraza (OWASP CRS)** — 6 tests E2E (`--test waf`) vérifiant le blocage actif du WAF : XSS dans URL, SQL injection dans URL, path traversal (défense en profondeur : 401 auth ou 403 WAF), OS command injection via User-Agent (Shellshock), XSS via header Referer. `SecRuleEngine On` avec seuil anomaly score 5. Total recette : ~102 tests

### Fixed
- **Permissions `read`/`write` non implémentées** (Known Issue v0.1.8) — Résolu par simplification du modèle. Le mécanisme `tool_ids` fournit un contrôle plus fin et plus adapté que read/write pour un serveur de tools

## [0.1.8] — 2026-03-12

### Added
- **Champ `email` sur les tokens** — Nouveau paramètre optionnel `email` pour la traçabilité des propriétaires de tokens. Stocké dans le JSON S3, affiché dans `token list` (colonne Email), `token info` et `token create`. Rétrocompatible : les tokens existants sans email affichent une cellule vide
- **CLI `--email`** — Option `--email` sur `token create` (Click et shell interactif). Ex : `token create ct-user --email user@cloud-temple.com --expires 180`
- **Console admin** — Le formulaire de création de token dans `/admin` supporte le champ `email`

### Changed
- **64 paramètres MCP** — Le nouveau paramètre `email` porte le total à 64 paramètres documentés avec `Annotated[type, Field(description="...")]`

## [0.1.7] — 2026-03-08

### Fixed
- **Bug critique `tool_ids` vide** — Un token créé sans `tool_ids` (accès à tous les outils attendu) voyait TOUS ses accès refusés. La condition `if not tool_ids or ...` dans `check_tool_access()` bloquait quand la liste était vide. Corrigé en `if tool_ids and ...` → liste vide = accès total (convention Cloud Temple §3 ARCHITECTURE.md)

### Improved
- **Descriptions des paramètres MCP** — Ajout de `Annotated[type, Field(description="...")]` sur les **63 paramètres** des 13 tools MCP (9 fichiers). Les clients MCP (Cline, Claude Desktop, etc.) affichent désormais une description utile pour chaque paramètre au lieu de "No description". Chaque description est concise et adaptée pour un usage par LLM (valeurs possibles, exemples, contraintes)

### Added
- **Guide Cline/VSCodium** (`starter-kit/CLINE_SETUP.md`) — Guide complet pour configurer un serveur MCP dans Cline : chemins par OS (macOS/Linux/Windows, VS Code et VSCodium), config minimale, bootstrap key, token S3, multi-serveurs, debug (point rouge/orange), serveur distant, SSE vs Streamable HTTP
- **Section Cline dans README.md** — Configuration rapide avec exemple JSON et commande de création de token dédié

### Changed
- **Starter-kit entièrement mis à jour** — Boilerplate aligné sur les innovations mcp-tools v0.1.6 :
  - `server.py` : `mcp.streamable_http_app()` (remplace `mcp.sse_app()`), pile 5 middlewares ASGI, bannière dynamique `_build_banner()`, `HealthCheckMiddleware`
  - `client.py` : SDK MCP `streamablehttp_client` (remplace `httpx-sse`)
  - Nouveau : `admin/middleware.py` + `admin/api.py` + `static/admin.html` (console admin web SPA)
  - Nouveau : `auth/token_store.py` (Token Store S3 + cache TTL 5min)
  - Nouveau : `__main__.py` (`python -m mon_service`)
  - `auth/middleware.py` : supprimé `HostNormalizerMiddleware`, ajout ring buffer 200 entrées
  - `waf/Caddyfile` : `/sse` → `/mcp`, port 8082
  - `docker-compose.yml` : `expose` au lieu de `ports`, WAF port 8082
- **DESIGN/mcp-vault/ARCHITECTURE.md** v0.2.1-draft — Aligné avec innovations mcp-tools : pile 5 middleware ASGI, console admin web, WAF dans docker-compose, ContextVar, Token Store cache TTL, ring buffer, sécurité enrichie (9 couches)

## [0.1.6] — 2026-03-07

### Added
- **Console d'administration web** (`/admin`) — Interface SPA reprenant le design Cloud Temple (dark theme #0f0f23, accent #41a890). 4 vues : Dashboard (état serveur, stats tokens), Tools (exécution interactive avec formulaires dynamiques et listes déroulantes pour les enums), Tokens (CRUD avec checkboxes tool_ids), Activité (logs temps réel avec auto-refresh)
- **AdminMiddleware ASGI** — Intercepte `/admin`, `/admin/static/*`, `/admin/api/*` en outermost de la pile ASGI. Sert les fichiers statiques et route vers l'API REST admin
- **API REST admin** — 7 endpoints : `GET /admin/api/health`, `GET /admin/api/tools` (avec paramètres + enums enrichis), `POST /admin/api/tools/run` (exécution interactive), `GET/POST /admin/api/tokens` (CRUD), `DELETE /admin/api/tokens/{name}`, `GET /admin/api/logs` (ring buffer 200 entrées)
- **Enum enrichment** — Mapping `_PARAM_ENUMS` dans l'API pour injecter les valeurs possibles des opérations (network: ping/traceroute/nslookup/dig, shell: bash/sh/python3/node, http: GET/POST/.../HEAD, etc.) non exposées par le schema FastMCP → listes déroulantes dans l'UI
- **Tests E2E admin** — 16 tests dans `test_service.py` (`--test admin`) : accès HTML/CSS/JS, path traversal bloqué, API sans/mauvais/non-admin token → 401, API avec admin → health/tools/run/logs/404

### Fixed
- **CORS admin** — Suppression du wildcard `Access-Control-Allow-Origin: *` sur l'API admin. Same-origin uniquement (pas de CORS cross-origin)
- **Status code logs** — `add_log` enregistre maintenant le vrai status HTTP (200/404/500) au lieu de toujours 200

### Changed
- **Pile ASGI** — `AdminMiddleware → HealthCheckMiddleware → AuthMiddleware → LoggingMiddleware → FastMCP` (AdminMiddleware ajouté en outermost)
- **Bannière de démarrage** — Affiche l'URL admin (`http://host:port/admin`)

## [0.1.5] — 2026-03-06

### Added
- **Nouveau tool `token`** — Gestion des tokens d'authentification MCP (admin uniquement). 4 opérations : `create`, `list`, `info`, `revoke`. Chaque token restreint l'accès aux outils via `tool_ids`. **12 tests E2E** (validation, CRUD, auth autorisée/refusée, revoke + 401, doublon)
- **Token Store S3** (`src/mcp_tools/auth/token_store.py`) — Tokens stockés en S3 sous `_tokens/{sha256_hash}.json`. Cache mémoire avec TTL 5 min. SHA-256 du token comme clé (token brut jamais persisté). Config hybride SigV2/SigV4 Dell ECS
- **Middleware auth étendu** — En plus du `ADMIN_BOOTSTRAP_KEY`, le middleware valide les tokens clients depuis le Token Store S3. Vérification expiration. Injection `tool_ids` dans le contexte pour `check_tool_access()`
- **CLI Click** — Groupe `token` avec sous-commandes `create`, `list`, `info`, `revoke`. Options `--tools`, `--permissions`, `--expires`
- **Shell interactif** — Commande `token` avec parsing `--tools`, `--permissions`, `--expires`
- **Affichage Rich** — `show_token_result()` avec panel jaune pour le token brut (affiché une seule fois), table des tokens, détails info

## [0.1.4] — 2026-03-06

### Added
- **Nouveau tool `ssh`** — Exécution de commandes et transfert de fichiers via SSH dans un **conteneur sandbox Docker** éphémère (`--network=bridge`, `--read-only`, `--cap-drop=ALL`). 4 opérations : `exec`, `status`, `upload`, `download`. Auth : `password` (via sshpass) ou `key` (clé privée écrite dans tmpfs). Pas de blocage RFC 1918 (SSH vers infra interne est légitime). Timeout max 60s. Sudo supporté. **10 tests E2E** (validation params + host inaccessible en sandbox)
- **Nouveau tool `files`** — Opérations fichiers sur **S3 Dell ECS** (Cloud Temple) dans un **conteneur sandbox Docker** éphémère (`--network=bridge`, `--read-only`, `--cap-drop=ALL`). 8 opérations : `list`, `read`, `write`, `delete`, `info`, `diff`, `versions`, `enable_versioning`. Configuration hybride **SigV2/SigV4** requise par Dell ECS : SigV2 pour données (PUT/GET/DELETE), SigV4 pour métadonnées (HEAD/LIST/versioning). **Versioning S3** : lister toutes les versions d'un objet, lire une version spécifique par `version_id`, soft delete avec delete markers, activer le versioning sur un bucket. Params S3 optionnels (endpoint, access_key, secret_key, bucket, region) avec fallback config `.env`. **23 tests E2E** intégrés dans `test_service.py` : validation params (4), CRUD S3 (7), overwrite + read modifié (2), diff (1), versioning (3 : versions, read par version_id, read latest), soft delete + delete markers + accès post-delete (3), cleanup (3)
- **sandbox/Dockerfile** — Ajout `openssh-client` + `sshpass` (tool ssh), `boto3` via pip (tool files)
- **CLI Click** — Nouvelles commandes `ssh` et `files` avec options complètes
- **Shell interactif** — Commandes `ssh` et `files` avec aide contextuelle et parsing d'options
- **Affichage Rich** — `show_ssh_result()` et `show_files_result()` avec panels, tables S3, diff syntax

### Changed
- **Tests S3 consolidés** — Tous les tests S3 (CRUD, versioning, delete markers) sont désormais dans `test_service.py` (`--test files`). Les scripts externes `test_s3_files.py` et `test_s3_versioning.py` ont été supprimés
- **Credentials S3 purgés de l'historique git** — Les scripts qui contenaient des credentials S3 en dur ont été retirés de l'historique via réécriture git + gc aggressive

## [0.1.3] — 2026-03-06

### Added
- **Nouveau tool `date`** — Manipulation de dates/heures (8 opérations : now, today, diff, add, format, parse, week_number, day_of_week). Fuseaux horaires via `zoneinfo` (stdlib). Parsing flexible : ISO 8601, DD/MM/YYYY, YYYYMMDD, etc. Sorties ISO 8601. **12 tests E2E**
- **Nouveau tool `calc`** — Calculs mathématiques dans une **sandbox Python Docker** isolée (--network=none, --read-only, --cap-drop=ALL). Interface simplifiée : 1 seul param `expr` (expression Python). Modules `math` et `statistics` pré-importés. Respecte la priorité des opérations, parenthèses, fonctions math. Fallback local (SANDBOX_ENABLED=false). **12 tests E2E** (arithmétique, priorité, parenthèses, puissance, division/0, math.sqrt, math.pi, statistics.mean/median, sandbox, grands nombres, erreur syntaxe)
- **Nouveau tool `perplexity_doc`** — Documentation technique via Perplexity AI. Params `query` (technologie/librairie/API) + `context` optionnel (aspect spécifique à approfondir). System prompt orienté syntaxe, exemples de code, bonnes pratiques. Citations incluses. **3 tests E2E**

### Removed
- **`perplexity_chat` abandonné** — Le tool de conversation continue avec Perplexity a été retiré de la roadmap Phase 1

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
