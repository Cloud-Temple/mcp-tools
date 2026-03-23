# Audit des Tests E2E — MCP Tools

> **Version** : v0.2.0  
> **Date** : 2026-03-23  
> **Script** : `scripts/test_service.py`  
> **Transport** : MCP Streamable HTTP (`/mcp`)  
> **Total** : ~108 tests (14 catégories)

## Lancement

```bash
# Recette complète (build + start + tests + stop)
python3 scripts/test_service.py

# Test d'une catégorie spécifique (serveur déjà lancé)
python3 scripts/test_service.py --test shell --no-docker

# Mode verbose (affiche les réponses JSON)
python3 scripts/test_service.py -v

# Tests disponibles :
#   connectivity, auth, shell, network, http, perplexity, perplexity_doc,
#   date, calc, ssh, files, token, admin, waf
```

---

## 1. Connectivité (3 tests)

Vérifie que le service est accessible et répond correctement.

| # | Test | Vérifie | Critère de succès |
|---|------|---------|-------------------|
| 1a | REST /health | Endpoint health REST direct | HTTP 200 |
| 1b | MCP system_health | Protocole MCP Streamable HTTP fonctionnel | `status: "ok"` |
| 1c | MCP system_about | Introspection du serveur (version, liste tools) | `status: "ok"`, tools_count > 0 |

**Pourquoi** : Si la connectivité échoue, tous les autres tests sont ignorés. Vérifie que la chaîne complète WAF → MCP fonctionne.

---

## 2. Authentification (3 tests)

Vérifie le contrôle d'accès Bearer token.

| # | Test | Vérifie | Critère de succès |
|---|------|---------|-------------------|
| 2a | POST /mcp sans token | Requête sans Authorization header | HTTP 401 |
| 2b | POST /mcp mauvais token | Token invalide | HTTP 401 |
| 2c | MCP avec token admin | Token admin (bootstrap key) valide | Session MCP initialisée |

**Pourquoi** : Valide que le `AuthMiddleware` bloque correctement les accès non autorisés. Tout appel MCP sans token valide doit être refusé.

---

## 3. Outil shell — Sandbox Docker (16 tests)

L'outil le plus sensible : exécution de commandes arbitraires dans un conteneur isolé.

### Tests de base (10 tests)

| # | Test | Vérifie | Critère de succès |
|---|------|---------|-------------------|
| 3a | shell echo | Exécution de commande basique | stdout contient `hello_mcp_tools` |
| 3b | shell sandbox active | Conteneur Docker éphémère utilisé | `sandbox: true` dans la réponse |
| 3c | shell user non-root | Exécution en tant qu'utilisateur sandbox | `whoami` retourne `sandbox` |
| 3d | shell réseau isolé | `--network=none` empêche tout accès réseau | `curl` échoue, `NETWORK_BLOCKED` affiché |
| 3e | shell param sh | Shell `sh` fonctionne | `status: "success"` |
| 3f | shell python3 calcul | Shell `python3` avec calcul | stdout = `1267650600228229401496703205376` |
| 3g | shell node JSON | Shell `node` avec sortie JSON | stdout contient `{"ok":true}` |
| 3h | shell invalide refusé | Shell non autorisé (`ruby`) bloqué | `status: "error"`, message "non autorisé" |
| 3i | shell erreur (exit ≠ 0) | Code retour non-zéro propagé | `returncode ≠ 0` |
| 3j | shell timeout | Commande longue interrompue | `status: "error"`, message "timeout" |

**Pourquoi** : Vérifie l'isolation de sécurité (non-root, pas de réseau, sandbox Docker), le support multi-shell, la gestion des erreurs et des timeouts.

### Tests packages Python pré-installés (3 tests)

| # | Test | Vérifie | Critère de succès |
|---|------|---------|-------------------|
| 3k | numpy pré-installé | Import numpy sans réseau | `status: "success"`, version affichée |
| 3l | pandas pré-installé | Import pandas sans réseau | `status: "success"`, version affichée |
| 3m | requests pré-installé | Import requests sans réseau | `status: "success"`, version affichée |

**Pourquoi** : L'image sandbox inclut des packages Python courants pour que les LLMs puissent les utiliser sans avoir besoin d'accès réseau. Vérifie que `OPENBLAS_NUM_THREADS=1` résout le conflit entre OpenBLAS et `--pids-limit=10`.

### Tests paramètre network (3 tests)

| # | Test | Vérifie | Critère de succès |
|---|------|---------|-------------------|
| 3n | network=true curl | `--network=bridge` permet l'accès HTTP | curl retourne HTTP 200 |
| 3o | network=true pip install | `pip install --user` fonctionne | Package cowsay installé + importé (`PIP_OK`) |
| 3p | network=false régression | Le défaut reste isolé | curl échoue, `STILL_BLOCKED` affiché |

**Pourquoi** : Le paramètre `network` permet aux LLMs de télécharger des modules Python. Le test de régression garantit que le comportement par défaut (isolé) n'est pas impacté.

**Matrice sécurité sandbox shell** :

| Paramètre | network=false (défaut) | network=true |
|-----------|----------------------|--------------|
| `--network` | none | bridge + DNS |
| `--read-only` | ✅ | ✅ |
| `--cap-drop` | ALL | ALL |
| `--user` | sandbox (non-root) | sandbox (non-root) |
| `--no-new-privileges` | ✅ | ✅ |
| `--pids-limit` | 10 | 50 |
| tmpfs /tmp | 32m + noexec | 256m (pas noexec) |
| tmpfs ~/.local | — | 128m |
| tmpfs ~/.cache | — | 64m |
| `OPENBLAS_NUM_THREADS` | 1 | 1 |
| `PIP_BREAK_SYSTEM_PACKAGES` | — | 1 |

---

## 4. Outil network — Diagnostic réseau (10 tests)

Ping, traceroute, nslookup, dig dans un conteneur sandbox avec réseau bridge.

| # | Test | Vérifie | Critère de succès |
|---|------|---------|-------------------|
| 4a | ping 8.8.8.8 | Ping IP publique fonctionne | `status: "success"` |
| 4b | sandbox active | Conteneur Docker utilisé | `sandbox: true` |
| 4c | nslookup google.com | Résolution DNS | `status: "success"` |
| 4d | dig google.com | Interrogation DNS avancée | `status: "success"` |
| 4e | traceroute 8.8.8.8 | Trace réseau | stdout non vide |
| 4f | opération invalide | Validation des opérations | `status: "error"` |
| 4g | RFC 1918 — 127.0.0.1 | Loopback bloqué | `status: "error"`, "privée" |
| 4h | RFC 1918 — 10.0.0.1 | Réseau privé classe A bloqué | `status: "error"`, "privée" |
| 4i | RFC 1918 — 192.168.1.1 | Réseau privé classe C bloqué | `status: "error"`, "privée" |
| 4j | injection commande | Host malicieux (`8.8.8.8; echo hacked`) bloqué | `status: "error"`, "invalide" |

**Pourquoi** : Vérifie que l'outil réseau fonctionne pour les diagnostics légitimes tout en bloquant les accès aux réseaux privés (anti-pivoting) et les injections de commande.

---

## 5. Outil http — Client HTTP/REST (10 tests)

Requêtes HTTP via curl dans un conteneur sandbox avec anti-SSRF.

| # | Test | Vérifie | Critère de succès |
|---|------|---------|-------------------|
| 5a | GET httpbin.org | Requête GET simple | HTTP 200 |
| 5b | sandbox active | Conteneur Docker utilisé | `sandbox: true` |
| 5c | POST JSON | Corps JSON envoyé et reçu | HTTP 200, body contient les données |
| 5d | POST texte brut | Corps texte brut | HTTP 200 |
| 5e | HTTP 404 = success | Erreur HTTP ≠ erreur transport | `status: "success"`, `status_code: 404` |
| 5f | méthode invalide | INVALID refusé | `status: "error"` |
| 5g | SSRF 127.0.0.1 | Anti-SSRF loopback | `status: "error"`, "privée" |
| 5h | SSRF 10.0.0.1 | Anti-SSRF réseau privé | `status: "error"`, "privée" |
| 5i | SSRF 169.254.169.254 | Anti-SSRF metadata cloud (AWS/GCP) | `status: "error"`, "privée" |
| 5j | auth bearer | Header Authorization propagé | Token visible dans la réponse |

**Pourquoi** : L'anti-SSRF est critique — un LLM ne doit pas pouvoir atteindre les services internes, le metadata cloud (169.254.169.254), ou le loopback. La validation se fait côté serveur **avant** l'exécution en sandbox (résolution DNS + vérification IP).

---

## 6. Outil perplexity_search (2 tests, skip si pas de clé API)

| # | Test | Vérifie | Critère de succès |
|---|------|---------|-------------------|
| 6a | perplexity_search (brief) | Recherche IA fonctionnelle | Contenu > 0 chars |
| 6b | perplexity citations | Citations retournées | Array de citations non vide |

---

## 6b. Outil perplexity_doc (3 tests, skip si pas de clé API)

| # | Test | Vérifie | Critère de succès |
|---|------|---------|-------------------|
| 6b-a | doc (query seul) | Documentation technique | Contenu > 0 chars |
| 6b-b | doc (query + context) | Contexte pris en compte | query et context reflétés |
| 6b-c | citations | Citations retournées | Array non vide |

---

## 7. Outil date (12 tests)

Manipulation de dates/heures, fuseaux horaires, parsing.

| # | Test | Vérifie | Critère de succès |
|---|------|---------|-------------------|
| 7a | now (UTC) | Date/heure courante | `datetime` présent |
| 7b | now (Europe/Paris) | Fuseau horaire | Offset +01:00 ou +02:00 |
| 7c | today | Date du jour | `date` présent |
| 7d | parse ISO | Parsing ISO 8601 | `2026-03-06` dans datetime |
| 7e | parse DD/MM/YYYY | Parsing format européen | `2026` dans datetime |
| 7f | format strftime | Formatage date | result = `06/03/2026` |
| 7g | add +10 jours | Addition de jours | `2026-03-16` dans result |
| 7h | diff (64 jours) | Différence entre dates | `diff_days = 64` |
| 7i | week_number | Numéro de semaine ISO | Entier retourné |
| 7j | day_of_week | Jour de la semaine | `Friday` (EN + FR) |
| 7k | opération invalide | Validation | `status: "error"` |
| 7l | timezone invalide | Validation fuseau | `status: "error"` |

---

## 8. Outil calc (12 tests)

Évaluation d'expressions mathématiques dans un conteneur sandbox Python.

| # | Test | Vérifie | Critère de succès |
|---|------|---------|-------------------|
| 8a | 17.5 + 42.3 | Arithmétique décimale | `result = 59.8` |
| 8b | 2 + 3 * 4 | Priorité des opérations | `result = 14` |
| 8c | parenthèses complexes | Groupement | `result = 13.0` |
| 8d | 2 ** 10 | Puissance | `result = 1024` |
| 8e | 42 / 0 | Division par zéro | `status: "error"` |
| 8f | math.sqrt + abs | Modules math pré-importés | `result = 17.0` |
| 8g | 2 * π arrondi | Constantes math | `result = 6.2832` |
| 8h | statistics.mean | Module statistics pré-importé | `result = 30` |
| 8i | statistics.median | Médiane | `result = 3.5` |
| 8j | sandbox active | Conteneur Docker utilisé | `sandbox: true` |
| 8k | 2¹⁰⁰ (grand nombre) | Pas d'overflow Python | Nombre exact |
| 8l | erreur syntaxe | Expression invalide | `status: "error"` |

---

## 9. Outil ssh (10 tests)

Validation des paramètres et sécurité SSH (pas de serveur SSH de test).

| # | Test | Vérifie | Critère de succès |
|---|------|---------|-------------------|
| 9a | opération invalide | Validation opérations | `status: "error"` |
| 9b | injection host | `host; rm -rf /` bloqué | `status: "error"`, "invalide" |
| 9c | username invalide | `user;hack` bloqué | `status: "error"`, "invalide" |
| 9d | auth_type invalide | Type non supporté | `status: "error"` |
| 9e | password requis | Auth password sans password | `status: "error"` |
| 9f | private_key requis | Auth key sans clé | `status: "error"` |
| 9g | exec sans commande | Paramètre manquant | `status: "error"` |
| 9h | download sans remote_path | Paramètre manquant | `status: "error"` |
| 9i | upload sans contenu | Paramètre manquant | `status: "error"` |
| 9j | status host inaccessible | Sandbox fonctionne (RFC 5737) | `status: "error"`, sandbox=true |

**Pourquoi** : Sans serveur SSH de test, on valide la validation des paramètres et la protection contre les injections. Le test 9j prouve que la sandbox SSH fonctionne (conteneur lancé).

---

## 10. Outil files — S3 Dell ECS (jusqu'à 23 tests, skip si S3 non configuré)

Cycle complet CRUD sur S3 avec versioning.

| # | Test | Vérifie | Critère de succès |
|---|------|---------|-------------------|
| 10a-d | Validation params | Opération/path/content/path2 requis | `status: "error"` |
| 10e | Write v1 | Écriture S3 | `status: "success"` |
| 10f | Sandbox active | Conteneur Docker | `sandbox: true` |
| 10g | Read v1 | Lecture cohérente | Contenu identique |
| 10h | Info (HEAD) | Métadonnées S3 | size > 0, etag présent |
| 10i | List | Listing prefix | count ≥ 1 |
| 10j | Write v2 (overwrite) | Écrasement | `status: "success"` |
| 10k | Read v2 | Modification vérifiée | Contient "MODIFIED" |
| 10l | Diff | Comparaison 2 fichiers | `identical: false` |
| 10m | Versions | Listing versions S3 | ≥ 2 versions |
| 10n | Read v1 par version_id | Accès version spécifique | Contenu v1 |
| 10o | Read latest = v2 | Version courante | Contient "MODIFIED" |
| 10p-s | Delete + cleanup | Suppression + vérification | count = 0 après cleanup |
| 10q-r | Delete markers | Soft delete S3 + accès v1 | Markers présents, v1 accessible |

**Pourquoi** : Valide la compatibilité Dell ECS (SigV2/SigV4 hybride) et le cycle complet de vie des objets S3 incluant le versioning.

---

## 11. Outil token — Gestion tokens S3 (12 tests, skip si S3 non configuré)

Cycle CRUD complet + isolation tool_ids.

| # | Test | Vérifie | Critère de succès |
|---|------|---------|-------------------|
| 11a | opération invalide | Validation | `status: "error"` |
| 11b | create sans name | Paramètre requis | `status: "error"` |
| 11c | create token | Création avec tool_ids=[date,calc] | Token retourné |
| 11d | doublon refusé | Unicité client_name | `status: "error"` |
| 11e | list | Token trouvé dans la liste | found=true |
| 11f | info | Métadonnées du token | client_name correct |
| 11g | auth → date (autorisé) | Token client accède à date | `status: "success"` |
| 11h | auth → shell (refusé) | Token client bloqué sur shell | `status: "error"`, "refusé" |
| 11i | revoke | Révocation | `status: "success"` |
| 11j | auth après revoke | Token révoqué refusé | HTTP 401 |
| 11k | list vide | Plus de tokens après revoke | count = 0 |
| 11l | info non trouvé | Token inexistant | `status: "error"` |

**Pourquoi** : Teste le modèle de sécurité par token — chaque token a un `tool_ids` qui restreint les outils accessibles. Le test **11g→11h** est critique : même token, outil autorisé (date) vs interdit (shell).

---

## 12. Console Admin (jusqu'à 16 tests)

Sécurité de l'interface web d'administration.

| # | Test | Vérifie | Critère de succès |
|---|------|---------|-------------------|
| 12a | GET /admin (HTML) | Page servie | HTTP 200, contient "MCP Tools" |
| 12b-c | CSS/JS accessibles | Assets statiques | HTTP 200 |
| 12d | Path traversal | `../../.env` bloqué | HTTP 403 ou 404 |
| 12e | Fichier inexistant | 404 correct | HTTP 404 |
| 12f-i | API sans token | 4 endpoints → 401 | HTTP 401 |
| 12j | API mauvais token | Token invalide | HTTP 401 |
| 12k | Non-admin → health OK | Lecture autorisée | HTTP 200 |
| 12k2 | Non-admin → tokens 403 | Tokens admin-only | HTTP 403 |
| 12k3 | Non-admin → logs 403 | Logs admin-only | HTTP 403 |
| 12k4 | Non-admin → tools filtrés | Filtrage par tool_ids | Seul "date" visible |
| 12l | Admin → health | Accès complet | HTTP 200, tools_count > 0 |
| 12m | Admin → tools (enums) | Paramètres avec enums | Enum operation présent |
| 12n | Admin → tools/run | Exécution depuis admin | HTTP 200, result présent |
| 12o | Admin → logs | Journal d'activité | count > 0 |
| 12p | Route inconnue | 404 API | HTTP 404 |

**Pourquoi** : L'admin console est un vecteur d'attaque — on vérifie path traversal, séparation des rôles (admin vs non-admin), et que les tokens non-admin ne voient que les outils autorisés par leur `tool_ids`.

---

## 13. WAF Coraza — OWASP CRS (6 tests)

Tests du Web Application Firewall (Caddy + Coraza + OWASP Core Rule Set).

| # | Test | Vérifie | Critère de succès |
|---|------|---------|-------------------|
| 13a | Requête normale | WAF laisse passer | HTTP 200 |
| 13b | XSS dans URL | `<script>alert(1)</script>` bloqué | HTTP 403 |
| 13c | SQL injection URL | `1 OR 1=1--` bloqué | HTTP 403 |
| 13d | Path traversal | `../../etc/passwd` bloqué | HTTP 401 ou 403 |
| 13e | Shellshock User-Agent | `() { :; };` bloqué | HTTP 403 |
| 13f | XSS via Referer | `<script>` dans header | HTTP 403 |

**Pourquoi** : Défense en profondeur. Le WAF bloque les attaques OWASP Top 10 **avant** qu'elles n'atteignent le service MCP. La route `/mcp` est exclue du WAF (incompatible avec SSE streaming), mais `/admin/*` et `/health` sont protégées.

---

## Résumé par catégorie de risque

### 🔴 Sécurité critique
- **Auth** (3 tests) : Contrôle d'accès Bearer token
- **Shell isolation** (3d, 3p) : `--network=none` par défaut
- **Anti-SSRF** (5g-5i) : Blocage IPs privées + metadata cloud
- **RFC 1918** (4g-4j) : Blocage réseaux privés + anti-injection
- **Token tool_ids** (11g-11h) : Isolation des outils par token
- **WAF** (13b-13f) : Protection OWASP Top 10

### 🟡 Isolation sandbox
- **Non-root** (3c) : Utilisateur sandbox
- **Sandbox active** (3b, 4b, 5b, 8j) : Conteneurs Docker éphémères
- **Pids-limit** (implicite via 3k-3l) : OpenBLAS limité à 1 thread
- **Read-only filesystem** (implicite) : Écriture seulement dans tmpfs

### 🟢 Fonctionnel
- **Multi-shell** (3e-3g) : bash, sh, python3, node
- **Packages Python** (3k-3m) : numpy, pandas, requests pré-installés
- **Network toggle** (3n-3o) : pip install avec network=true
- **S3 CRUD** (10e-10t) : Cycle complet avec versioning
- **Admin RBAC** (12k-12k4) : Séparation admin/non-admin
