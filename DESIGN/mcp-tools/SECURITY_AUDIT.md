# Audit de Sécurité — MCP Tools

> **Date** : 24 Mars 2026 (mis à jour)
> **Auditeur** : Agent Cline
> **Projet** : mcp-tools (v0.3.1)
> **Statut de l'audit** : Terminé ✅ — Revue complémentaire effectuée

## 1. Introduction et Périmètre de l'Audit

Cet audit a pour but d'analyser en profondeur les mécanismes de sécurité de la solution **MCP Tools**, qui sert de "boîte à outils" (shell, requêtes réseau, manipulation S3, etc.) pour les agents IA de l'écosystème Cloud Temple.

Le périmètre de l'audit couvre les aspects suivants :
- **Architecture Réseau et WAF** (`docker-compose.yml`, `waf/Caddyfile`).
- **Authentification et Autorisation** (`src/mcp_tools/auth/middleware.py`, `context.py`).
- **Isolation Sandbox** (`sandbox/Dockerfile`, implémentations `_run_in_sandbox`).
- **Outils sensibles** (`shell.py`, `network.py`, `http.py`, `ssh.py`, `files.py`).

---

## 2. Points Forts de la Sécurité (Défense en Profondeur)

### 2.1. Isolation par Sandboxes Docker Éphémères
L'approche de sécurité globale repose sur l'exécution des opérations sensibles (`shell`, `network`, `http`, `ssh`, `files`, `calc`) dans des conteneurs isolés et jetables (`docker run --rm`), construits depuis `alpine:3.20`. 
Les contraintes appliquées systématiquement sont excellentes et conformes aux meilleures pratiques :
- `User sandbox:sandbox` : Interdit les accès `root`.
- `--read-only` : Le système de fichiers est immuable.
- `--cap-drop=ALL` : Suppression des capacités noyau Linux (sauf `NET_RAW` explicitement ajouté pour `network` afin de permettre le `ping`).
- `--security-opt=no-new-privileges:true` : Bloque l'escalade de privilèges via setuid/setgid.
- `--memory=256m` et `--pids-limit=10` (ou 50) : Protège contre l'épuisement des ressources hôtes (fork-bombs et OOMs).
- `/tmp` monté en `tmpfs` avec options `nosuid,nodev` (et `noexec` par défaut pour l'isolation maximale).

### 2.2. Outil HTTP et Anti-SSRF Avancé
Le fichier `http.py` intègre un dispositif **anti-SSRF** très sophistiqué et efficace :
- Avant même d'instancier la sandbox, le nom d'hôte est extrait via `urlparse` et est vérifié.
- S'il s'agit d'un FQDN (nom de domaine), le service Python sur l'hôte procède à une **résolution DNS complète** (`socket.getaddrinfo`) pour interroger les IPs qui se cachent derrière le domaine.
- L'outil vérifie systématiquement que ces IPs ne tombent pas dans une plage privée/interdite (RFC 1918, `127.0.0.0/8`, `169.254.0.0/16`, etc.). Cela **bloque efficacement** les tentatives de rebinding DNS et de SSRF ciblant les métadonnées AWS/GCP (`169.254.169.254`).

### 2.3. Outils Réseau et Fichiers
- **`network.py`** (ping, traceroute, nslookup, dig) intègre une regex stricte pour empêcher l'injection de commandes shell (ex: `;&$|` bloqués dans `extra_args`).
- **`files.py`** injecte les paramètres S3 en tant que charge JSON (`json.loads(PARAMS_JSON)`) directement dans le script Python instancié dans la sandbox, éliminant ainsi le risque d'injection de code source Python. Les identifiants (`access_key`, `secret_key`) ne quittent pas la RAM du conteneur éphémère.

---

## 3. Vulnérabilités Identifiées et Recommandations

### 3.1. Contournement WAF sur l'endpoint `/mcp`
- **Analyse** : Dans `waf/Caddyfile`, la route `handle /mcp*` est transmise via `reverse_proxy` *sans* activer la directive `coraza_waf`. 
- **Risque (Faible/Moyen)** : Le serveur MCP Python doit parser lui-même les JSON reçus sans la protection des règles OWASP (ex. injection JSON, charge très volumineuse). Le choix architectural est compréhensible (compatibilité avec le flux SSE Streamable HTTP et les volumes en Base64), mais cela reporte toute la responsabilité de la validation des données sur Pydantic / FastMCP.
- **Recommandation** : S'assurer que les limites de taille de payload et les validations de format strictes sont implémentées sur l'endpoint HTTP Python de FastMCP pour éviter les attaques de déni de service (DDoS) ciblées sur cet endpoint (bien que le `rate_limit` de 60 requêtes/minute aide déjà énormément).

### 3.2. "Default Allow" si la liste `tool_ids` est vide
- **Analyse** : Dans `auth/context.py`, la logique de validation est la suivante : 
  `if tool_ids and tool_name not in tool_ids: raise ValueError(...)`
  Cela signifie que si la clé `tool_ids` est vide ou absente d'un Token, l'accès à **tous** les outils est accordé par défaut.
- **Risque (Moyen)** : En cas d'erreur de création d'un token (liste d'outils oubliée), le token hérite silencieusement des droits administrateurs complets sur les outils (ex: accès au shell, réseau, S3, etc.). Cela enfreint le principe de **moindre privilège**.
- **Recommandation** : 
  - Restreindre l'accès `default allow` aux tokens explicitement `admin`.
  - Pour les utilisateurs ayant seulement le droit `access`, imposer que la liste `tool_ids` soit peuplée avec au moins l'outil souhaité. 
  - (Ex: `if not "admin" in permissions and not tool_name in tool_ids: raise ValueError(...)`)
- **Statut** : ✅ **Corrigé v0.2.1** — Implémentation "fail-closed" dans `context.py`. Les tokens non-admin avec `tool_ids` vide sont désormais refusés.

### 3.3. Visibilité du mot de passe SSH dans l'arborescence des processus
- **Analyse** : Dans `ssh.py`, pour une authentification par mot de passe, l'option `sshpass -p {password}` est utilisée (exécutée par `shlex.quote`). 
- **Risque (Faible)** : Sous Linux, passer un secret en argument CLI le rend lisible via `/proc/[pid]/cmdline`. Bien que le conteneur soit isolé (`--network=bridge`, `user sandbox`) et éphémère, cela reste une mauvaise pratique de sécurité générale.
- **Recommandation** : Utiliser la variable d'environnement `SSHPASS` fournie par l'utilitaire `sshpass` (`export SSHPASS=mot_de_passe; sshpass -e ssh ...`) ou lire depuis un fichier temporaire monté en RAM, pour masquer ce mot de passe de l'historique et des processus.
- **Statut** : ✅ **Corrigé v0.2.1** — Utilisation de `SSHPASS` + flag `-e` dans `ssh.py`. Le mot de passe n'apparaît plus dans `/proc/[pid]/cmdline`.

### 3.4. Paramètre `network=true` du Shell affaiblissant l'isolation
- **Analyse** : Le tool `shell` inclut désormais `network=true`. Lorsque ce paramètre est activé pour télécharger des dépendances (ex: `pip install`), le flag `noexec` de `/tmp` est retiré et les limites de processus (PIDs) sont quintuplées. 
- **Risque (Moyen)** : Un attaquant (via une injection d'instructions ou une défaillance du LLM) pourrait écrire un script d'exfiltration ou un reverse-shell dans `/tmp` et l'exécuter. 
- **Recommandation** : Documenter que le paramètre `network=true` est une élévation de privilège. Limiter au maximum (au niveau des `tool_ids` / permissions) les profils capables d'utiliser un shell avec réseau. Les LLMs de profil standard devraient rester forcés sur du `network=false`.

### 3.5. Montage de `/var/run/docker.sock`
- **Analyse** : Le service `mcp-tools` mappe en lecture/écriture le socket de Docker hôte pour "Docker-out-of-Docker". 
- **Risque (Critique / Accepté)** : Toute compromission de l'applicatif Python expose directement les droits `root` de la machine hôte. Il suffit d'envoyer une requête forgée sur l'API Docker pour monter le répertoire `/` de l'hôte et prendre son contrôle.
- **Recommandation** : Le composant `mcp-tools` lui-même (qui héberge le code Python avec le module FastAPI/FastMCP) ne doit comporter aucune faille d'injection (Remote Code Execution) dans son propre code, car il tourne avec les droits Docker de la VM hôte. C'est le design choisi, mais l'hébergeur (Cloud Temple) doit en être conscient. 

### 3.6. Timing Attack sur la comparaison de la Bootstrap Key
- **Analyse** : Dans `auth/middleware.py` (ligne 67) et `admin/api.py` (ligne 91), la bootstrap key admin est comparée avec l'opérateur `==` standard de Python :
  ```python
  if token == settings.admin_bootstrap_key:
  ```
  L'opérateur `==` sur les chaînes Python s'arrête au premier caractère différent, ce qui crée une différence de temps mesurable. Un attaquant peut exploiter cette différence pour deviner la clé caractère par caractère.
- **Risque (Critique)** : Permet une attaque par canal auxiliaire (side-channel) pour extraire la clé admin. L'attaque nécessite un grand nombre de requêtes et une latence réseau faible, mais elle est théoriquement réalisable — surtout si l'attaquant est sur le même réseau ou co-hébergé.
- **Recommandation** : Remplacer `==` par `hmac.compare_digest()` dans les deux fichiers :
  ```python
  import hmac
  if hmac.compare_digest(token, settings.admin_bootstrap_key):
  ```
  `hmac.compare_digest()` effectue une comparaison en temps constant, éliminant le canal auxiliaire.
- **Statut** : ✅ **Corrigé v0.3.1** — `hmac.compare_digest()` utilisé dans `middleware.py` et `api.py`.

### 3.7. Clé Admin par Défaut sans Vérification au Démarrage
- **Analyse** : Dans `config.py`, la clé admin a une valeur par défaut en dur :
  ```python
  admin_bootstrap_key: str = "change_me_in_production"
  ```
  Si le fichier `.env` n'est pas configuré ou si la variable `ADMIN_BOOTSTRAP_KEY` n'est pas définie, le serveur démarre avec une clé publiquement connue (visible dans le code source open-source). Cette clé donne un accès **admin complet** : gestion des tokens, exécution de tous les outils, accès à la console d'administration.
- **Risque (Critique)** : Tout déploiement où la variable n'est pas explicitement modifiée est compromis dès l'instant où le serveur est accessible. Aucun avertissement n'est affiché.
- **Recommandation** : Au démarrage du serveur (`server.py`), vérifier que `admin_bootstrap_key` n'est pas la valeur par défaut. Si c'est le cas, afficher un avertissement critique sur stderr et idéalement refuser de démarrer en mode production.
- **Statut** : ✅ **Corrigé v0.3.1** — Le serveur affiche un avertissement ⚠️ CRITIQUE au démarrage si la bootstrap key n'a pas été changée.

### 3.8. Token d'authentification accepté en Query String
- **Analyse** : Dans `auth/middleware.py`, le token Bearer peut être passé en paramètre d'URL en plus du header Authorization :
  ```python
  for param in qs.split("&"):
      if param.startswith("token="):
          return param[6:]
  ```
- **Risque (Élevé)** : Les query strings sont enregistrées dans de multiples endroits :
  - **Logs serveur** (accès HTTP, WAF, reverse proxy amont)
  - **Historique du navigateur** (si utilisation depuis la console admin)
  - **Header `Referer`** envoyé aux sites tiers
  - **Proxies intermédiaires** et CDN qui loguent les URLs complètes
  Un token exfiltré de cette manière donne un accès immédiat au serveur.
- **Recommandation** : Supprimer le support du token en query string. Seul le header `Authorization: Bearer <token>` doit être accepté.
- **Statut** : ✅ **Corrigé v0.3.1** — Support query string supprimé de `middleware.py`.

### 3.9. Journal d'audit volatile (mémoire uniquement)
- **Analyse** : Dans `admin/api.py`, le journal d'audit (`_audit`) et les logs HTTP (`_logs`) sont stockés dans des listes Python en mémoire (ring buffer de 500 et 200 entrées respectivement). Aucune persistance sur disque, S3, ou syslog.
- **Risque (Moyen)** : En cas de redémarrage du conteneur (crash, mise à jour, OOM-kill), tout l'historique d'audit est perdu. Cela empêche toute investigation post-incident et rend les exigences de conformité (ISO 27001, SOC2, HDS) impossibles à satisfaire sur ce composant.
- **Recommandation** : 
  - **Court terme** : Écrire chaque entrée d'audit sur `stderr` au format JSON structuré (capturé par Docker logs → collecté par Loki/ELK/CloudWatch).
  - **Moyen terme** : Persister le journal d'audit sur S3 avec rotation (un fichier JSON par jour, rétention configurable).
- **Statut** : ✅ **Corrigé v0.3.1** — Chaque entrée d'audit est dupliquée sur `stderr` en JSON structuré pour collecte par Docker logs.

---

## 4. Conclusion Générale

L'architecture est de niveau "Entreprise". L'isolation est pensée depuis la base ("Secure by Design"), et les développements démontrent une solide compréhension des menaces classiques :
- Protection très stricte et intelligente contre la contrefaçon de requêtes (SSRF) avec les DNS bloquants.
- Emprisonnement de l'activité asynchrone dans un conteneur éphémère et impénétrable ("Throw-away environment").
- Utilisation des `tmpfs` non-exécutables.
- Protection par WAF des routes statiques.

### Historique des corrections

| §   | Vulnérabilité               | Sévérité     | Corrigé             |
| --- | --------------------------- | ------------ | ------------------- |
| 3.1 | WAF bypass `/mcp`           | Faible/Moyen | Design choice (SSE) |
| 3.2 | Default Allow tool_ids      | Moyen        | ✅ v0.2.1           |
| 3.3 | sshpass /proc visible       | Faible       | ✅ v0.2.1           |
| 3.4 | network=true isolation      | Moyen        | ✅ v0.2.1 (doc)     |
| 3.5 | docker.sock monté           | Critique     | Design choice       |
| 3.6 | Timing attack bootstrap key | Critique     | ✅ v0.3.1           |
| 3.7 | Bootstrap key par défaut    | Critique     | ✅ v0.3.1           |
| 3.8 | Token en query string       | Élevé        | ✅ v0.3.1           |
| 3.9 | Audit volatile              | Moyen        | ✅ v0.3.1           |

La solution **MCP Tools** remplit ses objectifs de sécurité hautement exigeants pour des agents d'intelligence artificielle. Les vulnérabilités identifiées lors de la revue complémentaire (timing attack, bootstrap key, query string, audit volatile) ont été corrigées dans la version 0.3.1.

***Fin du rapport d'audit***
