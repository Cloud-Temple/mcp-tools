# Coordination Mission #846 dans Tools

Ce document couvre trois tranches : les dépendances Files d'une Mission, la
rétention Access des calls Mission avec le retrait coordonné, et les journaux
techniques. Les sources 843 et 845 sont
composées par fusion normale dans cette branche, pas copiées. Aucun nouvel
endpoint public ni d'administration.

## Dépendances Files d'une Mission

Problème corrigé. Une lecture seule par une Mission B (outil `files`, opération
`read` ou `diff`, sous délégation hub) ne crée aucune opération Files. La
consultation historique `/internal/hub/tools-files` ne trouvait donc rien et
répondait `reference_state: unavailable`, même pour un fichier toujours vivant.

Ce que fait le code, si `FILES_MISSION_DEPENDENCIES_ENABLED=true` (fermé par
défaut, exige l'extension 845) :

- `FilesService.read_operations` insère une ligne `mission_file_dependencies`
  par génération servie, avant tout accès S3, et la relit après COMMIT. Valeurs
  prises dans la ligne servie et dans les claims de la délégation, jamais dans les
  arguments de l'outil. `list`, `info`, `metadata_batch` et `versions` n'en
  créent pas. Sans délégation (standalone), rien ne change.
- Le trigger owner `guard_file_dependency` prend `refs` en `FOR SHARE`, puis le
  verrou de pin 845 en mode partagé (`pg_advisory_xact_lock_shared`), puis
  vérifie `generation_visible`. Deux lectures du même fichier ne se sérialisent
  pas ; le GC, la publication et les intentions 845 prennent la même clé en mode
  exclusif et restent en conflit avec une acquisition. Les lignes d'un `diff`
  sont insérées dans l'ordre `(path, generation)`, celui de `guard_source_intent`.
  Une insertion refusée ou un COMMIT inconnu fait échouer la lecture sans octet.
- `published()` résout un call par une seule source : l'opération publiée 843,
  ou une dépendance active du même call et de la même opération d'activité, dans
  le scope exact tenant, Mission et agent racine des claims, sur une génération
  encore visible. Zéro source, deux sources ou deux dépendances (cas `diff`)
  donnent `unavailable`.
- Une suppression publique d'un chemin qui a une dépendance active est refusée
  à trois endroits. `prepare` refuse sans verrou. La transaction de réservation
  refait le contrôle sous `refs FOR UPDATE` : une acquisition commitée pendant
  l'attente du verrou y est vue, et le ROLLBACK ne laisse aucune opération. La
  publication refait le contrôle sous `refs FOR UPDATE` : si une dépendance a été
  commitée entre réservation et publication, la même transaction révoque et ferme
  l'opération (reçus `dependency_refusal` puis `dependency_refusal_closed`, phase
  laissée à `PUBLICATION_ARMED`, rien de publié). La réponse est
  `status: error`, `code: mission_dependency_active`, `effect_state: not_published`,
  `reconciliation_state: not_required`. Elle ne porte `operation_id` que pour ce
  refus de publication, seul cas où une opération existe ; un refus de `prepare`
  ou de réservation n'écrit rien et ne rend aucun identifiant. `operation_info`,
  ou le rejeu du même `operation_id`, relit l'opération close et rend la même
  réponse (`dependency_refusal_closed` présent, opération close et révoquée, sans
  reçu `publication`). Le trigger `guard_dependency_retirement`
  sur `refs` reste l'autorité finale. Une écriture qui remplace la version
  courante reste permise : l'ancienne génération reste visible et la lecture
  historique de B continue.
- `FileRecovery.referenced` compte les dépendances actives comme racines avant
  tout armement de suppression physique, une racine par génération
  (`SELECT DISTINCT`), quel que soit le nombre de Missions qui la lisent.
  L'argument `dependencies` n'a pas de défaut.

Rôles. L'app a `SELECT, INSERT` sur la table, ni `UPDATE` ni `DELETE`. La
maintenance a `SELECT` et `UPDATE(state, retired_at, revision)`. Le trigger
`guard_dependency_history` interdit `DELETE` et toute transition autre que
`active` vers `retired`.

Commandes opérateur, scope Mission exact, au plus 1000 lignes par passage,
résultat privé 0600 dans `--intent-dir` :

```sh
python -m src.mcp_tools.storage.files_recovery_cli dependencies \
  --profile /private/profile.json --app-role tools_files_app --intent-dir /private/i1 \
  --tenant-id tenant --mission-id mis_A --root-agent-id ag_A --batch 1000
python -m src.mcp_tools.storage.files_recovery_cli retire-dependencies \
  --profile /private/profile.json --app-role tools_files_app --intent-dir /private/i2 \
  --tenant-id tenant --mission-id mis_A --root-agent-id ag_A --batch 1000
```

`dependencies` est en lecture seule et ne rend ni la clé physique ni le contenu.
Sur stdout, les deux commandes n'impriment qu'un résumé (`rows_count`, `complete`) ;
les lignes call, génération et Mission ne sont que dans `result.json` (0600).
`retire-dependencies` ne touche que les lignes actives de ce scope ; une autre
Mission garde les siennes. `complete: false` demande un nouveau passage.

Activation. L'installeur et `check_schema` exigent une capture PG17 revue.
`ddl_sha256` (`files_recovery_contract.ddl_sha256`) couvre le DDL de base
(`files_schema.DDL`), le DDL 845 et, pour `files_dependency_contract.json`, le
DDL 846. Les deux captures du dépôt sortent d'un même run PG17 sur la
composition base (avec `operations.origin_call_id` de #843), 845 et 846, produit
deux fois à l'identique : `files_recovery_contract.json` (SHA-256 `21f6d22a…`) et
`files_dependency_contract.json` (`bc5f8681…`). La capture 845 précédente datait
d'avant `origin_call_id` : douze colonnes de `operations` y étaient décalées d'un
`attnum`. Le test `test_committed_recovery_capture_matches_the_current_base_schema`
verrouille la quatrième colonne. Une modification d'un des trois DDL change
l'empreinte : la capture concernée refuse alors avant tout SQL et doit être
refaite par le même kit. Ordre des verrous par point d'appel : docstring de
`files_dependency_schema.py`.

Condition d'ouverture. `FILES_MISSION_DEPENDENCIES_ENABLED` ne doit pas être
activé sans la partie Access. Aujourd'hui un call d'activité garde son échéance
d'admission (8760 h) au lieu de fin de Mission plus 365 jours, et aucun retrait
automatique des dépendances n'existe à la clôture : un fichier lu par une
Mission reste non supprimable tant que `retire-dependencies` n'est pas passé sur
son scope, et la consultation historique peut survivre au call qui la justifie
ou disparaître avant lui.

L'échéance des calls d'activité, le retrait coordonné et le reçu Mission sont
décrits dans la section « Rétention Access d'une Mission ».

### Limites connues (P3)

P3-1, interblocage acquisition contre intention 845. L'acquisition prend `refs`
en `FOR SHARE` puis le verrou de pin. `guard_source_intent` (845, sur l'INSERT
d'une opération `concat` ou d'une suppression publique) prend le verrou de pin
puis `refs FOR UPDATE`. Sur la même génération l'ordre est inversé, donc une
lecture Mission et un `concat` ou une suppression concurrents peuvent
s'interbloquer. PostgreSQL détecte l'interblocage ou `lock_timeout` (1000 ms en
profil) l'arrête : une des deux transactions est annulée, rien n'est servi ni
publié de ce côté, et l'appelant relance. L'origine est 845 : `publish` prend
`refs` puis le pin, `guard_source_intent` prend le pin puis `refs`. Aligner
`guard_source_intent` sur l'ordre de `publish` corrigerait les deux, dans une
évolution 845. Le tri Python par `(path, generation)` suit l'ordre des octets ;
`guard_source_intent` trie avec la collation de la base. Les deux ne coïncident
que pour des chemins ASCII sous collation `C`, ce qui ne change rien au cas
d'une seule génération.

P3-5, refus par le trigger seul. Si le trigger `guard_dependency_retirement`
refuse un jour l'UPDATE de `refs` alors que le contrôle explicite de `publish` est
passé, l'instruction échoue, la transaction est annulée et l'opération reste en
`PUBLICATION_ARMED`, `closed=false`, jusqu'à un `reconcile` admin. Sous
`refs FOR UPDATE` aucune acquisition ne peut aboutir entre ce contrôle et l'UPDATE
(elle attend `refs FOR SHARE`), donc ce cas n'a pas de chemin connu. Avant le
correctif de publication c'était le cas normal d'une course lecture contre
suppression ; le run PG17 r1 l'a montré (T10b bloqué sur `one_active_path`). Le
run r2 (`j0/run846-dep-r2`, source `ea8f8bc`) passe T7 à T10c sur PG17, S3 en
mémoire.

## Rétention Access d'une Mission (holds846)

Problème corrigé. Avec le schéma Access 31 seul, `admit_mission` fixe
`expires_at = admission + 8760 h` et quatre lectures filtrent sur cette date.
Une Mission de plus d'un an perdait son historique Tools avant sa propre fin, et
`purge_expired` supprimait un call encore utile à une dépendance Files.

### Installation

`ACCESS_MISSION_RETENTION_ENABLED=true` fait installer l'extension
`postgres_retention_846.py` par `postgres_operator install`, dans la transaction du
DDL v1, sur un domaine neuf seulement. Le DDL v1 et son `CHECKSUM` ne changent pas.
Un domaine v1 existant ne reçoit pas l'extension : il faut un domaine neuf.
L'extension n'a de sens que face à un domaine Mission `coordination_required=true`.

- Marqueur `retention_846_version` (`coordination_required=true`), immuable.
- Cinq routines de remplacement : `activity_page_846`, `hub_activity_page_846`,
  `hub_file_calls_846`, `hub_files_confirm_846`, `purge_expired_846`. Les routines
  v1 remplacées restent dans le schéma et ne sont accordées à personne.
- `verify` contrôle le marqueur dans les deux sens, les grants du profil, l'absence
  de droit direct sur les trois tables 846, la projection catalogue figée
  (`CATALOG` : triggers d'`activity_calls` avec `tgenabled`, contraintes, index,
  `prosecdef`, `proconfig`) et le `prosrc` de chaque fonction 846. Un trigger
  désactivé est refusé.
- Profil et domaine discordants : le store échoue fermé. `/ready` répond
  `Access SQL grants unavailable`, chaque appel métier rend une indisponibilité
  sans diagnostic. Le store lit aussi `retention_846_contract()` à chaque connexion.
- `FILES_MISSION_DEPENDENCIES_ENABLED=true` avec `ACCESS_BACKEND=postgres` exige
  `ACCESS_MISSION_RETENTION_ENABLED=true`.

### Sémantique

Un call `mission` n'a plus d'échéance par date. Il reste lisible sous les droits
courants et n'est jamais purgé par `purge_expired_846`, qui ne touche que les calls
`technical` (720 h) et les credentials expirés. Les échéances de credential, de
mapping et de JWT refusent toujours : une rétention prolongée n'autorise aucun accès.
`activity_page_846`, `hub_activity_page_846` et `hub_files_confirm_846` rendent
`expires_at` NULL pour un call `mission`, jamais une date passée.

Le retrait passe par une claim Mission vérifiée et seulement si
`clock_timestamp() > max(expires_at, retain_until)` pour chaque call du scope.

### Retrait : cinq étapes

```
python -m src.mcp_tools.retention_846 <étape> --operation-id UUID \
  --state-dir DIR_PRIVE --proof-file PREUVE_0600 --files-app-role ROLE [--batch N]
```

Profil : `ACCESS_PG_ROLE` = rôle de maintenance Access, `FILES_PG_ROLE` = rôle de
maintenance Files, `ACCESS_RETENTION_ISSUER`, `ACCESS_RETENTION_JWKS_URL` (même
origine HTTPS), `ACCESS_RETENTION_AUDIENCE` (audience `tools` du domaine Mission).

1. `access-prepare` : verrou du scope, `FOR UPDATE` sur ses calls, refus si un call
   du scope a un autre root (root vide : il faut zéro call), registre `prepared`.
   Inéligible : rien n'est écrit, `not_yet_eligible` et la date. Effet : admissions
   et lectures hub du scope refusées.
2. `files-prepare` : registre `mission_dependency_closures`. Toute nouvelle
   acquisition du scope est refusée. Root vide : zéro ligne de dépendance sur
   (tenant, mission) exigée, registre scellé à zéro.
3. `access-retire` : lots de 500 au plus. Le dernier lot scelle le registre dans la
   même transaction (compteurs, empreintes).
4. `files-retire` : refusé tant que `access-retire` n'est pas scellé. Lots de 1000
   au plus, le dernier scelle.
5. `receipt` : relit les deux registres scellés sous verrou, écrit
   `receipt.private.json` et `envelope.json` en 0600. `composed_at` vient du
   `sealed_at` en base : une réémission donne le même reçu.

Chaque étape vérifie la preuve (callback `claim-check`), passe son échéance de
30 s aux routines SQL, revérifie la preuve avant le COMMIT. COMMIT sans ACK :
`<étape>.unknown.json`, code non nul, toute étape suivante refusée jusqu'à
`reconcile`. `reconcile` (sans preuve) prend le même verrou de scope, lit les deux
registres et donne `next_step`. Un registre présent prouve le COMMIT ; absent ou
resté à l'état précédent, l'étape n'a pas commité et se relance avec le même
`operation_id`.

Le reçu porte trois références agrégées, toujours présentes, même à zéro :
`tools_activity_calls`, `tools_activity_events`, `tools_file_dependencies`.
`id` vaut `sha256:` suivi du SHA-256 des identifiants retirés triés en
`COLLATE "C"` et joints par `\n` (UUID pour Access, `call_id:generation:revision`
pour Files). `revision` porte le nombre d'éléments. C'est un détournement assumé du
champ : l'enveloppe Mission `9ded160c` ne change pas et Tools consomme 3
références du budget partagé de 1000.

### Absence de claim (option A, décision FGE en attente)

Sans claim, les calls `mission` restent sans limite de durée : identifiants
d'acteur et de binding, tenant, `mission_id`, root, hash de requête. Aucun contenu.
Requête de suivi, à lancer par l'owner en lecture seule, à la place d'un
diagnostic `retention-status` reporté :

```sql
SELECT c.tenant_id, c.mission_id, count(*) calls, min(c.created_at) oldest,
       min(c.created_at) < clock_timestamp() - interval '8760 hours' older_than_one_year
FROM tools_access.activity_calls c
WHERE c.category = 'mission' AND NOT EXISTS (SELECT 1 FROM tools_access.mission_retirements_846 r
  WHERE r.tenant_id = c.tenant_id AND r.mission_id = c.mission_id)
GROUP BY 1, 2 ORDER BY oldest;
```

Chemin d'effacement hors claim (demande de suppression, Mission perdue). Il
contourne la preuve, donc il passe par l'owner sous contrôle de changement, sur un
scope exact, dans une seule transaction :

```sql
BEGIN;
ALTER TABLE tools_access.activity_calls DISABLE TRIGGER retention_846_delete;
DELETE FROM tools_access.activity_events e USING tools_access.activity_calls c
 WHERE e.call_id = c.id AND c.tenant_id = :tenant AND c.mission_id = :mission;
DELETE FROM tools_access.activity_calls WHERE tenant_id = :tenant AND mission_id = :mission;
ALTER TABLE tools_access.activity_calls ENABLE TRIGGER retention_846_delete;
COMMIT;
```

`verify` refuse le domaine si le trigger reste désactivé. Aucun registre n'est
écrit : une admission ultérieure sur ce scope reste possible, ce qui convient à
un effacement, pas à une clôture. Aucun reçu Mission n'est produit.

### Ce qui reste conservé

Les registres scellés et `mission_retired_refs_846` ne contiennent que des
identifiants. `mission_file_dependencies.path` reste conservé avec les lignes
retirées : c'est un nom de fichier choisi par l'utilisateur, pas un identifiant
opaque. Leur durée de conservation n'est pas bornée par ce lot (P3).

## Journaux techniques

Aucun nouveau pouvoir SQL app pour cette partie.

`TECHNICAL_LOG_DIRECTORY` active un sink privé de diagnostics pendant le lifespan
ASGI. Le dossier doit être absolu, propriété de l'UID courant et mode0700.
Le point existant `record_activity` continue son buffer/stderr et transmet au
sink seulement date UTC, niveau, nom de logger et code d'événement. Arguments,
exceptions, détails, chemins Files, credentials et corps ne sont pas persistés.
Un nouveau fichier `tools-technical-AAAA-MM-JJ.log` mode0600 est ouvert chaque jour.
L'arrêt ASGI retire et ferme le handler. Sans configuration, aucun fichier créé.

Le propriétaire exécute périodiquement, dans son propre domaine :

```sh
python -m src.mcp_tools.technical_logs \
  --directory /private/tools-diagnostics --days 30 --batch 100
```

Seuls les fichiers réguliers privés portant ce préfixe et une date valide,
antérieurs aux30journées UTC complètes, sont retirés. Aucun parcours récursif.
Au plus1000 suppressions par passage ; `complete:false` signale qu'un autre
passage opérateur sera nécessaire. Les liens, autres noms, journaux d'audit,
segment du jour et permissions étrangères restent préservés. L'inventaire
dépassant10000entrées reste incomplet et ne supprime rien. Le retrait est fsync.

Ce réglage ne donne aucune politique à la collecte stdout/stderr de la plateforme :
l'opérateur de déploiement doit inventorier et configurer son sink technique30j
distinctement. Aucun volume Docker ou collecteur global n'est nettoyé ici.
L'activité métier PG reste annuelle, l'activité technique PG720h ; ni lecture,
ni maintenance, ni journalisation ne prolonge un droit ou un usage catalogue.

Tests locaux : filesystem réel avec horloge UTC contrôlée, jour29/31/audit,
symlinks/hardlinks, budget/fsync, canaries de payload, rotation et lifecycle ASGI
réel avec hook `record_activity`. Aucune qualification flotte ni ancien banc
réutilisé. Les deux E402 de `server.py` existent identiquement dans le main livré ;
le nouveau code passe Ruff complet, le fichier serveur est contrôlé avec cette
seule exception héritée, sans changement de son ordre d'initialisation MCP.
