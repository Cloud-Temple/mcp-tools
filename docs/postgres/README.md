# Installer le catalogue files PostgreSQL

Candidat non qualifié sur moteurs à ce stade. Le design est dans
[DATA_DESIGN](../../DESIGN/mcp-tools/DATA_DESIGN.md), les épreuves requises dans
`tests/postgres_files/public_recipe.py`. Infrastructure propre ou base externe
partagée : même code/API/droits, aucun composant Mission requis.

## Installation publique

Python 3.11, libpq système (`libpq5` sur Debian), PostgreSQL 17/18 et client
pg_dump/pg_restore compatible pour jobs de reprise, S3 HTTPS versionné. Installer
`requirements.lock`, puis le driver universel figé séparément :

```sh
python3 -m pip install -r requirements.lock
python3 -m pip install --no-deps --require-hashes -r requirements-postgres.lock
python3 -m pip check
```

Le Dockerfile embarque libpq5 et ce driver, sans bibliothèque PostgreSQL privée.
Build/lock complet image/CI à qualifier séparément ; aucun build exécuté ici.
Modules : `PYTHONPATH=src python3 -m mcp_tools.storage.files_bootstrap`, ou
`python3 -m src.mcp_tools.storage.files_bootstrap` depuis racine.

## Choisir autorité et credentials

`FILES_METADATA_BACKEND=s3` conserve seul le pilote historique et ses overrides.
`postgres` sélectionne seul ce catalogue, refuse tout override de profil dans
files et n'importe pas les objets historiques. `S3_*` existants désignent les
credentials du profil contenu ; magasin de tokens existant conserve sa propre
autorité. Préfixe génération `FILES_S3_PREFIX=files-generations/` dédié, sans
chevauchement avec tokens/voisins ; `FILES_S3_DATA_SIGNATURE=s3` Dell ECS,
`s3v4` pour provider choisi supportant SigV4. Provisionner versioning avant app.

| Réglage | Usage/défaut |
| --- | --- |
| FILES_CREDENTIALS_MODE | direct public ou vault explicite |
| FILES_PG_SERVICE | tools-app, service libpq direct |
| FILES_PG_DATABASE / ROLE / OWNER / SCHEMA | tools / tools_files_app / tools_files_owner / tools_files |
| FILES_PG_CA_FILE | CA vérifiée, requise, TLS verify-full |
| FILES_PG_SYSTEM_IDENTIFIER / TIMELINE | identité réelle relevée par opérateur, obligatoire / 1 |
| FILES_DURABILITY | local ou remote_apply, aucun fallback |
| FILES_CONNECT_TIMEOUT | 2s (1–10), readiness reste 2s global |
| FILES_QUORUM / REPLICATION_ROSTER | k=1 / JSON fini pour remote_apply |
| FILES_VAULT_URL / ID / PATH | fournisseur MCP Vault HTTPS, coffre Tools propre, secret SQL du job |
| FILES_VAULT_TOKEN_FILE / CA_FILE | Bearer privé 0600, CA fournisseur exacte |

Direct : service/passfile app privés 0600, CA en lecture seule. Secrets hors
.env suivi/argv/image. Service peut définir plusieurs hosts/ports libpq ;
TLS verify-full et target_session_attrs read-write sont imposés par le code.
Ce mode demeure légitime et autonome ; il est hors profil Vault-first.

Vault : aucun service/passfile direct de secours. Fournisseur **MCP Vault**
public, API `secret_read(vault_id,path)`, réponse status ok avec `data`. Secret
custom Tools : `host`, `port`, `dbname`, `user`, `password`, valeurs DB/rôle
conformes au job. Créer un coffre Tools propre et des paths distincts `sql/app`,
`sql/install`, `sql/backup`, `sql/restore` sous scopes de service distincts.
Ce sont des exemples Tools, pas des paramètres génériques factory. Ne pointer
**jamais** vers mount technique réservé aux propres credentials SQL de Vault.
Version publique fournisseur/scopes/auth/reprise à épingler et qualifier avec
son propriétaire, sans adaptation de Vault depuis Tools. Tout refus/timeout
ferme connexion/probe/job SQL, aucun cache ou fallback credential.

Profil de qualification Vault-first : ce provider obligatoire avant **tout**
SQL runtime/opérateur/probes/installation/grants/init/backup/restore, standalone
et externe. Opérateur restaure d'abord Vault/clefs/auth ; accès récupération
hors base Tools à restaurer pour éviter cycle. Transport passfile temporaire
de pg tools seulement après Vault, retiré à fin job. Chaque job/connexion
réautorise, aucun ancien fichier réutilisé après refus.

## Provisionnement et grants séparés

Sous provisionneur autorisé par Vault pour ce profil, créer base dédiée et
rôles : owner NOLOGIN sans droits superuser/CREATEDB/CREATEROLE/REPLICATION/
BYPASSRLS, installateur LOGIN temporaire avec SET ROLE owner, app LOGIN sans
membership ; backup/restore propres. Aucun secret provisionneur installé dans
app. HBA/DBaaS doit refuser app dans autres bases, identités voisines et SET ROLE.
Retirer CONNECT/CREATE/TEMP PUBLIC de base dédiée, retirer CREATE public, donner
CONNECT app explicitement ; aucune modification des bases voisines depuis Tools.
Membership temporaire installateur retirée après installation complète.
Pour l'import logique, accorder au rôle restore `SET TRUE, INHERIT FALSE`
sur l'owner configuré et CONNECT uniquement sur la cible neuve. `pg_restore`
fait SET ROLE vers `FILES_PG_OWNER` dans cette connexion ; propriétaires et
ACL de l'archive restent conservés. Vérifier le refus CONNECT vers la source
avant et après l'import, puis retirer la membership temporaire. Une cible
de qualification arrêtée doit être mise hors service (`ALLOW_CONNECTIONS false`)
et ne conserver aucune session avant le retour au service source.
Avant premier bootstrap, provisionneur accorde au job opérateur les deux probes
natives `pg_control_system()`/`pg_control_checkpoint()` nécessaires à vérifier
system identifier/timeline, sans les donner directement à app. Identité et
cluster attendus sont vérifiés aussi pour chaque job backup/restore ; configurer
`FILES_PG_ROLE` et son service/scope au rôle exact de ce job. Refus DBaaS de ces
probes = prérequis opérateur non disponible, aucune cible acceptée à l'aveugle.

Exemple opérateur (identités/domaines à vérifier, jamais copier mots de passe) :

```sql
-- Dans la base Tools provisionnée exclusivement pour ce domaine.
REVOKE ALL ON DATABASE tools FROM PUBLIC;
GRANT CONNECT ON DATABASE tools TO tools_files_app;
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
-- Identités provisionnées séparément, app ne possède pas la base.
```

Installer sous scope installateur/config job, `FILES_PG_ROLE` désigne le rôle
SQL attendu de ce job dans les deux modes, `--app-role` reste le rôle runtime cible :

```sh
FILES_PG_ROLE=tools_files_install PYTHONPATH=src python3 -m mcp_tools.storage.files_bootstrap \
  --operator-service tools-install --app-role tools_files_app --schema tools_files --apply
```

`--apply` refuse schema existant ; aucune répétition implicite en cas de COMMIT
inconnu. Une fois schema créé, provisionneur installe probe étroite
[infrastructure.sql](infrastructure.sql) ou équivalent DBaaS conforme, search_path
fixe/EXECUTE PUBLIC retiré ; elle est autorisée aux identités de jobs nécessaires
et app seulement. Cet exemple cible tools_files ; adapter au schéma opérateur
explicitement, aucune exécution automatique app. Owner reçoit seulement probes
et stats nécessaires, jamais app/pg_monitor. Puis `--check`, sous le même
opérateur avant retrait de sa membership/LOGIN, vérifie checksum/grants du rôle
`--app-role` et politique/cluster dans une transaction READ ONLY. Identité,
base et cluster sont contrôlés avant tout changement de rôle. Si l'opérateur
n'a pas USAGE sur le schéma mais possède SET owner, le contrôle fait
`SET LOCAL ROLE owner` avec cette seule autorité existante ; sinon il garde ses
droits actuels. Le search_path local place pg_catalog avant le schéma ; le rôle
local disparaît à la fin de la transaction. Un opérateur qui a déjà USAGE garde
ses grants explicites, notamment EXECUTE sur une probe DBaaS ; cela ne promet
aucun accès supplémentaire si ses autres droits manquent. Aucun grant
USAGE/SELECT compensatoire à l'installateur n'est nécessaire pour le chemin
NOINHERIT/SET owner. Après succès du check, retirer membership et LOGIN
temporaires, puis lancer app sous ses propres credentials et exiger `/ready`
200. `/health` n'est pas cette preuve.

remote_apply : renseigner `FILES_REPLICATION_ROSTER` tableau d'objets
`id,name,role,address,slot,dn`, membres distincts, standby_names `ANY k (noms)`
exact, rôles/certs/HBA/slots exclusifs vérifiés. La probe expose seulement ces
identités. Un application_name correct ne suffit pas. Sans preuve opérateur
HBA/cert/slot et quorum replay_lsn, profil non qualifié et readiness fermée
sur preuves manquantes. local reste durabilité locale explicite, aucune HA.

## Parcours et reprise

CLI : `files --catalog write -p exemple -c contenu` génère et affiche UUID
avant appel ; `--operation-id` fixe la corrélation, retry = inspection sans
mutation. `list --cursor`, `metadata_batch --source`, `operation_info` et
`reconcile --operation-id` utilisent le même tool. `--expected-revision` CAS
facultatif. Les clients doivent afficher incomplete/unknown/unverified/pending,
jamais traduire ligne SQL présente en ACK de mutation reconstruite.

Recette logique opérateur : `files_backup export|import --quiesced --archive
<répertoire privé>` ; export crée dossier nouveau 0700 et dump/manifests 0600,
conserve les pins et opérations actives, SHA256 streaming. Chiffrer archive,
retenir versions/markers S3 et chaîne auth Vault séparée. Quiesced est une
assertion opérateur, pas une API qui arrête les writers automatiquement.

Avant import, restaurer Vault/auth, créer **base/volume neufs**, rétablir les
rôles/ownership/defaults/grants sous provisionneur autorisé ; le dump ne fournit
pas les rôles globaux, aucune collision corrigée au détriment d'un voisin.
Import vérifie archive/pins/rôles et refuse schema déjà présent, ne fait aucun
DROP/recreate/migration. Rétablir scopes/probes HBA, effectuer `--check` sous le
rôle restore, puis retirer sa membership/LOGIN temporaires ; contrôler app
readiness et droits/auth actuels avant raccord. Le provider S3
doit préserver VersionId exact ; sinon reprise arrêtée sans réécriture pins.

Pour une copie logique aux identités distinctes, `import --project-roles
--app-role <application-cible>` exige un export récent avec empreinte de structure.
Configurer `FILES_PG_OWNER` et `FILES_PG_ROLE` pour owner/installer cible : les trois
identités doivent différer de celles du manifeste Source. L'installer reçoit
uniquement membership owner cible `INHERIT FALSE, SET TRUE`, sans admin option ni
CONNECT sur d'autres bases. Owner NOLOGIN, application sans membership/privilèges
élevés ; owner sans membership explicite et sans default ACL préexistante.
Seul son membership implicite `pg_database_owner`, limité à la base courante,
est admis ([contrat PostgreSQL17](https://www.postgresql.org/docs/17/predefined-roles.html)). Aucun droit
Source n'est accordé à la copie. Provisionner les probes
PG contrôle de l'owner/installer dans la cible avant import, jamais à l'application.
Le binaire utilise `--no-owner --no-acl`, puis la recette compare colonnes,
contraintes, indexes, triggers et définitions des deux fonctions du domaine,
projette les seuls grants applicatifs du contrat, retire PUBLIC et neutralise le
default global EXECUTE PUBLIC. Chaque grantee/grantor des schémas, tables et
fonctions ainsi que les defaults finaux est vérifié. Tout objet inattendu ou divergence arrête la recette ; la
copie partielle reste hors service, sans DROP/replay automatique. Retirer ensuite
membership, LOGIN et badge installer sous provisionneur avant raccordement public.
L'auth S3 actuelle et les versions épinglées restent inchangées ; cette option
n'effectue ni restauration de tokens ni PITR.

Backup de base seulement ≠ révocations auth restaurées : conserver l'autorité
tokens actuelle et chaîne Vault. Reprise antérieure à fence : anciens writers
arrêtés, reconcile neuf explicite avant clôture, aucun redispatch. Voisin B
relu par ses propres identités avant/après. Rollback et lecture finale indépendante
avant cleanup selon QUALIFICATION. RTO/RPO non mesurés, pas de PITR/HA implicite.

Après un delete dont le tombstone SQL est publié mais dont le marker S3 n'est
pas confirmé, `reconcile` admin ferme la réservation du chemin après sa fence
durable. Il consigne `delete_marker_unobserved` et `absence_not_proven=true` si
le marker ne peut pas être observé. Le tombstone SQL fait autorité ; aucune
absence physique S3 n'est déduite, aucun DELETE, purge ou republication n'est
réémis. Les versions historiques restent conservées et lisibles par leur pin.
Une nouvelle écriture peut ensuite utiliser ce chemin sans reconstruire l'ACK
de la suppression initiale. Une nouvelle inspection peut observer un marker
apparu plus tard ; elle ne relance aucune mutation S3.
