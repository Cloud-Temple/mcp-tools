# Données files : S3 et catalogue PostgreSQL

Statut : design et candidat d'implémentation pour #30. Qualification réelle,
revue indépendante du résultat et livraison restent à établir. Ce document
complète [ARCHITECTURE.md](ARCHITECTURE.md). Le parcours et la CI publics ne
requièrent aucun dépôt, service, schéma ou identité Mission.

## 1. Périmètre et parcours public

L'outil `files` et la CLI existants servent write → list/page → read/delete,
info, diff, versions et concat. PostgreSQL catalogue les fichiers de l'unique
profil configuré ; S3 garde seul leurs contenus. Lectures regroupées par
`metadata_batch(paths)` (1–64, ordre et doublons conservés) ; inspection par
`operation_info(operation_id)` et `reconcile(operation_id)` admin. Aucun tool
témoin ajouté. API HTTP d'administration existante appelle le même outil.

Le pilote historique S3 reste un produit public explicitement sélectionné
(`FILES_METADATA_BACKEND=s3`, défaut). PostgreSQL se choisit au démarrage ; il
refuse les overrides endpoint/credentials/bucket du caller. Aucun fallback,
double écriture d'autorité, migration, import de l'ancien stockage, purge ou
préemption des événements/tokens/hub. Les contenus historiques catalogue sont
accessibles par pins, sous les droits files courants.

## 2. Inventaire, autorité et invariants

| Donnée | Autorité | Identifiants/invariants | Bornes | Rétention |
| --- | --- | --- | --- | --- |
| Contenu | S3 versionné | clé physique UUID dédiée, VersionId non-null, SHA256/longueur attendus avant PUT | write 5M caractères/20M octets, concat 5M octets | versions conservées, aucune purge app |
| Référence actuelle | SQL refs | clé logique opaque, revision monotone, génération/operation, tombstone | pages 100/1000, curseur opaque | tombstones et générations conservés |
| Générations | SQL generations | pin/manifeste immuables, opération unique | batch 64, GET borné 20M | INSERT/SELECT seulement app |
| Intentions et journal | SQL operations/receipts | UUID avant dispatch, binding credential validé, digests ; reçus append-only | un intent actif/clé, un ID/reconcile, 64 reçus visibles par inspection | histoire originale conservée |
| Auth client | magasin tokens existant | token réellement validé, access/tool_ids/admin | cache/revocations existants | sans refonte de son autorité |
| Durabilité | moteur/politique opérateur | cluster/timeline, COMMIT propre, barrière WAL/quorum vérifiable | 4 connexions, deadlines | certificats historiques ≠ preuves fraîches |

Référence, revision/CAS et phase EFFECT_COMMITTED sont atomiques avec reçu de
publication SQL. S3 n'est pas transactionnel avec SQL : phases réservée/armée/
vérifiée précèdent leurs effets. Aucun HEAD a posteriori ne remplace l'attente
pré-PUT ; concat lit des versions SQL figées et ordonnées, vérifie leurs hashes,
assemble l'UTF-8 puis persiste hash/longueur de sortie et séparateur avant PUT.
Un PUT sans ACK ne se répète pas. Observation ultérieure compare à cette attente,
sans adopter un objet comme référence ni effacer son historique.

## 3. Droits et isolation

Auth serveur avant toute donnée/compteur : admin ou access avec tool_ids non
vide contenant files. Aucun nouveau tenant ou ACL par client_name : les droits
files legacy restent la règle. Journal réservé au credential d'origine ou
admin ; binding interne `tools-token-v1:<hash du token validé>` immuable,
jamais construit depuis un argument caller ni exposé. Révocation puis nom
client réutilisé ne donne pas accès au journal de l'ancien credential. Bootstrap
sans binding réel : ses opérations sont consultables par admin seulement.

Base dédiée par domaine ; owner NOLOGIN non administrateur, installateur
éphémère distinct, app sans membership/DDL/TEMP/CREATE/TRUNCATE/GRANT option,
backup/restore distincts. App peut SELECT/INSERT generations et receipts,
SELECT/INSERT/UPDATE refs et operations, SELECT schema_version. Trigger protège
intent/binding/identités/confirmation et transitions irréversibles de garde.
PUBLIC retiré du domaine ; defaults limités. Isolation des autres bases par
HBA/DBaaS sous provisionneur, sans modification des voisins depuis Tools.
Readiness inspecte version/checksum, rôle/cible, owners, grants effectifs,
membership, droits PUBLIC et garde SQL. Installation refuse schema existant
inconnu : contrôle explicite plutôt qu'initialisation vide.

## 4. Stockage et déploiement

Deux topologies publiques : PG/S3 propres ou PG externe partagé avec base et
rôles distincts par domaine, mêmes droits/API. Provider MCP Vault public peut
être local autonome ou externe explicitement configuré. Ni cluster commun,
checkout privé, package Mission, CI privée, ni accès SQL inter-base requis.

Credentials direct via service/passfile libpq privés : mode public légitime,
hors profil de qualification Vault-first. Dans ce profil, Vault-first est
obligatoire partout, dans les deux topologies : runtime, probes, provisionnement,
installation/grants/init, backup, restore, rollback. Provider exact MCP Vault
`secret_read(vault_id,path)` ; HTTPS/CA exacts, Bearer en fichier privé, secret
custom SQL dans **coffre Tools propre**, scopes app/install/backup/restore
séparés. Ne pas utiliser le mount réservé aux propres credentials SQL du
fournisseur Vault. Chaque connexion/job réautorise Vault, aucun credential
périmé/direct caché de secours, aucun secret en argv/Git/image/journal.

Bootstrap sans cycle : opérateur rétablit fournisseur Vault/clefs/auth par sa
chaîne publique autonome, accès de récupération détenus hors base Tools morte ;
il autorise les seuls scopes du domaine, puis provisionne SQL. App n'a ni
montage installateur/backup ni droit bootstrap DDL. Service/passfile temporaire
opérateur est un transport après Vault, pas un deuxième provider.

Configuration détaillée : [README PostgreSQL](../../docs/postgres/README.md).
Driver psycopg pur Python + libpq système, TLS verify-full/CA/SAN exacts,
target_session_attrs read-write, multi-host service libpq possible. Connect 2s,
statement 2s, lock 1s, idle transaction 3s, total tool ≤60s ; S3 4 admissions
conservées jusqu'à fin réelle des threads même après réponse perdue. Versioning
S3 requis avant app, signature Dell ECS s3 ou s3v4 explicite selon provider.

Lifecycle ASGI : startup probe bornée, ready seulement sur dépendances/contrat
valides, 503 sinon ; `/health` liveness distincte. Readiness TTL ≤5s et deadline
2s ; parcours files revérifie sa disponibilité, aucune DDL app ou substitution
privilégiée sur erreur. Aucun état vide fabriqué sur panne.

## 5. Concurrence et erreurs

Réservation durable de clé/UUID/attempt/génération et attente de revision avant
PUT. CONTENT_DISPATCH_ARMED confirmé avant S3 ; CONTENT_VERIFIED puis
PUBLICATION_ARMED confirmés avant publication. Chaque publisher prend verrou
opération **puis** référence en READ COMMITTED et relit UUID/génération/intent,
phase et publication_allowed ; garde + CAS + référence + effet dans même
transaction. Aucun booléen local ancien n'autorise une publication.

`reconcile` révoque sous ce même verrou avant conclure absence ; true→false
uniquement, UUID de révocation conservé. Il produit du WAL avec reçu de barrière,
exige COMMIT propre et quorum/local selon profil, puis relit garde/effet sous
nouveau verrou. Original déjà verrouillé : attendre ou pending, puis observer
son COMMIT/rollback réel. Original retardé avant verrou : après fence il voit
false et ne peut publier, même si CAS reste valable. Deadline/conflit/epoch ou
ACK de fence perdus = pending, jamais absence finale. Nouvelle invocation peut
établir une **nouvelle barrière**, sans réenvoyer COMMIT ni réarmer la tentative.

Absent publié + fence durable → clôture explicite `not_published`, sans succès
de mutation. Réservation libérée seulement avec garde false et preuve complète ;
COMMIT de clôture inconnu reste pending. Réconciliation ne publie jamais un
remplacement et ne fait aucun PUT/DELETE. Nouvelle mutation exige nouvel ID
explicite et nouvelle intention sous droits courants. Restart ne redispatche
rien. Les tentatives/générations anciennes ne sont pas purgées.

COMMIT local peut être visible malgré ACK inconnu : list/read/info servent cette
référence avec durability unverified, pas une ancienne version fictive. Delete
publie tombstone SQL puis marker S3 sur sa clé génération unique, sans supprimer
VersionId ; marker incertain = incomplete. Réconciliation peut observer le
marker réel, sans reconstruire son ACK ni réémettre DELETE.

`initial_confirmation` SQL immutable commence unknown ; reçus d'ACK serveur
append-only séparés. Seule réponse initiale avec COMMIT propre et preuve fraîche
porte remote_result confirmed ; processus neuf/duplicate ID renvoie inspection,
jamais ACK original reconstruit. Lecture status ok signifie lecture réussie.
Les inspections sont pending/unverified sans nouvelle barrière ; certificat
historique ne vaut jamais garantie permanente.

Profil local explicite : fsync on, synchronous_commit on, primaire writable,
barrière avec ACK propre + relecture, durabilité locale seule. Profil répliqué :
remote_apply, `ANY k (roster fini)` exact, cluster/timeline fixés, au moins k
membres distincts streaming/quorum/replay_lsn couvrant borne flush conservatrice.
Identités vérifiées rôle/address/cert DN/slot, pas application_name seul. Probe
opérateur SECURITY DEFINER étroite, search_path fixe, EXECUTE PUBLIC retiré,
aucun pg_monitor app. HBA/certificates/slots exclusifs à prouver réellement par
opérateur ; DBaaS sans preuve suffisante = indisponible, aucun downgrade local.

## 6. Backup, restauration et rollback

Recette opérateur logique pg_dump/pg_restore domaine seul ; jobs publics
`files_backup`, manifests distincts rôles/grants/defaults/pins/intents, private
0600/0700, hashes streaming. Archive chiffrée/rétention par opérateur, jamais
copie métier concurrente runtime ; pas de backup app automatique ni PITR/HA
implicite. Jobs ≤600s, pg tools ≤120s, générations ≤10000/opérations actives ≤64 ;
dépasser budget échoue en incomplet, préserver les artefacts pour inspection.

Arrêter écrivains et admins de mutation, exporter point quiescent catalogue et
pins/markers exacts, retenir versions S3 de toute archive. Vault/clefs/auth
avant SQL de reprise ; provisionneur crée base/volume **neufs**, restaure rôles,
ownership, membership/defaults/grants du domaine uniquement, collision = arrêt.
Un dump de base ne restaure pas les rôles globaux ; aucun pg_dumpall/mot de passe
ni modification des voisins. Import sous identité restore autorisée, retirer
accès temporaires et vérifier app/PUBLIC/probes avant app neuve. Rétablir auth
actuelle hors dump : ne pas ressusciter token révoqué pour son nom historique.

Pins S3 doivent survivre exactement ; manque non restaurable = arrêt, aucune
remap/migration cachée. Point restauré avant fence invalide ancienne preuve :
anciens écrivains/requêtes arrêtés, restart sans redispatch, reconcile explicite
révoque/fence dans nouvel epoch avant clôture. Rollback avec sources préservées,
cible cohérente/raccord explicite, jamais fallback. Voisin B et grants/pins
relus avant/après par ses identités ; lecture finale indépendante avant cleanup.
RTO/RPO non mesurés ; aucune qualification exécutée à ce stade.

## 7. Qualification et livraison

Recette publique `tests/postgres_files/public_recipe.py` : MCP/CLI/HTTP réels,
write/list/read/delete/restart/pages, denied sans counts, batch borné, concat
pins, UUID divergent, révocation/nom réutilisé, incertitudes S3/SQL/COMMIT,
entrelacement PUBLICATION_ARMED→attente pré-lock→fence→arrivée tardive→restart,
variants verrou détenu/rollback/fence ACK perdu/quorum/epoch, restore neuf et
rollback/voisins. Harnais séparé sans nouvelle API produit. Admission opérateur
avant moteurs/builds/faults ; CI locale pertinente groupée à diff stable puis
revue complète indépendante en session séparée. Après findings : checks affectés
et delta review, sans répéter toute campagne sans raison.

| Épreuve | État |
| --- | --- |
| Contrôles statiques/contrats locaux | À consigner sur candidat stabilisé |
| PostgreSQL/S3/Vault réels, restart/fautes/rollback | À exécuter après admission |
| État final persistant, voisins, secrets, droits | Relecture indépendante requise avant cleanup |
| Revue résultat et publication | Non réalisées ; aucun merge/deploy/release autorisé |
