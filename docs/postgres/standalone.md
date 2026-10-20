# Déployer Tools avec PostgreSQL local ou externe

Profil neuf uniquement : même code/image Tools, schémas/API/droits et fournisseurs
de secrets dans toutes les topologies. S3 conserve les contenus/versions, PG les
catalogues et accès. Aucune migration, runtime DDL, nouvelle authentification ou
suppression de Vault/OpenBao. Hub et extensions Mission restent désactivés.

Qualification locale du **20/10/2026** sur le code
[`48a79768587a3e5233527663f1048d4213bb20c1`](https://github.com/Cloud-Temple/mcp-tools/tree/48a79768587a3e5233527663f1048d4213bb20c1) :
les six parcours #45 PG/S3/Vault sont exécutés avec succès. Un complément de
service Python/externe partagé qualifie FILES direct + ACCESS Vault (#46).
La [matrice et ses limites](#qualification-locale-du-20102026) ci-dessous
séparent ces preuves des contrôles logiciels. Les livraisons historiques [#30/PR37](https://github.com/Cloud-Temple/mcp-tools/pull/37)
et [#31/PR38](https://github.com/Cloud-Temple/mcp-tools/pull/38) restent distinctes :
app #30 b7a06ced/imagee3b34dc7 et opérateur83b7e7f ; merge11ef86ed. #31 candidat37d3b6b,
merge268a0e8d, avec chaîne hub qualifiée séparément. Elles ne prouvent ni ce
Compose ni une HA/PITR d'instance unique, et ne sont pas réattribuées au candidat.

## Choisir les noms TLS et les secrets avant toute installation

| Parcours | Hôte du secret app et ACCESS_PG_HOSTS | SAN serveur | Profil opérateur |
| --- | --- | --- | --- |
| Compose/local | `postgresql` | DNS `postgresql` | Opérateur hôte vers `127.0.0.1` (SAN IP) ; source vue par PG mesurée, généralement gateway bridge, autorisée explicitement en HBA |
| Python/local | `127.0.0.1` | IP `127.0.0.1` | Même destination loopback publiée ; source PG mesurée du bridge, pas loopback du conteneur ; aucun `localhost` implicite |
| Compose/externe dédié | DNS réellement résolu depuis le conteneur | Ce DNS exact | DNS réellement résolu par le poste opérateur |
| Python/externe dédié | DNS du service PG depuis Python | Ce DNS exact | Même règle d'identité, pas de socket de secours |
| Compose/externe partagé | DNS autorisé du PG, base/rôles Tools propres | Ce DNS exact | Droits limités au nouveau domaine ; voisin séparé |
| Python/externe partagé | DNS autorisé depuis Python | Ce DNS exact | Refus CONNECT/SET ROLE vers les voisins vérifiés |

Les noms externes sont ceux de votre cible ; `pg-tools.example.invalid` est un
exemple non routable, pas un endpoint à utiliser. Pour local, le certificat
généré couvre `postgresql`, `localhost` et `127.0.0.1`, mais les secrets sélectionnent
**exactement** les hôtes de leur cellule. Ne pas mettre `localhost` dans un secret
destiné au conteneur : il désignerait ce conteneur. Pour le même rôle SQL,
plusieurs paths Vault peuvent décrire les endpoints Compose/Python en conservant
le même mot de passe géré par Vault. Des rôles ou mots de passe différents par
cible neuve restent des identités distinctes ; ne pas les recopier entre clusters.

ACCESS exige le port entier5432. Le PG interne et la publication locale loopback
utilisent5432 ; aucun nouveau flag de port n'est introduit. Si ce port est occupé
sur l'hôte ou si le service externe impose un autre port, signaler cette
restriction avant de lancer : ne pas changer le provider ni contourner TLS/Vault.

## Matériel et scopes opérateur

Installer les dépendances publiques du [guide FILES](README.md#installation-publique)
dans un environnement privé. Tous les jobs utilisent MCP Vault HTTPS avant SQL,
avec token privé et CA explicitement configurés. Vault doit déjà être disponible
et déverrouillé selon ses procédures ; ce CLI ne crée pas de coffre ni de secrets.
Chaque secret custom expose `host`, entier`port=5432`, `dbname`, `user`, `password`.
Pas de mount technique SQL interne de Vault, ni password dans un profil, argv ou
variable PGPASSWORD. Les mots de passe sont générés dans l'autorité existante :
32–256 caractères ASCII imprimables sans espaces. Les secrets ne sont pas saisis
dans les commandes de ce guide.

Ce préparateur privilégié tout-Vault exige un processus sans variables PG
ambiantes, y compris les sélecteurs FILES ; il refuse avant provider/SQL si elles
sont présentes non vides (`PGSERVICE` est refusé même vide). Cela ne change pas
la coexistence du runtime/opérateur ACCESS #46. Lancer les commandes de
préparation dans un processus isolé, par exemple
`env -i PATH="$PATH" LANG=C /operator/venv/bin/python scripts/prepare_postgres.py ...`,
avec profils et chemins absolus. Les workers produit reçoivent eux-mêmes un
environnement minimal, jamais une modification de l'environnement partagé.

`scripts/prepare_postgres.py` est un opérateur produit hors runtime. Il prépare
uniquement les noms canoniques `tools_files_*`/`tools_access_*`, une base Tools
neuve (nom réglable) et `tools_files`/`tools_access`. Pour des noms de rôles/schémas
différents, conserver les procédures détaillées existantes et les faire vérifier
explicitement ; ce CLI ne transforme pas un domaine existant.

| Identité/scope | Secret lu par le job | Droits et durée |
| --- | --- | --- |
| Provisionneur `tools_prepare` local, ou identité externe séparée | Ses propres profils `postgres` puis base Tools | Créer base/rôles neufs, accorder/reprendre memberships, probes contrôle et pg_read_all_stats au seul owner FILES. Capacité temporaire, jamais fournie à l'app. |
| Chaque app/install/maintenance/backup/restore | Son propre path et bearer | Job `role-verifier` calcule un SCRAM privé ; aucun droit de lire les secrets des autres rôles. |
| FILES install / ACCESS install | Leur propre secret SQL et scope | SET ROLE owner temporaire, installation/vérification ; NOLOGIN et membership/CONNECT retirés ensuite. |
| Apps FILES / ACCESS | Chacun son secret et bearer runtime | Seulement les droits app des procédures produit, pas de membership privilégiée. |
| ACCESS maintenance | Son secret propre | Routines maintenance existantes seulement. |
| FILES backup / restore / maintenance | Secrets et identités distincts | Backup lecture du domaine seulement ; restore sans CONNECT à la Source, droits temporaires à préparer sur cible neuve. Maintenance recovery non activée par ce profil. |

Un provisionneur externe doit disposer des délégations nécessaires aux probes et
grants décrits, pas seulement CREATEDB. Vérifier ces prérequis avant de commencer ;
les GRANT USAGE/SELECT/EXECUTE du backup sont exécutés sous son identité courante,
hors SET ROLE owner. Un simple membership owner INHERIT FALSE, SET TRUE ne suffit
pas à ces GRANT : l'autorité courante doit pouvoir les déléguer. Le provisionneur
local tools_prepare est SUPERUSER ; cela ne qualifie pas un provisionneur externe
non superuser. Aucun élargissement automatique ne remplace un prérequis manquant.
Si ces prérequis manquent, arrêter sans accorder ces droits à l'app pour débloquer. En cas
de refus découvert après un effet partiel, préserver le marqueur et inspecter.
HBA et rôles des bases voisines
ne sont jamais modifiés par cet opérateur. Les privilèges transitoires du
provisionneur sur les nouveaux owners sont retirés après les jobs.
Le nom `tools_prepare` est réservé à l'amorçage local de cette instance neuve.
Son `install` exige `--close-local-provisioner` : après confirmation des cinq
jobs produit et retrait des memberships, CONNECT explicite sur Tools est retiré
et le dernier SQL passe ce rôle `NOLOGIN`, puis ferme la session. Le rôle
d'amorçage reste SUPERUSER mais ne peut plus ouvrir de connexion ; aucun secret
ni droit privilégié ne passe aux apps. Travailler sous verrou opérateur exclusif,
sans autre session de ce rôle : NOLOGIN ne termine pas une session déjà ouverte.
La réactivation éventuelle relève d'une procédure DBA locale autorisée et auditée,
jamais d'une relance automatique du CLI ni d'un fallback. En externe, employer
une identité séparée, omettre ce flag : son LOGIN et ses droits globaux ne sont
pas modifiés. Les sélections incohérentes sont refusées avant Vault et effets.

Créer un fichier JSON0600 **par job**, contenant exactement ces clés et aucun
mot de passe (exemple à adapter pour un rôle app Compose/local) :

```json
{
  "database": "tools", "user": "tools_files_app", "hosts": "postgresql",
  "pg_ca_file": "/operator/pki/ca.crt",
  "vault_url": "https://vault.example.invalid", "vault_id": "tools",
  "vault_path": "sql/files-app/compose-local",
  "vault_token_file": "/operator/scopes/files-app.token",
  "vault_ca_file": "/operator/trust/vault-ca.pem"
}
```

Tous les chemins CA/credential sont absolus. Le profil du provisionneur initial
porte database`postgres`, user`tools_prepare`, host`127.0.0.1`. Son profil cible
porte la nouvelle base, même rôle et endpoints. Les profils installateurs
portent leurs propres rôles et hôtes opérateur, pas les bearers app. Les deux
profils runtime doivent partager base/endpoints/CA PG et bundle CA Vault ; un
bundle contenant les autorités requises peut être préparé par l'opérateur.

## Préparer un PG local et les identités

Exemples à exécuter uniquement sur le domaine neuf autorisé ; les répertoires
`/operator/...` doivent exister, être privés0700 et appartenir à l'identité du job.
Charger d'abord les images PG17 et Tools approuvées, **épinglées par digest**,
puis relever le UID réel postgres et le UID réel mcp de ces images.
Ils ne sont pas déduits d'une valeur999 ou
d'un tag. Ne pas présenter les UID de tests Python comme ceux des conteneurs.
Si UID_PG diffère de l'UID du job de préparation, celui-ci doit disposer de
`CAP_CHOWN` Linux effective (y compris s'il est root). Le script vérifie cette
capacité avant toute création exclusive de mot de passe ou PKI ; une plateforme
où cette capacité ne peut pas être vérifiée est refusée. Exécuter ce seul job
initial dans un contexte opérateur explicitement habilité, jamais l'app avec
ce privilège. Le propriétaire est posé par `fchown` sur le nouveau descripteur
avant d'y écrire le secret. Un refus filesystem retire uniquement cette sortie
incomplète créée par le job ; un fichier préexistant n'est ni adopté ni effacé.
Une panne ultérieure de PKI peut laisser des matériaux partiels : les préserver
et inspecter, sans prétendre reprendre automatiquement ni écraser la CA.

Préparer le réseau canonique `mcp-tools-network` sous la procédure opérateur,
avant de générer HBA. Inspecter sa configuration (`docker network inspect
mcp-tools-network`) et relever l'adresse source **vue par PG** du poste opérateur
sur le chemin publié. Avec un bridge Linux, c'est généralement sa gateway, et
non `127.0.0.1` du conteneur. La valeur doit être mesurée pour la cible ; ne pas
copier une gateway d'exemple, adopter un réseau tiers ou calculer un fallback.
Avant `provision`, confirmer ce chemin dans les journaux/probes TLS du PG neuf ;
si la source diffère, arrêter et faire valider une nouvelle HBA explicite.
Le paramètre `--operator-cidr` est obligatoire pour `hba`, répétable, et accepte
uniquement un hôte IPv4 canonique `/32` ou IPv6 `/128`. Fournir chaque source
mesurée nécessaire, y compris un loopback seulement si le job utilise réellement
ce chemin. Les réseaux larges, valeurs vides/invalides et doublons sont refusés,
sans `samenet`, `trust`, auto-détection ou règle admin universelle.

```sh
python scripts/prepare_postgres.py certificates --cert-dir /operator/pki --server-uid UID_PG
python scripts/prepare_postgres.py hba --database tools \
  --operator-cidr CIDR_SOURCE_OPERATEUR_MESURE --output /operator/pki/pg_hba.conf
python scripts/prepare_postgres.py initial-password --profile /operator/profiles/provision-postgres.json \
  --server-uid UID_PG --output /operator/pki/initial-password
```

Le fichier initial contient uniquement le secret du provisionneur et appartient
au UID PG0600 ; il n'est jamais monté dans Tools. Fournir dans un fichier privé
les paramètres `TOOLS_POSTGRES_IMAGE` (PG17 **épinglé par digest**),
`TOOLS_PG_SERVER_CERT`, `TOOLS_PG_SERVER_KEY`, `TOOLS_PG_INITIAL_PASSWORD_FILE` et
`TOOLS_PG_HBA_FILE`. Le profil local exige TLS/SCRAM : seuls les CIDR opérateur
explicites accèdent comme `tools_prepare` à `postgres` et Tools. Les règles app
restent limitées à Tools et aux huit rôles canoniques, sans provisionneur dans
leurs règles larges ; les autres connexions sont rejetées. L'accès socket local
du provisionneur exige aussi SCRAM et sera fermé par NOLOGIN après installation.

```sh
docker compose --env-file /operator/local.env -f compose.postgres-local.yml up -d postgresql
python scripts/prepare_postgres.py inspect --profile /operator/profiles/provision-postgres.json
```

Ce fichier Compose autonome lance **PG seul** pour Python. En externe, sauter la
création PKI/serveur et utiliser le PG TLS existant autorisé ; `inspect` reste
nécessaire. Conserver system_identifier et timeline observés, pas des constantes.
En externe dédié ou partagé, ne pas transposer l'hypothèse de gateway Docker :
le DBA configure TLS/HBA pour les sources réelles et délégations de cette cible,
sans régénérer sa HBA ni modifier ses voisins avec le profil local.

Sous chacun des huit scopes LOGIN du tableau, exécuter le job suivant avec son
profil et remettre **seulement** le fichier SCRAM privé au provisionneur :

```sh
python scripts/prepare_postgres.py role-verifier --profile /operator/profiles/ROLE.json \
  --output /operator/verifiers/ROLE.json
```

`ROLE` est exactement l'un des huit noms LOGIN du tableau ; les deux owners
NOLOGIN n'ont pas de mot de passe. La remise des vérificateurs conserve0600 et
la confidentialité ; ils restent des données sensibles. Le provisionneur n'a
pas besoin des droits Vault de lecture des huit mots de passe. PBKDF2/HMAC sont
calculés côté client ([SCRAM-SHA-256](https://www.rfc-editor.org/rfc/rfc7677.html)) ;
seul le vérificateur SCRAM atteint CREATE ROLE PASSWORD, jamais le plaintext.
Les journaux SQL contenant des vérificateurs restent réservés aux opérateurs.

```sh
python scripts/prepare_postgres.py provision --database tools --system-identifier ID_OBSERVE \
  --profile /operator/profiles/provision-postgres.json \
  --target-profile /operator/profiles/provision-tools.json \
  --verifier-dir /operator/verifiers --state-dir /operator/state
python scripts/prepare_postgres.py install --system-identifier ID_OBSERVE --timeline TIMELINE_OBSERVEE \
  --close-local-provisioner \
  --profile /operator/profiles/provision-tools.json \
  --files-profile /operator/profiles/files-install.json \
  --access-profile /operator/profiles/access-install.json \
  --state-dir /operator/state --token-file /operator/bootstrap/admin.token \
  --tenant-id TENANT_CHOISI --service-id SERVICE_CHOISI
```

La base est créée fermée avec template0 avant ses ACL. Les cibles/rôles neufs
sont vérifiés, les procédures `files_bootstrap`, infrastructure produit et
`postgres_operator` appelées, puis habilitations install retirées. Chaque worker
est un processus à environnement minimal, authentifié dans son scope ; aucune
mutation de l'environnement du processus parent. Un marqueur pending précède
le premier effet ; résultat inconnu/collision/schéma existant arrête sans replay.
Même après succès, réexécuter provision/install refuse : inspecter les objets et
utiliser les vérifications publiques sous une habilitation temporaire explicite,
pas supprimer le marqueur pour recommencer. Le token admin n'est écrit que par
le bootstrap produit,0600 après COMMIT ; son échéance24h est conservée.
La commande `install` ci-dessus est locale. Pour une cible externe, remplacer les
profils par l'identité externe déléguée et omettre `--close-local-provisioner`.
Un échec laisse `install.pending.json` sans `install.done.json` ; il ne prouve
ni la clôture du provisionneur ni une installation complète. Inspecter avant
toute action ; ne pas rouvrir automatiquement un rôle ni rejouer les jobs.

## Configurer et démarrer le même MCP

Créer une configuration par cellule depuis les profils **app**, sans lire leurs
secrets SQL ; les hôtes des deux profils doivent être identiques :

```sh
python scripts/prepare_postgres.py runtime-config --system-identifier ID_OBSERVE --timeline TIMELINE_OBSERVEE \
  --files-profile /operator/profiles/files-app-CELLULE.json \
  --access-profile /operator/profiles/access-app-CELLULE.json --output /operator/runtime-CELLULE.env
```

Compléter S3/versioning, `TOOLS_IMAGE` (même digest Tools approuvé pour toutes
les cellules) et les paramètres applicatifs existants dans une copie
privée. Ne pas ajouter les secrets SQL/provisionneur. Les champs PG générés sont
non secrets, hormis leurs références de fichiers privés ; FILES est explicitement
en Vault, ACCESS en postgres, hub off. En conteneur le profil PG remplace les
chemins hôte par `/run/tools/...`, avec quatre mounts RO sans création implicite
de fichiers. Le Compose de base seul conserve les défauts S3 historiques.

```sh
# Externe : PG déjà préparé, aucun serveur PG ajouté par ce profil.
docker compose --env-file /operator/runtime-externe.env -f docker-compose.yml -f compose.postgres.yml up -d --no-build
# Local : même Tools, plus la seule instance et le volume préparés.
docker compose --env-file /operator/local.env --env-file /operator/runtime-compose-local.env -f docker-compose.yml \
  -f compose.postgres.yml -f compose.postgres-local.yml up -d --no-build
```

Pour Python, placer la configuration privée choisie dans `.env` du checkout
public isolé (ou exporter explicitement ses paramètres non secrets et chemins)
et lancer `PYTHONPATH=src python -m mcp_tools`. S3 et les mêmes scopes Vault restent
requis. La ligne Dockerfile/code ne change pas selon la cible. `/health` prouve
la vie ; attendre `/ready` et ses contrats avant le parcours métier. Le verdict
FILES peut être réutilisé5s ; le healthcheck Docker seul ne prouve pas PG prêt.
Les fichiers Compose n'ajoutent pas de `depends_on` : l'opérateur attend
explicitement PG puis `/ready` avant les parcours, y compris après restart.

Avant démarrage/qualification, vérifier les **UID effectifs**, pas uniquement
le mode d'un secret Compose bind-monté :

```sh
python scripts/prepare_postgres.py check-material --app-uid UID_MCP \
  --bearer-file /operator/scopes/files-app.token --bearer-file /operator/scopes/access-app.token \
  --ca-file /operator/pki/ca.crt --ca-file /operator/trust/vault-ca.pem \
  --server-key /operator/pki/server.key --server-uid UID_PG \
  --server-cert /operator/pki/server.crt --hosts postgresql,127.0.0.1
```

Les tokens app0600 doivent appartenir à UID_MCP, la clé serveur0600 à UID_PG,
les CA doivent être lisibles et non modifiables par groupe/autres. Les scopes
opérateur et fichiers SCRAM ne sont pas montés dans l'app. Ces contrôles hôte ne
remplacent pas les probes de lecture sous les vrais UID dans l'image future.

## PKI, restart et reprise

La leaf locale dure397jours, avec renouvellement explicite avant la marge30jours.
`check-material` refuse une leaf proche de l'expiration ou sans les SAN demandés.
Programmer ce contrôle dans l'exploitation existante ; pas de TTL7jours sans
renouvellement. Sous verrou opérateur exclusif, sauvegarder les matériaux puis
`certificates --renew` avec les mêmes SAN/UID : CA et clé serveur sont conservées,
le certificat est remplacé atomiquement. Recharger PG selon sa procédure après
vérification ; aucune commande de reload n'est lancée par ce CLI. Une CA proche
de l'expiration refuse la leaf397jours : préparer une rotation coordonnée de CA,
distribuer la confiance puis remplacer les matériaux, sans supprimer l'ancienne
autorité avant validation des consommateurs.

Le volume PG reste sur arrêt/restart. Ne jamais employer `down -v` ou supprimer
le volume pour une relance. Qualifier séparément restart Tools puis PG+Tools :
fichiers/pins/access/activité relus, révocation persistante, curseurs RAM repris
de la première page. Pour la reprise logique, réutiliser [export/import FILES](README.md#parcours-et-reprise)
et [droits/révocations ACCESS](access-activity.md#maintenance-et-rollback) : arrêter
writers, retenir versions S3, Vault/auth actuels avant SQL, cible neuve fermée et
droits distincts Source/cible. Un backup n'est pas une autorité fraîche de droits.
Rollback : arrêter consommateurs, préserver volume/Source/archives, raccorder
explicitement une cible contrôlée ou revenir Source, jamais deux writers,
migration/remap ou relance aveugle. Une absence incertaine ne déclenche aucune
purge. Le voisin partagé est relu avec sa propre identité en fin de lot.

Le provisionneur autorise le backup à exécuter seulement la fonction étroite
`tools_files.files_infrastructure()`, en plus de ses USAGE/SELECT et probes PG
déjà prévues. Aucun SET owner, membership, DDL, écriture ou GRANT OPTION ne lui
est accordé. L'export ne se donne aucun droit et refuse une probe non autorisée.
Avant export, suspendre réellement les écrivains ; `--quiesced` ne les arrête pas.
Le scope Vault et les credentials S3 du job sont propres et réautorisés ; aucun
dump ne rétablit cette autorité ni ne remplace ses CA/identités actuelles.

Après export confirmé, l'autorité opérateur ferme l'accès SQL du job par NOLOGIN
ou par retrait effectif de CONNECT, termine ses sessions et vérifie un refus de
connexion frais ; elle retire aussi ses transports/scopes selon leurs procédures.
Révoquer le seul EXECUTE ferme la sonde et l'export, mais laisse possibles les
SELECT SQL tant que LOGIN/CONNECT/USAGE/SELECT restent effectifs. Ne pas rouvrir
automatiquement tools_prepare ni ajouter une commande runtime pour ce retrait.

L'import normal restaure les ACL du dump : un dump pris avant retrait peut donc
restituer EXECUTE au rôle backup cible déjà provisionné, ainsi que USAGE/SELECT.
Contrôler ces droits et l'auth actuelle avant raccord ; ne pas promettre leur
absence. À l'inverse, `--project-roles` utilise `--no-owner --no-acl` puis projette
seulement owner/app cible : il ne transporte pas l'identité backup Source. Les
habilitations de nouveaux jobs cible relèvent ensuite du provisionneur autorisé.

La fixture PG17 `tests/postgres_files/restore_projection.py --backup-install`
contrôle la vraie initialisation et l’export sous backup sans SET owner, via
credentials de test et socket Unix ; elle ne qualifie pas TLS/Vault/S3 natifs.
Les tests de configuration de cette branche contrôlent les Settings réels,
SCRAM et orchestration sans service. Restent à exécuter après revue du diff :
fusion Compose réelle, build/imports/scans, UID/RO, les six cellules du tableau,
installation → accès → write/list/read/activité → révocation → restart, pannes
PG/Vault sans effet, état SQL/S3 final et reprise/rollback. Même SHA/digest app
par cellule, version libpq Python et image relevées séparément ; pas de preuve
native déduite d'un double SQL ni de charge ou HA/PITR non mesurées.

## Qualification locale du 20/10/2026

Révision produit testée : `48a79768587a3e5233527663f1048d4213bb20c1`, arbre
`cea31b743cd02628b1b832d7544c3424224c5254`. Les modifications documentaires
ultérieures ne changent pas cette provenance. Les historiques #30/#31 cités
plus haut gardent leurs propres révisions et ne sont pas comptés comme ces runs.

| Cellule #45 | Autorités réellement exercées | Résultat |
| --- | --- | --- |
| Compose/local | PG17 TLS/SCRAM, S3 versionné HTTPS, FILES Vault + ACCESS Vault | PASS |
| Python/local | Processus Python hôte, mêmes autorités réelles, WAF | PASS |
| Compose/externe dédié | PG séparé du processus applicatif, fixture sur hôte local | PASS |
| Python/externe dédié | Python hôte vers cette topologie PG séparée | PASS |
| Compose/externe partagé | Voisin synthétique préexistant dans une autre base du PG local | PASS |
| Python/externe partagé | Même isolation partagée depuis Python hôte | PASS |

Chaque cellule utilise des états neufs et exerce le parcours public MCP/CLI :
écriture, lecture de versions/pins, pagination, droits limités et révocation ;
restart PG/application ; pannes PG/Vault puis retour ; export réel de quatre
générations avec `pg_dump` 17.11. Deux cibles neuves distinctes vérifient l'import
normal et `--project-roles`, les checks publics sans réappliquer le schéma, puis
la lecture des pins historiques par de nouveaux lecteurs autorisés. Les anciens
tokens ne sont pas restaurés : ils restent refusés, comme le nouveau lecteur
interdit. L'import normal conserve les ACL du dump ; la projection ne restaure
pas une autorité ACCESS historique. L'amorçage ACCESS de la copie normale précède
l'import FILES ; celui de la copie projetée le suit.

La Copy est fermée avant le retour à la Source. Les instantanés du catalogue
FILES et des ACL avant export/après retour sont égaux dans les six cellules.
Les refus backup SET owner/DDL/DML et app SET owner/DDL ont été observés. Les
cellules partagées vérifient le voisin avant provisionnement, après installation,
restart, fermeture Source, activation Copy et retour : données, propriétaires,
ACL et rôles identiques ; accès croisés refusés. Cela qualifie ces fixtures
locales, pas une offre DBaaS distante ou son provisionneur non superuser.

### Complément #46 : FILES direct et ACCESS Vault dans le même service

Une cellule **Python/externe partagé supplémentaire** emploie réellement
`FILES_CREDENTIALS_MODE=direct`, un service libpq et un passfile privés 0600,
avec seulement `PGSERVICEFILE`/`PGPASSFILE` comme variables PG. Aucun paramètre
`FILES_VAULT_*` n'est fourni au processus. ACCESS utilise exclusivement son
scope Vault HTTPS courant, avec son identité SQL distincte. `PGSERVICE` doit
être **absent** : même une valeur vide est refusée, conformément à la garde.
Les jobs de préparation privilégiés restent isolés et tout-Vault.

Le service réel passe `/ready`, bootstrap admin, tokens limités, MCP et CLI via
WAF HTTPS, écritures/lectures/pagination/activité. Après restart de l'application
**seule**, la première continuation FILES réussit, les pins restent identiques
et l'ancien bearer révoqué reçoit 401. Les curseurs ACCESS sont transitoires :
l'ancien reçoit 400 après restart, une première page et sa nouvelle continuation
fonctionnent et retrouvent l'activité. Ce refus est le contrat existant,
pas une restauration de curseur ACCESS.

Huit négatifs natifs distincts refusent l'accès sans contenu ni contournement :
service absent, permissions du passfile incorrectes, CA FILES incorrecte,
`PGSERVICE` vide, mot de passe Vault erroné, mot de passe Vault vide, Vault
indisponible, PG indisponible. Avec ACCESS en échec Vault, le Catalog FILES
direct conserve sa connexion SQL TLS indépendante, mais l'admission MCP reste
fermée. Les profils corrects sont rétablis et relus après les fautes ; aucune
écriture métier ambiguë n'est rejouée. Voisin préexistant inchangé et deux accès
croisés refusés. Cinq opérations closes, aucune référence des écritures sous
scope interdit. Ce parcours complète les **seize cas réels du canari #46**
antérieur sur `e064ca193004faaae4e0b549f5b082cab1432c37` (PG/Vault,
hôte/image, concurrence FILES/ACCESS et absence de fallback). Les gardes et
connecteurs concernés sont inchangés jusqu'à `48a` ; ces cas ne sont ni
réexécutés ni réattribués à ce SHA, et leurs comptes ne sont pas additionnés.

### Versions, CI et limites

- Image Tools ARM64 testée :
  `sha256:d2573b7e62277038eae8edd2897c6fbbb91d0ba130f3625fa7e38a1299159228`,
  Python 3.11.15, SDK 2.2.0, psycopg 3.3.6 implémentation Python/libpq170011.
  Processus hôte : Python 3.11.16, même SDK/psycopg, extra CI binary/libpq180006.
  Cette libpq hôte ne prouve pas celle de l'image. PG serveur et clients dump/
  restore 17.11 ; MinIO `RELEASE.2025-09-07T16-13-09Z`, MCP Vault 0.20.1.
  La version binaire Bao n'a pas été relevée séparément.
- Contrôles acquis sur `48a` : **499 tests HOST +8 subtests**, quatre sondes image
  entières, contrôles du catalogue de treize outils/imports, **49 E2E CI sans
  skip**, projection PG17 réelle avec frontière credentials/S3 de fixture.
  Les 499 tests, les seize canaris, les six cellules et le complément de service
  sont des ensembles différents ; leurs comptes ne s'additionnent pas.
- Aucun nouveau scan n'est déduit des builds : le Trivy historique informatif
  rapporte **125 HIGH et 7 CRITICAL** ; ce n'est pas un résultat zéro vulnérabilité
  ni un scan de la révision documentaire.
- PG18, DBaaS distant non superuser, HA/PITR et expiration réelle IAM/Vault ne sont
  pas qualifiés ici. Les révocations IAM et Vault observées sont distinctes.
  Les identités/schémas invalides et les autres variantes backend restent couverts
  par tests logiciels, sans prétendre une campagne native supplémentaire.
- UID/montages relevés pour les runs ; aucun socket Docker hôte monté dans l'app.
  Scopes Vault relus révoqués, clés IAM désactivées, jobs/connexions fermés et
  seuls services de recette retirés. Volumes, PKI et archives sont conservés.
  Ces résultats ne constituent ni un déploiement ni une livraison fusionnée.
