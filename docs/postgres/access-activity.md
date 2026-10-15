# Accès et activité durable Tools

Candidat #31 en préparation. Les tests SQL isolés du delta admin ne qualifient
pas encore le raccord HTTP/MCP, TLS, Vault, les pannes ou le rollback. Ne pas
présenter ce candidat comme prêt au déploiement.

`ACCESS_BACKEND=postgres` sélectionne une autorité distincte du magasin S3.
Le runtime n'initialise pas `_tokens/`, ne charge aucun ancien token et n'utilise
pas la clé `ADMIN_BOOTSTRAP_KEY`. Chaque opération relit le credential PG avec
un credential SQL obtenu auprès du Vault public ; pas de cache positif ni de
secours S3. `/health` reste une sonde de vie, pas une preuve d'autorisation.

## Installation autonome

PostgreSQL17, libpq17+ avec annulation sûre, driver de
`requirements-postgres.lock`, Vault HTTPS public avec coffre/scopes Tools propres.
Installer d'abord les dépendances décrites dans [README](README.md). Mission
n'est pas nécessaire. Les paramètres ne portent aucun secret en ligne de commande.

Provisionner une base dédiée, owner NOLOGIN, installateur LOGIN temporaire,
app et maintenance LOGIN sans membership ni droits directs sur les tables.
Retirer CONNECT/CREATE/TEMP de PUBLIC sur cette base et CREATE de public,
accorder CONNECT explicitement. Les jobs install/verify/bootstrap ont chacun
leur scope Vault et leur rôle attendu ; l'app ne reçoit jamais ces credentials.
Le rôle installateur peut temporairement SET ROLE vers l'owner ; retirer cette
membership une fois les opérations terminées. Aucune autre base n'est modifiée.

Paramètres : `ACCESS_PG_DATABASE`, `ACCESS_PG_ROLE` (identité du job courant),
`ACCESS_PG_OWNER`, liste exacte `ACCESS_PG_HOSTS`, `ACCESS_PG_CA_FILE` ; provider
`ACCESS_VAULT_URL/ID/PATH/TOKEN_FILE/CA_FILE`. Bearer privé0600 et CA RO, URL Vault
HTTPS sans suffixe `/mcp`. Le secret SQL contient exactement host, port5432,
dbname, user et password. Pas de variables libpq `PG*`, de socket Unix ou de
conninfo client. TLS verify-full et serveur read-write sont imposés.

```sh
PYTHONPATH=src python3 -m mcp_tools.auth.postgres_operator install --app-role tools_access_app --maintenance-role tools_access_maintenance
PYTHONPATH=src python3 -m mcp_tools.auth.postgres_operator verify --app-role tools_access_app --maintenance-role tools_access_maintenance
```

Installer une seule fois. Un schéma existant refuse `install` ; `verify` contrôle
version/checksum, rôles et grants réels. Aucune migration automatique. Chaque
nouvelle connexion runtime vérifie le contrat du schéma et l'identité SQL avant
la requête métier. `ACCESS_OPERATION_TIMEOUT` vaut5s (2–5), sans retry d'écriture.
Une réponse perdue ou un COMMIT inconnu exige une inspection sous identité
autorisée, jamais une réexécution automatique.

Dans un répertoire privé0700, créer ensuite le premier admin offline :

```sh
PYTHONPATH=src python3 -m mcp_tools.auth.postgres_operator bootstrap --tenant-id tenant-local --service-id tools-local --token-file /chemin/prive/initial-admin.token
```

Le token n'est écrit en0600 qu'après COMMIT confirmé, jamais affiché par ce job.
Il expire après24h ; créer les accès administratifs ordinaires pendant cette
fenêtre. Le bootstrap refuse un registre non vide et un fichier existant.
Un échec après COMMIT peut laisser l'admin créé sans fichier : conserver la cible
fermée et faire réconcilier cet état par l'opérateur, sans rejouer le bootstrap.

## Surfaces publiques

La console détecte le profil depuis `/admin/api/me`. La création demande tenant
et service ; acteur UUID optionnel pour une rotation explicite. Tenant, service,
acteur et échéance d'un credential existant ne sont pas modifiables. Un renommage
ne remplace pas l'acteur. Le brut ne revient qu'à la création.

En profil PG, les références sont les préfixes12hex retournés par `list/info`,
jamais un nom client utilisé pour choisir silencieusement une cible. Une collision
est refusée. Les mutations HTTP utilisent `/admin/api/tokens/{token_prefix}` ;
PUT reçoit `expected_version` dans JSON, DELETE dans la query. La version doit
venir de la lecture ayant servi à la décision. Une modification concurrente
demande une nouvelle lecture et une nouvelle décision ; pas de retry implicite.

```sh
python scripts/mcp_cli.py token create reader --tenant-id tenant-local --service-id tools-local --tools files,system_activity --json
python scripts/mcp_cli.py token list --limit 50 --json
python scripts/mcp_cli.py token info reader --token-prefix PREFIX --json
python scripts/mcp_cli.py token update reader --token-prefix PREFIX --expected-version VERSION --tools files --json
python scripts/mcp_cli.py token revoke reader --token-prefix PREFIX --expected-version VERSION --json
python scripts/mcp_cli.py activity --limit 50 --json
```

`list` et activité exposent des pages indépendantes, jamais un total global.
Suivre `next_cursor` jusqu'ànull. Les curseurs opaques sont bornés en RAM :
`ACCESS_CURSOR_TTL_SECONDS=60` (1–300), capacité1024 (1–10000). Ils sont liés au
credential, acteur, tenant, service, version, type et taille de page. Redémarrage,
expiration ou changement de droits imposent une nouvelle lecture depuis la
première page. La lecture ne prolonge pas leur vie. La page pleine peut proposer
une dernière continuation vide. Aucun hash complet n'est rendu.

Le non-admin ne voit que les traces de son acteur/tenant/service et de ses outils
encore autorisés. Retirer un outil masque aussi son historique ; retirer access
refuse la lecture. Les admins ont la vue globale. L'API et la console utilisent
uniquement cette activité durable ; le buffer diagnostic n'est pas un secours.

## Admission, conservation et exploitation

L'admission PG est confirmée avant l'appel d'un outil. La clôture après effet
doit aussi être confirmée ; sinon le résultat est explicitement incertain et
contient l'identifiant de l'admission à inspecter. Une révocation ne supprime pas
un effet déjà produit. Les attentes de slots S3 sont suivies d'une revalidation
avant dispatch. Le journal SQL conserve uniquement des métadonnées autorisées,
jamais arguments, corps, stdout, bearer ni contenu de fichier.

Standalone : rétention technique30j, immuable. L'annotation annuelle et le batch
hub restent non raccordés à ce stade ; une metadata Mission libre ne devient
jamais une corrélation de confiance. Le profil ne revendique pas une qualification
flotte déléguée. Aucune dépendance fonctionnelle à179/844 n'est ajoutée.

La purge appartient au rôle maintenance, pas à l'app ni à la console :

```sh
PYTHONPATH=src python3 -m mcp_tools.auth.postgres_operator purge --batch 500
```

Elle supprime uniquement les appels/événements expirés et les credentials dont
l'échéance est atteinte ; une lecture ou utilisation ne repousse aucune échéance.
Les tombstones de révocation sans échéance restent conservés.

Avant un rollback : préserver la Source, restaurer sur cible neuve fermée avec
identités backup/restore distinctes, puis recopier les révocations courantes
connues ou maintenir tous les accès restaurés fermés. Un backup d'accès n'est
pas une autorité fraîche. La qualification de ce parcours reste à produire avant
Ready ; aucune bascule S3 ou remise en service automatique n'est autorisée.
