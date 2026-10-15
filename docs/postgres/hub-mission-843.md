# Lecture des fichiers depuis Mission

Le hub optionnel utilise la même identité, la même audience et le même contrôle
live que [le raccord31](access-activity.md). L'autorité des accès et de l'activité
reste PostgreSQL Tools ; les références publiées restent dans le catalogue Files,
le contenu dans les versions S3. Mission ne reçoit aucun accès SQL/S3 direct.

Le lecteur opaque a **uniquement** `permissions=["hub_read"]`, avec
`tool_ids=["files"]`. `hub_read` ne se combine pas avec `access` ou `admin`.
L'opérateur le crée par `POST /admin/api/tokens`, avec `actor_id`, `tenant_id` et
`service_id` explicitement égaux à l'acteur du parcours. Ce credential est distinct
du writer MCP. Le mapping administré31 associe cet acteur au sujet Mission stable,
issuer/owner/tenant exacts ; ni création ni renouvellement automatique.
Une modification de droits utilise le CAS `expected_version` public31.

Le bearer n'autorise aucun `tools/call` MCP, même accompagné d'un contexte signé,
ni aucune administration. La lecture exige en plus une délégation live valide :

- Activité : `POST /internal/hub/tools-activity`, contrat31 inchangé, intersection
  acteur/tenant/service/mission/root et `tool_ids` courants.
- Fichiers : `POST /internal/hub/tools-files`, permission JWT exacte
  `tools.files.read`. Corps : `mission_id`, `root_agent_id`, `call_ids` (1–64 UUID
  distincts). Une lecture de contenu ajoute `content=true`, `offset` et `limit`,
  un seul call ; `limit` est borné par `HUB_FILES_PAGE_BYTES` (défaut/plafond30000).
  Headers : bearer opaque dans Authorization et JWT dans X-Tools-Activity-Context.
  Le digest signé porte sur les octets exacts ; aucun bucket/path/version arbitraire.

La référence exige call autorisé et non expiré → operation_id → origin_call_id
exact → génération publiée. `origin_call_id` est fixé côté serveur lors de la
réservation d'une mutation, après admission31. Il reste immuable, y compris après
retry/reconcile. Une opération recyclée sous un autre call ne déplace pas son
origine. Les opérations sans contexte historique ne sont pas rattachées après coup.

Les réponses contiennent métadonnées minimales et `reference_state`, jamais la clé
physique S3. Une génération historique utilise son pin version/ETag/taille/SHA,
pas la référence courante. Le contenu est une plage base64 ; `next_offset/end`
décrivent sa couverture. Métadonnées possibles sans S3, contenu indisponible503
si la source échoue. Révocation, changement de version ou expiry sont vérifiés
après les attentes. La décision SQL finale Files verrouille credential, mapping
et appels retenus dans la même transaction ; disparition/purge, modification du
lien ou expiry ferme la restitution. Son échéance d'activité minimale est encore
comparée à l'horloge fraîche avant projection, sans nouvelle attente d'autorité.

Les schémas sont installés par les opérateurs existants sur un domaine neuf,
avec checksum actualisé. Aucun DDL runtime, migration ou fallback ancien magasin.
La lecture ne prolonge aucune conservation et n'effectue ni purge ni publication.
Les droits/revocations de l'autorité courante restent nécessaires pour l'historique.
La qualification VM843 et la revue finale restent à produire avant livraison.
