# Runbook opérateur — mcp-cybersec

## Préconditions de mise en service

Avant tout démarrage hors laboratoire, vérifier :

1. une identité S3 **dédiée** à `mcp-cybersec`, cantonnée à son bucket et son
   préfixe ; ne pas reprendre les credentials `mcp-tools` ;
2. l'injection par Vault Agent de `CYBERSEC_S3_*` et
   `CYBERSEC_ADMIN_BOOTSTRAP_KEY` ; la valeur bootstrap par défaut interdit le
   rollout ;
3. les images d'exécution construites à partir du commit/tag approuvé ;
4. les réseaux scanner et le WAF cybersec séparés ;
5. `CYBERSEC_RUNTIME_HOST_DIR` préprovisionné en mode `01777`, dédié aux
   artefacts éphémères et monté au même chemin dans le service ;
6. un mandat écrit, tenant identifié, fenêtre, scope, capacités et limites
   explicitement approuvés.

Un healthcheck vert ou un catalogue MCP de 13 outils ne vaut pas autorisation
de scanner une cible.

## Qualification sans trafic cible

La qualification minimale ne fait aucun appel de sécurité vers une cible :

```bash
install -d -m 1777 "${CYBERSEC_RUNTIME_HOST_DIR:-/tmp/mcp-cybersec-runtime}"
docker compose -f docker-compose.cybersec.yml config
docker compose -f docker-compose.cybersec.yml build
docker compose -f docker-compose.cybersec.yml up -d
curl -fsS http://localhost:8081/health
python scripts/mcp_cybersec_cli.py --url http://localhost:8081 about
```

Utiliser des variables de test distinctes. Les opérations S3 de campagne ne
sont exécutées que lorsque l'identité de recette dédiée a été fournie. Arrêter
la stack de qualification avec la même composition (`docker compose ... down`) ;
ne pas toucher aux conteneurs `mcp-tools` existants.

## Recette du seul laboratoire autorisé

Préconditions supplémentaires : GO humain de recette, overlay
`docker-compose.cybersec.lab.yml`, manifeste
`cybersec/lab/manifest-5bis.json`, et aucune route/port vers un réseau partagé.

Le manifeste doit inclure `"laboratory": true`. Le service n'accepte la cible
`172.30.0.0/24` que si les trois conditions sont vraies simultanément :

- `CYBERSEC_LAB_MODE=true` ;
- `CYBERSEC_LAB_ALLOWED_CIDRS=172.30.0.0/24` ;
- mandat approuvé portant le flag laboratoire.

La première action reste `campaign.create`; puis l'admin vérifie le hash du
snapshot avant `campaign.approve`. Conserver le `campaign_id`, `trace_id`,
`job_id`, les IDs d'images et le manifeste dans le rapport. Ne lancer que des
profils explicitement accordés. Aucune cible Internet ou partagée n'est un
substitut acceptable au laboratoire.

## Arrêt d'urgence

1. Appeler `campaign.cancel` avec le tenant et un motif ; l'état devient
   annulé et les jobs reçoivent l'instruction d'arrêt.
2. Vérifier `/admin` puis `system_activity` par `trace_id`/`call_id` : le job
   doit devenir `cancelled`, `partial` ou `remote_result_uncertain`, pas
   `completed` par défaut.
3. Si l'application ne répond plus, arrêter uniquement les conteneurs de la
   composition cybersec. Ne supprimer ni S3, ni volumes de preuve, ni une
   campagne : les éléments servent à l'analyse d'incident.
4. Révoquer le token cybersec concerné si nécessaire ; conserver le hash,
   l'acteur et la date de révocation.

## Lecture des résultats

| État | Signification opératoire |
| --- | --- |
| `prepared` | Manifesté validé, aucune action réseau autorisée. |
| `approved` | Mandat figé ; actions limitées à la fenêtre/capacité/scope. |
| `running` | Job asynchrone en cours ; le scope est recontrôlé. |
| `completed` | Processus fini, mais les constats restent à confirmer humainement. |
| `cancelled` / `partial` | Arrêt demandé ou résultat incomplet ; ne jamais présenter comme exhaustif. |
| `remote_result_uncertain` | Une action distante a pu avoir eu lieu avant l'interruption. |

Un finding Nuclei/nmap est un signal `detected_to_confirm`. Seule une revue
humaine avec preuve, reproduction autorisée et contexte de périmètre peut
conclure à une vulnérabilité.

## Rétention et sécurité des journaux

Les événements `/admin`/`system_activity` sont un buffer local corrélé ; ils
servent au diagnostic immédiat et n'emportent pas de payload sensible. Les
preuves de campagne redacted et les métadonnées de job persistent dans S3. La
rétention et l'archivage S3 relèvent de la policy du bucket/du runtime, à
documenter avant une exploitation de production. Aucun purgeur applicatif n'est
introduit sans policy explicite, afin d'éviter une suppression de preuve.
