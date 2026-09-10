# Architecture — mcp-cybersec

## Décision

Le dépôt reste unique, mais `mcp-cybersec` est un service MCP distinct de
`mcp-tools` : image `mcp-cybersec`, processus sur `8051`, WAF sur `8081` par
défaut, réseaux Docker `mcp-cybersec-*` et configuration exclusivement
`CYBERSEC_*`. Il n'importe du socle existant que l'adaptateur d'observabilité
éprouvé ; aucun token, buffer mémoire, bucket ou conteneur n'est partagé à
l'exécution.

```
Agent / CLI / Admin
        │ Bearer cybersec
        ▼
WAF cybersec :8081 ───► mcp-cybersec :8051
                              │
              ┌───────────────┼───────────────────┐
              ▼               ▼                   ▼
        S3 dédié         Docker contrôlé      journal corrélé
   tenant/campaign       jobs/sondes          /admin + MCP
```

Le conteneur applicatif possède le socket Docker car il orchestre les images
fixes. Ce privilège n'est jamais remonté à un outil : le code n'accepte ni
image, ni volume, ni réseau, ni commande Docker fournis par l'agent. Une
évolution vers un socket-proxy peut être décidée après revue dédiée ; elle
n'est pas requise pour le contrat actuel et ne doit pas être ajoutée par
anticipation.

## Frontières de confiance

| Frontière | Contrôle |
| --- | --- |
| Agent → MCP | Bearer hashé en S3 ; token de mission = tenant + allow-list ; absence ou erreur de store = refus. |
| Action → campagne | `campaign_id`, état `approved`, fenêtre valide, capacité et limites du mandat. |
| Action → cible | validation du manifeste, DNS/IP/URL, blocage privé/metadata/loopback, revalidation juste avant l'appel ; HTTP et Nuclei utilisent l'IP validée (Host/SNI contrôlé), les redirections HTTP repassent ce contrôle. |
| Code non fiable | shell avec `--network=none`, FS racine lecture seule, UID non-root, ressources bornées ; seul le workspace S3 explicitement déclaré est copié. |
| Scanners | conteneurs éphémères, réseau scanner propre, commandes et images fixes ; nmap sans NSE arbitraire, Nuclei limité au catalogue de templates épinglés. |
| Persistance | uniquement S3 cybersec ; l'outil `files` ne voit que `workspace/`, jamais tokens, mandats, jobs ou preuves. |

## Cycle d'une campagne

1. `campaign.create` valide le manifeste et écrit l'état `prepared`.
2. Un administrateur appelle `campaign.approve`. Le service crée un snapshot
   horodaté du mandat et son SHA-256 : la campagne ne peut plus être modifiée.
3. Les outils passifs et actifs vérifient état, fenêtre, scope et capacité.
4. `nmap` et `nuclei` créent un job déterministe par clé d'idempotence ; un
   second appel identique restitue le même job.
5. Le job revalide le scope avant le démarrage, en cours d'exécution et avant
   les étapes réseau suivantes. `campaign.cancel` demande l'arrêt du
   conteneur et conserve les résultats partiels avec un état explicite.
6. Sortie brute redacted, métadonnées, preuve et constat normalisé sont écrits
   séparément. Un constat automatique est toujours `detected_to_confirm`, pas
   une vulnérabilité confirmée.

## Schéma S3 et isolement tenant

La racine est fixe :

```text
${CYBERSEC_S3_PREFIX}/
  tenants/<tenant_id>/campaigns/<campaign_id>/
    campaign.json
    mandates/<approved-at>-<sha>.json
    jobs/<job_id>.json
    workspace/<path>
    evidence/<job_id>/...
    findings/<job_id>.json
  _tokens/<sha256-bearer>.json
```

`campaign_id`, `tenant_id` et les chemins workspace sont validés avant la
construction de toute clé. Les raw bearers ne sont jamais persistés : seul leur
SHA-256 sert de clé. L'identité de runtime S3 doit être limitée à ce bucket et
ce préfixe ; Vault Agent injecte `CYBERSEC_S3_*` et
`CYBERSEC_ADMIN_BOOTSTRAP_KEY`, tandis que
`CYBERSEC_VAULT_SECRET_REFERENCE` conserve seulement une référence non secrète
pour l'exploitation.

## Images reproductibles

| Image | Rôle | Provenance figée |
| --- | --- | --- |
| `mcp-cybersec` | serveur MCP / admin / orchestration | Python base par digest, `requirements.lock` |
| `mcp-cybersec-network` | DNS, TCP/TLS, ping, traceroute et HTTP | Dockerfile local versionné |
| `mcp-cybersec-shell` | analyse locale d'artefacts | Dockerfile local ; réseau forcé à `none` |
| `mcp-cybersec-nmap` | profils nmap sûrs | version 7.98 et Dockerfile local |
| `mcp-cybersec-nuclei` | templates de détection | Nuclei 3.7.1 ; templates v10.4.2 au commit `8de881615f58b3427f0424338779d28de68d2ee1` |

Le catalogue Nuclei ne propose que les templates copiés au build. Aucun
template fourni par un agent, aucune mise à jour à l'exécution et aucun
Interactsh/OAST ne sont autorisés.

## Observabilité et non-promesses

Chaque appel traverse `ActivityMiddleware`, avec acteur, `trace_id`,
`call_id`, outil, chronologie HTTP/métier, durée et verdict terminal. Le
payload sensible (bearer, secrets, bodies, commandes, sorties brutes) n'est pas
placé dans le journal d'activité. Les preuves consultables sont stockées à part
dans le périmètre de campagne et redacted avant écriture.

Le verdict « réponse émise » démontre que l'ASGI a accepté l'enveloppe
terminale, non que l'agent l'a reçue. Toute interruption ambiguë est conservée
comme `remote_result_uncertain` ou état partiel, jamais comme succès complet.
