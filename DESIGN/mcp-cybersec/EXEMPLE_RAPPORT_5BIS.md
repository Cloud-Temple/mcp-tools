# Rapport de recette — laboratoire 5bis

> Statut : **gabarit, aucune exécution produite dans le dépôt**.
>
> À compléter uniquement après un GO humain, une exécution contre le conteneur
> local `lab.target.test` et une revue humaine. Il ne faut ni pré-remplir des
> résultats ni le présenter comme une recette passée.

## Identification

| Champ | Valeur |
| --- | --- |
| Date / opérateur | `À compléter` |
| Commit / image mcp-cybersec | `À compléter` |
| Version | `0.7.0` |
| Campagne / tenant | `À compléter` |
| Mandat snapshot SHA-256 | `À compléter` |
| Fenêtre approuvée | `À compléter` |
| Cible | `lab.target.test` (`172.30.0.10`) uniquement |
| Environnement | `docker-compose.cybersec.lab.yml` local |

## Contrôles avant action

- [ ] `CYBERSEC_LAB_MODE=true` et CIDR `172.30.0.0/24` vérifiés.
- [ ] Manifeste validé avec `laboratory=true`.
- [ ] Campagne passée de `prepared` à `approved` par un administrateur.
- [ ] Hash du snapshot de mandat noté avant tout job.
- [ ] Version/image Nmap et Nuclei/template manifest relevés.
- [ ] Aucun port de la cible n'est publié sur l'hôte ou un réseau partagé.

## Chronologie et preuves

| Horodatage | Trace / call / job | Action | Verdict | Référence de preuve |
| --- | --- | --- | --- | --- |
| `À compléter` | `trace_id` | Création campagne | `prepared` | `campaign.json` |
| `À compléter` | `trace_id` | Approbation | `approved` | `mandates/...json` |
| `À compléter` | `job_id` | Nmap/Nuclei profil autorisé | `completed` / `partial` | `evidence/...` |
| `À compléter` | `trace_id` | Export | `ok` | `findings/...json` |

## Résultat et limites

Décrire les constats en distinguant strictement :

- **observé** : sortie issue d'une preuve ;
- **détecté à confirmer** : sortie normalisée de scanner ;
- **confirmé** : uniquement après revue humaine et procédure autorisée.

Les absences de résultat ne prouvent pas l'absence de vulnérabilité. Mentionner
explicitement les annulations, timeouts, erreurs de résolution et états
`remote_result_uncertain`.

## Conclusion humaine

`À compléter : périmètre réellement atteint, éléments à investiguer, décision
de clôture et responsable.`
