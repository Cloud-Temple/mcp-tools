# Coordination Mission #846 — journaux techniques

Première tranche, depuis le main SDK2.2 livré. Aucune coordination métier846,
protection Mission ni récupération845 n'est encore livrée par ce Draft.
Les sources843/845 ne sont pas copiées ; leur composition sera normale après
livraison. Aucun nouveau endpoint d'administration ou pouvoir SQL app.

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
