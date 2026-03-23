#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Point d'entrée CLI du service MCP Tools v0.3.0.

CLI complète avec 13 commandes Click + shell interactif.
Chaque commande expose TOUS les paramètres MCP avec aide contextuelle.

Commandes (13) :
    health          ❤️  Vérifier l'état de santé (pas d'auth)
    about           ℹ️  Informations sur le service
    run-shell       🖥️  Exécuter une commande en sandbox Docker
    network         📡 Diagnostics réseau (ping, traceroute, dig, nslookup)
    http            🌐 Client HTTP/REST (anti-SSRF)
    search          🔍 Recherche internet via Perplexity AI
    doc             📚 Documentation technique via Perplexity AI
    date            🗓️  Manipulation de dates/heures
    calc            🧮 Calculs mathématiques en sandbox Python
    ssh             🔑 Commandes SSH / transfert fichiers
    files           📁 Opérations fichiers S3 Dell ECS
    token           🔑 Gestion tokens (create, list, info, update, revoke)
    shell           🐚 Shell interactif avec autocomplétion

Usage :
    python scripts/mcp_cli.py --help
    python scripts/mcp_cli.py health
    python scripts/mcp_cli.py about
    python scripts/mcp_cli.py run-shell "echo hello"
    python scripts/mcp_cli.py run-shell "import numpy; print(numpy.__version__)" --shell python3
    python scripts/mcp_cli.py run-shell "pip install cowsay" --network
    python scripts/mcp_cli.py network ping google.com
    python scripts/mcp_cli.py network dig google.com MX +short
    python scripts/mcp_cli.py http https://httpbin.org/get
    python scripts/mcp_cli.py http https://api.example.com/data --auth-type bearer --auth-value "mytoken"
    python scripts/mcp_cli.py search "Qu'est-ce que MCP ?"
    python scripts/mcp_cli.py doc "FastAPI" --context "middleware"
    python scripts/mcp_cli.py date now --tz Europe/Paris
    python scripts/mcp_cli.py calc "math.sqrt(144)"
    python scripts/mcp_cli.py ssh myserver.com root -c "uptime" -p "password"
    python scripts/mcp_cli.py files list --prefix "data/"
    python scripts/mcp_cli.py files versions -p "config/app.json"
    python scripts/mcp_cli.py token create agent-prod --tools shell,date,calc
    python scripts/mcp_cli.py token update agent-prod --tools all --email admin@ct.com
    python scripts/mcp_cli.py token list
    python scripts/mcp_cli.py shell

Variables d'environnement :
    MCP_URL   — URL du serveur (défaut: http://localhost:8082)
    MCP_TOKEN — Token d'authentification
    ADMIN_BOOTSTRAP_KEY — Clé admin (fallback si MCP_TOKEN non défini)

Outils MCP disponibles (12) :
    shell, network, http, ssh, files, date, calc,
    perplexity_search, perplexity_doc, token,
    system_health, system_about

65 paramètres MCP documentés avec Annotated[type, Field(description="...")].
"""

import sys
from pathlib import Path

# Ajouter le répertoire parent au path pour les imports relatifs
sys.path.insert(0, str(Path(__file__).parent))

from cli.commands import cli

if __name__ == "__main__":
    cli()
