#!/bin/bash
cd /Volumes/SSD_Public/PROJETS/tools
git add -A
git commit -m "feat: tool ping → network — sandbox Docker avec réseau + extra_args + CLI sous-commandes

Remplace l'ancien tool 'ping' par 'network' :
- Sandbox Docker éphémère avec réseau (--network=bridge, --cap-add=NET_RAW, --read-only)
- Blocage IPs privées RFC 1918 (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, loopback, link-local)
- Nouveau paramètre extra_args : passe tous les arguments directement aux commandes
  (ex: '-c 2' pour ping, '-type=mx' pour nslookup, 'MX +short' pour dig)
- Validation host (regex) + validation extra_args (regex anti-injection) + subprocess_exec
- Defaults par opération : ping → '-c 4', traceroute → '-m 15 -w 3'
- Backward compat : paramètre 'count' fonctionne toujours pour les anciens appelants

CLI :
- Sous-commandes Click : network ping/dig/nslookup/traceroute <host> [args...]
- Shell interactif : network <op> <host> [args...] avec aide contextuelle
- Tous les arguments passés en passthrough (ignore_unknown_options)

Sandbox :
- sandbox/Dockerfile : +iputils, +bind-tools, +traceroute
- 4 niveaux protection anti-injection (regex host, regex args, subprocess_exec, sandbox read-only)

Tests E2E : 13/13 (dont 10 network : ping, nslookup, dig, traceroute, sandbox, RFC1918 x3, injection, op invalide)

Documentation mise à jour :
- DESIGN/ (ARCHITECTURE, TOOLS_CATALOG, SYNTHESE_TRANSVERSE, mcp-mission, mcp-agent)
- README FR/EN, CHANGELOG v0.1.1
- Memory bank (activeContext, progress, systemPatterns)"
