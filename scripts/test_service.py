#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Script de recette end-to-end — MCP Tools

Teste toutes les fonctionnalités du service MCP Tools via le protocole
MCP Streamable HTTP (endpoint /mcp). Vérifie la connectivité, l'auth,
et chaque outil implémenté (shell, network, http, perplexity_search).

Usage:
    # Serveur local (défaut : http://localhost:8050)
    python3 scripts/test_service.py

    # Serveur distant
    MCP_URL=https://tools.example.com MCP_TOKEN=xxx python3 scripts/test_service.py

    # Mode verbose
    python3 scripts/test_service.py --verbose

    # Ne pas build/start docker (serveur déjà lancé)
    python3 scripts/test_service.py --no-docker

Prérequis:
    - pip install mcp>=1.8.0 httpx
    - docker compose (si --no-docker n'est pas passé)

Catégories de tests (5) :
    1. Connectivité     — REST /health + MCP system_health + system_about
    2. Authentification  — Sans token → 401, mauvais token → 401, admin → OK
    3. Outil shell       — Exécution de commandes
    4. Outil network     — ping, traceroute, nslookup, dig (sandbox + RFC 1918)
    5. Outil http        — Requête GET externe
    6. Outil perplexity  — Recherche IA (si clé API configurée)

Exit code: 0 si tous les tests passent, 1 sinon.
"""

import os
import sys
import json
import time
import asyncio
import argparse
import subprocess
import traceback
from datetime import datetime

# =============================================================================
# Configuration
# =============================================================================

BASE_URL = os.getenv("MCP_URL", "http://localhost:8082")
TOKEN = os.getenv("MCP_TOKEN", os.getenv("ADMIN_BOOTSTRAP_KEY", "change_me_in_production"))

# =============================================================================
# Helpers
# =============================================================================

VERBOSE = False
PASS = 0
FAIL = 0
SKIP = 0
RESULTS = []


def log(msg: str, level: str = "info"):
    ts = datetime.now().strftime("%H:%M:%S")
    prefix = {"info": "ℹ️", "ok": "✅", "fail": "❌", "warn": "⚠️", "skip": "⏭️"}.get(level, "")
    print(f"  [{ts}] {prefix} {msg}")


def record(test_name: str, passed: bool, detail: str = "", skipped: bool = False):
    global PASS, FAIL, SKIP
    if skipped:
        SKIP += 1
        status = "SKIP"
    elif passed:
        PASS += 1
        status = "PASS"
    else:
        FAIL += 1
        status = "FAIL"
    RESULTS.append({"test": test_name, "status": status, "detail": detail})
    emoji = {"PASS": "✅", "FAIL": "❌", "SKIP": "⏭️"}[status]
    print(f"  {emoji} {test_name}" + (f" — {detail}" if detail else ""))


async def call_tool(tool_name: str, args: dict = {}) -> dict:
    """
    Appelle un outil MCP via Streamable HTTP.
    Retourne le résultat parsé en dict.
    """
    from mcp import ClientSession
    from mcp.client.streamable_http import streamablehttp_client

    headers = {"Authorization": f"Bearer {TOKEN}"}

    async with streamablehttp_client(
        f"{BASE_URL}/mcp",
        headers=headers,
        timeout=30,
        sse_read_timeout=120,
    ) as (read, write, _):
        async with ClientSession(read, write) as session:
            await session.initialize()
            result = await session.call_tool(tool_name, args)

            text = ""
            if result.content:
                text = getattr(result.content[0], "text", "") or ""

            if not text:
                raise RuntimeError(f"Réponse vide pour {tool_name}")

            data = json.loads(text)

            if VERBOSE:
                print(f"    📦 {tool_name} → {json.dumps(data, indent=2, ensure_ascii=False)[:800]}")

            return data


async def call_rest(method: str, endpoint: str, headers: dict = None,
                    json_body: dict = None, expect_status: int = None) -> dict:
    """Appelle un endpoint REST."""
    import httpx
    hdrs = headers or {}
    async with httpx.AsyncClient(timeout=10) as client:
        resp = await client.request(method, f"{BASE_URL}{endpoint}",
                                     headers=hdrs, json=json_body)
        result = {"status_code": resp.status_code}
        try:
            result["body"] = resp.json()
        except Exception:
            result["body"] = resp.text
        return result


# =============================================================================
# Docker helpers
# =============================================================================

def docker_build_and_start():
    """Build et démarre docker compose."""
    print("\n🐳 Build et démarrage Docker...")
    print("=" * 50)

    r = subprocess.run(
        ["docker", "compose", "build", "--quiet"],
        capture_output=True, text=True
    )
    if r.returncode != 0:
        print(f"  ❌ docker compose build échoué:\n{r.stderr}")
        return False
    print("  ✅ Build OK")

    r = subprocess.run(
        ["docker", "compose", "up", "-d"],
        capture_output=True, text=True
    )
    if r.returncode != 0:
        print(f"  ❌ docker compose up échoué:\n{r.stderr}")
        return False
    print("  ✅ Container démarré")
    return True


def docker_stop():
    """Arrête docker compose."""
    print("\n🐳 Arrêt Docker...")
    subprocess.run(["docker", "compose", "down"], capture_output=True, text=True)
    print("  ✅ Containers arrêtés")


def wait_for_server(max_wait: int = 30) -> bool:
    """Attend que le serveur réponde sur /health."""
    import httpx
    print(f"\n⏳ Attente du serveur ({BASE_URL})...")
    for i in range(max_wait):
        try:
            r = httpx.get(f"{BASE_URL}/health", timeout=2)
            if r.status_code == 200:
                print(f"  ✅ Serveur prêt en {i+1}s")
                return True
        except Exception:
            pass
        time.sleep(1)
        if (i + 1) % 5 == 0:
            print(f"  ⏳ {i+1}s...")
    print(f"  ❌ Serveur non disponible après {max_wait}s")
    # Afficher les logs Docker pour debug
    r = subprocess.run(
        ["docker", "compose", "logs", "--tail=30", "mcp-tools"],
        capture_output=True, text=True
    )
    if r.stdout:
        print(f"\n📋 Logs Docker (dernières lignes):\n{r.stdout}")
    if r.stderr:
        print(f"{r.stderr}")
    return False


# =============================================================================
# Tests
# =============================================================================

async def test_01_connectivity():
    """Test 1: Connectivité de base"""
    print("\n🔌 TEST 1 — Connectivité")
    print("=" * 50)

    # 1a. REST /health
    try:
        data = await call_rest("GET", "/health")
        ok = data["status_code"] == 200
        record("REST /health", ok, f"HTTP {data['status_code']}")
    except Exception as e:
        record("REST /health", False, str(e))
        return False

    # 1b. MCP system_health
    try:
        data = await call_tool("system_health")
        ok = data.get("status") == "ok"
        record("MCP system_health", ok, data.get("service_name", "?"))
    except Exception as e:
        record("MCP system_health", False, str(e))
        return False

    # 1c. MCP system_about
    try:
        data = await call_tool("system_about")
        ok = data.get("status") == "ok"
        tools_count = data.get("tools_count", "?")
        tools_names = [t["name"] for t in data.get("tools", [])]
        record("MCP system_about", ok, f"{tools_count} outils: {tools_names}")
    except Exception as e:
        record("MCP system_about", False, str(e))

    return True


async def test_02_auth():
    """Test 2: Authentification"""
    print("\n🔐 TEST 2 — Authentification")
    print("=" * 50)

    # 2a. Sans token → 401
    try:
        data = await call_rest("POST", "/mcp", json_body={"jsonrpc": "2.0", "method": "initialize", "id": 1})
        ok = data["status_code"] == 401
        record("POST /mcp sans token", ok, f"HTTP {data['status_code']} (attendu: 401)")
    except Exception as e:
        record("POST /mcp sans token", False, str(e))

    # 2b. Mauvais token → 401
    try:
        data = await call_rest(
            "POST", "/mcp",
            headers={"Authorization": "Bearer bad_token_12345"},
            json_body={"jsonrpc": "2.0", "method": "initialize", "id": 1}
        )
        ok = data["status_code"] == 401
        record("POST /mcp mauvais token", ok, f"HTTP {data['status_code']} (attendu: 401)")
    except Exception as e:
        record("POST /mcp mauvais token", False, str(e))

    # 2c. Token admin valide → session MCP OK
    try:
        data = await call_tool("system_health")
        ok = data.get("status") == "ok"
        record("MCP avec token admin", ok, "Session MCP initialisée")
    except Exception as e:
        record("MCP avec token admin", False, str(e))


async def test_03_shell():
    """Test 3: Outil shell (sandbox Docker)"""
    print("\n🖥️ TEST 3 — Outil shell (sandbox)")
    print("=" * 50)

    # 3a. Commande simple
    try:
        data = await call_tool("shell", {"command": "echo hello_mcp_tools"})
        ok = data.get("status") == "success" and "hello_mcp_tools" in data.get("stdout", "")
        record("shell echo", ok, f"stdout={data.get('stdout', '').strip()[:50]}")
    except Exception as e:
        record("shell echo", False, str(e))

    # 3b. Sandbox active (sandbox: True dans la réponse)
    try:
        data = await call_tool("shell", {"command": "echo test"})
        is_sandbox = data.get("sandbox", None)
        record("shell sandbox active", is_sandbox is True, f"sandbox={is_sandbox}")
    except Exception as e:
        record("shell sandbox active", False, str(e))

    # 3c. User non-root (whoami == sandbox)
    try:
        data = await call_tool("shell", {"command": "whoami"})
        user = data.get("stdout", "").strip()
        ok = user == "sandbox"
        record("shell user non-root", ok, f"whoami={user}")
    except Exception as e:
        record("shell user non-root", False, str(e))

    # 3d. Isolation réseau (curl échoue)
    try:
        data = await call_tool("shell", {"command": "curl -s --max-time 3 https://google.com 2>&1 || echo NETWORK_BLOCKED"})
        ok = "NETWORK_BLOCKED" in data.get("stdout", "") or data.get("returncode", 0) != 0
        record("shell réseau isolé", ok, f"stdout={data.get('stdout', '').strip()[:60]}")
    except Exception as e:
        record("shell réseau isolé", False, str(e))

    # 3e. Param shell (sh)
    try:
        data = await call_tool("shell", {"command": "echo $0", "shell": "sh"})
        ok = data.get("status") == "success"
        record("shell param sh", ok, f"stdout={data.get('stdout', '').strip()[:30]}")
    except Exception as e:
        record("shell param sh", False, str(e))

    # 3f. Param shell (python3 — calcul)
    try:
        data = await call_tool("shell", {"command": "print(2**100)", "shell": "python3"})
        ok = data.get("status") == "success" and "1267650600228229401496703205376" in data.get("stdout", "")
        record("shell python3 calcul", ok, f"stdout={data.get('stdout', '').strip()[:40]}")
    except Exception as e:
        record("shell python3 calcul", False, str(e))

    # 3g. Param shell (node — JSON)
    try:
        data = await call_tool("shell", {"command": "console.log(JSON.stringify({ok:true}))", "shell": "node"})
        ok = data.get("status") == "success" and "ok" in data.get("stdout", "")
        record("shell node JSON", ok, f"stdout={data.get('stdout', '').strip()[:40]}")
    except Exception as e:
        record("shell node JSON", False, str(e))

    # 3h. Shell invalide refusé
    try:
        data = await call_tool("shell", {"command": "echo test", "shell": "ruby"})
        ok = data.get("status") == "error" and "non autorisé" in data.get("message", "")
        record("shell invalide refusé", ok, data.get("message", "?")[:60])
    except Exception as e:
        record("shell invalide refusé", False, str(e))

    # 3g. Commande avec code de retour non-zéro
    try:
        data = await call_tool("shell", {"command": "ls /nonexistent_path_xyz"})
        ok = data.get("returncode", 0) != 0
        record("shell erreur (exit ≠ 0)", ok, f"returncode={data.get('returncode')}")
    except Exception as e:
        record("shell erreur", False, str(e))

    # 3h. Timeout
    try:
        data = await call_tool("shell", {"command": "sleep 60", "timeout": 2})
        ok = "timeout" in data.get("message", "").lower() or data.get("status") == "error"
        record("shell timeout", ok, data.get("message", data.get("status", "?")))
    except Exception as e:
        record("shell timeout", False, str(e))


async def test_04_network():
    """Test 4: Outil network (sandbox Docker avec réseau)"""
    print("\n📡 TEST 4 — Outil network (sandbox)")
    print("=" * 50)

    # 4a. Ping IP publique (8.8.8.8)
    try:
        data = await call_tool("network", {"host": "8.8.8.8", "operation": "ping", "count": 2})
        ok = data.get("status") == "success"
        record("network ping 8.8.8.8", ok, f"{data.get('stdout', '')[:60]}...")
    except Exception as e:
        record("network ping 8.8.8.8", False, str(e))

    # 4b. Sandbox active
    try:
        data = await call_tool("network", {"host": "8.8.8.8", "operation": "ping", "count": 1})
        is_sandbox = data.get("sandbox", None)
        record("network sandbox active", is_sandbox is True, f"sandbox={is_sandbox}")
    except Exception as e:
        record("network sandbox active", False, str(e))

    # 4c. nslookup google.com
    try:
        data = await call_tool("network", {"host": "google.com", "operation": "nslookup"})
        ok = data.get("status") == "success"
        record("network nslookup google.com", ok, f"{data.get('stdout', '')[:60]}...")
    except Exception as e:
        record("network nslookup google.com", False, str(e))

    # 4d. dig google.com
    try:
        data = await call_tool("network", {"host": "google.com", "operation": "dig"})
        ok = data.get("status") == "success"
        record("network dig google.com", ok, f"{data.get('stdout', '')[:60]}...")
    except Exception as e:
        record("network dig google.com", False, str(e))

    # 4e. traceroute (court, IP publique)
    try:
        data = await call_tool("network", {"host": "8.8.8.8", "operation": "traceroute", "timeout": 15})
        # traceroute peut ne pas aboutir complètement, mais doit répondre
        ok = data.get("status") in ("success", "error") and len(data.get("stdout", "")) > 0
        record("network traceroute 8.8.8.8", ok, f"{data.get('stdout', '')[:60]}...")
    except Exception as e:
        record("network traceroute 8.8.8.8", False, str(e))

    # 4f. Opération invalide
    try:
        data = await call_tool("network", {"host": "google.com", "operation": "invalid_op"})
        ok = data.get("status") == "error"
        record("network opération invalide", ok, data.get("message", "?")[:60])
    except Exception as e:
        record("network opération invalide", False, str(e))

    # 4g. RFC 1918 bloqué — 127.0.0.1 (loopback)
    try:
        data = await call_tool("network", {"host": "127.0.0.1", "operation": "ping"})
        ok = data.get("status") == "error" and "privée" in data.get("message", "").lower()
        record("network RFC1918 127.0.0.1 bloqué", ok, data.get("message", "?")[:60])
    except Exception as e:
        record("network RFC1918 127.0.0.1 bloqué", False, str(e))

    # 4h. RFC 1918 bloqué — 10.0.0.1
    try:
        data = await call_tool("network", {"host": "10.0.0.1", "operation": "ping"})
        ok = data.get("status") == "error" and "privée" in data.get("message", "").lower()
        record("network RFC1918 10.0.0.1 bloqué", ok, data.get("message", "?")[:60])
    except Exception as e:
        record("network RFC1918 10.0.0.1 bloqué", False, str(e))

    # 4i. RFC 1918 bloqué — 192.168.1.1
    try:
        data = await call_tool("network", {"host": "192.168.1.1", "operation": "ping"})
        ok = data.get("status") == "error" and "privée" in data.get("message", "").lower()
        record("network RFC1918 192.168.1.1 bloqué", ok, data.get("message", "?")[:60])
    except Exception as e:
        record("network RFC1918 192.168.1.1 bloqué", False, str(e))

    # 4j. Injection commande bloquée
    try:
        data = await call_tool("network", {"host": "8.8.8.8; echo hacked", "operation": "ping"})
        ok = data.get("status") == "error" and "invalide" in data.get("message", "").lower()
        record("network injection bloquée", ok, data.get("message", "?")[:60])
    except Exception as e:
        record("network injection bloquée", False, str(e))


async def test_05_http():
    """Test 5: Outil http (sandbox Docker + anti-SSRF)"""
    print("\n🌐 TEST 5 — Outil http (sandbox)")
    print("=" * 50)

    # 5a. GET simple
    try:
        data = await call_tool("http", {"url": "https://httpbin.org/get", "method": "GET"})
        ok = data.get("status") == "success" and data.get("status_code") == 200
        record("http GET httpbin.org", ok, f"HTTP {data.get('status_code')}")
    except Exception as e:
        record("http GET httpbin.org", False, str(e))

    # 5b. Sandbox active
    try:
        data = await call_tool("http", {"url": "https://httpbin.org/get"})
        is_sandbox = data.get("sandbox", None)
        record("http sandbox active", is_sandbox is True, f"sandbox={is_sandbox}")
    except Exception as e:
        record("http sandbox active", False, str(e))

    # 5c. POST avec body JSON
    try:
        data = await call_tool("http", {
            "url": "https://httpbin.org/post",
            "method": "POST",
            "json_body": {"test": "mcp-tools", "value": 42}
        })
        ok = data.get("status") == "success" and data.get("status_code") == 200
        body = data.get("body", "")
        has_json = "mcp-tools" in body
        record("http POST JSON", ok and has_json, f"HTTP {data.get('status_code')}, body contient data={has_json}")
    except Exception as e:
        record("http POST JSON", False, str(e))

    # 5d. POST avec body texte brut
    try:
        data = await call_tool("http", {
            "url": "https://httpbin.org/post",
            "method": "POST",
            "body": "Hello from MCP Tools"
        })
        ok = data.get("status") == "success" and data.get("status_code") == 200
        record("http POST body texte", ok, f"HTTP {data.get('status_code')}")
    except Exception as e:
        record("http POST body texte", False, str(e))

    # 5e. HTTP 404 → status success (réponse reçue, pas une erreur transport)
    try:
        data = await call_tool("http", {"url": "https://httpbin.org/status/404"})
        ok = data.get("status") == "success" and data.get("status_code") == 404
        record("http 404 = success", ok, f"status={data.get('status')}, code={data.get('status_code')}")
    except Exception as e:
        record("http 404 = success", False, str(e))

    # 5f. Méthode invalide
    try:
        data = await call_tool("http", {"url": "https://httpbin.org/get", "method": "INVALID"})
        ok = data.get("status") == "error"
        record("http méthode invalide", ok, data.get("message", "?")[:60])
    except Exception as e:
        record("http méthode invalide", False, str(e))

    # 5g. Anti-SSRF : 127.0.0.1 bloqué
    try:
        data = await call_tool("http", {"url": "http://127.0.0.1:8080/test"})
        ok = data.get("status") == "error" and "privée" in data.get("message", "").lower()
        record("http SSRF 127.0.0.1 bloqué", ok, data.get("message", "?")[:60])
    except Exception as e:
        record("http SSRF 127.0.0.1 bloqué", False, str(e))

    # 5h. Anti-SSRF : 10.0.0.1 bloqué
    try:
        data = await call_tool("http", {"url": "http://10.0.0.1/admin"})
        ok = data.get("status") == "error" and "privée" in data.get("message", "").lower()
        record("http SSRF 10.0.0.1 bloqué", ok, data.get("message", "?")[:60])
    except Exception as e:
        record("http SSRF 10.0.0.1 bloqué", False, str(e))

    # 5i. Anti-SSRF : 169.254.169.254 (metadata cloud) bloqué
    try:
        data = await call_tool("http", {"url": "http://169.254.169.254/latest/meta-data"})
        ok = data.get("status") == "error" and "privée" in data.get("message", "").lower()
        record("http SSRF metadata cloud bloqué", ok, data.get("message", "?")[:60])
    except Exception as e:
        record("http SSRF metadata cloud bloqué", False, str(e))

    # 5j. Auth bearer (httpbin renvoie les headers)
    try:
        data = await call_tool("http", {
            "url": "https://httpbin.org/headers",
            "auth_type": "bearer",
            "auth_value": "test_token_123"
        })
        ok = data.get("status") == "success" and "test_token_123" in data.get("body", "")
        record("http auth bearer", ok, f"token visible dans headers={ok}")
    except Exception as e:
        record("http auth bearer", False, str(e))


async def test_06_perplexity():
    """Test 6: Outil perplexity_search (nécessite clé API)"""
    print("\n🔍 TEST 6 — Outil perplexity_search")
    print("=" * 50)

    # Vérifier si la clé est configurée
    try:
        data = await call_tool("perplexity_search", {
            "query": "Quelle est la capitale de la France ?",
            "detail_level": "brief"
        })

        if data.get("status") == "error" and "non configurée" in data.get("message", ""):
            record("perplexity_search", False, "Clé API non configurée", skipped=True)
            return

        ok = data.get("status") == "success" and len(data.get("content", "")) > 0
        content_preview = data.get("content", "")[:80]
        record("perplexity_search (brief)", ok, f"{len(data.get('content',''))} chars: {content_preview}...")

        citations = data.get("citations", [])
        if citations:
            record("perplexity citations", True, f"{len(citations)} citations")

    except Exception as e:
        record("perplexity_search", False, str(e))


async def test_06b_perplexity_doc():
    """Test 6b: Outil perplexity_doc (nécessite clé API)"""
    print("\n📚 TEST 6b — Outil perplexity_doc")
    print("=" * 50)

    # 6b-a. Doc simple (query seul)
    try:
        data = await call_tool("perplexity_doc", {
            "query": "Python asyncio"
        })

        if data.get("status") == "error" and "non configurée" in data.get("message", ""):
            record("perplexity_doc", False, "Clé API non configurée", skipped=True)
            return

        ok = data.get("status") == "success" and len(data.get("content", "")) > 0
        content_preview = data.get("content", "")[:80]
        record("perplexity_doc (query)", ok, f"{len(data.get('content',''))} chars: {content_preview}...")
    except Exception as e:
        record("perplexity_doc (query)", False, str(e))

    # 6b-b. Doc avec context
    try:
        data = await call_tool("perplexity_doc", {
            "query": "Python asyncio",
            "context": "TaskGroup et gestion des exceptions"
        })

        ok = data.get("status") == "success" and len(data.get("content", "")) > 0
        has_query = data.get("query") == "Python asyncio"
        has_context = data.get("context") == "TaskGroup et gestion des exceptions"
        record("perplexity_doc (context)", ok and has_query and has_context,
               f"query={has_query}, context={has_context}, {len(data.get('content',''))} chars")
    except Exception as e:
        record("perplexity_doc (context)", False, str(e))

    # 6b-c. Citations présentes
    try:
        citations = data.get("citations", [])
        if citations:
            record("perplexity_doc citations", True, f"{len(citations)} citations")
    except Exception as e:
        record("perplexity_doc citations", False, str(e))


async def test_07_date():
    """Test 7: Outil date (manipulation dates/heures)"""
    print("\n🗓️ TEST 7 — Outil date")
    print("=" * 50)

    # 7a. now (UTC)
    try:
        data = await call_tool("date", {"operation": "now"})
        ok = data.get("status") == "success" and "datetime" in data
        record("date now (UTC)", ok, f"datetime={data.get('datetime', '?')[:25]}")
    except Exception as e:
        record("date now (UTC)", False, str(e))

    # 7b. now avec timezone
    try:
        data = await call_tool("date", {"operation": "now", "tz": "Europe/Paris"})
        ok = data.get("status") == "success" and "+01:00" in data.get("datetime", "") or "+02:00" in data.get("datetime", "")
        record("date now (Europe/Paris)", ok, f"datetime={data.get('datetime', '?')[:25]}")
    except Exception as e:
        record("date now (Europe/Paris)", False, str(e))

    # 7c. today
    try:
        data = await call_tool("date", {"operation": "today"})
        ok = data.get("status") == "success" and "date" in data
        record("date today", ok, f"date={data.get('date', '?')}")
    except Exception as e:
        record("date today", False, str(e))

    # 7d. parse ISO
    try:
        data = await call_tool("date", {"operation": "parse", "date": "2026-03-06T10:30:00"})
        ok = data.get("status") == "success" and "2026-03-06" in data.get("datetime", "")
        record("date parse ISO", ok, f"datetime={data.get('datetime', '?')}")
    except Exception as e:
        record("date parse ISO", False, str(e))

    # 7e. parse format DD/MM/YYYY
    try:
        data = await call_tool("date", {"operation": "parse", "date": "06/03/2026"})
        ok = data.get("status") == "success" and "2026" in data.get("datetime", "")
        record("date parse DD/MM/YYYY", ok, f"datetime={data.get('datetime', '?')}")
    except Exception as e:
        record("date parse DD/MM/YYYY", False, str(e))

    # 7f. format strftime
    try:
        data = await call_tool("date", {"operation": "format", "date": "2026-03-06", "format": "%d/%m/%Y"})
        ok = data.get("status") == "success" and data.get("result") == "06/03/2026"
        record("date format strftime", ok, f"result={data.get('result', '?')}")
    except Exception as e:
        record("date format strftime", False, str(e))

    # 7g. add (jours)
    try:
        data = await call_tool("date", {"operation": "add", "date": "2026-03-06", "days": 10})
        ok = data.get("status") == "success" and "2026-03-16" in data.get("result", "")
        record("date add +10 jours", ok, f"result={data.get('result', '?')[:16]}")
    except Exception as e:
        record("date add +10 jours", False, str(e))

    # 7h. diff entre 2 dates
    try:
        data = await call_tool("date", {"operation": "diff", "date": "2026-01-01", "date2": "2026-03-06"})
        ok = data.get("status") == "success" and data.get("diff_days") == 64
        record("date diff (64 jours)", ok, f"diff_days={data.get('diff_days', '?')}, human={data.get('diff_human', '?')}")
    except Exception as e:
        record("date diff (64 jours)", False, str(e))

    # 7i. week_number
    try:
        data = await call_tool("date", {"operation": "week_number", "date": "2026-03-06"})
        ok = data.get("status") == "success" and isinstance(data.get("week_number"), int)
        record("date week_number", ok, f"week={data.get('week_number', '?')}")
    except Exception as e:
        record("date week_number", False, str(e))

    # 7j. day_of_week
    try:
        data = await call_tool("date", {"operation": "day_of_week", "date": "2026-03-06"})
        ok = data.get("status") == "success" and data.get("day_name_en") == "Friday"
        record("date day_of_week", ok, f"day={data.get('day_name_en', '?')} ({data.get('day_name_fr', '?')})")
    except Exception as e:
        record("date day_of_week", False, str(e))

    # 7k. opération invalide
    try:
        data = await call_tool("date", {"operation": "invalid_op"})
        ok = data.get("status") == "error" and "inconnue" in data.get("message", "").lower()
        record("date opération invalide", ok, data.get("message", "?")[:60])
    except Exception as e:
        record("date opération invalide", False, str(e))

    # 7l. timezone invalide
    try:
        data = await call_tool("date", {"operation": "now", "tz": "Invalid/Zone"})
        ok = data.get("status") == "error" and "fuseau" in data.get("message", "").lower()
        record("date timezone invalide", ok, data.get("message", "?")[:60])
    except Exception as e:
        record("date timezone invalide", False, str(e))


async def test_08_calc():
    """Test 8: Outil calc (sandbox Python)"""
    print("\n🧮 TEST 8 — Outil calc (sandbox Python)")
    print("=" * 50)

    # 8a. Arithmétique simple
    try:
        data = await call_tool("calc", {"expr": "17.5 + 42.3"})
        ok = data.get("status") == "success" and data.get("result") == 59.8
        record("calc 17.5+42.3", ok, f"result={data.get('result', '?')}")
    except Exception as e:
        record("calc addition", False, str(e))

    # 8b. Priorité des opérations
    try:
        data = await call_tool("calc", {"expr": "2 + 3 * 4"})
        ok = data.get("status") == "success" and data.get("result") == 14
        record("calc priorité (2+3*4=14)", ok, f"result={data.get('result', '?')}")
    except Exception as e:
        record("calc priorité", False, str(e))

    # 8c. Parenthèses complexes
    try:
        data = await call_tool("calc", {"expr": "(3 + 5) * (2 - 1) + (10 / 2)"})
        ok = data.get("status") == "success" and data.get("result") == 13.0
        record("calc parenthèses complexes", ok, f"result={data.get('result', '?')}")
    except Exception as e:
        record("calc parenthèses", False, str(e))

    # 8d. Puissance
    try:
        data = await call_tool("calc", {"expr": "2 ** 10"})
        ok = data.get("status") == "success" and data.get("result") == 1024
        record("calc puissance (2¹⁰=1024)", ok, f"result={data.get('result', '?')}")
    except Exception as e:
        record("calc puissance", False, str(e))

    # 8e. Division par zéro
    try:
        data = await call_tool("calc", {"expr": "42 / 0"})
        ok = data.get("status") == "error"
        record("calc division par zéro", ok, data.get("message", "?")[:60])
    except Exception as e:
        record("calc division par zéro", False, str(e))

    # 8f. math.sqrt + abs
    try:
        data = await call_tool("calc", {"expr": "math.sqrt(144) + abs(-5)"})
        ok = data.get("status") == "success" and data.get("result") == 17.0
        record("calc math.sqrt+abs", ok, f"result={data.get('result', '?')}")
    except Exception as e:
        record("calc math.sqrt+abs", False, str(e))

    # 8g. math.pi
    try:
        data = await call_tool("calc", {"expr": "round(2 * math.pi, 4)"})
        ok = data.get("status") == "success" and data.get("result") == 6.2832
        record("calc 2*π arrondi", ok, f"result={data.get('result', '?')}")
    except Exception as e:
        record("calc 2*pi", False, str(e))

    # 8h. statistics.mean
    try:
        data = await call_tool("calc", {"expr": "statistics.mean([10, 20, 30, 40, 50])"})
        ok = data.get("status") == "success" and data.get("result") == 30
        record("calc statistics.mean", ok, f"result={data.get('result', '?')}")
    except Exception as e:
        record("calc statistics.mean", False, str(e))

    # 8i. statistics.median
    try:
        data = await call_tool("calc", {"expr": "statistics.median([3, 1, 4, 1, 5, 9, 2, 6])"})
        ok = data.get("status") == "success" and data.get("result") == 3.5
        record("calc statistics.median", ok, f"result={data.get('result', '?')}")
    except Exception as e:
        record("calc statistics.median", False, str(e))

    # 8j. Sandbox active
    try:
        data = await call_tool("calc", {"expr": "1 + 1"})
        is_sandbox = data.get("sandbox", None)
        record("calc sandbox active", is_sandbox is True, f"sandbox={is_sandbox}")
    except Exception as e:
        record("calc sandbox active", False, str(e))

    # 8k. Grand nombre (pas d'overflow)
    try:
        data = await call_tool("calc", {"expr": "2 ** 100"})
        ok = data.get("status") == "success" and data.get("result") == 1267650600228229401496703205376
        record("calc 2¹⁰⁰ (grand nombre)", ok, f"result={str(data.get('result', '?'))[:30]}")
    except Exception as e:
        record("calc grand nombre", False, str(e))

    # 8l. Erreur syntaxe
    try:
        data = await call_tool("calc", {"expr": "2 +* 3"})
        ok = data.get("status") == "error"
        record("calc erreur syntaxe", ok, data.get("message", "?")[:60])
    except Exception as e:
        record("calc erreur syntaxe", False, str(e))


async def test_09_ssh():
    """Test 9: Outil ssh (sandbox Docker avec réseau)"""
    print("\n🔑 TEST 9 — Outil ssh (sandbox)")
    print("=" * 50)

    # 9a. Opération invalide
    try:
        data = await call_tool("ssh", {"host": "example.com", "username": "test", "operation": "invalid_op"})
        ok = data.get("status") == "error" and "non supportée" in data.get("message", "")
        record("ssh opération invalide", ok, data.get("message", "?")[:60])
    except Exception as e:
        record("ssh opération invalide", False, str(e))

    # 9b. Host invalide (injection)
    try:
        data = await call_tool("ssh", {"host": "host; rm -rf /", "username": "test", "operation": "status", "password": "test"})
        ok = data.get("status") == "error" and "invalide" in data.get("message", "").lower()
        record("ssh injection host bloquée", ok, data.get("message", "?")[:60])
    except Exception as e:
        record("ssh injection host bloquée", False, str(e))

    # 9c. Username invalide
    try:
        data = await call_tool("ssh", {"host": "example.com", "username": "user;hack", "operation": "status", "password": "test"})
        ok = data.get("status") == "error" and "invalide" in data.get("message", "").lower()
        record("ssh username invalide", ok, data.get("message", "?")[:60])
    except Exception as e:
        record("ssh username invalide", False, str(e))

    # 9d. Auth type invalide
    try:
        data = await call_tool("ssh", {"host": "example.com", "username": "test", "auth_type": "invalid"})
        ok = data.get("status") == "error" and "non supporté" in data.get("message", "")
        record("ssh auth_type invalide", ok, data.get("message", "?")[:60])
    except Exception as e:
        record("ssh auth_type invalide", False, str(e))

    # 9e. Password manquant pour auth password
    try:
        data = await call_tool("ssh", {"host": "example.com", "username": "test", "auth_type": "password"})
        ok = data.get("status") == "error" and "password" in data.get("message", "").lower()
        record("ssh password requis", ok, data.get("message", "?")[:60])
    except Exception as e:
        record("ssh password requis", False, str(e))

    # 9f. Private key manquante pour auth key
    try:
        data = await call_tool("ssh", {"host": "example.com", "username": "test", "auth_type": "key"})
        ok = data.get("status") == "error" and "private_key" in data.get("message", "").lower()
        record("ssh private_key requis", ok, data.get("message", "?")[:60])
    except Exception as e:
        record("ssh private_key requis", False, str(e))

    # 9g. Exec sans commande
    try:
        data = await call_tool("ssh", {"host": "example.com", "username": "test", "operation": "exec", "password": "test"})
        ok = data.get("status") == "error" and "command" in data.get("message", "").lower()
        record("ssh exec sans commande", ok, data.get("message", "?")[:60])
    except Exception as e:
        record("ssh exec sans commande", False, str(e))

    # 9h. Download sans remote_path
    try:
        data = await call_tool("ssh", {"host": "example.com", "username": "test", "operation": "download", "password": "test"})
        ok = data.get("status") == "error" and "remote_path" in data.get("message", "").lower()
        record("ssh download sans remote_path", ok, data.get("message", "?")[:60])
    except Exception as e:
        record("ssh download sans remote_path", False, str(e))

    # 9i. Upload sans contenu
    try:
        data = await call_tool("ssh", {"host": "example.com", "username": "test", "operation": "upload", "password": "test", "remote_path": "/tmp/test"})
        ok = data.get("status") == "error" and "content" in data.get("message", "").lower()
        record("ssh upload sans contenu", ok, data.get("message", "?")[:60])
    except Exception as e:
        record("ssh upload sans contenu", False, str(e))

    # 9j. Status vers host inaccessible (sandbox, timeout court)
    try:
        data = await call_tool("ssh", {
            "host": "192.0.2.1",
            "username": "test",
            "operation": "status",
            "password": "test",
            "timeout": 5,
        })
        # Doit échouer (host RFC 5737 non routable) mais prouver que la sandbox fonctionne
        ok = data.get("status") == "error"
        is_sandbox = data.get("sandbox", None)
        record("ssh status host inaccessible", ok, f"sandbox={is_sandbox}, exit={data.get('exit_code', '?')}")
    except Exception as e:
        record("ssh status host inaccessible", False, str(e))


async def test_10_files():
    """Test 10: Outil files (S3 Dell ECS, sandbox Docker)"""
    print("\n📁 TEST 10 — Outil files (S3 sandbox)")
    print("=" * 50)

    # --- Tests de validation (pas besoin de S3) ---

    # 10a. Opération invalide
    try:
        data = await call_tool("files", {"operation": "invalid_op"})
        ok = data.get("status") == "error" and "non supportée" in data.get("message", "")
        record("files opération invalide", ok, data.get("message", "?")[:60])
    except Exception as e:
        record("files opération invalide", False, str(e))

    # 10b. Read sans path
    try:
        data = await call_tool("files", {"operation": "read"})
        ok = data.get("status") == "error" and "path" in data.get("message", "").lower()
        record("files read sans path", ok, data.get("message", "?")[:60])
    except Exception as e:
        record("files read sans path", False, str(e))

    # 10c. Write sans content
    try:
        data = await call_tool("files", {"operation": "write", "path": "test.txt"})
        ok = data.get("status") == "error" and "content" in data.get("message", "").lower()
        record("files write sans content", ok, data.get("message", "?")[:60])
    except Exception as e:
        record("files write sans content", False, str(e))

    # 10d. Diff sans path2
    try:
        data = await call_tool("files", {"operation": "diff", "path": "a.txt"})
        ok = data.get("status") == "error" and "path2" in data.get("message", "").lower()
        record("files diff sans path2", ok, data.get("message", "?")[:60])
    except Exception as e:
        record("files diff sans path2", False, str(e))

    # --- Tests S3 réels (nécessitent credentials) ---
    test_key = "mcp-tools-test/e2e-test.txt"
    test_key2 = "mcp-tools-test/e2e-test2.txt"
    test_content_v1 = "Hello from MCP Tools E2E test!"
    test_content_v2 = "Hello from MCP Tools E2E test v2 - MODIFIED!"

    # 10e. Write v1
    try:
        data = await call_tool("files", {
            "operation": "write",
            "path": test_key,
            "content": test_content_v1,
        })
        if data.get("status") == "error" and ("non configuré" in data.get("message", "") or "endpoint" in data.get("message", "").lower()):
            record("files S3 write", False, "S3 non configuré", skipped=True)
            return  # Skip les tests S3 suivants
        ok = data.get("status") == "success"
        record("files S3 write v1", ok, data.get("message", "?")[:60])
    except Exception as e:
        record("files S3 write v1", False, str(e))
        return

    # 10f. Sandbox active
    try:
        is_sandbox = data.get("sandbox", None)
        record("files sandbox active", is_sandbox is True, f"sandbox={is_sandbox}")
    except Exception as e:
        record("files sandbox active", False, str(e))

    # 10g. Read v1
    try:
        data = await call_tool("files", {
            "operation": "read",
            "path": test_key,
        })
        ok = data.get("status") == "success" and data.get("content", "").strip() == test_content_v1
        record("files S3 read v1", ok, f"content={data.get('content', '?')[:40]}")
    except Exception as e:
        record("files S3 read v1", False, str(e))

    # 10h. Info (HEAD)
    try:
        data = await call_tool("files", {
            "operation": "info",
            "path": test_key,
        })
        ok = data.get("status") == "success" and data.get("size", 0) > 0
        record("files S3 info", ok, f"size={data.get('size', '?')}, etag={data.get('etag', '?')[:20]}")
    except Exception as e:
        record("files S3 info", False, str(e))

    # 10i. List (au moins 1 objet)
    try:
        data = await call_tool("files", {
            "operation": "list",
            "prefix": "mcp-tools-test/",
        })
        ok = data.get("status") == "success" and data.get("count", 0) >= 1
        record("files S3 list", ok, f"count={data.get('count', '?')}")
    except Exception as e:
        record("files S3 list", False, str(e))

    # 10j. Overwrite — Write v2 (même clé, contenu modifié)
    try:
        data = await call_tool("files", {
            "operation": "write",
            "path": test_key,
            "content": test_content_v2,
        })
        ok = data.get("status") == "success"
        record("files S3 write v2 (overwrite)", ok, data.get("message", "?")[:60])
    except Exception as e:
        record("files S3 write v2 (overwrite)", False, str(e))

    # 10k. Read v2 — vérifier la modification
    try:
        data = await call_tool("files", {
            "operation": "read",
            "path": test_key,
        })
        ok = data.get("status") == "success" and "MODIFIED" in data.get("content", "")
        record("files S3 read v2 (modified)", ok, f"contient MODIFIED={ok}")
    except Exception as e:
        record("files S3 read v2 (modified)", False, str(e))

    # 10l. Write 2ème fichier + Diff
    try:
        await call_tool("files", {
            "operation": "write",
            "path": test_key2,
            "content": test_content_v1,
        })
        data = await call_tool("files", {
            "operation": "diff",
            "path": test_key,
            "path2": test_key2,
        })
        ok = data.get("status") == "success" and not data.get("identical", True)
        record("files S3 diff", ok, f"identical={data.get('identical', '?')}")
    except Exception as e:
        record("files S3 diff", False, str(e))

    # --- Tests versioning S3 (skip si non supporté) ---

    # 10m. Versions — lister les versions de test_key
    versioning_supported = False
    vid_v1 = ""
    try:
        data = await call_tool("files", {
            "operation": "versions",
            "path": test_key,
        })
        versions = data.get("versions", [])
        # Si on a au moins 2 versions, le versioning est actif
        if data.get("status") == "success" and len(versions) >= 2:
            versioning_supported = True
            ok = True
            record("files S3 versions", ok, f"count={data.get('count', '?')}")
            # Identifier v1 (pas latest) et v2 (latest)
            v_latest = [v for v in versions if v.get("is_latest")]
            v_old = [v for v in versions if not v.get("is_latest")]
            vid_v1 = v_old[0]["version_id"] if v_old else ""
            vid_v2 = v_latest[0]["version_id"] if v_latest else ""
            if VERBOSE and versions:
                for v in versions:
                    latest = " ⭐" if v.get("is_latest") else ""
                    log(f"  {v['version_id'][:20]}... size={v['size']}{latest}", "info")
        elif data.get("status") == "success" and len(versions) < 2:
            record("files S3 versions", False, "Versioning non actif sur le bucket", skipped=True)
        else:
            record("files S3 versions", False, data.get("message", "?")[:60], skipped=True)
    except Exception as e:
        record("files S3 versions", False, str(e), skipped=True)

    if versioning_supported and vid_v1:
        # 10n. Read v1 par version_id
        try:
            data = await call_tool("files", {
                "operation": "read",
                "path": test_key,
                "version_id": vid_v1,
            })
            ok = data.get("status") == "success" and test_content_v1 in data.get("content", "")
            record("files S3 read v1 (version_id)", ok, f"content={data.get('content', '?')[:40]}")
        except Exception as e:
            record("files S3 read v1 (version_id)", False, str(e))

        # 10o. Read latest = v2
        try:
            data = await call_tool("files", {
                "operation": "read",
                "path": test_key,
            })
            ok = data.get("status") == "success" and "MODIFIED" in data.get("content", "")
            record("files S3 read latest = v2", ok, f"contient MODIFIED={ok}")
        except Exception as e:
            record("files S3 read latest = v2", False, str(e))

    # --- Cleanup ---

    # 10p. Delete fichier 1
    try:
        data = await call_tool("files", {"operation": "delete", "path": test_key})
        ok = data.get("status") == "success"
        record("files S3 delete file 1", ok, data.get("message", "?")[:40])
    except Exception as e:
        record("files S3 delete file 1", False, str(e))

    if versioning_supported:
        # 10q. Delete markers présents après soft delete
        try:
            data = await call_tool("files", {
                "operation": "versions",
                "path": test_key,
            })
            markers = data.get("delete_markers", [])
            ok = len(markers) > 0
            record("files S3 delete markers", ok, f"markers={len(markers)}, versions={data.get('count', '?')}")
        except Exception as e:
            record("files S3 delete markers", False, str(e))

        # 10r. Read v1 toujours accessible par version_id après soft delete
        if vid_v1:
            try:
                data = await call_tool("files", {
                    "operation": "read",
                    "path": test_key,
                    "version_id": vid_v1,
                })
                ok = data.get("status") == "success" and test_content_v1 in data.get("content", "")
                record("files S3 v1 accessible après delete", ok, f"content={data.get('content', '?')[:40]}")
            except Exception as e:
                record("files S3 v1 accessible après delete", False, str(e))

    # 10s. Delete fichier 2
    try:
        data = await call_tool("files", {"operation": "delete", "path": test_key2})
        ok = data.get("status") == "success"
        record("files S3 delete file 2", ok, data.get("message", "?")[:40])
    except Exception as e:
        record("files S3 delete file 2", False, str(e))

    # 10t. List vide après cleanup
    try:
        data = await call_tool("files", {
            "operation": "list",
            "prefix": "mcp-tools-test/",
        })
        ok = data.get("status") == "success" and data.get("count", -1) == 0
        record("files S3 list vide (cleanup)", ok, f"count={data.get('count', '?')}")
    except Exception as e:
        record("files S3 list vide (cleanup)", False, str(e))


async def test_11_token():
    """Test 11: Outil token (gestion des tokens, admin)"""
    print("\n🔑 TEST 11 — Outil token (gestion tokens)")
    print("=" * 50)

    created_token = None
    test_client = "e2e-test-agent"

    # 11a. Opération invalide
    try:
        data = await call_tool("token", {"operation": "invalid_op"})
        ok = data.get("status") == "error" and "non supportée" in data.get("message", "")
        record("token opération invalide", ok, data.get("message", "?")[:60])
    except Exception as e:
        record("token opération invalide", False, str(e))

    # 11b. Create sans client_name
    try:
        data = await call_tool("token", {"operation": "create"})
        ok = data.get("status") == "error" and "client_name" in data.get("message", "").lower()
        record("token create sans name", ok, data.get("message", "?")[:60])
    except Exception as e:
        record("token create sans name", False, str(e))

    # 11c. Create token avec tool_ids restreints
    try:
        data = await call_tool("token", {
            "operation": "create",
            "client_name": test_client,
            "tool_ids": ["date", "calc"],
            "permissions": ["read", "write"],
            "expires_days": 1,
        })
        if data.get("status") == "error" and "S3" in data.get("message", ""):
            record("token create", False, "S3 non disponible pour tokens", skipped=True)
            return
        ok = data.get("status") == "success" and "token" in data
        created_token = data.get("token", "")
        record("token create", ok, f"client={data.get('client_name', '?')}, tool_ids={data.get('tool_ids', [])}")
    except Exception as e:
        record("token create", False, str(e))
        return

    # 11d. Create doublon refusé
    try:
        data = await call_tool("token", {
            "operation": "create",
            "client_name": test_client,
            "tool_ids": ["shell"],
        })
        ok = data.get("status") == "error" and "existe déjà" in data.get("message", "")
        record("token create doublon refusé", ok, data.get("message", "?")[:60])
    except Exception as e:
        record("token create doublon refusé", False, str(e))

    # 11e. List contient le token créé
    try:
        data = await call_tool("token", {"operation": "list"})
        ok = data.get("status") == "success" and data.get("count", 0) >= 1
        found = any(t.get("client_name") == test_client for t in data.get("tokens", []))
        record("token list", ok and found, f"count={data.get('count', '?')}, found={found}")
    except Exception as e:
        record("token list", False, str(e))

    # 11f. Info du token
    try:
        data = await call_tool("token", {"operation": "info", "client_name": test_client})
        ok = data.get("status") == "success" and data.get("client_name") == test_client
        record("token info", ok, f"client={data.get('client_name', '?')}, expired={data.get('expired', '?')}")
    except Exception as e:
        record("token info", False, str(e))

    # 11g. Auth avec le token client — outil autorisé (date)
    if created_token:
        try:
            from mcp import ClientSession
            from mcp.client.streamable_http import streamablehttp_client

            headers = {"Authorization": f"Bearer {created_token}"}
            async with streamablehttp_client(
                f"{BASE_URL}/mcp", headers=headers, timeout=15, sse_read_timeout=30,
            ) as (read, write, _):
                async with ClientSession(read, write) as session:
                    await session.initialize()
                    result = await session.call_tool("date", {"operation": "now"})
                    text = getattr(result.content[0], "text", "") if result.content else ""
                    data = json.loads(text) if text else {}
                    ok = data.get("status") == "success"
                    record("token auth → date (autorisé)", ok, f"datetime={data.get('datetime', '?')[:20]}")
        except Exception as e:
            record("token auth → date (autorisé)", False, str(e))

    # 11h. Auth avec le token client — outil interdit (shell)
    if created_token:
        try:
            from mcp import ClientSession
            from mcp.client.streamable_http import streamablehttp_client

            headers = {"Authorization": f"Bearer {created_token}"}
            async with streamablehttp_client(
                f"{BASE_URL}/mcp", headers=headers, timeout=15, sse_read_timeout=30,
            ) as (read, write, _):
                async with ClientSession(read, write) as session:
                    await session.initialize()
                    result = await session.call_tool("shell", {"command": "echo hack"})
                    text = getattr(result.content[0], "text", "") if result.content else ""
                    data = json.loads(text) if text else {}
                    ok = data.get("status") == "error" and "refusé" in data.get("message", "").lower()
                    record("token auth → shell (refusé)", ok, data.get("message", "?")[:60])
        except Exception as e:
            record("token auth → shell (refusé)", False, str(e))

    # 11i. Revoke
    try:
        data = await call_tool("token", {"operation": "revoke", "client_name": test_client})
        ok = data.get("status") == "success"
        record("token revoke", ok, data.get("message", "?")[:60])
    except Exception as e:
        record("token revoke", False, str(e))

    # 11j. Auth après revoke → 401
    if created_token:
        try:
            data = await call_rest(
                "POST", "/mcp",
                headers={"Authorization": f"Bearer {created_token}"},
                json_body={"jsonrpc": "2.0", "method": "initialize", "id": 1}
            )
            ok = data["status_code"] == 401
            record("token auth après revoke → 401", ok, f"HTTP {data['status_code']} (attendu: 401)")
        except Exception as e:
            record("token auth après revoke → 401", False, str(e))

    # 11k. List vide après revoke
    try:
        data = await call_tool("token", {"operation": "list"})
        ok = data.get("status") == "success" and data.get("count", -1) == 0
        record("token list vide après revoke", ok, f"count={data.get('count', '?')}")
    except Exception as e:
        record("token list vide après revoke", False, str(e))

    # 11l. Info token non trouvé
    try:
        data = await call_tool("token", {"operation": "info", "client_name": "inexistant"})
        ok = data.get("status") == "error" and "non trouvé" in data.get("message", "")
        record("token info non trouvé", ok, data.get("message", "?")[:60])
    except Exception as e:
        record("token info non trouvé", False, str(e))


# =============================================================================
# Main
# =============================================================================

async def test_12_admin():
    """Test 12: Console admin (/admin) — sécurité et API"""
    print("\n🛠️ TEST 12 — Console Admin (/admin)")
    print("=" * 50)

    # ── Accès public (sans auth) ──

    # 12a. GET /admin → 200 (HTML servi sans auth, login géré côté JS)
    try:
        data = await call_rest("GET", "/admin")
        ok = data["status_code"] == 200
        body = data.get("body", "")
        has_html = "MCP Tools" in str(body)
        record("admin GET /admin (HTML)", ok and has_html, f"HTTP {data['status_code']}, contient HTML={has_html}")
    except Exception as e:
        record("admin GET /admin (HTML)", False, str(e))

    # 12b. GET /admin/static/css/admin.css → 200
    try:
        data = await call_rest("GET", "/admin/static/css/admin.css")
        ok = data["status_code"] == 200
        record("admin CSS accessible", ok, f"HTTP {data['status_code']}")
    except Exception as e:
        record("admin CSS accessible", False, str(e))

    # 12c. GET /admin/static/js/app.js → 200
    try:
        data = await call_rest("GET", "/admin/static/js/app.js")
        ok = data["status_code"] == 200
        record("admin JS accessible", ok, f"HTTP {data['status_code']}")
    except Exception as e:
        record("admin JS accessible", False, str(e))

    # ── Sécurité : path traversal ──

    # 12d. Path traversal bloqué
    try:
        data = await call_rest("GET", "/admin/static/../../.env")
        ok = data["status_code"] in (404, 403)
        record("admin path traversal bloqué", ok, f"HTTP {data['status_code']} (attendu: 404)")
    except Exception as e:
        record("admin path traversal bloqué", False, str(e))

    # 12e. Fichier inexistant → 404
    try:
        data = await call_rest("GET", "/admin/static/inexistant.xyz")
        ok = data["status_code"] == 404
        record("admin fichier inexistant → 404", ok, f"HTTP {data['status_code']}")
    except Exception as e:
        record("admin fichier inexistant → 404", False, str(e))

    # ── API sans token → 401 ──

    # 12f. API health sans token → 401
    try:
        data = await call_rest("GET", "/admin/api/health")
        ok = data["status_code"] == 401
        record("admin API sans token → 401", ok, f"HTTP {data['status_code']} (attendu: 401)")
    except Exception as e:
        record("admin API sans token → 401", False, str(e))

    # 12g. API tools sans token → 401
    try:
        data = await call_rest("GET", "/admin/api/tools")
        ok = data["status_code"] == 401
        record("admin API tools sans token → 401", ok, f"HTTP {data['status_code']}")
    except Exception as e:
        record("admin API tools sans token → 401", False, str(e))

    # 12h. API tokens sans token → 401
    try:
        data = await call_rest("GET", "/admin/api/tokens")
        ok = data["status_code"] == 401
        record("admin API tokens sans token → 401", ok, f"HTTP {data['status_code']}")
    except Exception as e:
        record("admin API tokens sans token → 401", False, str(e))

    # 12i. API tools/run sans token → 401
    try:
        data = await call_rest("POST", "/admin/api/tools/run",
                                json_body={"tool_name": "date", "arguments": {"operation": "now"}})
        ok = data["status_code"] == 401
        record("admin API tools/run sans token → 401", ok, f"HTTP {data['status_code']}")
    except Exception as e:
        record("admin API tools/run sans token → 401", False, str(e))

    # ── API avec mauvais token → 401 ──

    # 12j. API health mauvais token → 401
    try:
        data = await call_rest("GET", "/admin/api/health",
                                headers={"Authorization": "Bearer bad_token_xyz"})
        ok = data["status_code"] == 401
        record("admin API mauvais token → 401", ok, f"HTTP {data['status_code']}")
    except Exception as e:
        record("admin API mauvais token → 401", False, str(e))

    # ── API avec token non-admin → 401 ──
    # (Créer un token read-only via MCP, puis tenter l'admin API)

    non_admin_token = None
    try:
        create_data = await call_tool("token", {
            "operation": "create",
            "client_name": "e2e-admin-test-readonly",
            "permissions": ["read"],
            "tool_ids": ["date"],
            "expires_days": 1,
        })
        if create_data.get("status") == "success":
            non_admin_token = create_data.get("token")
    except Exception:
        pass

    if non_admin_token:
        non_admin_headers = {"Authorization": f"Bearer {non_admin_token}"}

        # 12k. Token non-admin → health OK (200)
        try:
            data = await call_rest("GET", "/admin/api/health", headers=non_admin_headers)
            ok = data["status_code"] == 200
            record("admin non-admin → health OK", ok, f"HTTP {data['status_code']} (attendu: 200)")
        except Exception as e:
            record("admin non-admin → health OK", False, str(e))

        # 12k2. Token non-admin → tokens REFUSÉ (403)
        try:
            data = await call_rest("GET", "/admin/api/tokens", headers=non_admin_headers)
            ok = data["status_code"] == 403
            record("admin non-admin → tokens 403", ok, f"HTTP {data['status_code']} (attendu: 403)")
        except Exception as e:
            record("admin non-admin → tokens 403", False, str(e))

        # 12k3. Token non-admin → logs REFUSÉ (403)
        try:
            data = await call_rest("GET", "/admin/api/logs", headers=non_admin_headers)
            ok = data["status_code"] == 403
            record("admin non-admin → logs 403", ok, f"HTTP {data['status_code']} (attendu: 403)")
        except Exception as e:
            record("admin non-admin → logs 403", False, str(e))

        # 12k4. Token non-admin → tools filtrés par tool_ids
        try:
            data = await call_rest("GET", "/admin/api/tools", headers=non_admin_headers)
            ok = data["status_code"] == 200
            body = data.get("body", {})
            tool_names = [t["name"] for t in body.get("tools", [])] if isinstance(body, dict) else []
            # Le token a tool_ids=["date"] → ne devrait voir que date
            has_date = "date" in tool_names
            no_shell = "shell" not in tool_names
            record("admin non-admin → tools filtrés", ok and has_date and no_shell,
                   f"tools={tool_names}")
        except Exception as e:
            record("admin non-admin → tools filtrés", False, str(e))

        # Cleanup
        try:
            await call_tool("token", {"operation": "revoke", "client_name": "e2e-admin-test-readonly"})
        except Exception:
            pass
    else:
        record("admin non-admin → health OK", False, "S3 non dispo pour créer token test", skipped=True)

    # ── API avec token admin → succès ──

    admin_headers = {"Authorization": f"Bearer {TOKEN}"}

    # 12l. API health avec admin token
    try:
        data = await call_rest("GET", "/admin/api/health", headers=admin_headers)
        ok = data["status_code"] == 200
        body = data.get("body", {})
        has_tools_count = isinstance(body, dict) and body.get("tools_count", 0) > 0
        record("admin API health (admin)", ok and has_tools_count,
               f"HTTP {data['status_code']}, tools_count={body.get('tools_count', '?')}")
    except Exception as e:
        record("admin API health (admin)", False, str(e))

    # 12m. API tools — params peuplés avec enums
    try:
        data = await call_rest("GET", "/admin/api/tools", headers=admin_headers)
        ok = data["status_code"] == 200
        body = data.get("body", {})
        tools = body.get("tools", []) if isinstance(body, dict) else []
        # Vérifier que network a des params avec enum
        net = next((t for t in tools if t.get("name") == "network"), {})
        net_params = net.get("parameters", [])
        has_params = len(net_params) > 0
        op_param = next((p for p in net_params if p.get("name") == "operation"), {})
        has_enum = isinstance(op_param.get("enum"), list) and len(op_param.get("enum", [])) > 0
        record("admin API tools (params+enums)", ok and has_params and has_enum,
               f"network params={len(net_params)}, operation enum={op_param.get('enum', [])}")
    except Exception as e:
        record("admin API tools (params+enums)", False, str(e))

    # 12n. API tools/run — exécution via admin
    try:
        data = await call_rest("POST", "/admin/api/tools/run",
                                headers={**admin_headers, "Content-Type": "application/json"},
                                json_body={"tool_name": "date", "arguments": {"operation": "now"}})
        ok = data["status_code"] == 200
        body = data.get("body", {})
        has_result = isinstance(body, dict) and "result" in body
        record("admin API tools/run (date now)", ok and has_result,
               f"HTTP {data['status_code']}, duration={body.get('duration_ms', '?')}ms")
    except Exception as e:
        record("admin API tools/run (date now)", False, str(e))

    # 12o. API logs — contient des entrées
    try:
        data = await call_rest("GET", "/admin/api/logs", headers=admin_headers)
        ok = data["status_code"] == 200
        body = data.get("body", {})
        count = body.get("count", 0) if isinstance(body, dict) else 0
        record("admin API logs", ok and count > 0, f"count={count}")
    except Exception as e:
        record("admin API logs", False, str(e))

    # 12p. Route inconnue → 404
    try:
        data = await call_rest("GET", "/admin/api/inexistant", headers=admin_headers)
        ok = data["status_code"] == 404
        record("admin API route inconnue → 404", ok, f"HTTP {data['status_code']}")
    except Exception as e:
        record("admin API route inconnue → 404", False, str(e))


# Registre des tests (nom → fonction)
TEST_REGISTRY = {
    "connectivity":    test_01_connectivity,
    "auth":            test_02_auth,
    "shell":           test_03_shell,
    "network":         test_04_network,
    "http":            test_05_http,
    "perplexity":      test_06_perplexity,
    "perplexity_doc":  test_06b_perplexity_doc,
    "date":            test_07_date,
    "calc":            test_08_calc,
    "ssh":             test_09_ssh,
    "files":           test_10_files,
    "token":           test_11_token,
    "admin":           test_12_admin,
}


async def run_all_tests(only: str = None):
    """Exécute les tests. Si only est spécifié, lance uniquement ce test."""
    print("=" * 60)
    print("🧪 TEST END-TO-END — MCP Tools")
    print(f"   Serveur  : {BASE_URL}")
    print(f"   Token    : {'***' + TOKEN[-8:] if len(TOKEN) > 8 else '***'}")
    print(f"   Date     : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    if only:
        print(f"   Test     : {only}")
    print("=" * 60)

    t0 = time.monotonic()

    # Toujours vérifier la connectivité d'abord
    connected = await test_01_connectivity()
    if not connected:
        print("\n❌ ARRÊT — Impossible de se connecter au serveur")
        print(f"   Vérifiez : docker compose up -d && docker compose logs -f mcp-tools")
        return False

    if only:
        # Lancer un test spécifique
        if only == "connectivity":
            pass  # Déjà fait ci-dessus
        elif only in TEST_REGISTRY:
            await TEST_REGISTRY[only]()
        else:
            print(f"\n❌ Test inconnu: '{only}'")
            print(f"   Tests disponibles: {', '.join(TEST_REGISTRY.keys())}")
            return False
    else:
        # Lancer tous les tests
        await test_02_auth()
        await test_03_shell()
        await test_04_network()
        await test_05_http()
        await test_06_perplexity()
        await test_06b_perplexity_doc()
        await test_07_date()
        await test_08_calc()
        await test_09_ssh()
        await test_10_files()
        await test_11_token()
        await test_12_admin()

    # Résumé
    elapsed = round(time.monotonic() - t0, 1)
    total = PASS + FAIL + SKIP

    print("\n" + "=" * 60)
    print("📊 RÉSUMÉ")
    print("=" * 60)
    print(f"  Tests   : {total} total")
    print(f"  ✅ PASS  : {PASS}")
    print(f"  ❌ FAIL  : {FAIL}")
    print(f"  ⏭️ SKIP  : {SKIP}")
    print(f"  ⏱️ Durée  : {elapsed}s")
    print(f"  🔗 Transport : Streamable HTTP (/mcp)")
    print("=" * 60)

    if FAIL == 0:
        print("\n🎉 TOUS LES TESTS PASSENT !")
    else:
        print(f"\n⚠️  {FAIL} TEST(S) EN ÉCHEC")
        print("\nDétails des échecs :")
        for r in RESULTS:
            if r["status"] == "FAIL":
                print(f"  ❌ {r['test']}: {r['detail']}")

    return FAIL == 0


def main():
    global VERBOSE
    parser = argparse.ArgumentParser(
        description="Test end-to-end du service MCP Tools",
        epilog=f"Tests disponibles: {', '.join(TEST_REGISTRY.keys())}",
    )
    parser.add_argument("--verbose", "-v", action="store_true", help="Affiche les réponses complètes")
    parser.add_argument("--no-docker", action="store_true", help="Ne pas build/start docker (serveur déjà lancé)")
    parser.add_argument("--test", "-t", default=None, metavar="NOM",
                        help=f"Lancer un test spécifique ({', '.join(TEST_REGISTRY.keys())})")
    args = parser.parse_args()
    VERBOSE = args.verbose
    test_only = args.test

    use_docker = not args.no_docker

    if use_docker:
        if not docker_build_and_start():
            sys.exit(1)

        if not wait_for_server(max_wait=30):
            docker_stop()
            sys.exit(1)

    try:
        success = asyncio.run(run_all_tests(only=test_only))
    except KeyboardInterrupt:
        print("\n\n⚠️  Interrompu par l'utilisateur")
        success = False
    except Exception as e:
        print(f"\n❌ Erreur inattendue: {e}")
        if VERBOSE:
            traceback.print_exc()
        success = False
    finally:
        if use_docker:
            docker_stop()

    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
