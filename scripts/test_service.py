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


# =============================================================================
# Main
# =============================================================================

# Registre des tests (nom → fonction)
TEST_REGISTRY = {
    "connectivity": test_01_connectivity,
    "auth":         test_02_auth,
    "shell":        test_03_shell,
    "network":      test_04_network,
    "http":         test_05_http,
    "perplexity":   test_06_perplexity,
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
