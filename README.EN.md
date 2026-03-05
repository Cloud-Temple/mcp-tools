# 🔧 MCP Tools

> **Executable tool library for AI agents** — Cloud Temple MCP Server
>
> [Version française](README.md)

MCP Tools is a passive MCP server that exposes **tools** (shell, network, HTTP, AI search…) to autonomous agents via the **Streamable HTTP** protocol. It serves as the "toolbox" of the Cloud Temple ecosystem.

## Quick Start

### 1. Configuration

```bash
cp .env.example .env
# Edit .env with your S3, Perplexity credentials, etc.
```

### 2. Launch (Docker Compose)

```bash
docker compose build
docker compose up -d

# Verify
curl http://localhost:8082/health
# → {"status":"ok","service":"mcp-tools","version":"0.1.0","transport":"streamable-http"}
```

### 3. CLI

```bash
# Create Python venv
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# Health check (no auth required)
python scripts/mcp_cli.py health

# Service info
python scripts/mcp_cli.py about

# Execute a shell command
python scripts/mcp_cli.py run-shell "hostname && uptime"

# Network diagnostics
python scripts/mcp_cli.py ping google.com --op dig

# HTTP request
python scripts/mcp_cli.py http https://httpbin.org/get

# AI search (Perplexity)
python scripts/mcp_cli.py search "What is the MCP protocol?"

# Interactive shell
python scripts/mcp_cli.py shell
```

### 4. End-to-end test suite

```bash
# All tests (build + start + test + stop)
python scripts/test_service.py

# Specific test (shell, ping, http, perplexity, auth, connectivity)
python scripts/test_service.py --test shell

# Server already running
python scripts/test_service.py --no-docker

# Verbose (full responses)
python scripts/test_service.py --test shell -v
```

### 5. Local development (without Docker)

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
PYTHONPATH=src python -m mcp_tools
```

## Architecture

```
Internet/LAN → :8082 (WAF Caddy+Coraza) → mcp-tools:8050 (internal)
```

### ASGI Stack

```
HealthCheckMiddleware → AuthMiddleware → LoggingMiddleware → FastMCP streamable_http_app
```

### 3-layer pattern (Cloud Temple standard)

| Layer            | File                         | Role                       |
| ---------------- | ---------------------------- | -------------------------- |
| MCP Tools        | `src/mcp_tools/server.py`    | MCP API (Streamable HTTP)  |
| CLI Click        | `scripts/cli/commands.py`    | Scriptable interface       |
| Interactive Shell| `scripts/cli/shell.py`       | Interactive interface      |
| Display          | `scripts/cli/display.py`     | Shared Rich output (2+3)  |

### Available Tools (Phase 1)

| Tool               | Description                                          |
| ------------------ | ---------------------------------------------------- |
| `shell`            | Isolated Docker sandbox (bash, sh, python3, node, openssl) — no network |
| `ping`             | Network diagnostics (ping, traceroute, nslookup, dig)|
| `http`             | HTTP/REST client (GET, POST, PUT, DELETE, PATCH)     |
| `perplexity_search`| Internet search via Perplexity AI                    |
| `system_health`    | Service health check                                 |
| `system_about`     | Metadata and tool listing                            |

### Security

- **WAF Caddy + Coraza**: OWASP CRS, security headers, rate limiting
- **Bearer token auth**: Every /mcp request is authenticated
- **`tool_ids`**: Token can restrict access to a subset of tools
- **Docker sandbox**: Each shell command runs in an ephemeral isolated container (--network=none, --cap-drop=ALL, --read-only, non-root)
- **Non-root user** in Docker
- **Timeouts and limits** on all tools
- **Automatic kill** of sandbox containers on timeout

## Environment Variables

### Server (.env)

| Variable               | Description                     | Default                    |
| ---------------------- | ------------------------------- | -------------------------- |
| `WAF_PORT`             | Exposed WAF port                | `8082`                     |
| `MCP_SERVER_NAME`      | Service name                    | `mcp-tools`                |
| `MCP_SERVER_PORT`      | Internal MCP port               | `8050`                     |
| `ADMIN_BOOTSTRAP_KEY`  | Admin token (⚠️ change it!)    | `change_me_in_production`  |
| `S3_ENDPOINT_URL`      | S3 endpoint                     |                            |
| `S3_ACCESS_KEY_ID`     | S3 access key                   |                            |
| `S3_SECRET_ACCESS_KEY` | S3 secret                       |                            |
| `S3_BUCKET_NAME`       | S3 bucket                       | `mcp-tools`                |
| `PERPLEXITY_API_KEY`   | Perplexity API key              |                            |
| `PERPLEXITY_MODEL`     | Perplexity model                | `sonar-reasoning-pro`      |

### CLI Client

| Variable    | Description        | Default                   |
| ----------- | ------------------ | ------------------------- |
| `MCP_URL`   | Server URL         | `http://localhost:8082`   |
| `MCP_TOKEN` | Auth token         | (empty)                   |

## Roadmap

- **Phase 1** (current): shell, ping, http, perplexity_search — ✅
- **Phase 1** (todo): ssh, docker, files, date, calc, generate, mcp_call, perplexity_doc/chat
- **Phase 2**: git, s3, db, host_audit, ssh_diagnostics, sqlite, script_executor, email_send, pdf, doc_scraper
- **Phase 3**: imap, perplexity_api, perplexity_deprecated

## License

Apache 2.0 — Cloud Temple
