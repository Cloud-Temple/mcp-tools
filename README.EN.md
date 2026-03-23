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
# → {"status":"healthy","service":"mcp-tools","version":"0.1.9","transport":"streamable-http"}

# Admin console
open http://localhost:8082/admin
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
python scripts/mcp_cli.py network ping google.com
python scripts/mcp_cli.py network dig google.com MX +short
python scripts/mcp_cli.py network nslookup google.com -type=mx

# HTTP request
python scripts/mcp_cli.py http https://httpbin.org/get

# Date and time
python scripts/mcp_cli.py date now --tz Europe/Paris
python scripts/mcp_cli.py date add 2026-03-06 --days 10
python scripts/mcp_cli.py date diff 2026-01-01 --date2 2026-03-06
python scripts/mcp_cli.py date day_of_week 2026-03-06

# Math calculations
python scripts/mcp_cli.py calc "2 + 3 * 4"
python scripts/mcp_cli.py calc "math.sqrt(144) + statistics.mean([10,20,30])"

# AI search (Perplexity)
python scripts/mcp_cli.py search "What is the MCP protocol?"

# Technical documentation (Perplexity)
python scripts/mcp_cli.py doc "Python asyncio"
python scripts/mcp_cli.py doc "FastAPI" --context "middleware and dependencies"

# SSH (remote execution)
python scripts/mcp_cli.py ssh exec myserver.com --user admin --password secret "uptime"
python scripts/mcp_cli.py ssh status myserver.com --user admin --password secret

# S3 files
python scripts/mcp_cli.py files list --prefix logs/
python scripts/mcp_cli.py files read config/app.yaml
python scripts/mcp_cli.py files write test.txt --content "Hello World"

# Token management (admin)
python scripts/mcp_cli.py token create agent-prod --tools shell,date,calc --expires 90
python scripts/mcp_cli.py token create ct-user --email user@cloud-temple.com --expires 180
python scripts/mcp_cli.py token list
python scripts/mcp_cli.py token info agent-prod
python scripts/mcp_cli.py token revoke agent-prod

# Interactive shell
python scripts/mcp_cli.py shell
```

### 4. End-to-end test suite

```bash
# All tests (build + start + test + stop)
python scripts/test_service.py

# Specific test (14 categories)
python scripts/test_service.py --test shell
python scripts/test_service.py --test network
python scripts/test_service.py --test http
python scripts/test_service.py --test ssh
python scripts/test_service.py --test files
python scripts/test_service.py --test token
python scripts/test_service.py --test admin
python scripts/test_service.py --test waf
python scripts/test_service.py --test date
python scripts/test_service.py --test calc

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
AdminMiddleware → HealthCheckMiddleware → AuthMiddleware → LoggingMiddleware → FastMCP streamable_http_app
```

### 3-layer pattern (Cloud Temple standard)

| Layer            | File                      | Role                       |
| ---------------- | ------------------------- | -------------------------- |
| MCP Tools        | `src/mcp_tools/server.py` | MCP API (Streamable HTTP)  |
| CLI Click        | `scripts/cli/commands.py` | Scriptable interface       |
| Interactive Shell| `scripts/cli/shell.py`    | Interactive interface      |
| Display          | `scripts/cli/display.py`  | Shared Rich output (2+3)  |

### Available Tools (12/27 — Phase 1)

> **All parameters** for each tool are documented with detailed descriptions via the MCP protocol. Compatible clients (Cline, Claude Desktop…) automatically display these descriptions.

| Tool               | Description                                                                                                                                                            |
| ------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `shell`             | Isolated Docker sandbox (bash, sh, python3, node) — no network by default, `network=true` for pip install. Pre-installed Python packages: numpy, pandas, requests, beautifulsoup4, scipy, matplotlib… |
| `network`           | Network diagnostics in Docker sandbox (ping, traceroute, nslookup, dig) — RFC 1918 private IPs blocked                                                                 |
| `http`              | HTTP/REST client in Docker sandbox (anti-SSRF, auth basic/bearer/api_key) — private IPs blocked                                                                        |
| `ssh`               | SSH command execution and file transfer in Docker sandbox (exec, status, upload, download) — password/key auth                                                          |
| `files`             | File operations on S3 Dell ECS in Docker sandbox (list, read, write, delete, info, diff, versions, enable_versioning) — hybrid SigV2/SigV4 config, S3 versioning       |
| `perplexity_search` | Internet search via Perplexity AI                                                                                                                                      |
| `perplexity_doc`    | Technical documentation for a technology/library/API via Perplexity AI                                                                                                 |
| `date`              | Date/time manipulation (now, today, diff, add, format, parse, week_number, day_of_week) — timezone support                                                             |
| `calc`              | Math calculations in Python Docker sandbox (expressions, math, statistics) — no network                                                                                |
| `token`             | MCP authentication token management (create, list, info, revoke) — admin only, tool_ids isolation, owner email                                                         |
| `system_health`     | Service health check                                                                                                                                                   |
| `system_about`      | Metadata and tool listing                                                                                                                                              |

### Admin Console (`/admin`)

A web administration interface is available at `/admin`:

```
http://localhost:8082/admin
```

**4 views**: Dashboard (server status), Tools (interactive execution with dynamic forms), Tokens (CRUD), Activity (real-time logs).

Admin authentication required (ADMIN_BOOTSTRAP_KEY or S3 token with admin permission). Cloud Temple design (dark theme). Same-origin only (no cross-origin CORS).

### Security

- **Security audit**: Full report in `DESIGN/mcp-tools/SECURITY_AUDIT.md` — architecture rated "Enterprise-grade"
- **WAF Caddy + Coraza**: OWASP CRS in blocking mode (`SecRuleEngine On`), security headers, rate limiting (1000 req/min MCP) — 6 E2E tests (`--test waf`)
- **Bearer token auth**: Every /mcp request is authenticated. Permissions: `access` (call tools) or `admin` (everything). Fail-closed: non-admin tokens with empty `tool_ids` are denied
- **`tool_ids`**: Token can restrict access to a subset of tools (per-tool whitelisting)
- **Docker sandbox**: Each shell/network/http command runs in an ephemeral isolated container (--cap-drop=ALL, --read-only, non-root)
- **S3 Token Manager**: Tokens stored in S3 Dell ECS (`_tokens/{sha256}.json`), in-memory cache TTL 5min, `tool_ids` isolation
- **Admin same-origin**: `/admin` console with no cross-origin CORS, admin auth required on API
- **Anti-SSRF**: DNS resolution + RFC 1918 / loopback / cloud metadata blocking for `http` and `network` tools
- **Non-root user** in Docker
- **Timeouts and limits** on all tools
- **Automatic kill** of sandbox containers on timeout

## Environment Variables

### Server (.env)

| Variable               | Description                  | Default                    |
| ---------------------- | ---------------------------- | -------------------------- |
| `WAF_PORT`             | Exposed WAF port             | `8082`                     |
| `MCP_SERVER_NAME`      | Service name                 | `mcp-tools`                |
| `MCP_SERVER_PORT`      | Internal MCP port            | `8050`                     |
| `ADMIN_BOOTSTRAP_KEY`  | Admin token (⚠️ change it!)| `change_me_in_production`  |
| `S3_ENDPOINT_URL`      | S3 endpoint                  |                            |
| `S3_ACCESS_KEY_ID`     | S3 access key                |                            |
| `S3_SECRET_ACCESS_KEY` | S3 secret                    |                            |
| `S3_BUCKET_NAME`       | S3 bucket                    | `mcp-tools`                |
| `PERPLEXITY_API_KEY`   | Perplexity API key           |                            |
| `PERPLEXITY_MODEL`     | Perplexity model             | `sonar-reasoning-pro`      |
| `SANDBOX_DNS`          | DNS for network sandboxes    | `8.8.8.8,8.8.4.4`         |

### CLI Client

| Variable    | Description    | Default                 |
| ----------- | -------------- | ----------------------- |
| `MCP_URL`   | Server URL     | `http://localhost:8082` |
| `MCP_TOKEN` | Auth token     | (empty)                 |

## File Structure

```
mcp-tools/
├── src/mcp_tools/
│   ├── server.py              # MCP Server + HealthCheck + banner
│   ├── config.py              # pydantic-settings configuration (sandbox, etc.)
│   ├── admin/                 # Web admin console (/admin)
│   ├── static/                # Admin static files (HTML, CSS, JS)
│   ├── auth/                  # Auth middleware + S3 Token Store
│   └── tools/                 # MCP tools (shell, network, http, perplexity)
├── sandbox/
│   └── Dockerfile             # Alpine sandbox image (python3, node, openssl…)
├── scripts/
│   ├── mcp_cli.py             # CLI entry point
│   ├── test_service.py        # E2E test suite (--test NAME to target)
│   └── cli/                   # CLI Click + Shell + Display
├── waf/                       # WAF Caddy + Coraza
├── Dockerfile                 # Python 3.11 + static docker CLI
├── docker-compose.yml         # sandbox + mcp-tools + waf + docker.sock
├── .env.example
└── VERSION
```

## Configure in Cline (VS Code / VSCodium)

To connect MCP Tools to **Cline**, add the following to your `cline_mcp_settings.json`
(accessible via ⚙️ MCP Servers in the Cline sidebar):

```json
{
  "mcpServers": {
    "mcp-tools": {
      "disabled": false,
      "timeout": 60,
      "type": "streamableHttp",
      "url": "http://localhost:8082/mcp",
      "headers": {
        "Authorization": "Bearer YOUR_TOKEN_HERE"
      }
    }
  }
}
```

| Parameter        | Value                       | Description                                                    |
| ---------------- | --------------------------- | -------------------------------------------------------------- |
| `type`           | `streamableHttp`            | **Required** — tells Cline which MCP transport to use          |
| `url`            | `http://localhost:8082/mcp` | Streamable HTTP endpoint (via WAF, **always `/mcp`**)          |
| `timeout`        | `60`                        | Timeout in seconds (recommended for long-running tools)        |
| `Authorization`  | `Bearer YOUR_TOKEN`         | Bootstrap key or S3 token                                      |
| `disabled`       | `false`                     | Allows disabling the server without removing the config        |

To create a dedicated token for Cline with specific tools:

```bash
python scripts/mcp_cli.py --token $ADMIN_BOOTSTRAP_KEY \
  token create cline-dev --tools shell,http,network,date,calc,perplexity_search --expires 365
```

> **Full guide**: see [`starter-kit/CLINE_SETUP.md`](starter-kit/CLINE_SETUP.md) for config file paths by OS, multi-server setup, debugging, etc.

## Roadmap

- **Phase 1** (current): shell, network, http, ssh, files, perplexity_search, perplexity_doc, date, calc — ✅
- **Phase 1** (todo): docker, generate, mcp_call
- **Phase 2**: git, s3, db, host_audit, ssh_diagnostics, sqlite, script_executor, email_send, pdf, doc_scraper
- **Phase 3**: imap, perplexity_api, perplexity_deprecated

## License

Apache 2.0 — Cloud Temple
