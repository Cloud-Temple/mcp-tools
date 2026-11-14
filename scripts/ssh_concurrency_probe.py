#!/usr/bin/env python3
"""Probe borné : huit appels MCP Tools SSH simultanés exécutant ``hostname``.

Le probe mesure la concurrence présentée à MCP Tools. Il ne permet pas, seul,
de distinguer le temps Docker, le temps SSH et le temps du transport MCP.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import math
import os
import time
from contextlib import AsyncExitStack
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable
from urllib.parse import urlsplit


CONCURRENCY = 8
TRANSPORT_TIMEOUT_SECONDS = 10
INITIALIZE_TIMEOUT_SECONDS = 20
TEARDOWN_TIMEOUT_SECONDS = 10


@dataclass(frozen=True)
class ProbeConfig:
    url: str
    host: str
    username: str
    expected_hostname: str
    port: int = 22
    ssh_timeout: int = 30
    setup_timeout: float = TRANSPORT_TIMEOUT_SECONDS + INITIALIZE_TIMEOUT_SECONDS
    teardown_timeout: float = TEARDOWN_TIMEOUT_SECONDS

    @property
    def call_timeout(self) -> float:
        # Le serveur accorde déjà ssh_timeout + 15 s au conteneur.
        return self.ssh_timeout + 30


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def validate_config(config: ProbeConfig) -> None:
    parsed = urlsplit(config.url)
    if parsed.scheme != "https":
        raise ValueError("MCP Tools URL must use https")
    if not parsed.hostname or parsed.username or parsed.password:
        raise ValueError("MCP Tools URL must not contain credentials")
    if parsed.query or parsed.fragment or parsed.path != "/mcp":
        raise ValueError("MCP Tools URL must end exactly with /mcp")
    if not config.host or not config.username or not config.expected_hostname:
        raise ValueError("host, username and expected hostname are required")
    if not 1 <= config.port <= 65535:
        raise ValueError("SSH port must be between 1 and 65535")
    if not 1 <= config.ssh_timeout <= 60:
        raise ValueError("SSH timeout must be between 1 and 60 seconds")


def silence_sensitive_loggers() -> None:
    # Le SDK peut journaliser le message MCP complet au niveau DEBUG.
    logging.disable(logging.CRITICAL)
    for name in ("mcp", "httpx", "httpcore"):
        logger = logging.getLogger(name)
        logger.handlers.clear()
        logger.addHandler(logging.NullHandler())
        logger.propagate = False
        logger.disabled = True


def nearest_rank(values: list[float], percentile: int) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    rank = max(1, math.ceil(percentile / 100 * len(ordered)))
    return round(ordered[rank - 1], 3)


def _text_payload(result: Any) -> dict[str, Any] | None:
    blocks = []
    for item in getattr(result, "content", []) or []:
        text = getattr(item, "text", None)
        if isinstance(text, str):
            blocks.append(text)
    if not blocks:
        return None
    if len(blocks) != 1:
        raise ValueError("ambiguous text payload")
    parsed = json.loads(blocks[0])
    if not isinstance(parsed, dict):
        raise ValueError("text payload is not an object")
    return parsed


def validate_tool_result(result: Any, expected_hostname: str) -> dict[str, Any]:
    """Valide strictement le résultat sans recopier le payload brut."""
    if getattr(result, "is_error", None) is not False:
        raise ValueError("MCP result is an error")

    structured = getattr(result, "structured_content", None)
    if structured is not None and not isinstance(structured, dict):
        raise ValueError("structured payload is not an object")
    textual = _text_payload(result)
    if structured is not None and textual is not None and structured != textual:
        raise ValueError("structured and text payloads differ")
    payload = structured if structured is not None else textual
    if not isinstance(payload, dict):
        raise ValueError("missing Tools payload")

    exit_code = payload.get("exit_code")
    stdout = payload.get("stdout")
    if payload.get("status") != "success":
        raise ValueError("Tools status is not success")
    if type(exit_code) is not int or exit_code != 0:
        raise ValueError("SSH exit code is not zero")
    if not isinstance(stdout, str):
        raise ValueError("hostname output is missing")
    lines = stdout.splitlines()
    if len(lines) != 1 or not lines[0]:
        raise ValueError("hostname output is not exactly one non-empty line")
    if lines[0] != expected_hostname:
        raise ValueError("hostname does not match expected target")

    return {
        "mcp_is_error": False,
        "tools_status": "success",
        "ssh_exit_code": 0,
        "observed_hostname": lines[0],
    }


def _no_redirect_http_client(headers=None, timeout=None, auth=None):
    import httpx2

    return httpx2.AsyncClient(
        headers=headers,
        timeout=timeout,
        auth=auth,
        follow_redirects=False,
    )


class MCPWorker:
    def __init__(self, index: int, config: ProbeConfig, token: str):
        self.index = index
        self.config = config
        self.token = token
        self.stack: AsyncExitStack | None = None
        self.session: Any = None
        self.timings: dict[str, float] = {}

    async def prepare(self) -> None:
        from mcp import ClientSession
        from mcp.client.streamable_http import streamable_http_client

        self.stack = AsyncExitStack()
        await self.stack.__aenter__()
        started = time.monotonic()
        import httpx2

        client = await self.stack.enter_async_context(
            _no_redirect_http_client(
                headers={"Authorization": f"Bearer {self.token}"},
                timeout=httpx2.Timeout(TRANSPORT_TIMEOUT_SECONDS, read=self.config.call_timeout + self.config.teardown_timeout),
            )
        )
        streams = await self.stack.enter_async_context(
            streamable_http_client(self.config.url, http_client=client)
        )
        self.timings["transport_context_enter_ms"] = (time.monotonic() - started) * 1000

        started = time.monotonic()
        self.session = await self.stack.enter_async_context(ClientSession(streams[0], streams[1]))
        async with asyncio.timeout(INITIALIZE_TIMEOUT_SECONDS):
            await self.session.initialize()
        self.timings["mcp_initialize_ms"] = (time.monotonic() - started) * 1000

    async def call(self, private_key: str) -> Any:
        return await self.session.call_tool(
            "ssh",
            {
                "host": self.config.host,
                "username": self.config.username,
                "operation": "exec",
                "auth_type": "key",
                "private_key": private_key,
                "command": "hostname",
                "sudo": False,
                "port": self.config.port,
                "timeout": self.config.ssh_timeout,
            },
        )

    async def close(self) -> None:
        if self.stack is not None:
            await self.stack.aclose()


def _empty_result(index: int, expected_hostname: str) -> dict[str, Any]:
    return {
        "index": index,
        "probe_status": "not_attempted",
        "error_category": None,
        "attempted": False,
        "call_status": "not_attempted",
        "mcp_result_received": False,
        "mcp_is_error": None,
        "tools_status": None,
        "ssh_exit_code": None,
        "expected_hostname": expected_hostname,
        "observed_hostname": None,
        "transport_context_enter_ms": None,
        "mcp_initialize_ms": None,
        "call_tool_ms": None,
        "teardown_ms": None,
        "teardown_status": "pending",
        "teardown_error_category": None,
    }


async def run_probe(
    config: ProbeConfig,
    token: str,
    private_key: str,
    worker_factory: Callable[[int, ProbeConfig, str], Any] = MCPWorker,
) -> dict[str, Any]:
    validate_config(config)
    silence_sensitive_loggers()
    started_utc = utc_now()
    started = time.monotonic()
    workers = [worker_factory(i, config, token) for i in range(CONCURRENCY)]
    results = [_empty_result(i, config.expected_hostname) for i in range(CONCURRENCY)]

    setup_done = [asyncio.Event() for _ in range(CONCURRENCY)]
    decision = asyncio.Event()
    prepared = [False] * CONCURRENCY
    release_decision = False
    dispatch_started: list[float] = []

    async def worker_lifecycle(index: int) -> None:
        try:
            try:
                async with asyncio.timeout(config.setup_timeout):
                    await workers[index].prepare()
                results[index].update(workers[index].timings)
                results[index]["probe_status"] = "ready"
                prepared[index] = True
            except TimeoutError:
                results[index].update(
                    probe_status="error", error_category="setup_timeout"
                )
            except Exception:
                results[index].update(
                    probe_status="error", error_category="setup_failed"
                )
            finally:
                setup_done[index].set()

            if prepared[index]:
                await decision.wait()

            if prepared[index] and release_decision:
                dispatch_started.append(time.monotonic())
                results[index]["attempted"] = True
                call_started = time.monotonic()
                try:
                    async with asyncio.timeout(config.call_timeout):
                        mcp_result = await workers[index].call(private_key)
                    results[index]["call_tool_ms"] = (
                        time.monotonic() - call_started
                    ) * 1000
                    results[index]["mcp_result_received"] = True
                    results[index].update(
                        validate_tool_result(mcp_result, config.expected_hostname)
                    )
                    results[index].update(
                        probe_status="success", call_status="success"
                    )
                except TimeoutError:
                    results[index].update(
                        probe_status="error",
                        call_status="error",
                        error_category="call_timeout",
                        observed_at_least_ms=round(config.call_timeout * 1000, 3),
                    )
                except Exception:
                    results[index].update(
                        probe_status="error",
                        call_status="error",
                        error_category="call_failed",
                    )
            elif prepared[index]:
                results[index].update(
                    probe_status="aborted", error_category="setup_quorum_failed"
                )
        finally:
            close_started = time.monotonic()
            try:
                async with asyncio.timeout(config.teardown_timeout):
                    await workers[index].close()
                results[index]["teardown_status"] = "success"
            except TimeoutError:
                results[index].update(
                    teardown_status="timeout",
                    teardown_error_category="teardown_timeout",
                )
            except Exception:
                results[index].update(
                    teardown_status="error",
                    teardown_error_category="teardown_failed",
                )
            results[index]["teardown_ms"] = (
                time.monotonic() - close_started
            ) * 1000

    tasks = [asyncio.create_task(worker_lifecycle(i)) for i in range(CONCURRENCY)]
    await asyncio.gather(*(event.wait() for event in setup_done))
    initialized_count = sum(prepared)
    release_decision = initialized_count == CONCURRENCY
    released = release_decision
    decision.set()
    await asyncio.gather(*tasks)

    completed_durations = [
        float(item["call_tool_ms"])
        for item in results
        if item["mcp_result_received"] and item["call_tool_ms"] is not None
    ]
    attempted = sum(bool(item["attempted"]) for item in results)
    completed = sum(bool(item["mcp_result_received"]) for item in results)
    succeeded = sum(item["call_status"] == "success" for item in results)
    teardown_failed = sum(item["teardown_status"] != "success" for item in results)
    dispatch_skew_ms = None
    if dispatch_started:
        dispatch_skew_ms = round(
            (max(dispatch_started) - min(dispatch_started)) * 1000, 3
        )

    return {
        "probe_status": (
            "success"
            if succeeded == CONCURRENCY and teardown_failed == 0
            else "error"
        ),
        "started_at_utc": started_utc,
        "finished_at_utc": utc_now(),
        "target": {
            "mcp_url": config.url,
            "ssh_host": config.host,
            "ssh_port": config.port,
            "ssh_username": config.username,
            "expected_hostname": config.expected_hostname,
        },
        "requested": CONCURRENCY,
        "initialized_count": initialized_count,
        "released": released,
        "attempted": attempted,
        "completed": completed,
        "succeeded": succeeded,
        "failed": CONCURRENCY - succeeded,
        "teardown_failed": teardown_failed,
        "dispatch_skew_ms": dispatch_skew_ms,
        "call_tool_statistics": {
            "population": "calls_with_complete_mcp_result",
            "sample_size": len(completed_durations),
            "percentile_method": "nearest_rank",
            "min_ms": round(min(completed_durations), 3) if completed_durations else None,
            "p50_ms": nearest_rank(completed_durations, 50),
            "p95_ms": nearest_rank(completed_durations, 95),
            "max_ms": round(max(completed_durations), 3) if completed_durations else None,
        },
        "total_ms": round((time.monotonic() - started) * 1000, 3),
        "results": results,
        "interpretation_limit": (
            "This probe observes concurrent MCP Tools SSH calls; it does not "
            "separate Docker, SSH and MCP transport latency."
        ),
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Launch exactly 8 concurrent MCP Tools SSH hostname calls."
    )
    parser.add_argument("--url", default=os.getenv("MCP_TOOLS_URL"), required=False)
    parser.add_argument("--host", required=True)
    parser.add_argument("--username", required=True)
    parser.add_argument("--expected-hostname", required=True)
    parser.add_argument("--port", type=int, default=22)
    parser.add_argument("--ssh-timeout", type=int, default=30)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    token = os.getenv("MCP_TOOLS_TOKEN", "")
    private_key = os.getenv("MCP_SSH_PRIVATE_KEY", "")
    try:
        if not args.url:
            raise ValueError("--url or MCP_TOOLS_URL is required")
        if not token or not private_key:
            raise ValueError(
                "MCP_TOOLS_TOKEN and MCP_SSH_PRIVATE_KEY are required"
            )
        config = ProbeConfig(
            url=args.url,
            host=args.host,
            username=args.username,
            expected_hostname=args.expected_hostname,
            port=args.port,
            ssh_timeout=args.ssh_timeout,
        )
        validate_config(config)
    except ValueError:
        print(json.dumps({"probe_status": "configuration_error"}))
        return 2

    report = asyncio.run(run_probe(config, token, private_key))
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["probe_status"] == "success" else 1


if __name__ == "__main__":
    raise SystemExit(main())
