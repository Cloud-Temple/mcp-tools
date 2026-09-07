# -*- coding: utf-8 -*-
"""Contrats HTTP/shell/files sans socket, Docker ni cible de laboratoire."""

import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from src.mcp_cybersec.campaigns import CampaignService
from src.mcp_cybersec.config import CybersecSettings
from src.mcp_cybersec.identity import AuthorizationError
from src.mcp_cybersec.models import ValidationError
from src.mcp_cybersec.probes import DockerHttpCommandRunner, HttpService
from src.mcp_cybersec.scope import ScopeGuard
from src.mcp_cybersec.storage import CybersecRepository, MemoryObjectStore
from src.mcp_cybersec.workspace import DockerShellRunner, EvidenceService, FilesService, ShellService


MISSION = {
    "client_name": "agent-lab",
    "permissions": ["access"],
    "tool_ids": ["campaign", "scope", "http", "shell", "files", "evidence"],
    "tenant_id": "tenant-a",
}
ADMIN = {"client_name": "human-admin", "permissions": ["admin", "access"], "tool_ids": []}


class FakeHttpRunner:
    def __init__(self, redirect=None):
        self.calls = []
        self.redirect = redirect

    async def run_once(self, **kwargs):
        self.calls.append(kwargs)
        headers = "HTTP/1.1 302 Found\r\nLocation: " + self.redirect + "\r\n\r\n" if self.redirect else "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\n"
        return {"status": "success", "returncode": 0, "headers_raw": headers, "body": "ok", "stderr": ""}


class FakeShellRunner:
    async def run(self, *, command, shell, workspace: Path, timeout):
        (workspace / "processed.txt").write_text((workspace / "input.txt").read_text().upper())
        return {"status": "success", "returncode": 0, "stdout": "done", "stderr": "", "sandbox": True, "network": False}


class CybersecWorkspaceProbesTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.repository = CybersecRepository(MemoryObjectStore(), "cybersec-test")
        self.runtime = TemporaryDirectory()
        self.addCleanup(self.runtime.cleanup)
        self.settings = CybersecSettings(cybersec_runtime_host_dir=self.runtime.name)
        self.campaigns = CampaignService(self.repository, self.settings)
        async def resolver(host):
            return ["93.184.216.34"] if host == "lab.example.test" else ["203.0.113.10"]
        self.scope = ScopeGuard(self.campaigns, resolver=resolver)
        now = datetime.now(timezone.utc)
        self.raw = {
            "mandate_ref": "MANDAT-5BIS-LAB",
            "client": "Laboratoire",
            "owner": "owner@example.test",
            "source_address": "198.51.100.10",
            "emergency_contact": "soc@example.test",
            "window": {"starts_at": (now - timedelta(minutes=1)).isoformat(), "ends_at": (now + timedelta(hours=1)).isoformat()},
            "targets": {"domains": ["lab.example.test"], "ips": [], "cidrs": [], "urls": [], "ports": [443]},
            "allowed_test_classes": ["recon", "active_standard"],
            "rate_limit": 10,
            "concurrency": 1,
        }
        self.campaign = await self.campaigns.create(self.raw, MISSION)

    async def _approved(self):
        return await self.campaigns.approve(self.campaign["campaign_id"], ADMIN, admin_tenant_id="tenant-a")

    async def test_http_does_not_call_runner_before_approval(self):
        runner = FakeHttpRunner()
        service = HttpService(self.repository, self.campaigns, self.scope, self.settings, runner)
        with self.assertRaises(AuthorizationError):
            await service.request(campaign_id=self.campaign["campaign_id"], url="https://lab.example.test/", token_info=MISSION)
        self.assertEqual([], runner.calls)

    async def test_http_redirect_outside_scope_is_blocked_before_second_request(self):
        await self._approved()
        runner = FakeHttpRunner(redirect="https://evil.example.test/")
        service = HttpService(self.repository, self.campaigns, self.scope, self.settings, runner)
        with self.assertRaises(AuthorizationError):
            await service.request(campaign_id=self.campaign["campaign_id"], url="https://lab.example.test/", token_info=MISSION)
        self.assertEqual(1, len(runner.calls))

    async def test_sensitive_http_header_is_refused(self):
        await self._approved()
        service = HttpService(self.repository, self.campaigns, self.scope, self.settings, FakeHttpRunner())
        with self.assertRaises(AuthorizationError):
            await service.request(campaign_id=self.campaign["campaign_id"], url="https://lab.example.test/", token_info=MISSION, headers={"Authorization": "Bearer hidden"})

    async def test_files_cannot_escape_campaign_workspace(self):
        files = FilesService(self.repository, self.campaigns, self.settings)
        with self.assertRaises(ValidationError):
            await files.run(campaign_id=self.campaign["campaign_id"], token_info=MISSION, operation="read", path="../_tokens/x.json")

    async def test_shell_processes_workspace_without_network_and_writes_declared_output(self):
        files = FilesService(self.repository, self.campaigns, self.settings)
        await files.run(campaign_id=self.campaign["campaign_id"], token_info=MISSION, operation="write", path="input.txt", content="hello")
        shell = ShellService(self.repository, self.campaigns, self.settings, FakeShellRunner())
        result = await shell.run(
            campaign_id=self.campaign["campaign_id"], token_info=MISSION,
            command="cat input.txt > processed.txt", input_paths=["input.txt"], output_paths=["processed.txt"],
        )
        self.assertFalse(result["network"])
        output = await files.run(campaign_id=self.campaign["campaign_id"], token_info=MISSION, operation="read", path="processed.txt")
        self.assertEqual("HELLO", output["content"])

    async def test_real_shell_runner_forces_network_none_and_no_docker_socket(self):
        """Le chemin runtime ne peut pas dériver vers un shell réseau."""
        captured = {}

        class Process:
            returncode = 0

            async def communicate(self):
                return b"ok", b""

        async def fake_subprocess(*args, **kwargs):
            captured["command"] = args
            captured["kwargs"] = kwargs
            return Process()

        runner = DockerShellRunner(self.settings)
        with TemporaryDirectory() as workspace:
            with patch("src.mcp_cybersec.workspace.asyncio.create_subprocess_exec", fake_subprocess):
                result = await runner.run(command="echo ok", shell="bash", workspace=Path(workspace), timeout=5)

        command = captured["command"]
        self.assertEqual("docker", command[0])
        self.assertIn("--network=none", command)
        self.assertIn("--read-only", command)
        self.assertIn("--cap-drop=ALL", command)
        self.assertIn("--security-opt=no-new-privileges:true", command)
        self.assertNotIn("/var/run/docker.sock", " ".join(command))
        self.assertTrue(any(value.endswith(",dst=/workspace") for value in command))
        self.assertNotIn(",rw", " ".join(command))
        self.assertTrue(result["network"] is False)

    async def test_real_http_runner_uses_valid_readwrite_and_readonly_mounts(self):
        captured = {}

        class Process:
            returncode = 0

            async def communicate(self):
                return b"", b""

        async def fake_subprocess(*args, **kwargs):
            captured["command"] = args
            captured["kwargs"] = kwargs
            return Process()

        runner = DockerHttpCommandRunner(self.settings)
        with patch("src.mcp_cybersec.probes.asyncio.create_subprocess_exec", fake_subprocess):
            result = await runner.run_once(
                url="https://lab.example.test/", address="93.184.216.34", method="POST",
                headers={}, body=b"payload", timeout=5,
            )

        command = captured["command"]
        self.assertEqual("docker", command[0])
        self.assertTrue(any(value.endswith(",dst=/output") for value in command))
        self.assertTrue(any(value.endswith(",dst=/input/body.bin,readonly") for value in command))
        self.assertNotIn(",rw", " ".join(command))
        self.assertNotIn(",ro", " ".join(command))
        self.assertEqual("success", result["status"])

    async def test_evidence_export_is_written_inside_workspace_only(self):
        evidence = EvidenceService(self.repository, self.campaigns, self.settings)
        result = await evidence.run(campaign_id=self.campaign["campaign_id"], token_info=MISSION, operation="export")
        self.assertTrue(result["workspace_path"].startswith("reports/"))
        files = FilesService(self.repository, self.campaigns, self.settings)
        exported = await files.run(campaign_id=self.campaign["campaign_id"], token_info=MISSION, operation="read", path=result["workspace_path"])
        self.assertIn(self.campaign["campaign_id"], exported["content"])


if __name__ == "__main__":
    unittest.main()
