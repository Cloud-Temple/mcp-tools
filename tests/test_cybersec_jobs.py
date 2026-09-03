# -*- coding: utf-8 -*-
"""Contrats jobs/preuves, sans Docker ni trafic réseau."""

import asyncio
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from src.mcp_cybersec.campaigns import CampaignService
from src.mcp_cybersec.config import CybersecSettings
from src.mcp_cybersec.jobs import ScanJobManager
from src.mcp_cybersec.models import ValidationError
from src.mcp_cybersec.scope import ScopeGuard
from src.mcp_cybersec.storage import CybersecRepository, MemoryObjectStore


MISSION = {
    "client_name": "agent-lab",
    "permissions": ["access"],
    "tool_ids": ["campaign", "scope", "nmap", "nuclei"],
    "tenant_id": "tenant-a",
}
ADMIN = {"client_name": "human-admin", "permissions": ["admin", "access"], "tool_ids": []}


class FakeRunner:
    def __init__(self, wait=False):
        self.calls = []
        self.cancelled = set()
        self.wait = wait
        self.started = asyncio.Event()

    async def run(self, tool, job_id, arguments, output_dir: Path, should_continue):
        self.calls.append((tool, job_id, arguments))
        self.started.set()
        while self.wait and job_id not in self.cancelled:
            if not await should_continue():
                break
            await asyncio.sleep(0.005)
        if job_id in self.cancelled or not await should_continue():
            return {
                "status": "interrupted",
                "returncode": -9,
                "artifacts": {"nmap.xml": b"<nmaprun/>"},
            }
        if tool == "nmap":
            return {
                "status": "completed",
                "returncode": 0,
                "artifacts": {
                    "nmap.xml": b'<nmaprun><host><address addr="93.184.216.34"/><ports><port protocol="tcp" portid="443"><state state="open"/><service name="https" product="test"/></port></ports></host></nmaprun>',
                    "nmap.txt": b"Nmap scan report",
                },
            }
        return {
            "status": "completed",
            "returncode": 0,
            "artifacts": {
                "nuclei.jsonl": b'{"template-id":"http-security-headers","host":"https://lab.example.test","matched-at":"https://lab.example.test","info":{"name":"Headers","severity":"low"}}\n'
            },
        }

    async def cancel(self, job_id):
        self.cancelled.add(job_id)


class CybersecJobTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.repository = CybersecRepository(MemoryObjectStore(), "cybersec-test")
        self.settings = CybersecSettings(cybersec_job_cancel_poll_seconds=0.2)
        self.campaigns = CampaignService(self.repository, self.settings)

        async def resolver(_host):
            return ["93.184.216.34"]

        self.scope = ScopeGuard(self.campaigns, resolver=resolver)
        self.runner = FakeRunner()
        self.manager = ScanJobManager(self.repository, self.campaigns, self.scope, self.settings, self.runner)
        now = datetime.now(timezone.utc)
        raw = {
            "mandate_ref": "MANDAT-5BIS-LAB",
            "client": "Laboratoire",
            "owner": "owner@example.test",
            "source_address": "198.51.100.10",
            "emergency_contact": "soc@example.test",
            "window": {"starts_at": (now - timedelta(minutes=1)).isoformat(), "ends_at": (now + timedelta(hours=1)).isoformat()},
            "targets": {"domains": ["lab.example.test"], "ips": [], "cidrs": [], "urls": [], "ports": [80, 443]},
            "allowed_test_classes": ["recon", "active_standard"],
            "rate_limit": 20,
            "concurrency": 2,
        }
        self.campaign = await self.campaigns.create(raw, MISSION)
        self.campaign = await self.campaigns.approve(self.campaign["campaign_id"], ADMIN, admin_tenant_id="tenant-a")

    async def _wait_jobs(self):
        while self.manager._tasks:
            await asyncio.sleep(0.005)

    async def test_nmap_is_async_idempotent_and_persists_evidence_findings(self):
        started = await self.manager.start_nmap(
            campaign_id=self.campaign["campaign_id"], target="lab.example.test",
            idempotency_key="same-start-key", token_info=MISSION,
            profile="quick", ports=[443],
        )
        self.assertEqual("accepted", started["status"])
        self.assertFalse(started["traffic_emitted"])
        duplicate = await self.manager.start_nmap(
            campaign_id=self.campaign["campaign_id"], target="lab.example.test",
            idempotency_key="same-start-key", token_info=MISSION,
            profile="quick", ports=[443],
        )
        self.assertTrue(duplicate["deduplicated"])
        await self._wait_jobs()
        self.assertEqual(1, len(self.runner.calls))
        job = await self.repository.get_job("tenant-a", self.campaign["campaign_id"], started["job_id"])
        self.assertEqual("completed", job["status"])
        self.assertIn(f"{started['job_id']}/nmap.xml", job["evidence_refs"])
        findings = await self.repository.read_findings("tenant-a", self.campaign["campaign_id"], started["job_id"])
        self.assertEqual("detected_to_confirm", findings[0]["status"])
        campaign = await self.repository.get_campaign("tenant-a", self.campaign["campaign_id"])
        self.assertEqual("completed", campaign["status"])

    async def test_nuclei_rejects_unversioned_template(self):
        with self.assertRaises(ValidationError):
            await self.manager.start_nuclei(
                campaign_id=self.campaign["campaign_id"], target="lab.example.test",
                idempotency_key="nuclei-unknown", token_info=MISSION,
                profile="recon", template_ids=["agent-supplied-template"],
            )

    async def test_nuclei_uses_scope_validated_ips_and_preserves_approved_host(self):
        started = await self.manager.start_nuclei(
            campaign_id=self.campaign["campaign_id"], target="https://lab.example.test/check",
            idempotency_key="nuclei-pinned-address", token_info=MISSION,
            profile="recon",
        )
        await self._wait_jobs()
        self.assertEqual("accepted", started["status"])
        _, _, arguments = self.runner.calls[0]
        targets = [arguments[index + 1] for index, value in enumerate(arguments[:-1]) if value == "-u"]
        self.assertEqual(["https://93.184.216.34/check"], targets)
        self.assertIn("Host: lab.example.test", arguments)
        self.assertIn("-sni", arguments)
        self.assertNotIn("https://lab.example.test/check", targets)

    async def test_cancel_kills_job_and_keeps_interrupted_result(self):
        self.runner = FakeRunner(wait=True)
        self.manager.runner = self.runner
        started = await self.manager.start_nmap(
            campaign_id=self.campaign["campaign_id"], target="lab.example.test",
            idempotency_key="cancel-start-key", token_info=MISSION,
            profile="quick", ports=[443],
        )
        await asyncio.wait_for(self.runner.started.wait(), timeout=1)
        cancelled_campaign = await self.campaigns.cancel(
            self.campaign["campaign_id"], MISSION, reason="test arrêt"
        )
        self.assertEqual("cancelled", cancelled_campaign["status"])
        self.assertEqual(1, await self.manager.cancel_campaign(cancelled_campaign))
        await self._wait_jobs()
        job = await self.repository.get_job("tenant-a", self.campaign["campaign_id"], started["job_id"])
        self.assertEqual("interrupted", job["status"])
        self.assertIn(f"{started['job_id']}/nmap.xml", job["evidence_refs"])


if __name__ == "__main__":
    unittest.main()
