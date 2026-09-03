# -*- coding: utf-8 -*-
"""Contrats de sûreté du lot campagne/périmètre, sans DNS réel ni S3."""

import asyncio
import unittest
from datetime import datetime, timedelta, timezone

from src.mcp_cybersec.campaigns import CampaignService
from src.mcp_cybersec.config import CybersecSettings
from src.mcp_cybersec.identity import AuthorizationError
from src.mcp_cybersec.models import ValidationError
from src.mcp_cybersec.scope import ScopeGuard
from src.mcp_cybersec.storage import CybersecRepository, MemoryObjectStore, ObjectNotFound


MISSION = {
    "client_name": "agent-lab",
    "permissions": ["access"],
    "tool_ids": ["campaign", "scope", "network", "http", "nmap", "nuclei", "evidence", "shell", "files"],
    "tenant_id": "tenant-a",
}
ADMIN = {
    "client_name": "human-admin",
    "permissions": ["admin", "access"],
    "tool_ids": [],
}


def manifest(*, urls=None, domains=None, classes=None) -> dict:
    now = datetime.now(timezone.utc)
    return {
        "mandate_ref": "MANDAT-5BIS-LAB",
        "client": "Laboratoire",
        "owner": "owner@example.test",
        "source_address": "198.51.100.10",
        "emergency_contact": "soc@example.test",
        "window": {
            "starts_at": (now - timedelta(minutes=1)).isoformat(),
            "ends_at": (now + timedelta(hours=1)).isoformat(),
        },
        "targets": {
            "domains": domains if domains is not None else ["lab.example.test"],
            "ips": [],
            "cidrs": [],
            "urls": urls or [],
            "ports": [80, 443],
        },
        "allowed_test_classes": classes or ["recon", "active_standard"],
        "rate_limit": 5,
        "concurrency": 1,
    }


class CybersecFoundationTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.repository = CybersecRepository(MemoryObjectStore(), "cybersec-test")
        self.service = CampaignService(self.repository, CybersecSettings())

    async def _create(self, raw=None):
        return await self.service.create(raw or manifest(), MISSION)

    async def _approve(self, campaign):
        return await self.service.approve(
            campaign["campaign_id"], ADMIN, admin_tenant_id=campaign["tenant_id"]
        )

    async def test_tenant_is_derived_from_mission_token(self):
        raw = manifest()
        raw["tenant_id"] = "tenant-b"
        campaign = await self._create(raw)
        self.assertEqual("tenant-a", campaign["tenant_id"])

    async def test_mission_cannot_approve_its_campaign(self):
        campaign = await self._create()
        with self.assertRaises(AuthorizationError):
            await self.service.approve(campaign["campaign_id"], MISSION, admin_tenant_id="tenant-a")

    async def test_no_active_authorization_before_approval(self):
        campaign = await self._create()
        with self.assertRaises(AuthorizationError):
            await self.service.authorize(
                campaign["campaign_id"], MISSION, required_test_class="recon"
            )

    async def test_approval_persists_immutable_mandate_hash(self):
        campaign = await self._create()
        approved = await self._approve(campaign)
        self.assertEqual("approved", approved["status"])
        self.assertEqual(approved["manifest_hash"], approved["approval"]["manifest_hash"])
        self.assertIn("/mandates/", approved["approval"]["mandate_key"])

    async def test_other_tenant_cannot_read_campaign(self):
        campaign = await self._create()
        other = {**MISSION, "tenant_id": "tenant-b"}
        with self.assertRaises(ObjectNotFound):
            await self.service.get(campaign["campaign_id"], other)

    async def test_private_resolution_is_refused_before_network_tool(self):
        campaign = await self._approve(await self._create())

        async def resolver(_host):
            return ["127.0.0.1"]

        guard = ScopeGuard(self.service, resolver=resolver)
        with self.assertRaises(AuthorizationError):
            await guard.check(
                campaign["campaign_id"], "lab.example.test", MISSION, required_test_class="recon"
            )

    async def test_redirect_url_outside_path_is_refused(self):
        campaign = await self._approve(
            await self._create(manifest(urls=["https://lab.example.test/allowed"], domains=[]))
        )

        async def resolver(_host):
            return ["93.184.216.34"]

        guard = ScopeGuard(self.service, resolver=resolver)
        decision = await guard.check(
            campaign["campaign_id"],
            "lab.example.test",
            MISSION,
            url="https://lab.example.test/private",
        )
        self.assertFalse(decision["allowed"])
        self.assertEqual("URL absente du mandat", decision["reason"])

    async def test_ineligible_profile_is_refused(self):
        campaign = await self._approve(await self._create())
        with self.assertRaises(AuthorizationError):
            await self.service.authorize(
                campaign["campaign_id"], MISSION, required_test_class="active_extended"
            )

    async def test_manifest_refuses_private_direct_target(self):
        raw = manifest()
        raw["targets"]["ips"] = ["10.0.0.1"]
        with self.assertRaises(ValidationError):
            await self._create(raw)

    async def test_private_lab_target_requires_explicit_local_mode_and_manifest_flag(self):
        settings = CybersecSettings(cybersec_lab_mode=True, cybersec_lab_allowed_cidrs="172.30.0.0/24")
        repository = CybersecRepository(MemoryObjectStore(), "cybersec-test-lab")
        campaigns = CampaignService(repository, settings)
        raw = manifest(domains=["lab.target.test"])
        raw["laboratory"] = True
        campaign = await campaigns.create(raw, MISSION)
        await campaigns.approve(campaign["campaign_id"], ADMIN, admin_tenant_id="tenant-a")

        async def resolver(_host):
            return ["172.30.0.10"]

        guard = ScopeGuard(campaigns, resolver=resolver, settings=settings)
        decision = await guard.check(campaign["campaign_id"], "lab.target.test", MISSION, required_test_class="recon")
        self.assertTrue(decision["allowed"])
        self.assertEqual(["172.30.0.10"], decision["addresses"])


if __name__ == "__main__":
    unittest.main()
