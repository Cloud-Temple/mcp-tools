# -*- coding: utf-8 -*-
"""Persistance S3 cloisonnée par tenant et campagne.

Le seul backend de production est S3. ``MemoryObjectStore`` ne sert qu'aux
tests de contrat : il permet de démontrer les gardes sans pointer un bucket.
Toutes les clés sont construites ici ; aucun outil MCP n'accepte un bucket ou
un préfixe en paramètre.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Optional, Protocol

from .config import CybersecSettings
from .models import ValidationError, require_identifier, validate_relative_path


class ObjectNotFound(FileNotFoundError):
    pass


class ObjectAlreadyExists(FileExistsError):
    pass


class ObjectStore(Protocol):
    async def put_bytes(self, key: str, body: bytes, *, content_type: str = "application/octet-stream") -> dict: ...
    async def put_if_absent(self, key: str, body: bytes, *, content_type: str = "application/octet-stream") -> bool: ...
    async def get_bytes(self, key: str) -> bytes: ...
    async def head(self, key: str) -> dict: ...
    async def list(self, prefix: str) -> list[dict]: ...
    async def versions(self, key: str) -> list[dict]: ...


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class MemoryObjectStore:
    """Double S3 minimal, volontairement explicite et réservé aux tests."""

    def __init__(self):
        self.objects: dict[str, list[dict[str, Any]]] = {}
        self._lock = asyncio.Lock()

    async def put_bytes(self, key: str, body: bytes, *, content_type: str = "application/octet-stream") -> dict:
        async with self._lock:
            records = self.objects.setdefault(key, [])
            record = {
                "body": bytes(body),
                "content_type": content_type,
                "last_modified": _now(),
                "version_id": str(len(records) + 1),
            }
            records.append(record)
            return {"key": key, "version_id": record["version_id"], "size": len(body)}

    async def put_if_absent(self, key: str, body: bytes, *, content_type: str = "application/octet-stream") -> bool:
        async with self._lock:
            if key in self.objects:
                return False
            self.objects[key] = [{
                "body": bytes(body),
                "content_type": content_type,
                "last_modified": _now(),
                "version_id": "1",
            }]
            return True

    async def get_bytes(self, key: str) -> bytes:
        try:
            return bytes(self.objects[key][-1]["body"])
        except (KeyError, IndexError) as exc:
            raise ObjectNotFound(key) from exc

    async def head(self, key: str) -> dict:
        try:
            record = self.objects[key][-1]
        except (KeyError, IndexError) as exc:
            raise ObjectNotFound(key) from exc
        return {
            "key": key,
            "size": len(record["body"]),
            "last_modified": record["last_modified"],
            "version_id": record["version_id"],
            "content_type": record["content_type"],
        }

    async def list(self, prefix: str) -> list[dict]:
        result = []
        for key in sorted(self.objects):
            if key.startswith(prefix):
                result.append(await self.head(key))
        return result

    async def versions(self, key: str) -> list[dict]:
        if key not in self.objects:
            raise ObjectNotFound(key)
        return [
            {
                "key": key,
                "size": len(record["body"]),
                "last_modified": record["last_modified"],
                "version_id": record["version_id"],
                "content_type": record["content_type"],
            }
            for record in reversed(self.objects[key])
        ]


class S3ObjectStore:
    """Adaptateur boto3 asynchrone, sans fuite de paramètres S3 aux tools."""

    def __init__(self, settings: CybersecSettings):
        self.settings = settings
        if not settings.cybersec_s3_endpoint_url:
            raise RuntimeError("CYBERSEC_S3_ENDPOINT_URL est requis pour le runtime S3.")
        import boto3
        from botocore.config import Config

        self.client = boto3.client(
            "s3",
            endpoint_url=settings.cybersec_s3_endpoint_url,
            aws_access_key_id=settings.cybersec_s3_access_key_id,
            aws_secret_access_key=settings.cybersec_s3_secret_access_key,
            region_name=settings.cybersec_s3_region_name,
            config=Config(signature_version="s3v4", retries={"max_attempts": 3, "mode": "standard"}),
        )
        self.bucket = settings.cybersec_s3_bucket_name

    async def _call(self, name: str, **kwargs: Any) -> Any:
        try:
            return await asyncio.to_thread(getattr(self.client, name), **kwargs)
        except Exception as exc:
            code = getattr(exc, "response", {}).get("Error", {}).get("Code", "")
            if code in {"NoSuchKey", "404", "NotFound"}:
                raise ObjectNotFound(kwargs.get("Key", "")) from exc
            if code in {"PreconditionFailed", "412"}:
                raise ObjectAlreadyExists(kwargs.get("Key", "")) from exc
            raise

    async def put_bytes(self, key: str, body: bytes, *, content_type: str = "application/octet-stream") -> dict:
        result = await self._call(
            "put_object", Bucket=self.bucket, Key=key, Body=body, ContentType=content_type
        )
        return {"key": key, "version_id": result.get("VersionId"), "size": len(body)}

    async def put_if_absent(self, key: str, body: bytes, *, content_type: str = "application/octet-stream") -> bool:
        try:
            await self._call(
                "put_object",
                Bucket=self.bucket,
                Key=key,
                Body=body,
                ContentType=content_type,
                IfNoneMatch="*",
            )
            return True
        except ObjectAlreadyExists:
            return False

    async def get_bytes(self, key: str) -> bytes:
        result = await self._call("get_object", Bucket=self.bucket, Key=key)
        return await asyncio.to_thread(result["Body"].read)

    async def head(self, key: str) -> dict:
        result = await self._call("head_object", Bucket=self.bucket, Key=key)
        return {
            "key": key,
            "size": result.get("ContentLength", 0),
            "last_modified": result.get("LastModified").isoformat() if result.get("LastModified") else None,
            "version_id": result.get("VersionId"),
            "content_type": result.get("ContentType", "application/octet-stream"),
        }

    async def list(self, prefix: str) -> list[dict]:
        def list_all() -> list[dict]:
            paginator = self.client.get_paginator("list_objects_v2")
            items: list[dict] = []
            for page in paginator.paginate(Bucket=self.bucket, Prefix=prefix):
                items.extend(page.get("Contents", []))
            return items

        contents = await asyncio.to_thread(list_all)
        return [
            {
                "key": item["Key"],
                "size": item.get("Size", 0),
                "last_modified": item.get("LastModified").isoformat() if item.get("LastModified") else None,
                "version_id": None,
                "content_type": "application/octet-stream",
            }
            for item in contents
        ]

    async def versions(self, key: str) -> list[dict]:
        result = await self._call("list_object_versions", Bucket=self.bucket, Prefix=key)
        versions = [item for item in result.get("Versions", []) if item.get("Key") == key]
        if not versions:
            raise ObjectNotFound(key)
        return [
            {
                "key": item["Key"],
                "size": item.get("Size", 0),
                "last_modified": item.get("LastModified").isoformat() if item.get("LastModified") else None,
                "version_id": item.get("VersionId"),
                "content_type": "application/octet-stream",
            }
            for item in versions
        ]


@dataclass
class CybersecRepository:
    """Contrat de clés S3 du service, y compris les zones internes réservées."""

    store: ObjectStore
    prefix: str

    def __post_init__(self) -> None:
        self.prefix = self.prefix.strip("/")
        if not self.prefix:
            raise ValueError("Le préfixe S3 cybersec est requis.")

    def _tenant_root(self, tenant_id: str) -> str:
        return f"{self.prefix}/tenants/{require_identifier(tenant_id, 'tenant_id')}"

    def _campaign_root(self, tenant_id: str, campaign_id: str) -> str:
        return f"{self._tenant_root(tenant_id)}/campaigns/{require_identifier(campaign_id, 'campaign_id')}"

    def _campaign_key(self, tenant_id: str, campaign_id: str) -> str:
        return f"{self._campaign_root(tenant_id, campaign_id)}/campaign.json"

    @staticmethod
    def _json(value: Any) -> bytes:
        return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")

    async def _read_json(self, key: str) -> dict:
        try:
            value = json.loads((await self.store.get_bytes(key)).decode("utf-8"))
        except json.JSONDecodeError as exc:
            raise RuntimeError("Objet de campagne corrompu.") from exc
        if not isinstance(value, dict):
            raise RuntimeError("Objet de campagne invalide.")
        return value

    async def create_campaign(self, campaign: dict) -> bool:
        tenant_id = campaign["tenant_id"]
        campaign_id = campaign["campaign_id"]
        return await self.store.put_if_absent(
            self._campaign_key(tenant_id, campaign_id), self._json(campaign), content_type="application/json"
        )

    async def get_campaign(self, tenant_id: str, campaign_id: str) -> dict:
        return await self._read_json(self._campaign_key(tenant_id, campaign_id))

    async def save_campaign(self, campaign: dict) -> None:
        await self.store.put_bytes(
            self._campaign_key(campaign["tenant_id"], campaign["campaign_id"]),
            self._json(campaign),
            content_type="application/json",
        )

    async def list_campaigns(self, tenant_id: Optional[str] = None) -> list[dict]:
        prefix = self._tenant_root(tenant_id) if tenant_id else f"{self.prefix}/tenants/"
        items = await self.store.list(prefix)
        campaigns = []
        for item in items:
            if not item["key"].endswith("/campaign.json"):
                continue
            try:
                campaigns.append(await self._read_json(item["key"]))
            except (ObjectNotFound, RuntimeError):
                # Un objet incomplet ne doit pas masquer les autres campagnes.
                continue
        return sorted(campaigns, key=lambda item: item.get("requested_at", ""), reverse=True)

    async def save_approved_mandate(self, campaign: dict) -> str:
        root = self._campaign_root(campaign["tenant_id"], campaign["campaign_id"])
        key = f"{root}/mandates/{campaign['manifest_hash']}.json"
        await self.store.put_if_absent(key, self._json(campaign), content_type="application/json")
        return key

    def _job_key(self, tenant_id: str, campaign_id: str, job_id: str) -> str:
        return f"{self._campaign_root(tenant_id, campaign_id)}/jobs/{require_identifier(job_id, 'job_id')}.json"

    async def create_job(self, job: dict) -> bool:
        return await self.store.put_if_absent(
            self._job_key(job["tenant_id"], job["campaign_id"], job["job_id"]),
            self._json(job), content_type="application/json"
        )

    async def get_job(self, tenant_id: str, campaign_id: str, job_id: str) -> dict:
        return await self._read_json(self._job_key(tenant_id, campaign_id, job_id))

    async def save_job(self, job: dict) -> None:
        await self.store.put_bytes(
            self._job_key(job["tenant_id"], job["campaign_id"], job["job_id"]),
            self._json(job), content_type="application/json"
        )

    async def list_jobs(self, tenant_id: str, campaign_id: str) -> list[dict]:
        prefix = f"{self._campaign_root(tenant_id, campaign_id)}/jobs/"
        jobs = []
        for item in await self.store.list(prefix):
            if item["key"].endswith(".json"):
                try:
                    jobs.append(await self._read_json(item["key"]))
                except (ObjectNotFound, RuntimeError):
                    continue
        return sorted(jobs, key=lambda item: item.get("created_at", ""), reverse=True)

    def _workspace_key(self, tenant_id: str, campaign_id: str, path: str) -> str:
        return f"{self._campaign_root(tenant_id, campaign_id)}/workspace/{validate_relative_path(path)}"

    async def write_workspace(self, tenant_id: str, campaign_id: str, path: str, body: bytes, *, content_type: str = "application/octet-stream") -> dict:
        return await self.store.put_bytes(
            self._workspace_key(tenant_id, campaign_id, path), body, content_type=content_type
        )

    async def read_workspace(self, tenant_id: str, campaign_id: str, path: str) -> bytes:
        return await self.store.get_bytes(self._workspace_key(tenant_id, campaign_id, path))

    async def workspace_info(self, tenant_id: str, campaign_id: str, path: str) -> dict:
        return await self.store.head(self._workspace_key(tenant_id, campaign_id, path))

    async def workspace_versions(self, tenant_id: str, campaign_id: str, path: str) -> list[dict]:
        return await self.store.versions(self._workspace_key(tenant_id, campaign_id, path))

    async def list_workspace(self, tenant_id: str, campaign_id: str, prefix: str = "") -> list[dict]:
        safe_prefix = "" if not prefix else validate_relative_path(prefix.rstrip("/")) + "/"
        root = f"{self._campaign_root(tenant_id, campaign_id)}/workspace/{safe_prefix}"
        items = await self.store.list(root)
        base = f"{self._campaign_root(tenant_id, campaign_id)}/workspace/"
        return [{**item, "path": item["key"][len(base):]} for item in items]

    def _evidence_key(self, tenant_id: str, campaign_id: str, job_id: str, filename: str) -> str:
        filename = validate_relative_path(filename)
        if "/" in filename:
            raise ValidationError("Une preuve doit avoir un nom de fichier simple.")
        return f"{self._campaign_root(tenant_id, campaign_id)}/evidence/{require_identifier(job_id, 'job_id')}/{filename}"

    async def write_evidence(self, tenant_id: str, campaign_id: str, job_id: str, filename: str, body: bytes, *, content_type: str = "application/octet-stream") -> dict:
        key = self._evidence_key(tenant_id, campaign_id, job_id, filename)
        result = await self.store.put_bytes(key, body, content_type=content_type)
        return {"evidence_ref": f"{job_id}/{filename}", **result}

    async def read_evidence(self, tenant_id: str, campaign_id: str, evidence_ref: str) -> bytes:
        job_id, sep, filename = evidence_ref.partition("/")
        if not sep:
            raise ValidationError("Référence de preuve invalide.")
        return await self.store.get_bytes(self._evidence_key(tenant_id, campaign_id, job_id, filename))

    async def list_evidence(self, tenant_id: str, campaign_id: str, job_id: Optional[str] = None) -> list[dict]:
        root = self._campaign_root(tenant_id, campaign_id)
        prefix = f"{root}/evidence/" + (f"{require_identifier(job_id, 'job_id')}/" if job_id else "")
        items = await self.store.list(prefix)
        base = f"{root}/evidence/"
        return [{**item, "evidence_ref": item["key"][len(base):]} for item in items]

    async def write_findings(self, tenant_id: str, campaign_id: str, job_id: str, findings: list[dict]) -> str:
        key = f"{self._campaign_root(tenant_id, campaign_id)}/findings/{require_identifier(job_id, 'job_id')}.json"
        await self.store.put_bytes(key, self._json(findings), content_type="application/json")
        return f"findings/{job_id}.json"

    async def read_findings(self, tenant_id: str, campaign_id: str, job_id: str) -> list[dict]:
        key = f"{self._campaign_root(tenant_id, campaign_id)}/findings/{require_identifier(job_id, 'job_id')}.json"
        raw = await self.store.get_bytes(key)
        value = json.loads(raw.decode("utf-8"))
        return value if isinstance(value, list) else []

    def _token_key(self, token_hash: str) -> str:
        if len(token_hash) != 64 or any(char not in "0123456789abcdef" for char in token_hash):
            raise ValidationError("Référence de jeton invalide.")
        return f"{self.prefix}/_tokens/{token_hash}.json"

    async def save_token(self, token_hash: str, record: dict) -> None:
        await self.store.put_bytes(self._token_key(token_hash), self._json(record), content_type="application/json")

    async def get_token(self, token_hash: str) -> dict:
        return await self._read_json(self._token_key(token_hash))

    async def list_token_records(self) -> list[dict]:
        records = []
        for item in await self.store.list(f"{self.prefix}/_tokens/"):
            if item["key"].endswith(".json"):
                try:
                    records.append(await self._read_json(item["key"]))
                except (ObjectNotFound, RuntimeError):
                    continue
        return sorted(records, key=lambda item: item.get("created_at", ""), reverse=True)


def build_repository(settings: CybersecSettings) -> CybersecRepository:
    """Construit la persistance de production ; le fallback mémoire est interdit."""
    return CybersecRepository(S3ObjectStore(settings), settings.cybersec_s3_prefix)


def stable_job_id(tenant_id: str, campaign_id: str, tool: str, idempotency_key: str) -> str:
    """ID déterministe : même lancement => même job, y compris après reconnexion."""
    if not isinstance(idempotency_key, str) or not 8 <= len(idempotency_key) <= 128:
        raise ValidationError("La clé d'idempotence doit contenir 8 à 128 caractères.")
    digest = hashlib.sha256(f"{tenant_id}\0{campaign_id}\0{tool}\0{idempotency_key}".encode()).hexdigest()
    return f"job_{digest[:24]}"
