# -*- coding: utf-8 -*-
"""Bearer tokens cybersec : hash S3, tenant obligatoire et middleware ASGI."""

from __future__ import annotations

import hashlib
import hmac
import json
import secrets
from datetime import datetime, timedelta, timezone
from typing import Optional

from .config import CybersecSettings
from .identity import current_token_info
from .models import ValidationError, iso_now, parse_utc, require_identifier
from .storage import CybersecRepository, ObjectNotFound


class CybersecTokenStore:
    """Jetons opaques dont seul le SHA-256 persiste dans S3."""

    def __init__(self, repository: CybersecRepository):
        self.repository = repository
        self._cache: dict[str, dict] = {}

    @staticmethod
    def _hash(token: str) -> str:
        return hashlib.sha256(token.encode("utf-8")).hexdigest()

    async def create(
        self,
        *,
        client_name: str,
        tenant_id: Optional[str],
        tool_ids: list[str],
        permissions: Optional[list[str]] = None,
        expires_days: int = 90,
    ) -> dict:
        if not isinstance(client_name, str) or not 2 <= len(client_name.strip()) <= 128:
            raise ValidationError("client_name token invalide.")
        permissions = permissions or ["access"]
        if not set(permissions).issubset({"access", "admin"}) or not permissions:
            raise ValidationError("Permissions token invalides.")
        if "admin" not in permissions:
            tenant_id = require_identifier(str(tenant_id or ""), "tenant_id")
            if not tool_ids:
                raise ValidationError("Un jeton de mission doit porter une allow-list tool_ids.")
        elif tenant_id:
            tenant_id = require_identifier(tenant_id, "tenant_id")
        if not isinstance(tool_ids, list) or len(tool_ids) > 32 or not all(isinstance(item, str) and item for item in tool_ids):
            raise ValidationError("tool_ids invalide.")
        if not isinstance(expires_days, int) or not 1 <= expires_days <= 3650:
            raise ValidationError("Durée de jeton invalide.")
        token = "mcpc_" + secrets.token_urlsafe(32)
        token_hash = self._hash(token)
        record = {
            "schema_version": 1,
            "client_name": client_name.strip(),
            "tenant_id": tenant_id,
            "permissions": sorted(set(permissions)),
            "tool_ids": sorted(set(tool_ids)),
            "created_at": iso_now(),
            "expires_at": (datetime.now(timezone.utc) + timedelta(days=expires_days)).isoformat(),
            "revoked_at": None,
        }
        await self.repository.save_token(token_hash, record)
        self._cache[token_hash] = record
        # Le bearer brut est uniquement restitué à la création, jamais stocké
        # ni reconstitué dans les réponses list/info.
        return {"status": "success", "token": token, **record}

    async def validate(self, token: str) -> Optional[dict]:
        token_hash = self._hash(token)
        record = self._cache.get(token_hash)
        if record is None:
            try:
                record = await self.repository.get_token(token_hash)
            except (ObjectNotFound, Exception):
                return None
            self._cache[token_hash] = record
        if record.get("revoked_at"):
            return None
        try:
            if parse_utc(record.get("expires_at"), "expires_at") <= datetime.now(timezone.utc):
                return None
        except ValidationError:
            return None
        if "admin" not in record.get("permissions", []) and not record.get("tenant_id"):
            return None
        return {
            "client_name": record.get("client_name", "unknown"),
            "tenant_id": record.get("tenant_id"),
            "permissions": record.get("permissions", []),
            "tool_ids": record.get("tool_ids", []),
        }

    async def list(self) -> list[dict]:
        return [
            {
                key: record.get(key)
                for key in ("client_name", "tenant_id", "permissions", "tool_ids", "created_at", "expires_at", "revoked_at")
            }
            for record in await self.repository.list_token_records()
        ]

    async def info(self, client_name: str) -> Optional[dict]:
        for record in await self.repository.list_token_records():
            if hmac.compare_digest(str(record.get("client_name", "")), client_name):
                return {
                    key: record.get(key)
                    for key in ("client_name", "tenant_id", "permissions", "tool_ids", "created_at", "expires_at", "revoked_at")
                }
        return None

    async def revoke(self, client_name: str, actor: str) -> bool:
        for token_hash, record in await self._records_with_hash():
            if hmac.compare_digest(str(record.get("client_name", "")), client_name):
                record["revoked_at"] = iso_now()
                record["revoked_by"] = actor[:128]
                await self.repository.save_token(token_hash, record)
                self._cache[token_hash] = record
                return True
        return False

    async def _records_with_hash(self):
        # list_token_records deliberately hides object keys. This private
        # helper only reads the service-owned token prefix, never a user path.
        records = []
        for item in await self.repository.store.list(f"{self.repository.prefix}/_tokens/"):
            key = item.get("key", "")
            if not key.endswith(".json"):
                continue
            token_hash = key.rsplit("/", 1)[-1][:-5]
            try:
                records.append((token_hash, await self.repository.get_token(token_hash)))
            except (ObjectNotFound, ValidationError):
                continue
        return records


class CybersecAuthMiddleware:
    # La SPA /admin ne transporte aucune donnée ni identité : elle demande le
    # bearer en mémoire du navigateur et toutes ses API restent authentifiées.
    # Cela conserve le contrat du service historique : /admin = 200, mais
    # /admin/api/* = 401 sans identité.
    PUBLIC_PATHS = {"/health", "/healthz", "/ready", "/favicon.ico", "/admin", "/admin/"}
    PUBLIC_PREFIXES = ("/static/", "/admin/static/")
    OAUTH_DENY_PREFIXES = ("/.well-known/",)
    OAUTH_DENY_PATHS = {"/register"}

    def __init__(self, app, settings: CybersecSettings, token_store_factory):
        self.app = app
        self.settings = settings
        self.token_store_factory = token_store_factory

    async def __call__(self, scope, receive, send):
        if scope["type"] not in {"http", "websocket"}:
            return await self.app(scope, receive, send)
        path = scope.get("path", "")
        if path in self.PUBLIC_PATHS or any(path.startswith(prefix) for prefix in self.PUBLIC_PREFIXES):
            return await self.app(scope, receive, send)
        if path in self.OAUTH_DENY_PATHS or any(path.startswith(prefix) for prefix in self.OAUTH_DENY_PREFIXES):
            return await self._error(send, 404, "Not Found")
        token = self._extract(scope)
        token_info = await self._validate(token) if token else None
        if token_info is None:
            return await self._error(send, 401, "Authorization header required ou invalide")

        # mcp_tools.observability est réutilisé dans ce processus séparé. Son
        # décorateur lit ce contexte historique ; l'alimenter ici ne partage
        # aucune identité avec le service mcp-tools déployé séparément.
        from src.mcp_tools.auth.context import current_token_info as trace_token_info

        token_context = current_token_info.set(token_info)
        trace_context = trace_token_info.set(token_info)
        try:
            await self.app(scope, receive, send)
        finally:
            trace_token_info.reset(trace_context)
            current_token_info.reset(token_context)

    @staticmethod
    def _extract(scope) -> Optional[str]:
        headers = dict(scope.get("headers", []))
        authorization = headers.get(b"authorization", b"").decode("utf-8", errors="ignore")
        return authorization[7:] if authorization.startswith("Bearer ") else None

    async def _validate(self, token: str) -> Optional[dict]:
        if hmac.compare_digest(token, self.settings.cybersec_admin_bootstrap_key):
            return {"client_name": "admin", "tenant_id": None, "permissions": ["admin", "access"], "tool_ids": []}
        try:
            return await self.token_store_factory().validate(token)
        except Exception:
            # Une indisponibilité de stockage refuse le bearer plutôt que de
            # laisser passer une identité impossible à vérifier.
            return None

    @staticmethod
    async def _error(send, status: int, message: str) -> None:
        body = json.dumps({"error": message}).encode("utf-8")
        await send({
            "type": "http.response.start", "status": status,
            "headers": [(b"content-type", b"application/json"), (b"content-length", str(len(body)).encode())],
        })
        await send({"type": "http.response.body", "body": body})
