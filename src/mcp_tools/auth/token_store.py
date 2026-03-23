# -*- coding: utf-8 -*-
"""
Token Store — Gestion des tokens MCP avec stockage S3 + cache mémoire.

Architecture :
  - Tokens stockés en S3 sous _tokens/{sha256_hash}.json
  - Cache in-memory avec TTL (5 min)
  - SHA-256 hash comme filename (token brut jamais stocké en S3)
  - Config hybride SigV2/SigV4 pour Dell ECS Cloud Temple

Opérations :
  - create   : Génère un token aléatoire, stocke le hash en S3
  - list     : Liste tous les tokens (sans valeur brute)
  - info     : Détails d'un token par client_name
  - revoke   : Supprime un token par client_name
  - validate : Vérifie un token brut et retourne ses infos
"""

import hashlib
import json
import secrets
import sys
import time
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional

TOKENS_PREFIX = "_tokens/"
CACHE_TTL = 300  # 5 minutes


class TokenStore:
    """Gestionnaire de tokens avec backend S3 et cache mémoire."""

    def __init__(self, settings):
        self.settings = settings
        self._cache: Dict[str, dict] = {}  # token_hash -> token_data
        self._cache_loaded_at: float = 0
        self._s3_available: bool = False

    # =========================================================================
    # S3 helpers
    # =========================================================================

    def _get_s3_clients(self):
        """Crée les clients boto3 SigV2 (data) et SigV4 (metadata)."""
        import boto3
        from botocore.config import Config as BotoConfig

        config_v2 = BotoConfig(
            region_name=self.settings.s3_region_name,
            signature_version="s3",
            s3={"addressing_style": "path"},
            retries={"max_attempts": 3, "mode": "adaptive"},
            connect_timeout=10,
            read_timeout=30,
        )
        config_v4 = BotoConfig(
            region_name=self.settings.s3_region_name,
            signature_version="s3v4",
            s3={"addressing_style": "path", "payload_signing_enabled": False},
            retries={"max_attempts": 3, "mode": "adaptive"},
            connect_timeout=10,
            read_timeout=30,
        )

        kwargs = dict(
            endpoint_url=self.settings.s3_endpoint_url,
            aws_access_key_id=self.settings.s3_access_key_id,
            aws_secret_access_key=self.settings.s3_secret_access_key,
        )

        client_v2 = boto3.client("s3", config=config_v2, **kwargs)
        client_v4 = boto3.client("s3", config=config_v4, **kwargs)
        return client_v2, client_v4

    def _s3_key(self, token_hash: str) -> str:
        return f"{TOKENS_PREFIX}{token_hash}.json"

    # =========================================================================
    # Crypto helpers
    # =========================================================================

    @staticmethod
    def hash_token(token: str) -> str:
        """SHA-256 du token brut."""
        return hashlib.sha256(token.encode()).hexdigest()

    @staticmethod
    def generate_token() -> str:
        """Génère un token aléatoire URL-safe de 43 chars."""
        return secrets.token_urlsafe(32)

    # =========================================================================
    # Initialisation / cache
    # =========================================================================

    def initialize(self) -> None:
        """Charge tous les tokens depuis S3 dans le cache. Appelé au démarrage."""
        if not self.settings.s3_endpoint_url or not self.settings.s3_access_key_id:
            print(
                "  ⚠️  Token Store: S3 non configuré — seul le bootstrap key fonctionne",
                file=sys.stderr,
                flush=True,
            )
            return

        try:
            client_v2, client_v4 = self._get_s3_clients()
            resp = client_v4.list_objects_v2(
                Bucket=self.settings.s3_bucket_name,
                Prefix=TOKENS_PREFIX,
            )

            self._cache.clear()
            for obj in resp.get("Contents", []):
                key = obj["Key"]
                if not key.endswith(".json"):
                    continue
                try:
                    r = client_v2.get_object(
                        Bucket=self.settings.s3_bucket_name, Key=key
                    )
                    data = json.loads(r["Body"].read().decode())
                    token_hash = data.get("token_hash", "")
                    if token_hash:
                        self._cache[token_hash] = data
                except Exception:
                    pass

            self._cache_loaded_at = time.monotonic()
            self._s3_available = True
            print(
                f"  🔑 Token Store: {len(self._cache)} token(s) chargés depuis S3",
                file=sys.stderr,
                flush=True,
            )

            # Migration : convertir les anciennes permissions read/write → access
            self._migrate_permissions(client_v2)

        except Exception as e:
            print(f"  ⚠️  Token Store: Erreur S3 — {e}", file=sys.stderr, flush=True)

    def _migrate_permissions(self, client_v2) -> None:
        """
        Migration forcée : remplace les permissions 'read'/'write' par 'access'.
        Réécrit les tokens modifiés en S3.
        """
        migrated = 0
        for token_hash, data in self._cache.items():
            old_perms = data.get("permissions", [])
            has_legacy = "read" in old_perms or "write" in old_perms

            if not has_legacy:
                continue

            # Construire les nouvelles permissions
            new_perms = []
            if "admin" in old_perms:
                new_perms.append("admin")
            new_perms.append("access")

            # Mettre à jour le cache
            data["permissions"] = new_perms

            # Réécrire en S3
            try:
                client_v2.put_object(
                    Bucket=self.settings.s3_bucket_name,
                    Key=self._s3_key(token_hash),
                    Body=json.dumps(data, indent=2).encode(),
                    ContentType="application/json",
                )
                migrated += 1
            except Exception as e:
                print(
                    f"  ⚠️  Migration token {data.get('client_name', '?')}: {e}",
                    file=sys.stderr,
                    flush=True,
                )

        if migrated:
            print(
                f"  🔄 Token Store: {migrated} token(s) migrés (read/write → access)",
                file=sys.stderr,
                flush=True,
            )

    def _maybe_refresh_cache(self) -> None:
        """Rafraîchit le cache si le TTL est dépassé."""
        if self._s3_available and (time.monotonic() - self._cache_loaded_at > CACHE_TTL):
            self.initialize()

    # =========================================================================
    # Validation (appelé par le middleware)
    # =========================================================================

    def validate_token(self, token: str) -> Optional[dict]:
        """
        Valide un token brut et retourne ses infos, ou None si invalide.
        Vérifie l'expiration.
        """
        self._maybe_refresh_cache()

        token_hash = self.hash_token(token)
        info = self._cache.get(token_hash)

        if info is None:
            return None

        # Vérifier l'expiration
        expires_at = info.get("expires_at")
        if expires_at:
            try:
                exp = datetime.fromisoformat(expires_at)
                if exp.tzinfo is None:
                    exp = exp.replace(tzinfo=timezone.utc)
                if exp < datetime.now(timezone.utc):
                    return None  # Token expiré
            except Exception:
                pass

        return {
            "client_name": info.get("client_name", "unknown"),
            "permissions": info.get("permissions", ["access"]),
            "tool_ids": info.get("tool_ids", []),
        }

    # =========================================================================
    # CRUD operations (appelées par le tool token)
    # =========================================================================

    def create(
        self,
        client_name: str,
        permissions: List[str],
        tool_ids: List[str],
        expires_days: int = 90,
        created_by: str = "admin",
        email: str = "",
    ) -> dict:
        """
        Crée un nouveau token. Retourne le token brut (affiché une seule fois).
        """
        # Vérifier unicité du client_name
        for data in self._cache.values():
            if data.get("client_name") == client_name:
                return {
                    "status": "error",
                    "message": f"Un token existe déjà pour '{client_name}'. Révoquez-le d'abord.",
                }

        raw_token = self.generate_token()
        token_hash = self.hash_token(raw_token)

        now = datetime.now(timezone.utc)
        expires = now + timedelta(days=expires_days) if expires_days > 0 else None

        token_data = {
            "token_hash": token_hash,
            "client_name": client_name,
            "email": email,
            "permissions": permissions,
            "tool_ids": tool_ids,
            "created_at": now.isoformat(),
            "expires_at": expires.isoformat() if expires else None,
            "created_by": created_by,
        }

        # Stocker en S3
        if self._s3_available:
            try:
                client_v2, _ = self._get_s3_clients()
                client_v2.put_object(
                    Bucket=self.settings.s3_bucket_name,
                    Key=self._s3_key(token_hash),
                    Body=json.dumps(token_data, indent=2).encode(),
                    ContentType="application/json",
                )
            except Exception as e:
                return {"status": "error", "message": f"Erreur S3 lors de la création : {e}"}
        else:
            return {"status": "error", "message": "S3 non disponible — impossible de créer un token."}

        # Mettre à jour le cache
        self._cache[token_hash] = token_data

        return {
            "status": "success",
            "token": raw_token,  # ⚠️ Affiché UNE SEULE FOIS
            "token_hash": token_hash[:16] + "...",
            "client_name": client_name,
            "email": email,
            "permissions": permissions,
            "tool_ids": tool_ids,
            "expires_at": expires.isoformat() if expires else None,
            "message": f"Token créé pour '{client_name}'. ⚠️ Sauvegardez le token, il ne sera plus affiché !",
        }

    def list_tokens(self) -> dict:
        """Liste tous les tokens (sans valeur brute)."""
        self._maybe_refresh_cache()

        tokens = []
        for data in self._cache.values():
            expired = False
            expires_at = data.get("expires_at")
            if expires_at:
                try:
                    exp = datetime.fromisoformat(expires_at)
                    if exp.tzinfo is None:
                        exp = exp.replace(tzinfo=timezone.utc)
                    expired = exp < datetime.now(timezone.utc)
                except Exception:
                    pass

            tokens.append({
                "client_name": data.get("client_name", "?"),
                "email": data.get("email", ""),
                "permissions": data.get("permissions", []),
                "tool_ids": data.get("tool_ids", []),
                "created_at": data.get("created_at", "?"),
                "expires_at": expires_at,
                "expired": expired,
                "created_by": data.get("created_by", "?"),
                "token_hash_prefix": data.get("token_hash", "?")[:16] + "...",
            })

        # Trier par date de création
        tokens.sort(key=lambda t: t.get("created_at", ""), reverse=True)

        return {
            "status": "success",
            "count": len(tokens),
            "tokens": tokens,
        }

    def info(self, client_name: str) -> dict:
        """Détails d'un token par client_name."""
        self._maybe_refresh_cache()

        for data in self._cache.values():
            if data.get("client_name") == client_name:
                expired = False
                expires_at = data.get("expires_at")
                if expires_at:
                    try:
                        exp = datetime.fromisoformat(expires_at)
                        if exp.tzinfo is None:
                            exp = exp.replace(tzinfo=timezone.utc)
                        expired = exp < datetime.now(timezone.utc)
                    except Exception:
                        pass

                return {
                    "status": "success",
                    "client_name": data.get("client_name"),
                    "email": data.get("email", ""),
                    "permissions": data.get("permissions", []),
                    "tool_ids": data.get("tool_ids", []),
                    "created_at": data.get("created_at", "?"),
                    "expires_at": expires_at,
                    "expired": expired,
                    "created_by": data.get("created_by", "?"),
                    "token_hash_prefix": data.get("token_hash", "?")[:16] + "...",
                }

        return {"status": "error", "message": f"Token '{client_name}' non trouvé."}

    def revoke(self, client_name: str) -> dict:
        """Révoque (supprime) un token par client_name."""
        self._maybe_refresh_cache()

        target_hash = None
        for h, data in self._cache.items():
            if data.get("client_name") == client_name:
                target_hash = h
                break

        if target_hash is None:
            return {"status": "error", "message": f"Token '{client_name}' non trouvé."}

        # Supprimer de S3
        if self._s3_available:
            try:
                client_v2, _ = self._get_s3_clients()
                client_v2.delete_object(
                    Bucket=self.settings.s3_bucket_name,
                    Key=self._s3_key(target_hash),
                )
            except Exception as e:
                return {"status": "error", "message": f"Erreur S3 lors de la révocation : {e}"}

        # Supprimer du cache
        del self._cache[target_hash]

        return {
            "status": "success",
            "client_name": client_name,
            "message": f"Token '{client_name}' révoqué.",
        }


# =============================================================================
# Singleton global
# =============================================================================

_token_store: Optional[TokenStore] = None


def get_token_store() -> TokenStore:
    """Retourne le singleton TokenStore."""
    global _token_store
    if _token_store is None:
        from ..config import get_settings
        _token_store = TokenStore(get_settings())
    return _token_store


def init_token_store() -> TokenStore:
    """Initialise le TokenStore (charge les tokens depuis S3)."""
    store = get_token_store()
    store.initialize()
    return store
