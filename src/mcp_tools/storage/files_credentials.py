"""Credentials par connexion ; aucun fallback/cache Vault et aucune valeur journalisée."""
import asyncio
import json
import os
import ssl
import stat
from pathlib import Path
from urllib.parse import urlparse


class StorageUnavailable(RuntimeError):
    """Diagnostic public constant, sans exception libpq/HTTP contenant un secret."""


def private_text(filename: str) -> str:
    p = Path(filename)
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(p, flags)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_mode & 0o077 or st.st_size > 65536:
            raise StorageUnavailable("Fichier credential privé invalide")
        with os.fdopen(fd, "r", encoding="utf-8", closefd=False) as f:
            return f.read().strip()
    finally:
        os.close(fd)


class Credentials:
    def __init__(self, settings):
        self.s = settings

    async def sql(self, service=None):
        s = self.s
        if s.files_credentials_mode == "direct":
            # libpq service/passfile : transport public autonome, explicitement hors profil Vault-first.
            return {"service": service or s.files_pg_service}
        if s.files_credentials_mode != "vault":
            raise StorageUnavailable("Provider credentials invalide")
        if service is not None:
            raise StorageUnavailable("Override service interdit en mode Vault")
        if urlparse(s.files_vault_url).scheme != "https":
            raise StorageUnavailable("Vault exige HTTPS")
        try:
            from mcp import ClientSession
            from mcp.client.streamable_http import streamable_http_client
            import httpx2
            token = private_text(s.files_vault_token_file)
            tls = ssl.create_default_context(cafile=s.files_vault_ca_file)
            async with asyncio.timeout(s.files_connect_timeout):
                async with httpx2.AsyncClient(verify=tls, follow_redirects=False,
                        timeout=s.files_connect_timeout,
                        headers={"Authorization": "Bearer " + token}) as http:
                    async with streamable_http_client(s.files_vault_url.rstrip("/") + "/mcp",
                            http_client=http) as (read, write):
                        async with ClientSession(read, write) as session:
                            await session.initialize()
                            result = await session.call_tool("secret_read", {
                                "vault_id": s.files_vault_id, "path": s.files_vault_path})
                            if getattr(result, "is_error", False) or len(result.content) != 1:
                                raise StorageUnavailable("Vault non autorisé ou indisponible")
                            payload = json.loads(result.content[0].text)
            if payload.get("status") != "ok" or payload.get("vault_id") != s.files_vault_id or payload.get("path") != s.files_vault_path:
                raise StorageUnavailable("Vault non autorisé ou indisponible")
            data = payload.get("data", {})
            # Secret Tools custom : aucun conninfo/options SQL arbitraire provenant du coffre.
            required = ("host", "port", "dbname", "user", "password")
            if any(not isinstance(data.get(k), (str, int)) or not str(data[k]) for k in required):
                raise StorageUnavailable("Contrat credential Vault invalide")
            if data["dbname"] != s.files_pg_database or data["user"] != s.files_pg_role:
                raise StorageUnavailable("Cible credential Vault invalide")
            return {k: data[k] for k in required}
        except StorageUnavailable:
            raise
        except Exception:
            raise StorageUnavailable("Vault non autorisé ou indisponible") from None
