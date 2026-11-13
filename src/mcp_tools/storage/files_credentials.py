"""Login PostgreSQL lu dans Vault, gardé en mémoire et relu en arrière-plan.

Une tâche relit Vault toutes les `files_vault_refresh_seconds` ; les requêtes lisent la
mémoire. Le login sert au plus `files_vault_validity_seconds` après la dernière lecture
réussie, puis le refus est fermé. Un refus explicite de Vault l'oublie tout de suite.
Avec un intervalle à 0, chaque connexion relit Vault (comportement d'origine).
Aucune valeur journalisée, rien sur disque.
"""
import asyncio
import json
import os
import re
import ssl
import stat
import time
import weakref
from pathlib import Path
from urllib.parse import urlparse

_now = time.monotonic  # horloge de validité, remplaçable par les tests
RETRY_SECONDS = 5.0  # attente après une lecture Vault en échec
MIN_SPACING_SECONDS = 1.0  # entre deux lectures, même réveillées par un refus PostgreSQL
STOP_SECONDS = 2.0  # attente maximale de la tâche à l'arrêt

# Réponses de Vault qui disent « tu n'as pas le droit » ou « ta demande est fausse ».
# Toute autre réponse en échec est une panne : le login reste servi jusqu'à sa validité.
_REFUSAL_TYPES = frozenset({
    "permission_denied", "unauthenticated", "invalid_token", "access_denied", "jwt_invalid",
    "binding_mismatch", "binding_incomplete", "not_found", "mission_inactive",
    "reserved_for_operator_jit", "invalid_input", "invalid_request", "misconfigured",
    "configuration_error",
})


_LIVE = weakref.WeakSet()  # instances dont une tâche de relecture a démarré


def _record_refresh_stopped(error):
    """Raison fermée (nom de type seul) : jamais de message, d'URL ni de secret."""
    try:
        from ..observability import record_activity
        name = type(error).__name__
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,63}", name):
            name = "unclassified"
        record_activity("credential.refresh_stopped", level="error",
                        message="Relecture du login PostgreSQL arrêtée",
                        details={"error_type": name})
    except Exception:
        pass


async def stop_refreshers():
    """Arrêt propre des tâches de relecture, appelé au shutdown de l'application."""
    for credentials in list(_LIVE):
        await credentials.aclose()


def _consume(task):
    # Résultat d'une lecture abandonnée : récupéré pour ne laisser aucun avertissement.
    if not task.cancelled():
        task.exception()


class StorageUnavailable(RuntimeError):
    """Diagnostic public constant, sans exception libpq/HTTP contenant un secret."""


class VaultRefused(StorageUnavailable):
    """Vault a répondu et refuse, ou a livré un login hors contrat : on l'oublie."""


class _HttpRefusal(Exception):
    """Levée par le hook HTTP : le client MCP ne remonte pas le code 401/403."""


def _refusal(error):
    if isinstance(error, (_HttpRefusal, VaultRefused)):
        return True
    return any(_refusal(inner) for inner in getattr(error, "exceptions", None) or ())


def _error_type(blocks):
    for block in blocks:
        try:
            value = json.loads(getattr(block, "text", "") or "")
        except ValueError:
            continue
        if isinstance(value, dict) and value.get("error_type") in _REFUSAL_TYPES:
            return value["error_type"]
    return None


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
    """Le login appartient à l'instance. Les services longs (Access, Files) la gardent
    pour la durée du processus ; un chemin opérateur ou CLI crée la sienne, donc lit Vault."""

    def __init__(self, settings):
        self.s = settings
        self._cache = None  # (horloge monotone de la lecture réussie, descripteur)
        self._loop = None
        self._task = None
        self._wake = None
        self._changed = None
        self._generation = 0  # change à chaque oubli : une lecture engagée avant est caduque

    def invalidate(self, descriptor):
        """Oublie ce login s'il est encore en mémoire et demande une relecture.

        Appelé quand PostgreSQL refuse la connexion ou que l'identité SQL ne correspond
        pas (rotation, cible déplacée). Un login plus récent n'est jamais effacé.
        """
        if self._cache is not None and self._cache[1] == descriptor:
            self._forget()
            if self._wake is not None:
                self._wake.set()

    def _forget(self):
        """Retire le login et rend caduque toute lecture déjà engagée."""
        self._cache = None
        self._generation += 1

    def _valid(self):
        if (self._cache is not None
                and _now() - self._cache[0] < self.s.files_vault_validity_seconds):
            return dict(self._cache[1])
        return None

    def _ensure_refresher(self):
        loop = asyncio.get_running_loop()
        if self._loop is loop and self._task is not None:
            # Même boucle : une tâche morte n'est pas relancée. Le login expire à sa
            # validité puis le refus est fermé ; le journal dit pourquoi elle s'est arrêtée.
            return
        self._loop = loop
        self._wake = asyncio.Event()
        self._changed = asyncio.Condition()
        self._task = loop.create_task(self._refresh_forever(self._wake, self._changed))
        self._task.add_done_callback(self._stopped)
        _LIVE.add(self)

    @staticmethod
    def _stopped(task):
        if not task.cancelled() and task.exception() is not None:
            _record_refresh_stopped(task.exception())

    async def aclose(self):
        """Arrête la tâche de cette boucle et oublie le login, en temps borné."""
        task = self._task
        self.reset()
        if task is not None and not task.done() and task.get_loop() is asyncio.get_running_loop():
            task.cancel()
            await asyncio.wait({task}, timeout=STOP_SECONDS)

    def reset(self):
        """Oublie tâche, boucle et login, sans attendre (boucle d'un test déjà fermée)."""
        self._task = self._loop = self._wake = self._changed = None
        self._forget()
        _LIVE.discard(self)

    async def _attempt(self):
        """Une lecture Vault dans sa propre tâche.

        Quand Vault refuse en cours de protocole, le client MCP peut avaler une annulation.
        L'appelant attend derrière shield : il reçoit toujours la sienne.
        """
        reader = asyncio.ensure_future(self._read())
        reader.add_done_callback(_consume)
        try:
            return await asyncio.shield(reader)
        except asyncio.CancelledError:
            reader.cancel()
            raise

    async def _refresh_forever(self, wake, changed):
        me = asyncio.current_task()
        last_attempt, failed = None, False
        # Après reset ou aclose, l'instance ne désigne plus cette tâche : elle s'arrête.
        while self._task is me:
            if last_attempt is not None:
                spacing = RETRY_SECONDS if failed else MIN_SPACING_SECONDS
                await asyncio.sleep(max(0.0, last_attempt + spacing - _now()))
            wake.clear()
            last_attempt = _now()
            generation = self._generation
            try:
                data = await self._attempt()
            except VaultRefused:
                if self._task is me:
                    self._forget()
                failed = True
            except Exception:
                # _read ne laisse sortir aucun détail ; une panne garde le login valide.
                failed = True
            else:
                failed = False
                async with changed:
                    # Oubli pendant la lecture (refus PostgreSQL, refus Vault) : résultat caduc.
                    if self._task is me and self._generation == generation:
                        self._cache = (_now(), dict(data))
                        changed.notify_all()
            if self._task is not me:
                return
            delay = RETRY_SECONDS if failed else self.s.files_vault_refresh_seconds
            # Pas d'asyncio.wait_for : en 3.11 il avale une annulation qui arrive en même
            # temps que le réveil (gh-86296), et la tâche ne s'arrête plus au shutdown.
            try:
                async with asyncio.timeout(delay):
                    await wake.wait()
            except TimeoutError:
                pass

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
        if s.files_vault_refresh_seconds <= 0:
            return await self._attempt()
        self._ensure_refresher()
        current = self._valid()
        if current is not None:
            return current
        if self._task.done():
            raise StorageUnavailable("Vault non autorisé ou indisponible")
        # Premier usage ou login expiré : attendre la tâche, dans le budget Vault seulement.
        try:
            async with asyncio.timeout(s.files_connect_timeout):
                async with self._changed:
                    await self._changed.wait_for(lambda: self._valid() is not None)
                    return self._valid()
        except TimeoutError:
            raise StorageUnavailable("Vault non autorisé ou indisponible") from None

    async def _read(self):
        s = self.s
        # Le SDK absorbe certaines réponses (notification initialized, flux GET, DELETE de
        # fin de session) : le refus noté par le hook fait foi, que l'exception remonte ou non.
        refused = []
        try:
            from mcp import ClientSession
            from mcp.client.streamable_http import streamable_http_client
            import httpx2
            token = private_text(s.files_vault_token_file)
            tls = ssl.create_default_context(cafile=s.files_vault_ca_file)
            async def reject_redirect(response):
                if response.is_redirect:
                    raise httpx2.HTTPStatusError("MCP_REDIRECT_REFUSED", request=response.request, response=response)
                if response.status_code in (401, 403):
                    refused.append(response.status_code)
                    self._forget()  # sans attendre la fin de la session
                    raise _HttpRefusal()
            async with asyncio.timeout(s.files_connect_timeout):
                async with httpx2.AsyncClient(verify=tls, follow_redirects=False,
                        event_hooks={"response": [reject_redirect]},
                        timeout=s.files_connect_timeout,
                        headers={"Authorization": "Bearer " + token}) as http:
                    async with streamable_http_client(s.files_vault_url.rstrip("/") + "/mcp",
                            http_client=http) as (read, write):
                        async with ClientSession(read, write) as session:
                            await session.initialize()
                            result = await session.call_tool("secret_read", {
                                "vault_id": s.files_vault_id, "path": s.files_vault_path})
            if refused:
                raise VaultRefused("Vault non autorisé ou indisponible")
            return self._login(result)
        except VaultRefused:
            raise
        except StorageUnavailable:
            if refused:
                raise VaultRefused("Vault non autorisé ou indisponible") from None
            raise
        except Exception as error:
            if refused or _refusal(error):
                raise VaultRefused("Vault non autorisé ou indisponible") from None
            raise StorageUnavailable("Vault non autorisé ou indisponible") from None

    def _login(self, result):
        """Toute réponse réussie hors contrat est un refus : le login gardé est oublié."""
        s = self.s
        blocks = getattr(result, "content", None) or []
        if getattr(result, "is_error", False):
            if _error_type(blocks):
                raise VaultRefused("Vault non autorisé ou indisponible")
            raise StorageUnavailable("Vault non autorisé ou indisponible")
        if len(blocks) != 1:
            raise VaultRefused("Contrat credential Vault invalide")
        try:
            payload = json.loads(getattr(blocks[0], "text", None))
        except (TypeError, ValueError):
            raise VaultRefused("Contrat credential Vault invalide") from None
        if not isinstance(payload, dict):
            raise VaultRefused("Contrat credential Vault invalide")
        status = payload.get("status")
        if status == "error":
            if _error_type(blocks):
                raise VaultRefused("Vault non autorisé ou indisponible")
            raise StorageUnavailable("Vault non autorisé ou indisponible")
        if status != "ok":
            raise VaultRefused("Contrat credential Vault invalide")
        if payload.get("vault_id") != s.files_vault_id or payload.get("path") != s.files_vault_path:
            raise VaultRefused("Vault non autorisé ou indisponible")
        data = payload.get("data")
        # Secret Tools custom : aucun conninfo/options SQL arbitraire provenant du coffre.
        required = ("host", "port", "dbname", "user", "password")
        if (not isinstance(data, dict)
                or any(not isinstance(data.get(k), (str, int)) or not str(data[k]) for k in required)):
            raise VaultRefused("Contrat credential Vault invalide")
        if data["dbname"] != s.files_pg_database or data["user"] != s.files_pg_role:
            raise VaultRefused("Cible credential Vault invalide")
        return {k: data[k] for k in required}
