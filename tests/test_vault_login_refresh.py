"""Login PostgreSQL relu en arrière-plan : contrat de validité, refus fermé, lecture unique.

Les tests pilotent Vault par un double de `Credentials._read` et l'âge du login par
l'horloge `_now`. La boucle asyncio reste réelle ; seuls les espacements sont réduits.
Le classement des réponses Vault passe par le vrai client MCP sur un transport simulé.
"""
import asyncio
import json
import time
from types import SimpleNamespace
from unittest.mock import patch

import httpx2
import pytest

from src.mcp_tools.storage import files_credentials as fc
from src.mcp_tools.storage.files_credentials import Credentials, StorageUnavailable, VaultRefused

LOGIN_A = {"host": "db", "port": 5432, "dbname": "tools", "user": "app", "password": "A"}
LOGIN_B = {**LOGIN_A, "password": "B"}


def cfg(**overrides):
    values = dict(files_credentials_mode="vault", files_pg_service="",
                  files_vault_url="https://vault.invalid", files_vault_token_file="unused",
                  files_vault_ca_file=None, files_connect_timeout=0.3, files_vault_id="scoped",
                  files_vault_path="connection", files_pg_database="tools", files_pg_role="app",
                  files_vault_refresh_seconds=30, files_vault_validity_seconds=60)
    values.update(overrides)
    return SimpleNamespace(**values)


class Vault:
    """Double de `_read` : rejoue un script, puis la valeur par défaut."""

    def __init__(self, *script, default=LOGIN_A, gate=None):
        self.script, self.default, self.gate = list(script), default, gate
        self.reads, self.times = 0, []

    async def __call__(self):
        self.reads += 1
        self.times.append(time.monotonic())
        if self.gate is not None:
            await self.gate.wait()
        outcome = self.script.pop(0) if self.script else self.default
        if isinstance(outcome, BaseException):
            raise outcome
        return dict(outcome)


def wired(vault, **overrides):
    credentials = Credentials(cfg(**overrides))
    credentials._read = vault
    return credentials


@pytest.fixture
def clock(monkeypatch):
    """Âge du login piloté ; les espacements de la tâche restent en temps réel."""
    now = [1000.0]
    monkeypatch.setattr(fc, "_now", lambda: now[0])
    return now


@pytest.fixture(autouse=True)
def short_spacing(monkeypatch):
    monkeypatch.setattr(fc, "MIN_SPACING_SECONDS", 0.01)
    monkeypatch.setattr(fc, "RETRY_SECONDS", 0.02)


async def until(predicate, limit=2.0):
    deadline = time.monotonic() + limit
    while not predicate():
        assert time.monotonic() < deadline, "condition jamais atteinte"
        await asyncio.sleep(0.005)


# --- Relecture de fond et service depuis la mémoire ---------------------------------

def test_requests_are_served_from_memory_without_reading_vault():
    async def scenario():
        vault = Vault()
        credentials = wired(vault)
        first = await credentials.sql()
        logins = await asyncio.gather(*(credentials.sql() for _ in range(100)))
        # La copie rendue ne modifie pas le login gardé.
        first["password"] = "changed"
        return vault.reads, logins, await credentials.sql()
    reads, logins, again = asyncio.run(scenario())
    assert reads == 1
    assert all(login == LOGIN_A for login in logins) and again == LOGIN_A


def test_background_task_rereads_vault_without_any_request():
    async def scenario():
        vault = Vault()
        credentials = wired(vault, files_vault_refresh_seconds=0.03)
        await credentials.sql()
        # Aucune requête ici : seule la tâche de fond peut relire.
        await until(lambda: vault.reads >= 4)
        gaps = [b - a for a, b in zip(vault.times, vault.times[1:])]
        return gaps
    gaps = asyncio.run(scenario())
    # Les relectures suivent l'intervalle, pas une boucle serrée.
    assert min(gaps) >= 0.025


def test_rotated_login_is_picked_up_by_the_next_background_read():
    async def scenario():
        vault = Vault(LOGIN_A, default=LOGIN_B)
        credentials = wired(vault, files_vault_refresh_seconds=0.03)
        assert await credentials.sql() == LOGIN_A
        await until(lambda: vault.reads >= 2)
        return await credentials.sql()
    assert asyncio.run(scenario()) == LOGIN_B


# --- Démarrage : jamais d'accès sans login valide ------------------------------------

def test_first_request_waits_for_the_first_read_within_the_budget():
    async def scenario():
        gate = asyncio.Event()
        vault = Vault(gate=gate)
        credentials = wired(vault, files_connect_timeout=1.0)
        asyncio.get_running_loop().call_later(0.05, gate.set)
        return await credentials.sql(), vault.reads
    login, reads = asyncio.run(scenario())
    assert login == LOGIN_A and reads == 1


@pytest.mark.parametrize("failure", [None, StorageUnavailable("panne"), VaultRefused("refus")])
def test_startup_without_a_successful_read_fails_closed_after_the_budget(failure):
    async def scenario():
        # None : Vault ne répond jamais ; sinon Vault échoue à chaque essai.
        vault = Vault(gate=asyncio.Event()) if failure is None else Vault(default=failure)
        credentials = wired(vault, files_connect_timeout=0.15)
        started = time.monotonic()
        with pytest.raises(StorageUnavailable, match="Vault non autorisé ou indisponible"):
            await credentials.sql()
        return time.monotonic() - started
    elapsed = asyncio.run(scenario())
    assert 0.14 <= elapsed < 1.0


# --- Validité : 60 s après la dernière lecture réussie, puis refus fermé -------------

def test_vault_outage_keeps_the_login_until_validity_then_fails_closed(clock):
    async def scenario():
        vault = Vault(LOGIN_A, default=StorageUnavailable("panne"))
        credentials = wired(vault, files_vault_refresh_seconds=0.03, files_connect_timeout=0.1)
        assert await credentials.sql() == LOGIN_A
        await until(lambda: vault.reads >= 3)  # la panne est bien vue par la tâche
        clock[0] = 1059.9
        assert await credentials.sql() == LOGIN_A
        clock[0] = 1060.0
        with pytest.raises(StorageUnavailable):
            await credentials.sql()
        # Vault revient : le login suivant est servi sans redémarrer le processus.
        vault.default = LOGIN_B
        clock[0] = 1061.0
        await until(lambda: credentials._valid() is not None)
        return await credentials.sql()
    assert asyncio.run(scenario()) == LOGIN_B


def test_explicit_vault_refusal_forgets_the_login_immediately(clock):
    async def scenario():
        vault = Vault(LOGIN_A, default=VaultRefused("refus"))
        credentials = wired(vault, files_vault_refresh_seconds=0.03, files_connect_timeout=0.1)
        assert await credentials.sql() == LOGIN_A
        await until(lambda: vault.reads >= 2)
        # L'horloge n'a pas bougé : seul le refus explicite peut fermer l'accès.
        with pytest.raises(StorageUnavailable):
            await credentials.sql()
    asyncio.run(scenario())


# --- Tâche morte : journal à raison fermée, pas de relance, expiration ---------------

class Boom(BaseException):
    """Échappe au `except Exception` de la tâche, comme un défaut de programmation."""


def test_dead_refresher_is_logged_with_a_closed_reason_and_login_expires(clock, monkeypatch):
    events = []
    from src.mcp_tools import observability
    monkeypatch.setattr(observability, "record_activity",
                        lambda event, **fields: events.append((event, fields)))

    async def scenario():
        vault = Vault(LOGIN_A, Boom("PRIVATE-CANARY password=secret"))
        credentials = wired(vault, files_vault_refresh_seconds=0.03, files_connect_timeout=5)
        assert await credentials.sql() == LOGIN_A
        task = credentials._task
        await until(task.done)
        await asyncio.sleep(0.1)
        clock[0] = 1059.0
        assert await credentials.sql() == LOGIN_A
        clock[0] = 1060.0
        started = time.monotonic()
        with pytest.raises(StorageUnavailable):
            await credentials.sql()
        # Refus immédiat : rien n'attend une tâche qui ne répondra plus.
        assert time.monotonic() - started < 0.5
        assert credentials._task is task and vault.reads == 2
    asyncio.run(scenario())
    assert events == [("credential.refresh_stopped", {
        "level": "error", "message": "Relecture du login PostgreSQL arrêtée",
        "details": {"error_type": "Boom"}})]


def test_cancelled_refresher_is_not_reported_as_dead(monkeypatch):
    events = []
    from src.mcp_tools import observability
    monkeypatch.setattr(observability, "record_activity", lambda event, **fields: events.append(event))

    async def scenario():
        credentials = wired(Vault())
        await credentials.sql()
        await credentials.aclose()
    asyncio.run(scenario())
    assert events == []


# --- Invalidation : refus PG ou identité inattendue ----------------------------------

def test_invalidation_triggers_one_read_for_many_concurrent_failures():
    async def scenario():
        gate = asyncio.Event()
        vault = Vault(LOGIN_A, default=LOGIN_B)
        credentials = wired(vault, files_connect_timeout=1.0)
        stale = await credentials.sql()
        vault.gate = gate
        # Cinquante connexions refusées en même temps avec le même login.
        for _ in range(50):
            credentials.invalidate(stale)
        waiters = [asyncio.create_task(credentials.sql()) for _ in range(20)]
        await until(lambda: vault.reads == 2)
        for _ in range(50):
            credentials.invalidate(stale)
        gate.set()
        logins = await asyncio.gather(*waiters)
        await asyncio.sleep(0.05)
        return vault.reads, logins
    reads, logins = asyncio.run(scenario())
    assert reads == 2
    assert all(login == LOGIN_B for login in logins)


def test_stale_invalidation_never_erases_a_newer_login():
    async def scenario():
        vault = Vault(LOGIN_A, default=LOGIN_B)
        credentials = wired(vault)
        old = await credentials.sql()
        credentials.invalidate(old)
        await until(lambda: credentials._valid() is not None)
        assert await credentials.sql() == LOGIN_B
        credentials.invalidate(old)  # un appelant en retard rapporte l'ancien login
        await asyncio.sleep(0.05)
        return vault.reads, await credentials.sql()
    reads, login = asyncio.run(scenario())
    assert reads == 2 and login == LOGIN_B


def test_invalidated_login_is_never_served_while_vault_is_down(clock):
    async def scenario():
        vault = Vault(LOGIN_A, default=StorageUnavailable("panne"))
        credentials = wired(vault, files_connect_timeout=0.1)
        rejected = await credentials.sql()
        credentials.invalidate(rejected)
        with pytest.raises(StorageUnavailable):
            await credentials.sql()
    asyncio.run(scenario())


# --- Espacement des lectures ----------------------------------------------------------

def test_reads_are_spaced_after_success_and_after_failure(monkeypatch):
    monkeypatch.setattr(fc, "MIN_SPACING_SECONDS", 0.15)
    monkeypatch.setattr(fc, "RETRY_SECONDS", 0.25)

    async def scenario():
        vault = Vault(LOGIN_A, LOGIN_B, StorageUnavailable("panne"), default=LOGIN_A)
        credentials = wired(vault, files_connect_timeout=2.0)
        await credentials.sql()
        credentials.invalidate(LOGIN_A)  # réveil immédiat, freiné par l'espacement minimal
        await until(lambda: vault.reads >= 2)
        credentials.invalidate(LOGIN_B)  # troisième lecture : panne
        await until(lambda: vault.reads >= 4)
        return [b - a for a, b in zip(vault.times, vault.times[1:])]
    after_success, after_wake, after_failure = asyncio.run(scenario())
    assert after_success >= 0.14 and after_wake >= 0.14
    # Après une panne : nouvel essai à RETRY_SECONDS, bien avant l'intervalle de 30 s.
    assert 0.24 <= after_failure < 2.0


# --- Retour arrière : 0 relit Vault à chaque connexion --------------------------------

def test_zero_interval_reads_vault_on_every_connection_without_a_task():
    async def scenario():
        vault = Vault(LOGIN_A, StorageUnavailable("panne"), default=LOGIN_B)
        credentials = wired(vault, files_vault_refresh_seconds=0, files_vault_validity_seconds=0)
        first = await credentials.sql()
        with pytest.raises(StorageUnavailable):
            await credentials.sql()
        third = await credentials.sql()
        return vault.reads, first, third, credentials._task
    reads, first, third, task = asyncio.run(scenario())
    assert (reads, first, third, task) == (3, LOGIN_A, LOGIN_B, None)
    assert not list(fc._LIVE)


# --- Arrêt propre ---------------------------------------------------------------------

def test_stop_refreshers_cancels_every_task_and_forgets_logins():
    async def scenario():
        access, files = wired(Vault()), wired(Vault())
        await access.sql()
        await files.sql()
        tasks = [access._task, files._task]
        await fc.stop_refreshers()
        return tasks, access, files
    tasks, access, files = asyncio.run(scenario())
    assert all(task.cancelled() for task in tasks)
    assert access._cache is None and files._cache is None and not list(fc._LIVE)


def test_lifespan_shutdown_stops_refreshers(monkeypatch):
    from src.mcp_tools.storage.files_lifecycle import StorageLifecycleMiddleware

    async def app(scope, receive, send):
        await receive()
        await send({"type": "lifespan.startup.complete"})
        await receive()
        await send({"type": "lifespan.shutdown.complete"})

    async def scenario():
        credentials = wired(Vault())
        await credentials.sql()
        task = credentials._task
        messages = iter([{"type": "lifespan.startup"}, {"type": "lifespan.shutdown"}])
        async def receive():
            return next(messages)
        async def send(message):
            pass
        settings = SimpleNamespace(files_metadata_backend="s3")
        await StorageLifecycleMiddleware(app, settings)({"type": "lifespan"}, receive, send)
        # Vérifié dans la boucle : asyncio.run annulerait de toute façon la tâche en sortant.
        return task.done(), task, list(fc._LIVE)
    stopped, task, live = asyncio.run(scenario())
    assert stopped and task.cancelled() and live == []


def test_a_new_event_loop_starts_a_fresh_task_and_read():
    vault = Vault()
    credentials = wired(vault)

    async def once():
        return await credentials.sql(), credentials._task
    first, task_one = asyncio.run(once())
    second, task_two = asyncio.run(once())
    assert first == second == LOGIN_A
    assert task_one is not task_two and vault.reads == 2


# --- Configuration --------------------------------------------------------------------

def test_defaults_are_thirty_and_sixty_seconds():
    from src.mcp_tools.config import Settings
    s = Settings(_env_file=None)
    assert (s.access_vault_refresh_seconds, s.access_vault_validity_seconds) == (30, 60)
    assert (s.files_vault_refresh_seconds, s.files_vault_validity_seconds) == (30, 60)


@pytest.mark.parametrize("prefix", ["access", "files"])
@pytest.mark.parametrize("refresh,validity,ok", [
    (0, 0, True), (0, 60, True), (1, 2, True), (30, 60, True), (300, 600, True),
    (60, 60, False), (61, 60, False), (30, 0, False), (0.5, 60, False),
    (-1, 60, False), (301, 600, False), (30, 601, False),
    (float("nan"), 60, False), (float("inf"), 60, False), (30, float("inf"), False),
])
def test_refresh_must_be_zero_or_shorter_than_validity(prefix, refresh, validity, ok):
    from src.mcp_tools.config import Settings
    values = {prefix + "_vault_refresh_seconds": refresh, prefix + "_vault_validity_seconds": validity}
    if ok:
        Settings(_env_file=None, **values)
    else:
        with pytest.raises(ValueError):
            Settings(_env_file=None, **values)


# --- Classement des réponses Vault par le vrai client MCP ----------------------------

def vault_server(tool_reply=None, status=200):
    payload = {"status": "ok", "vault_id": "scoped", "path": "connection", "data": LOGIN_A}

    def handle(request):
        if status != 200:
            return httpx2.Response(status)
        if request.method != "POST":
            return httpx2.Response(405)
        body = json.loads(request.content)
        if "id" not in body:
            return httpx2.Response(202)
        if body["method"] == "initialize":
            result = {"protocolVersion": body["params"]["protocolVersion"], "capabilities": {},
                      "serverInfo": {"name": "local-contract", "version": "1"}}
        elif body["method"] == "tools/list":
            result = {"tools": [{"name": "secret_read", "inputSchema": {"type": "object"}}]}
        else:
            result = tool_reply or {"content": [{"type": "text", "text": json.dumps(payload)}],
                                    "isError": False}
        return httpx2.Response(200, json={"jsonrpc": "2.0", "id": body["id"], "result": result})
    return handle


def error_reply(error_type):
    text = json.dumps({"status": "error", "error_type": error_type, "message": "x"})
    return {"content": [{"type": "text", "text": text}], "isError": True}


@pytest.mark.parametrize("server,expected", [
    (vault_server(), None),
    (vault_server(status=401), VaultRefused),
    (vault_server(status=403), VaultRefused),
    (vault_server(error_reply("permission_denied")), VaultRefused),
    (vault_server(error_reply("not_found")), VaultRefused),
    (vault_server({"content": [{"type": "text", "text": json.dumps(
        {"status": "ok", "vault_id": "other", "path": "connection", "data": LOGIN_A})}],
        "isError": False}), VaultRefused),
    (vault_server({"content": [{"type": "text", "text": json.dumps(
        {"status": "ok", "vault_id": "scoped", "path": "connection",
         "data": {**LOGIN_A, "user": "superuser"}})}], "isError": False}), VaultRefused),
    # Pannes : le login en mémoire reste servi jusqu'à sa validité.
    (vault_server(status=500), StorageUnavailable),
    (vault_server(status=503), StorageUnavailable),
    (vault_server(error_reply("backend_unavailable")), StorageUnavailable),
])
def test_vault_answers_are_classified_as_refusal_or_outage(tmp_path, server, expected):
    token = tmp_path / "token"
    token.write_text("synthetic")
    token.chmod(0o600)
    credentials = Credentials(cfg(files_vault_token_file=str(token), files_connect_timeout=2))
    original = httpx2.AsyncClient

    def factory(**kwargs):
        return original(transport=httpx2.MockTransport(server), **kwargs)
    with patch.object(httpx2, "AsyncClient", side_effect=factory):
        if expected is None:
            assert asyncio.run(credentials._read()) == LOGIN_A
            return
        with pytest.raises(StorageUnavailable) as error:
            asyncio.run(credentials._read())
    # VaultRefused hérite de StorageUnavailable : le type exact compte.
    assert type(error.value) is expected
    assert str(error.value) in ("Vault non autorisé ou indisponible",
                                "Contrat credential Vault invalide", "Cible credential Vault invalide")


def test_http_401_from_vault_closes_access_before_validity(tmp_path, clock):
    token = tmp_path / "token"
    token.write_text("synthetic")
    token.chmod(0o600)
    state = {"server": vault_server()}
    original = httpx2.AsyncClient

    def factory(**kwargs):
        return original(transport=httpx2.MockTransport(lambda r: state["server"](r)), **kwargs)

    async def scenario():
        credentials = Credentials(cfg(files_vault_token_file=str(token), files_connect_timeout=1,
                                      files_vault_refresh_seconds=0.05))
        assert await credentials.sql() == LOGIN_A
        state["server"] = vault_server(status=401)  # jeton Vault révoqué
        await until(lambda: credentials._cache is None)
        with pytest.raises(StorageUnavailable):
            await credentials.sql()
    with patch.object(httpx2, "AsyncClient", side_effect=factory):
        asyncio.run(scenario())


# --- Les chemins Access et Files invalident au bon moment ----------------------------

def test_access_store_rechecks_tokens_on_every_request_with_a_warm_login(monkeypatch):
    """Le cache ne porte que le login : une révocation de jeton se voit tout de suite."""
    import psycopg
    from src.mcp_tools.auth import postgres_store
    from src.mcp_tools.auth.postgres_store import PostgresAccessStore
    from src.mcp_tools.auth.postgres_schema import CHECKSUM, VERSION

    table = {"rows": [{"credential": "active"}]}
    lookups = []

    class Cursor:
        async def __aenter__(self): return self
        async def __aexit__(self, *args): pass
        async def execute(self, query, *args):
            self.query = query
            if "credential_get" in query:
                lookups.append(query)
        async def fetchall(self):
            if "schema_contract" in self.query:
                return [{"version": VERSION, "checksum": CHECKSUM}]
            if "pg_roles" in self.query:
                return [{"role": "app", "db": "tools", "recovery": False, "privileged": False}]
            return list(table["rows"])

    class Connection:
        pgconn = SimpleNamespace(finish=lambda: None)
        def cursor(self): return Cursor()
        async def commit(self): pass

    async def connect(**kwargs):
        return Connection()
    monkeypatch.setattr(psycopg.AsyncConnection, "connect", connect)
    monkeypatch.setattr(psycopg.capabilities, "has_cancel_safe", lambda: True)
    monkeypatch.setattr(postgres_store, "authenticate_row", lambda row, binding, now: row)

    vault = Vault()
    store = PostgresAccessStore(wired(vault), ca_file="ca", role="app", database="tools")

    async def scenario():
        before = await store.authenticate("opaque")
        table["rows"] = []  # jeton révoqué en base
        after = await store.authenticate("opaque")
        return before, after
    before, after = asyncio.run(scenario())
    assert before == {"credential": "active"} and after is None
    assert len(lookups) == 2 and vault.reads == 1


def files_settings():
    return cfg(files_pg_schema="files", files_durability="local", files_pg_system_identifier="1",
               files_replication_roster="[]", files_quorum=0, files_pg_timeline=1,
               files_pg_ca_file="ca", files_recovery_enabled=False)


class Recorder:
    def __init__(self):
        self.invalidated = []

    async def sql(self, service=None):
        return dict(LOGIN_A)

    def invalidate(self, descriptor):
        self.invalidated.append(descriptor)


class FakeConnection:
    def __init__(self, identity):
        self.identity, self.closed = identity, False

    def add_notice_handler(self, handler):
        pass

    async def execute(self, query, args=()):
        identity = self.identity
        class Result:
            async def fetchone(self):
                return identity
        return Result()

    async def close(self):
        self.closed = True


@pytest.mark.parametrize("case,invalidated", [
    ("connect_refused", 1), ("identity_mismatch", 1), ("caller_error_after_open", 0), ("ok", 0),
])
def test_files_catalog_invalidates_only_before_the_connection_is_handed_out(monkeypatch, case, invalidated):
    import psycopg
    from src.mcp_tools.storage.files_postgres import Catalog

    identity = {"db": "tools", "role": "app", "recovery": False}
    if case == "identity_mismatch":
        identity = {**identity, "role": "intruder"}

    async def connect(**kwargs):
        if case == "connect_refused":
            raise psycopg.OperationalError("password authentication failed PRIVATE-CANARY")
        return FakeConnection(identity)
    monkeypatch.setattr(psycopg.AsyncConnection, "connect", connect)

    catalog = Catalog(files_settings())
    catalog.credentials = Recorder()

    async def ok(*args, **kwargs):
        return None
    monkeypatch.setattr(catalog, "check_schema", ok)
    monkeypatch.setattr(catalog, "infrastructure", ok)

    async def scenario():
        async with catalog.connection():
            if case == "caller_error_after_open":
                raise RuntimeError("erreur métier après ouverture")
    if case == "ok":
        asyncio.run(scenario())
    else:
        with pytest.raises(StorageUnavailable) as error:
            asyncio.run(scenario())
        assert "PRIVATE" not in str(error.value)
    assert catalog.credentials.invalidated == [LOGIN_A] * invalidated
