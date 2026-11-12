"""Diagnostic d'accès fermé : transport doublé, aucun PostgreSQL/Vault réel."""

import asyncio
import json
from types import SimpleNamespace
from unittest.mock import Mock

import psycopg
import pytest

from src.mcp_tools import observability
from src.mcp_tools.auth import postgres_store
from src.mcp_tools.auth.token_store import TokenStoreUnavailable
from test_hub_sql_refusal_31 import install_transport, sql_error
from test_postgres_access_store_31 import Provider, contract_rows

PHASES = ("credentials", "connect", "schema", "authority", "operation", "commit")
CANARY = "PRIVATE_QUERY_PARAMS_CONNINFO_CREDENTIAL_ROLE_TOKEN_HASH_SQL_MESSAGE_950"
QUERY = "SELECT private_operation(%s) /* " + CANARY + " */"
CONTEXT = {
    "trace_id": "trace-test-access-950",
    "call_id": "call-test-access-950",
    "operation_id": "00000000-0000-0000-0000-000000000950",
}


class SecretError(Exception):
    sqlstate = "08006"

    def __str__(self):
        raise AssertionError("le diagnostic ne doit pas formater l'exception")

    def __repr__(self):
        raise AssertionError("le diagnostic ne doit pas représenter l'exception")


def transport_double(monkeypatch, failing_phase=None, error=None):
    """Même contrat de doubles que test_postgres_access_store_31."""
    flags = {"credentials": 0, "connect": 0, "operations": 0, "commits": 0, "closed": 0}

    def fail(phase):
        if phase == failing_phase:
            raise error

    class Credentials(Provider):
        async def sql(self):
            flags["credentials"] += 1
            fail("credentials")
            return await super().sql()

    class Cursor:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            pass

        async def execute(self, query, *args):
            self.query = query
            if "schema_contract" in query:
                fail("schema")
            elif "pg_roles" in query:
                fail("authority")
            else:
                flags["operations"] += 1
                fail("operation")

        async def fetchall(self):
            return contract_rows(self.query)

    def close():
        flags["closed"] += 1

    class Connection:
        pgconn = SimpleNamespace(finish=close)

        def cursor(self):
            return Cursor()

        async def commit(self):
            flags["commits"] += 1
            fail("commit")

    async def connect(**kwargs):
        flags["connect"] += 1
        fail("connect")
        return Connection()

    monkeypatch.setattr(psycopg.AsyncConnection, "connect", connect)
    monkeypatch.setattr(psycopg.capabilities, "has_cancel_safe", lambda: True)
    monkeypatch.setattr(postgres_store, "access_environment_allowed", lambda: True)
    store = postgres_store.PostgresAccessStore(
        Credentials(), ca_file=CANARY, role="app", database="access",
    )
    return store, flags


def assert_diagnostic(record, phase, error_type, sqlstate=None, elapsed=None):
    details = {"phase": phase, "error_type": error_type}
    if sqlstate is not None:
        details["sqlstate"] = sqlstate
    if elapsed is not None:
        details["elapsed_ms"] = elapsed
    record.assert_called_once_with(
        "access.failure", level="error", message="Échec du magasin d’accès", details=details,
    )
    assert CANARY not in json.dumps(record.call_args.kwargs, ensure_ascii=False)


@pytest.mark.parametrize("phase", PHASES)
def test_run_records_exact_failure_phase_without_leaking_or_retrying(monkeypatch, phase):
    record = Mock()
    monkeypatch.setattr(postgres_store, "record_activity", record)
    error = SecretError(CANARY, {"credential": CANARY, "sql": CANARY})
    store, flags = transport_double(monkeypatch, phase, error)
    with pytest.raises(TokenStoreUnavailable) as caught:
        asyncio.run(store._run(QUERY, (CANARY,)))
    assert type(caught.value) is TokenStoreUnavailable
    assert caught.value.args == ("Access operation unavailable or uncertain",)
    assert caught.value.__cause__ is None
    assert caught.value.__suppress_context__ is True
    elapsed = record.call_args.kwargs['details']['elapsed_ms']
    assert set(elapsed) == set(PHASES[:PHASES.index(phase) + 1])
    assert all(type(value) is int and 0 <= value <= 5000 for value in elapsed.values())
    assert_diagnostic(record, phase, "SecretError", "08006", elapsed)
    assert flags["credentials"] == 1
    assert flags["connect"] == (0 if phase == "credentials" else 1)
    assert flags["commits"] == (1 if phase == "commit" else 0)
    assert flags["closed"] == (0 if phase in {"credentials", "connect"} else 1)
    assert not postgres_store._ACTIVE


@pytest.mark.parametrize("phase", PHASES)
def test_helper_never_formats_exception_or_emits_arguments(monkeypatch, phase):
    record = Mock()
    monkeypatch.setattr(postgres_store, "record_activity", record)
    error = SecretError(CANARY, {"query": CANARY, "params": [CANARY]})
    postgres_store._record_access_failure(phase, error)
    assert_diagnostic(record, phase, "SecretError", "08006")


@pytest.mark.parametrize("name", ["Bad Name", "Bad-Name", "Échec", "9Bad", "A" * 65, "Bad\nName"])
def test_invalid_error_type_is_unclassified(monkeypatch, name):
    record = Mock()
    monkeypatch.setattr(postgres_store, "record_activity", record)
    postgres_store._record_access_failure("operation", type(name, (Exception,), {})(CANARY))
    assert_diagnostic(record, "operation", "unclassified")


def test_error_type_accepts_exact_ascii_64_character_boundary(monkeypatch):
    record = Mock()
    monkeypatch.setattr(postgres_store, "record_activity", record)
    name = "A" * 64
    postgres_store._record_access_failure("schema", type(name, (Exception,), {})(CANARY))
    assert_diagnostic(record, "schema", name)


@pytest.mark.parametrize("phase", [None, False, 1, "unknown", CANARY])
def test_unknown_phase_is_unclassified(monkeypatch, phase):
    record = Mock()
    monkeypatch.setattr(postgres_store, "record_activity", record)
    postgres_store._record_access_failure(phase, RuntimeError(CANARY))
    assert_diagnostic(record, "unclassified", "RuntimeError")


class SQLStateSubclass(str):
    pass


@pytest.mark.parametrize("value", [
    None, False, 23505, b"23505", SQLStateSubclass("23505"), "", "1234", "123456",
    "42p01", "23505\n", "É0000", CANARY,
])
def test_sqlstate_requires_exact_str_and_closed_five_character_format(monkeypatch, value):
    record = Mock()
    monkeypatch.setattr(postgres_store, "record_activity", record)
    error = SecretError(CANARY)
    error.sqlstate = value
    postgres_store._record_access_failure("operation", error)
    assert_diagnostic(record, "operation", "SecretError")


@pytest.mark.parametrize("value", ["23505", "08006", "42P01", "A1B2C"])
def test_valid_sqlstate_is_the_only_optional_detail(monkeypatch, value):
    record = Mock()
    monkeypatch.setattr(postgres_store, "record_activity", record)
    error = SecretError(CANARY)
    error.sqlstate = value
    postgres_store._record_access_failure("connect", error)
    assert_diagnostic(record, "connect", "SecretError", value)


def test_native_activity_context_is_preserved_without_exception_data(capsys):
    token = observability._activity_context.set(dict(CONTEXT))
    try:
        postgres_store._record_access_failure("connect", SecretError(CANARY))
    finally:
        observability._activity_context.reset(token)
    emitted = json.loads(capsys.readouterr().err)["activity"]
    assert all(emitted[key] == value for key, value in CONTEXT.items())
    assert emitted["event"] == "access.failure"
    assert emitted["message"] == "Échec du magasin d’accès"
    assert emitted["details"] == {"phase": "connect", "error_type": "SecretError", "sqlstate": "08006"}
    assert CANARY not in json.dumps(emitted, ensure_ascii=False)


def test_elapsed_phase_fields_are_bounded_in_the_real_existing_log(capsys):
    postgres_store._record_access_failure('credentials', SecretError(CANARY), {
        'credentials': 2050, 'connect': True, 'schema': -1, 'operation': 5001, CANARY: 7,
    })
    emitted = json.loads(capsys.readouterr().err)['activity']
    assert emitted['event'] == 'access.failure'
    assert emitted['details']['elapsed_ms'] == {'credentials': 2050}
    assert CANARY not in json.dumps(emitted)


def test_logger_failure_preserves_commit_unknown_and_original_public_error(monkeypatch):
    record = Mock(side_effect=RuntimeError(CANARY))
    monkeypatch.setattr(postgres_store, "record_activity", record)
    store, flags = transport_double(monkeypatch, "commit", SecretError(CANARY))
    with pytest.raises(TokenStoreUnavailable) as caught:
        asyncio.run(store._run(QUERY, (CANARY,)))
    assert caught.value.args == ("Access operation unavailable or uncertain",)
    assert flags["commits"] == flags["closed"] == 1
    elapsed = record.call_args.kwargs['details']['elapsed_ms']
    assert set(elapsed) == set(PHASES)
    assert_diagnostic(record, "commit", "SecretError", "08006", elapsed)
    assert not postgres_store._ACTIVE


def test_success_returns_legacy_rows_without_failure_event(monkeypatch):
    record = Mock()
    monkeypatch.setattr(postgres_store, "record_activity", record)
    store, flags = transport_double(monkeypatch)
    assert asyncio.run(store._run(QUERY, (CANARY,))) == [{"admitted": True}]
    record.assert_not_called()
    assert flags == {"credentials": 1, "connect": 1, "operations": 1, "commits": 1, "closed": 1}
    assert not postgres_store._ACTIVE


@pytest.mark.parametrize("phase", PHASES)
def test_cancelled_error_keeps_native_cancellation_without_diagnostic(monkeypatch, phase):
    record = Mock()
    monkeypatch.setattr(postgres_store, "record_activity", record)
    store, flags = transport_double(monkeypatch, phase, asyncio.CancelledError())
    with pytest.raises(asyncio.CancelledError):
        asyncio.run(store._run(QUERY, (CANARY,)))
    record.assert_not_called()
    assert flags["commits"] == (1 if phase == "commit" else 0)
    assert not postgres_store._ACTIVE


@pytest.mark.parametrize("query,context,message", [
    (
        postgres_store._HUB_ACCESS_CONFIRM,
        "PL/pgSQL function tools_access.hub_access_confirm(text,bigint,uuid,bigint,text,text,text,text) "
        "line 25 at RAISE",
        "local access or binding changed",
    ),
    (
        postgres_store._HUB_FILES_CONFIRM,
        "PL/pgSQL function tools_access.hub_files_confirm(text,bigint,uuid,bigint,text,text,text,text,text,text,"
        "uuid[],uuid[]) line 42 at RAISE",
        "current hub file access refused",
    ),
    (
        postgres_store._HUB_FILES_CONFIRM_846,
        "PL/pgSQL function tools_access.hub_files_confirm_846(text,bigint,uuid,bigint,text,text,text,text,text,text,"
        "uuid[],uuid[]) line 42 at RAISE",
        "current hub file access refused",
    ),
])
def test_known_final_403_is_translated_before_failure_diagnostic(monkeypatch, query, context, message):
    record = Mock()
    monkeypatch.setattr(postgres_store, "record_activity", record)
    monkeypatch.setattr(postgres_store, "access_environment_allowed", lambda: True)
    flags = install_transport(monkeypatch, sql_error(message=message, context=context))
    store = postgres_store.PostgresAccessStore(Provider(), ca_file="ca", role="app", database="access")
    with pytest.raises(ValueError) as caught:
        asyncio.run(store._run(query, ()))
    assert caught.value.args == ("Current local hub access refused",)
    record.assert_not_called()
    assert flags == {"closed": 1, "operations": 1}
    assert not postgres_store._ACTIVE
