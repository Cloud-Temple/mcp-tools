"""Refus métier SQL final distingué des pannes ; transport simulé ici, PG réel séparé."""

import asyncio
import json
from types import SimpleNamespace

import psycopg
import pytest
from psycopg.pq import DiagnosticField as F
from src.mcp_tools.auth.postgres_store import _ACTIVE, _HUB_ACCESS_CONFIRM, PostgresAccessStore
from src.mcp_tools.auth.token_store import TokenStoreUnavailable

from test_hub_activity_31 import Client, Store, cfg, hub, issuer
from test_postgres_access_store_31 import Provider, contract_rows

ORIGIN = (
    "PL/pgSQL function tools_access.hub_access_confirm(text,bigint,uuid,bigint,text,text,text,text) line 25 at RAISE"
)


def sql_error(
    message="local access or binding changed", context=ORIGIN, error_type=psycopg.errors.InsufficientPrivilege
):
    return error_type("PRIVATE-SQL-CANARY", info={F.MESSAGE_PRIMARY: message.encode(), F.CONTEXT: context.encode()})


def install_transport(monkeypatch, error):
    state = {"closed": 0, "operations": 0}

    class Cursor:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            pass

        async def execute(self, query, *args):
            self.query = query
            if "schema_contract" not in query and "pg_roles" not in query:
                state["operations"] += 1
                raise error

        async def fetchall(self):
            return contract_rows(self.query)

    def close():
        state["closed"] += 1

    class Connection:
        pgconn = SimpleNamespace(finish=close)

        def cursor(self):
            return Cursor()

        async def commit(self):
            raise AssertionError("refused statement cannot commit")

    async def connect(**kwargs):
        return Connection()

    monkeypatch.setattr(psycopg.AsyncConnection, "connect", connect)
    monkeypatch.setattr(psycopg.capabilities, "has_cancel_safe", lambda: True)
    return state


@pytest.mark.parametrize(
    "message", ["local access changed", "local binding changed", "local access or binding changed"]
)
def test_only_known_final_sql_business_refusals_become_domain_refusals(monkeypatch, message):
    state = install_transport(monkeypatch, sql_error(message))
    store = PostgresAccessStore(Provider(), ca_file="ca", role="app", database="access")
    with pytest.raises(ValueError, match="Current local hub access refused"):
        asyncio.run(store._run(_HUB_ACCESS_CONFIRM, ()))
    assert state == {"closed": 1, "operations": 1} and not _ACTIVE


@pytest.mark.parametrize(
    "error,query",
    [
        (sql_error("permission denied for function hub_access_confirm", ""), _HUB_ACCESS_CONFIRM),
        (sql_error(context=ORIGIN.replace("tools_access.", "other_schema.")), _HUB_ACCESS_CONFIRM),
        (sql_error(context=ORIGIN.replace("hub_access_confirm", "admit_mission")), _HUB_ACCESS_CONFIRM),
        (sql_error(context=ORIGIN + "\nSQL statement nested helper"), _HUB_ACCESS_CONFIRM),
        (sql_error(error_type=psycopg.errors.UndefinedFunction), _HUB_ACCESS_CONFIRM),
        (sql_error(error_type=psycopg.errors.QueryCanceled), _HUB_ACCESS_CONFIRM),
        (sql_error("unexpected backend diagnostic"), _HUB_ACCESS_CONFIRM),
        (sql_error(), "SELECT * FROM tools_access.admit_mission()"),
        (RuntimeError("PRIVATE-CONNECTION-CANARY"), _HUB_ACCESS_CONFIRM),
    ],
)
def test_acl_schema_cancel_unexpected_sql_and_other_routines_remain_unavailable(monkeypatch, error, query):
    state = install_transport(monkeypatch, error)
    store = PostgresAccessStore(Provider(), ca_file="ca", role="app", database="access")
    with pytest.raises(TokenStoreUnavailable) as failure:
        asyncio.run(store._run(query, ()))
    assert "PRIVATE" not in str(failure.value)
    assert state == {"closed": 1, "operations": 1} and not _ACTIVE


@pytest.mark.parametrize(
    "error,expected",
    [
        (sql_error(), 403),
        (sql_error("permission denied for function hub_access_confirm", ""), 503),
        (sql_error(error_type=psycopg.errors.UndefinedFunction), 503),
        (sql_error(error_type=psycopg.errors.QueryCanceled), 503),
    ],
)
def test_real_store_error_translation_reaches_public_batch_route_without_projection(monkeypatch, error, expected):
    install_transport(monkeypatch, error)
    monkeypatch.setattr(hub.ssl, "create_default_context", lambda **kwargs: object())

    async def scenario():
        real = PostgresAccessStore(Provider(), ca_file="ca", role="app", database="access")

        class Reader(Store):
            async def confirm_hub_access(self, *args):
                return await real.confirm_hub_access(*args)

        body = json.dumps(dict(mission_id="mis_1", root_agent_id="ag_root", limit=1)).encode()
        token, keys, _ = issuer(body)
        sent = []

        async def receive():
            return dict(type="http.request", body=body)

        async def send(message):
            sent.append(message)

        route = hub.HubActivityMiddleware(
            None, cfg(), client_factory=lambda **kwargs: Client(keys), store_factory=Reader
        )
        await route(
            dict(
                type="http",
                path=hub.PATH,
                method="POST",
                headers=[(b"authorization", b"Bearer local-opaque"), (b"x-tools-activity-context", token.encode())],
            ),
            receive,
            send,
        )
        assert sent[0]["status"] == expected
        value = json.loads(sent[1]["body"])
        assert not {"calls", "count", "next_cursor"} & value.keys()
        assert "PRIVATE" not in sent[1]["body"].decode()

    asyncio.run(scenario())
