"""Diagnostic Files fermé, avec doubles déclarés et sans PG/S3/Docker réels."""

import asyncio
import json
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

import pytest

from src.mcp_tools import observability
from src.mcp_tools.auth import access_runtime
from src.mcp_tools.auth.context import current_token_info
from src.mcp_tools.storage import files_service
from src.mcp_tools.storage.files_credentials import StorageUnavailable
from src.mcp_tools.storage.files_postgres import Conflict
from src.mcp_tools.tools import files

OPERATION_ID = "00000000-0000-0000-0000-000000000950"
CANARY = "CANARY_PRIVATE_PATH_BODY_CREDENTIAL_EXCEPTION_950"
CONTEXT = {"trace_id": "trace-test-950", "call_id": "call-test-950", "operation_id": OPERATION_ID}


class FakeMCP:
    """Registre de test : seul le corps réel du handler est exercé ici."""

    def tool(self):
        def register(function):
            self.handler = function
            return function
        return register


def handler(monkeypatch, *, backend="postgres"):
    # Les décorateurs admission/MCP ne sont pas l'objet de ces tests unitaires.
    monkeypatch.setattr(files, "traced_tool", lambda name: lambda function: function)
    monkeypatch.setattr(files, "check_tool_access", Mock())
    monkeypatch.setattr(files, "get_settings", lambda: SimpleNamespace(files_metadata_backend=backend))
    registry = FakeMCP()
    files.register(registry)
    return registry.handler


def service_double(monkeypatch):
    """Le vrai dispatch, mais toutes ses dépendances à effets sont doublées."""
    service = object.__new__(files_service.FilesService)
    service.calls = asyncio.Semaphore(1)
    service.ready = AsyncMock()
    service.mutate = AsyncMock(return_value={"status": "ok", "result": "test-only"})
    service.info = AsyncMock(return_value={"status": "ok", "result": "test-only"})
    service.reconcile = AsyncMock(return_value={"status": "ok", "result": "test-only"})
    service.read_operations = AsyncMock(return_value={"status": "ok", "result": "test-only"})
    monkeypatch.setattr(files_service, "check_tool_access", Mock())
    refresh = AsyncMock()
    monkeypatch.setattr(access_runtime, "refresh_access", refresh)
    return service, refresh


def dispatch(service, operation="list", **arguments):
    token = current_token_info.set({"permissions": ["admin"], "tool_ids": ["files"]})
    try:
        return asyncio.run(service.dispatch(operation, {"operation_id": OPERATION_ID, **arguments}))
    finally:
        current_token_info.reset(token)


def assert_diagnostic(record, phase, error_type):
    record.assert_called_once_with(
        "files.failure", level="error", message="Échec Files",
        details={"phase": phase, "error_type": error_type},
    )
    assert CANARY not in str(record.call_args)


@pytest.mark.parametrize("phase", [
    "ready", "access_refresh", "mutate", "operation_info", "reconcile", "read", "validate",
    "catalog_initialize", "catalog_dispatch",
])
def test_helper_details_are_closed_and_do_not_format_exception(monkeypatch, phase):
    class SecretError(Exception):
        sqlstate = CANARY

        def __str__(self):
            raise AssertionError("diagnostic must not format exception")

        def __repr__(self):
            raise AssertionError("diagnostic must not represent exception")

    record = Mock()
    monkeypatch.setattr(files_service, "record_activity", record)
    files_service._record_files_failure(phase, SecretError(CANARY, {"credential": CANARY}))
    assert_diagnostic(record, phase, "SecretError")


@pytest.mark.parametrize("name", ["Bad Name", "Bad-Name", "Échec", "A" * 65, "Bad\nName"])
def test_invalid_exception_class_names_are_unclassified(monkeypatch, name):
    record = Mock()
    monkeypatch.setattr(files_service, "record_activity", record)
    error = type(name, (Exception,), {})(CANARY)
    files_service._record_files_failure("ready", error)
    assert_diagnostic(record, "ready", "unclassified")


def test_ascii_exception_class_name_at_64_character_boundary(monkeypatch):
    record = Mock()
    monkeypatch.setattr(files_service, "record_activity", record)
    name = "A" * 64
    files_service._record_files_failure("ready", type(name, (Exception,), {})(CANARY))
    assert_diagnostic(record, "ready", name)


@pytest.mark.parametrize("phase", [None, 1, False, CANARY, "catalog_validate"])
def test_unknown_helper_phases_are_unclassified(monkeypatch, phase):
    record = Mock()
    monkeypatch.setattr(files_service, "record_activity", record)
    files_service._record_files_failure(phase, RuntimeError(CANARY))
    assert_diagnostic(record, "unclassified", "RuntimeError")


def test_helper_logger_failure_is_swallowed(monkeypatch):
    record = Mock(side_effect=RuntimeError(CANARY))
    monkeypatch.setattr(files_service, "record_activity", record)
    assert files_service._record_files_failure("mutate", ValueError(CANARY)) is None
    assert record.call_count == 1


def test_real_activity_context_is_retained_without_exception_data(capsys):
    token = observability._activity_context.set(dict(CONTEXT))
    try:
        files_service._record_files_failure("mutate", ValueError(CANARY))
    finally:
        observability._activity_context.reset(token)
    emitted = json.loads(capsys.readouterr().err)["activity"]
    assert all(emitted[key] == value for key, value in CONTEXT.items())
    assert emitted["event"] == "files.failure"
    assert emitted["details"] == {"phase": "mutate", "error_type": "ValueError"}
    assert CANARY not in json.dumps(emitted)


@pytest.mark.parametrize(("phase", "operation", "method"), [
    ("ready", "list", "ready"),
    ("access_refresh", "list", "refresh"),
    ("mutate", "write", "mutate"),
    ("operation_info", "operation_info", "info"),
    ("reconcile", "reconcile", "reconcile"),
    ("read", "list", "read_operations"),
])
@pytest.mark.parametrize("error_class", [Conflict, StorageUnavailable, TimeoutError])
def test_dispatch_phase_and_legacy_response_are_preserved(
    monkeypatch, phase, operation, method, error_class,
):
    service, refresh = service_double(monkeypatch)
    target = refresh if method == "refresh" else getattr(service, method)
    target.side_effect = error_class(CANARY)
    record = Mock()
    monkeypatch.setattr(files_service, "record_activity", record)
    actual = dispatch(service, operation, path=CANARY, content=CANARY)
    if error_class is Conflict:
        if operation in {"write", "reconcile"}:
            expected = {
                "status": "incomplete", "message": CANARY, "remote_result": "uncertain",
                "durability_state": "unverified", "initial_confirmation": "unknown",
                "reconciliation_state": "pending", "operation_id": OPERATION_ID,
            }
        else:
            expected = {"status": "error", "message": CANARY, "operation_id": OPERATION_ID}
    else:
        expected = {
            "status": "incomplete",
            "message": "Dépendance/effet non confirmé ; inspection explicite requise",
            "remote_result": "uncertain", "effect_state": "unobserved",
            "durability_state": "unverified", "initial_confirmation": "unknown",
            "reconciliation_state": "pending", "operation_id": OPERATION_ID,
        }
    assert actual == expected
    assert json.dumps(actual, ensure_ascii=False).encode() == json.dumps(
        expected, ensure_ascii=False,
    ).encode()
    assert_diagnostic(record, phase, error_class.__name__)
    if phase in {"ready", "access_refresh"}:
        service.mutate.assert_not_awaited()
        service.read_operations.assert_not_awaited()


def test_read_post_refresh_has_its_own_failure_phase(monkeypatch):
    service, refresh = service_double(monkeypatch)
    refresh.side_effect = [None, StorageUnavailable(CANARY)]
    record = Mock()
    monkeypatch.setattr(files_service, "record_activity", record)
    result = dispatch(service)
    service.read_operations.assert_awaited_once()
    assert result["status"] == "incomplete"
    assert_diagnostic(record, "access_refresh", "StorageUnavailable")


def test_dependency_refusal_keeps_original_known_no_publication_response(monkeypatch):
    service, _ = service_double(monkeypatch)
    service.mutate.side_effect = files_service.DependencyRefused(CANARY, operation_id=OPERATION_ID)
    record = Mock()
    monkeypatch.setattr(files_service, "record_activity", record)
    assert dispatch(service, "delete", path=CANARY) == {
        "status": "error", "code": "mission_dependency_active", "message": CANARY,
        "effect_state": "not_published", "reconciliation_state": "not_required",
        "operation_id": OPERATION_ID,
    }
    assert_diagnostic(record, "mutate", "DependencyRefused")


@pytest.mark.parametrize("operation", ["enable_versioning", "unknown_operation"])
def test_unsupported_catalog_operation_is_classified_before_read(monkeypatch, operation):
    service, _ = service_double(monkeypatch)
    record = Mock()
    monkeypatch.setattr(files_service, "record_activity", record)
    result = dispatch(service, operation)
    assert result["status"] == "error"
    assert result["operation_id"] == OPERATION_ID
    assert_diagnostic(record, "validate", "Conflict")
    service.read_operations.assert_not_awaited()


@pytest.mark.parametrize(("operation", "method"), [
    ("list", "read_operations"), ("write", "mutate"),
    ("operation_info", "info"), ("reconcile", "reconcile"),
])
def test_success_does_not_emit_failure_diagnostic(monkeypatch, operation, method):
    service, _ = service_double(monkeypatch)
    record = Mock()
    monkeypatch.setattr(files_service, "record_activity", record)
    result = dispatch(service, operation)
    expected = {"status": "ok", "result": "test-only"}
    if operation == "list":
        expected = {"operation": "list", **expected}
    assert result == expected
    getattr(service, method).assert_awaited_once()
    record.assert_not_called()


def test_journal_failure_does_not_change_dispatch_refusal(monkeypatch):
    service, _ = service_double(monkeypatch)
    service.ready.side_effect = Conflict(CANARY)
    monkeypatch.setattr(files_service, "record_activity", Mock(side_effect=ValueError(CANARY)))
    assert dispatch(service) == {"status": "error", "message": CANARY, "operation_id": OPERATION_ID}


@pytest.mark.parametrize("phase", ["catalog_initialize", "catalog_dispatch"])
@pytest.mark.parametrize("journal_fails", [False, True])
def test_handler_catalog_exception_diagnostic_preserves_response(monkeypatch, phase, journal_fails):
    call = handler(monkeypatch)
    error = ValueError(CANARY)
    service = SimpleNamespace(dispatch=AsyncMock(side_effect=error))
    factory = Mock(side_effect=error) if phase == "catalog_initialize" else Mock(return_value=service)
    monkeypatch.setattr(files_service, "get_files_service", factory)
    record = Mock(side_effect=RuntimeError(CANARY) if journal_fails else None)
    monkeypatch.setattr(files_service, "record_activity", record)
    assert asyncio.run(call(operation="write", path=CANARY, content=CANARY)) == {
        "status": "error", "message": CANARY,
    }
    assert_diagnostic(record, phase, "ValueError")
    if phase == "catalog_initialize":
        service.dispatch.assert_not_awaited()


def test_malformed_dispatch_timeout_is_classified_by_handler_not_rewritten(monkeypatch):
    call = handler(monkeypatch)
    service, _ = service_double(monkeypatch)
    service.ready = AsyncMock(side_effect=AssertionError("ready must not be entered"))
    monkeypatch.setattr(files_service, "get_files_service", Mock(return_value=service))
    record = Mock()
    monkeypatch.setattr(files_service, "record_activity", record)
    result = asyncio.run(call(operation="write", timeout=None, operation_id=OPERATION_ID))
    assert result["status"] == "error"
    assert_diagnostic(record, "catalog_dispatch", "TypeError")
    service.ready.assert_not_awaited()


def test_handler_success_keeps_service_result_and_suppresses_failure_log(monkeypatch):
    call = handler(monkeypatch)
    service = SimpleNamespace(dispatch=AsyncMock(return_value={"status": "ok", "proof": "test-only"}))
    monkeypatch.setattr(files_service, "get_files_service", Mock(return_value=service))
    record = Mock()
    monkeypatch.setattr(files_service, "record_activity", record)
    monkeypatch.setattr(files, "record_activity", record)
    assert asyncio.run(call(operation="info", path=CANARY)) == {
        "operation": "info", "status": "ok", "proof": "test-only",
    }
    record.assert_not_called()


@pytest.mark.parametrize("override", ["endpoint", "access_key", "secret_key", "bucket", "region"])
@pytest.mark.parametrize("journal_fails", [False, True])
def test_s3_override_refusal_does_not_construct_catalog_or_leak_values(
    monkeypatch, override, journal_fails,
):
    call = handler(monkeypatch)
    factory = Mock(side_effect=AssertionError("catalog must not be constructed"))
    monkeypatch.setattr(files_service, "get_files_service", factory)
    record = Mock(side_effect=RuntimeError(CANARY) if journal_fails else None)
    monkeypatch.setattr(files, "record_activity", record)
    assert asyncio.run(call(operation="write", path=CANARY, content=CANARY, **{override: CANARY})) == {
        "status": "error", "message": "Override S3 interdit en mode catalogue",
    }
    factory.assert_not_called()
    record.assert_called_once_with(
        "files.failure", level="error", message="Échec Files",
        details={"phase": "catalog_validate", "code": "s3_override_forbidden"},
    )
    assert CANARY not in str(record.call_args)


def test_override_diagnostic_retains_real_native_call_context(monkeypatch, capsys):
    call = handler(monkeypatch)
    factory = Mock(side_effect=AssertionError("catalog must not be constructed"))
    monkeypatch.setattr(files_service, "get_files_service", factory)
    token = observability._activity_context.set(dict(CONTEXT))
    try:
        result = asyncio.run(call(operation="write", endpoint=CANARY, path=CANARY, content=CANARY))
    finally:
        observability._activity_context.reset(token)
    emitted = json.loads(capsys.readouterr().err)["activity"]
    assert result["status"] == "error"
    assert all(emitted[key] == value for key, value in CONTEXT.items())
    assert emitted["details"] == {"phase": "catalog_validate", "code": "s3_override_forbidden"}
    assert CANARY not in json.dumps(emitted)
    factory.assert_not_called()


def test_legacy_s3_reserved_parameter_refusal_does_not_gain_catalog_diagnostics(monkeypatch):
    call = handler(monkeypatch, backend="s3")
    record = Mock()
    monkeypatch.setattr(files, "record_activity", record)
    monkeypatch.setattr(files_service, "record_activity", record)
    assert asyncio.run(call(operation="read", path=CANARY, operation_id=OPERATION_ID)) == {
        "status": "error", "message": "Paramètres/opération réservés au catalogue PostgreSQL",
    }
    record.assert_not_called()
