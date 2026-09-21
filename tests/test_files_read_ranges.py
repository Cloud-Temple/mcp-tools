"""Contrats de la lecture S3 paginée de ``files``."""

from __future__ import annotations

import base64
import contextlib
import io
import json
import sys
import types
from datetime import datetime, timezone
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.mcp_tools.tools import files


class _Body:
    def __init__(self, payload: bytes) -> None:
        self.payload = payload

    def read(self) -> bytes:
        return self.payload


class _FakeS3:
    def __init__(self, payload: bytes, *, version_id: str | None = "v1", etag: str = '"etag-v1"') -> None:
        self.payload = payload
        self.version_id = version_id
        self.etag = etag
        self.head_calls: list[dict] = []
        self.get_calls: list[dict] = []

    def head_object(self, **kwargs) -> dict:
        self.head_calls.append(kwargs)
        result = {
            "ContentLength": len(self.payload), "ETag": self.etag,
            "ContentType": "application/octet-stream",
            "LastModified": datetime(2026, 1, 1, tzinfo=timezone.utc),
        }
        if self.version_id is not None:
            result["VersionId"] = self.version_id
        return result

    def get_object(self, **kwargs) -> dict:
        self.get_calls.append(kwargs)
        if kwargs.get("IfMatch") and kwargs["IfMatch"] != self.etag:
            error = RuntimeError("precondition failed")
            error.response = {"Error": {"Code": "PreconditionFailed"}}
            raise error
        payload = self.payload
        if "Range" in kwargs:
            start, end = (int(item) for item in kwargs["Range"].removeprefix("bytes=").split("-"))
            payload = payload[start:end + 1]
            return {
                "Body": _Body(payload), "ContentLength": len(payload),
                "ContentRange": f"bytes {start}-{end}/{len(self.payload)}",
            }
        return {
            "Body": _Body(payload), "ContentLength": len(payload),
            "ContentType": "application/octet-stream",
            "LastModified": datetime(2026, 1, 1, tzinfo=timezone.utc),
        }


def _run_read(monkeypatch: pytest.MonkeyPatch, fake: _FakeS3, **kwargs: object) -> dict:
    boto3 = types.ModuleType("boto3")
    boto3.client = lambda *args, **kwargs: fake
    botocore = types.ModuleType("botocore")
    botocore_config = types.ModuleType("botocore.config")
    botocore_config.Config = lambda **kwargs: object()
    monkeypatch.setitem(sys.modules, "boto3", boto3)
    monkeypatch.setitem(sys.modules, "botocore", botocore)
    monkeypatch.setitem(sys.modules, "botocore.config", botocore_config)
    script = files._build_python_script(
        operation=kwargs.pop("operation", "read"), endpoint="https://s3.invalid",
        access_key="access", secret_key="secret", bucket="bucket", region="fr1",
        path="document", path2=None, content=None, prefix=None, max_keys=100,
        max_output_chars=50_000, **kwargs,
    )
    stdout = io.StringIO()
    with contextlib.redirect_stdout(stdout):
        exec(compile(script, "<files-sandbox>", "exec"), {"__name__": "__main__"})
    return json.loads(stdout.getvalue())


def test_paged_read_reassembles_utf8_bytes_when_a_page_cuts_a_character(monkeypatch: pytest.MonkeyPatch) -> None:
    payload = b"a" + "€".encode() + b"z"
    fake = _FakeS3(payload)
    first = _run_read(monkeypatch, fake, offset=0, limit=2)
    pages = [
        first,
        _run_read(monkeypatch, fake, offset=2, limit=2, version_id=first["version_id"]),
        _run_read(monkeypatch, fake, offset=4, limit=2, version_id=first["version_id"]),
    ]

    assert b"".join(base64.b64decode(page["content_base64"]) for page in pages) == payload
    assert [page["next_offset"] for page in pages] == [2, 4, 5]
    assert pages[-1]["end"] is True
    assert [call["Range"] for call in fake.get_calls] == ["bytes=0-1", "bytes=2-3", "bytes=4-4"]
    assert all(call["VersionId"] == "v1" for call in fake.get_calls)


def test_paged_read_is_byte_exact_for_binary_and_exact_final_page(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = _FakeS3(b"\x00\xffab")

    result = _run_read(monkeypatch, fake, offset=0, limit=4)

    assert base64.b64decode(result["content_base64"]) == b"\x00\xffab"
    assert result["returned_bytes"] == 4
    assert result["next_offset"] == 4
    assert result["end"] is True
    assert result["encoding"] == "base64"


def test_unversioned_pagination_requires_and_honors_the_previous_etag(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = _FakeS3(b"abcdef", version_id=None)

    first = _run_read(monkeypatch, fake, offset=0, limit=3)
    missing_guard = _run_read(monkeypatch, fake, offset=3, limit=3)
    guarded = _run_read(monkeypatch, fake, offset=3, limit=3, if_match=first["etag"])

    assert first["etag"] == '"etag-v1"'
    assert missing_guard == {
        "status": "error", "operation": "read", "code": "object_changed",
        "message": "La reprise d'une lecture paginée exige le VersionId ou l'ETag de la page précédente.",
    }
    assert base64.b64decode(guarded["content_base64"]) == b"def"
    assert fake.get_calls[-1]["IfMatch"] == '"etag-v1"'


def test_offset_at_end_returns_an_empty_terminal_page_and_info_exposes_version(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = _FakeS3(b"abc")

    page = _run_read(monkeypatch, fake, offset=3, limit=2, version_id="v1")
    info = _run_read(monkeypatch, fake, operation="info", version_id="v1")

    assert page["content_base64"] == ""
    assert page["end"] is True
    assert page["next_offset"] == 3
    assert fake.get_calls == []
    assert fake.head_calls[-1]["VersionId"] == "v1"
    assert info["etag"] == '"etag-v1"'
    assert info["version_id"] == "v1"


def test_null_version_is_not_a_resume_token_and_uses_etag_chaining(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = _FakeS3(b"abcdef", version_id="null")

    first = _run_read(monkeypatch, fake, offset=0, limit=3, version_id="null")
    second = _run_read(monkeypatch, fake, offset=3, limit=3, if_match=first["etag"])

    assert "version_id" not in first
    assert "VersionId" not in fake.head_calls[0]
    assert "VersionId" not in fake.get_calls[0]
    assert second["end"] is True
    assert fake.get_calls[-1]["IfMatch"] == '"etag-v1"'


def test_versioned_resume_never_adopts_a_newly_discovered_version(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = _FakeS3(b"abcdef", version_id="v1")

    first = _run_read(monkeypatch, fake, offset=0, limit=3)
    fake.version_id = "v2"
    resumed_without_token = _run_read(monkeypatch, fake, offset=3, limit=3)

    assert first["version_id"] == "v1"
    assert resumed_without_token["code"] == "object_changed"
    assert "VersionId ou l'ETag" in resumed_without_token["message"]
    assert len(fake.get_calls) == 1


def test_paged_read_fails_closed_without_a_version_or_etag(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = _FakeS3(b"abc", version_id=None, etag="")

    result = _run_read(monkeypatch, fake, offset=0, limit=2)

    assert result["status"] == "error"
    assert "exige un ETag S3" in result["message"]
    assert fake.get_calls == []


def test_legacy_read_and_range_validation_remain_explicit(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = _FakeS3(b"plain text")

    legacy = _run_read(monkeypatch, fake)

    assert legacy == {
        "status": "success", "operation": "read", "bucket": "bucket",
        "path": "document", "content": "plain text", "size": 10,
        "content_type": "application/octet-stream",
        "last_modified": "2026-01-01T00:00:00+00:00",
    }
    assert files._validate_read_range_inputs(True, None, None, 50_000) == (
        "Le paramètre 'offset' doit être un entier en octets supérieur ou égal à 0."
    )
    assert files._validate_read_range_inputs(None, 50_000, None, 50_000).startswith(
        "Le paramètre 'limit' doit être entre 1 et"
    )
