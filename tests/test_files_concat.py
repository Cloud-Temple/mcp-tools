"""Contrats hermétiques de ``files operation='concat'``.

Le script réellement confié à la sandbox est exécuté avec un faux boto3 : les
tests vérifient donc le chemin qui lit et écrit les octets, sans Docker ni S3.
"""

from __future__ import annotations

import contextlib
import hashlib
import io
import json
import sys
import types
from unittest.mock import ANY

import pytest

from mcp_tools.tools import files


class _Body:
    def __init__(self, payload: bytes, chunk_size: int = 65_536) -> None:
        self.payload = payload
        self.chunk_size = chunk_size
        self.offset = 0
        self.closed = False

    def read(self, requested: int = -1) -> bytes:
        if self.offset >= len(self.payload):
            return b""
        size = self.chunk_size if requested < 0 else min(requested, self.chunk_size)
        chunk = self.payload[self.offset:self.offset + size]
        self.offset += len(chunk)
        return chunk

    def close(self) -> None:
        self.closed = True


class _FakeS3:
    def __init__(self, heads: dict[str, bytes], payloads: dict[str, bytes], *, chunk_size: int = 65_536) -> None:
        self.heads = heads
        self.payloads = payloads
        self.chunk_size = chunk_size
        self.puts: list[dict] = []
        self.get_calls: list[dict] = []

    def head_object(self, *, Bucket: str, Key: str) -> dict:
        if Key not in self.heads:
            raise RuntimeError("missing")
        return {"ContentLength": len(self.heads[Key]), "VersionId": f"version-{Key}"}

    def get_object(self, **kwargs) -> dict:
        self.get_calls.append(kwargs)
        key = kwargs["Key"]
        if key not in self.payloads:
            raise RuntimeError("missing")
        return {"Body": _Body(self.payloads[key], self.chunk_size)}

    def put_object(self, **kwargs) -> dict:
        self.puts.append({**kwargs, "payload": kwargs["Body"].read()})
        return {"ETag": '"assembled"', "VersionId": "output-version"}


def _run_concat(monkeypatch: pytest.MonkeyPatch, fake: _FakeS3, *, paths: list[str], path: str = "out.md", separator: str = "\n\n") -> dict:
    boto3 = types.ModuleType("boto3")
    boto3.client = lambda *args, **kwargs: fake
    botocore = types.ModuleType("botocore")
    botocore_config = types.ModuleType("botocore.config")
    botocore_config.Config = lambda **kwargs: object()
    monkeypatch.setitem(sys.modules, "boto3", boto3)
    monkeypatch.setitem(sys.modules, "botocore", botocore)
    monkeypatch.setitem(sys.modules, "botocore.config", botocore_config)
    script = files._build_python_script(
        operation="concat",
        endpoint="https://s3.invalid",
        access_key="access",
        secret_key="secret",
        bucket="bucket",
        region="fr1",
        path=path,
        path2=None,
        content=None,
        prefix=None,
        max_keys=100,
        max_output_chars=50_000,
        paths=paths,
        separator=separator,
    )
    stdout = io.StringIO()
    with contextlib.redirect_stdout(stdout):
        exec(compile(script, "<files-sandbox>", "exec"), {"__name__": "__main__"})
    return json.loads(stdout.getvalue())


def test_concat_keeps_ordered_bytes_and_returns_verifiable_manifest(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = _FakeS3(
        {"a.md": b"alpha", "empty.md": b"", "b.md": "\u03a9".encode()},
        {"a.md": b"alpha", "empty.md": b"", "b.md": "\u03a9".encode()},
        chunk_size=1,
    )

    result = _run_concat(monkeypatch, fake, paths=["a.md", "empty.md", "b.md"], separator="|")

    expected = b"alpha||" + "\u03a9".encode()
    assert result == {
        "status": "success",
        "operation": "concat",
        "bucket": "bucket",
        "path": "out.md",
        "size": len(expected),
        "sha256": hashlib.sha256(expected).hexdigest(),
        "parts": 3,
        "sources": [
            {"path": "a.md", "offset": 0, "size": 5, "sha256": hashlib.sha256(b"alpha").hexdigest(), "version_id": "version-a.md"},
            {"path": "empty.md", "offset": 6, "size": 0, "sha256": hashlib.sha256(b"").hexdigest(), "version_id": "version-empty.md"},
            {"path": "b.md", "offset": 7, "size": 2, "sha256": hashlib.sha256("\u03a9".encode()).hexdigest(), "version_id": "version-b.md"},
        ],
        "separator_bytes": 1,
        "etag": '"assembled"',
        "version_id": "output-version",
    }
    assert fake.puts == [{
        "Bucket": "bucket", "Key": "out.md", "ContentType": "text/plain; charset=utf-8", "Body": ANY,
        "payload": expected,
    }]
    assert [call["VersionId"] for call in fake.get_calls] == ["version-a.md", "version-empty.md", "version-b.md"]


def test_concat_refuses_binary_source_without_writing_destination(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = _FakeS3({"binary": b"\xff"}, {"binary": b"\xff"})

    result = _run_concat(monkeypatch, fake, paths=["binary"])

    assert result["status"] == "error"
    assert "Source non UTF-8 : binary" in result["message"]
    assert fake.puts == []


def test_concat_marks_a_put_failure_as_remote_result_uncertain(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = _FakeS3({"a": b"ok"}, {"a": b"ok"})
    fake.put_object = lambda **kwargs: (_ for _ in ()).throw(RuntimeError("connection reset"))

    result = _run_concat(monkeypatch, fake, paths=["a"])

    assert result == {
        "status": "error",
        "operation": "concat",
        "message": "Écriture de destination indéterminée.",
        "remote_result": "uncertain",
    }


def test_concat_enforces_separator_in_preflight_size_limit(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(files, "FILES_MAX_CONTENT_SIZE", 7)
    fake = _FakeS3({"a": b"abc", "b": b"def"}, {"a": b"abc", "b": b"def"})

    result = _run_concat(monkeypatch, fake, paths=["a", "b"], separator="--")

    assert result["status"] == "error"
    assert "Résultat trop volumineux (8 octets, max 7)" in result["message"]
    assert fake.puts == []


def test_concat_rechecks_size_when_source_changes_after_head(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(files, "FILES_MAX_CONTENT_SIZE", 5)
    fake = _FakeS3({"a": b"x"}, {"a": b"abcdef"})

    result = _run_concat(monkeypatch, fake, paths=["a"])

    assert result["status"] == "error"
    assert "Résultat trop volumineux pendant la concaténation" in result["message"]
    assert fake.puts == []


def test_concat_rejects_destination_as_source_at_mcp_boundary() -> None:
    assert files._validate_concat_inputs("report.md", ["report.md"], "\n") == (
        "La destination 'path' ne peut pas aussi être une source de concaténation."
    )


def test_concat_timeout_is_recorded_as_an_uncertain_remote_result(monkeypatch: pytest.MonkeyPatch) -> None:
    events: list[tuple] = []
    monkeypatch.setattr(files, "bind_activity", lambda **kwargs: events.append(("bind", kwargs)))
    monkeypatch.setattr(files, "record_activity", lambda *args, **kwargs: events.append(("record", args, kwargs)))

    files._record_uncertain_concat_result("out.md", "timeout")

    assert events == [
        ("bind", {"remote_result": "uncertain"}),
        ("record", ("remote.result_uncertain",), {
            "level": "warning",
            "message": "Concaténation S3 interrompue : effet distant indéterminé",
            "details": {"operation": "concat", "path": "out.md", "reason": "timeout"},
        }),
    ]
