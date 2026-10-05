"""Scanner failure closure, real lock coverage and artifact positive controls."""

import json
import os
from pathlib import Path

import httpx
import pytest

from arbiter.operations.security_checks import SENTINELS, dependency_audit, inspect_artifacts


def test_artifact_inspection_accepts_safe_reports(tmp_path: Path) -> None:
    (tmp_path / "report.xml").write_text('<testsuite tests="1" failures="0"/>')
    (tmp_path / "runtime.log").write_text('{"level":"ERROR","exception":true}')
    assert inspect_artifacts(tmp_path) == {"artifacts_checked": 2, "passed": True}
    nested = tmp_path / "nested"
    nested.mkdir()
    (nested / "report.log").write_text("safe nested report")
    assert inspect_artifacts(tmp_path) == {"artifacts_checked": 3, "passed": True}


def test_artifact_inspection_propagates_nested_enumeration_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / "a-safe.log").write_text("safe")
    blocked = tmp_path / "z-blocked"
    blocked.mkdir()
    (blocked / "secret.log").write_text(SENTINELS[0])
    scandir = os.scandir

    def unreadable(path: str | Path) -> object:
        if Path(path) == blocked:
            raise PermissionError("inert enumeration denial")
        return scandir(path)

    # Deterministic even under a root container or Windows ACL semantics.
    monkeypatch.setattr(os, "scandir", unreadable)
    with pytest.raises(PermissionError, match="enumeration denial"):
        inspect_artifacts(tmp_path)


def test_artifact_inspection_propagates_file_read_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / "a-safe.log").write_text("safe")
    blocked = tmp_path / "z-unreadable.log"
    blocked.write_text(SENTINELS[0])
    read_bytes = Path.read_bytes

    def unreadable(path: Path) -> bytes:
        if path == blocked:
            raise PermissionError("inert file read denial")
        return read_bytes(path)

    monkeypatch.setattr(Path, "read_bytes", unreadable)
    with pytest.raises(PermissionError, match="file read denial"):
        inspect_artifacts(tmp_path)


@pytest.mark.parametrize("encoding", ["utf-16", "utf-8-sig"])
def test_artifact_inspection_handles_windows_reports_without_missing_sentinels(
    tmp_path: Path,
    encoding: str,
) -> None:
    path = tmp_path / "output.log"
    path.write_text("safe operational output", encoding=encoding)
    assert inspect_artifacts(tmp_path)["passed"] is True
    path.write_text(SENTINELS[0], encoding=encoding)
    with pytest.raises(ValueError, match="forbidden content"):
        inspect_artifacts(tmp_path)


@pytest.mark.parametrize("sentinel", SENTINELS, ids=range(len(SENTINELS)))
def test_artifact_inspection_rejects_each_forbidden_content(tmp_path: Path, sentinel: str) -> None:
    (tmp_path / "failure.log").write_text(sentinel)
    with pytest.raises(ValueError, match="forbidden content"):
        inspect_artifacts(tmp_path)


@pytest.mark.parametrize("kind", ["empty", "backup", "binary", "symlink"])
def test_artifact_inspection_does_not_silently_skip_unsupported_files(
    tmp_path: Path, kind: str
) -> None:
    if kind == "backup":
        (tmp_path / "sensitive.dump").write_bytes(b"archive")
    elif kind == "binary":
        (tmp_path / "binary.log").write_bytes(b"\xff\xff")
    elif kind == "symlink":
        (tmp_path / "link.log").symlink_to(tmp_path / "other.log")
    with pytest.raises((ValueError, UnicodeError)):
        inspect_artifacts(tmp_path)


@pytest.mark.parametrize("mode", ["clean", "finding", "partial", "paged", "server_error"])
def test_dependency_scan_uses_resolved_pins_and_fails_closed(mode: str) -> None:
    root = Path(__file__).resolve().parents[1]

    def reply(request: httpx.Request) -> httpx.Response:
        queries = json.loads(request.content)["queries"]
        assert all(item["package"]["ecosystem"] == "PyPI" and item["version"] for item in queries)
        assert len(queries) >= 30
        results: list[dict[str, object]] = [{} for _ in queries]
        if mode == "finding":
            results[0] = {"vulns": [{"id": "GHSA-inert-fixture-advisory"}]}
        elif mode == "partial":
            results.pop()
        elif mode == "paged":
            results[0] = {"next_page_token": "inert-fixture"}
        return httpx.Response(503 if mode == "server_error" else 200, json={"results": results})

    with httpx.Client(transport=httpx.MockTransport(reply)) as client:
        if mode in {"partial", "paged", "server_error"}:
            with pytest.raises((ValueError, httpx.HTTPStatusError)):
                dependency_audit(root, client)
        else:
            report = dependency_audit(root, client)
            assert report["passed"] is (mode == "clean")
            if mode == "finding":
                assert report["findings"]
