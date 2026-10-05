"""Resolved-lock OSV audit and explicit content-sentinel artifact inspection."""

import importlib.metadata
import json
import os
import re
import stat
from collections.abc import Iterator
from pathlib import Path

import httpx

from arbiter.operations.provision import OperatorParser

SENTINELS = tuple(
    "SENTINEL_" + name
    for name in (
        "API_KEY_SECRET",
        "AUTHORIZATION_TOKEN",
        "PROMPT_CONTENT",
        "COMPLETION_CONTENT",
        "DATABASE_PASSWORD",
        "REDIS_PASSWORD",
        "PROVIDER_BODY",
    )
)
_PIN = re.compile(r"^([A-Za-z0-9_.-]+)==([A-Za-z0-9_.+-]+) --hash=sha256:[a-f0-9]{64}")


def locked_packages(root: Path) -> list[tuple[str, str]]:
    packages: dict[str, str] = {}
    for file in ("requirements.lock", "requirements-dev.lock"):
        for line in (root / file).read_text(encoding="utf-8").splitlines():
            if not line.strip() or line.startswith("#"):
                continue
            match = _PIN.match(line)
            if match is None:
                raise ValueError("unsupported lock entry")
            name, version = match.groups()
            canonical = re.sub(r"[-_.]+", "-", name).lower()
            if canonical in packages and packages[canonical] != version:
                raise ValueError("conflicting lock pins")
            if importlib.metadata.version(canonical) != version:
                raise ValueError("installed environment differs from locks")
            packages[canonical] = version
    return sorted(packages.items())


def dependency_audit(root: Path, client: httpx.Client) -> dict[str, object]:
    packages = locked_packages(root)
    response = client.post(
        "https://api.osv.dev/v1/querybatch",
        json={
            "queries": [
                {"package": {"name": name, "ecosystem": "PyPI"}, "version": version}
                for name, version in packages
            ]
        },
    )
    response.raise_for_status()
    results = response.json()["results"]
    if not isinstance(results, list) or len(results) != len(packages):
        raise ValueError("incomplete advisory response")
    findings = []
    for (name, version), result in zip(packages, results, strict=True):
        if not isinstance(result, dict) or result.get("next_page_token"):
            raise ValueError("incomplete advisory response")
        for advisory in result.get("vulns", []):
            identifier = advisory["id"]
            if (
                not isinstance(identifier, str)
                or re.fullmatch(r"[A-Za-z0-9_-]{1,128}", identifier) is None
            ):
                raise ValueError("invalid advisory identity")
            findings.append({"package": name, "version": version, "advisory": identifier})
    # Reject every advisory, including unscored ones; no severity-based silent omission.
    return {"packages_checked": len(packages), "findings": findings, "passed": not findings}


def _artifact_files(root: Path) -> Iterator[Path]:
    # scandir and entry metadata operations propagate errors; no incomplete walk
    # can be accepted merely because some other readable file was inspected.
    with os.scandir(root) as directory:
        entries = sorted(directory, key=lambda entry: entry.name)
    for entry in entries:
        if entry.is_symlink():
            raise ValueError("artifact symlink refused")
        path = Path(entry.path)
        if entry.is_dir(follow_symlinks=False):
            yield from _artifact_files(path)
        elif entry.is_file(follow_symlinks=False):
            yield path
        else:
            raise ValueError("only regular textual artifacts may be inspected")


def inspect_artifacts(root: Path) -> dict[str, object]:
    """Only textual operator reports. Refuse backups/binary/links, not silent skips."""
    if not stat.S_ISDIR(root.lstat().st_mode):
        raise ValueError("expected artifact directory")
    checked = 0
    for path in _artifact_files(root):
        if path.suffix.lower() not in {".json", ".jsonl", ".xml", ".log", ".txt", ".exit"}:
            raise ValueError("only textual operational artifacts may be inspected")
        if path.stat().st_size > 32 * 1024 * 1024:
            raise ValueError("artifact exceeds inspection bound")
        raw = path.read_bytes()
        # Windows PowerShell 5's Tee-Object emits BOM-marked UTF-16 reports.
        encoding = "utf-16" if raw.startswith((b"\xff\xfe", b"\xfe\xff")) else "utf-8-sig"
        content = raw.decode(encoding)
        if any(sentinel in content for sentinel in SENTINELS):
            raise ValueError("forbidden content detected in operational artifacts")
        checked += 1
    if checked == 0:
        raise ValueError("no artifacts inspected")
    return {"artifacts_checked": checked, "passed": True}


def main() -> None:
    parser = OperatorParser(description="Read-only security checks")
    parser.add_argument("operation", choices=("dependencies", "artifacts"))
    parser.add_argument("--root", type=Path, required=True)
    args = parser.parse_args()
    try:
        if args.operation == "dependencies":
            with httpx.Client(timeout=30, follow_redirects=False, trust_env=False) as client:
                result = dependency_audit(args.root, client)
        else:
            result = inspect_artifacts(args.root)
    except Exception:
        raise SystemExit("security check incomplete or failed") from None
    print(json.dumps(result, sort_keys=True))
    raise SystemExit(0 if result["passed"] else 1)


if __name__ == "__main__":
    main()
