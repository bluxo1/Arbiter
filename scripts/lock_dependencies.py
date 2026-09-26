"""Resolve hash-pinned binary locks on the supported Python 3.13 Linux amd64 image."""

import json
import subprocess
import sys
import tempfile
import tomllib
from pathlib import Path

root = Path(__file__).resolve().parents[1]
project = tomllib.loads((root / "pyproject.toml").read_text())["project"]
for filename, dependencies in (
    ("requirements.lock", project["dependencies"]),
    ("requirements-dev.lock", project["dependencies"] + project["optional-dependencies"]["dev"]),
):
    with tempfile.TemporaryDirectory() as directory:
        report = Path(directory) / "resolution.json"
        subprocess.run(  # noqa: S603 -- fixed interpreter/module; pins are repository inputs
            [
                sys.executable,
                "-m",
                "pip",
                "install",
                "--dry-run",
                "--ignore-installed",
                "--only-binary=:all:",
                "--report",
                str(report),
                *dependencies,
            ],
            check=True,
        )
        resolved = json.loads(report.read_text())["install"]
    rows = ["# Python 3.13 / Linux amd64. Regenerate with scripts/lock_dependencies.py."]
    for package in sorted(resolved, key=lambda item: item["metadata"]["name"].lower()):
        metadata = package["metadata"]
        digest = package["download_info"]["archive_info"]["hashes"]["sha256"]
        rows.append(f"{metadata['name']}=={metadata['version']} --hash=sha256:{digest}")
    (root / filename).write_text("\n".join(rows) + "\n")
