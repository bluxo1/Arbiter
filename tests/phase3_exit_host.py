"""Opaque file handshake with the host controlling only the disposable test stack."""

import json
import os
from pathlib import Path
from time import monotonic, sleep
from typing import Literal
from uuid import uuid4

import pytest

Operation = Literal["redis_stop", "redis_start", "redis_restart", "postgres_stop", "postgres_start"]


def request_host(operation: Operation) -> None:
    root = Path(os.environ["ARBITER_TEST_EXIT_CONTROL"])
    ticket = uuid4().hex
    temporary = root / f"{ticket}.tmp"
    request, reply = root / f"{ticket}.request.json", root / f"{ticket}.reply.json"
    temporary.write_text(json.dumps({"operation": operation}), encoding="utf-8")
    temporary.rename(request)
    deadline = monotonic() + 60
    while monotonic() < deadline:
        if reply.is_file():
            assert json.loads(reply.read_text(encoding="utf-8")) == {"complete": True}
            return
        sleep(0.1)
    pytest.fail(f"host did not complete disposable-stack operation {operation}")
