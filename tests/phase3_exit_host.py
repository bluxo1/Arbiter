"""Opaque file handshake with the host controlling only the disposable test stack."""

import json
import os
from pathlib import Path
from time import monotonic, sleep
from typing import Literal
from uuid import uuid4

import pytest

Operation = Literal["redis_stop", "redis_start", "redis_restart", "postgres_stop", "postgres_start"]
HOST_REPLY_TIMEOUT_SECONDS = 90
POSTGRES_START_REPLY_TIMEOUT_SECONDS = 240
HOST_REPLY_POLL_SECONDS = 0.1


def request_host(operation: Operation) -> None:
    root = Path(os.environ["ARBITER_TEST_EXIT_CONTROL"])
    ticket = uuid4().hex
    temporary = root / f"{ticket}.tmp"
    request, reply = root / f"{ticket}.request.json", root / f"{ticket}.reply.json"
    temporary.write_text(json.dumps({"operation": operation}), encoding="utf-8")
    temporary.rename(request)
    # PostgreSQL recovery may use the full 180-second health wait after docker start.
    reply_timeout = (
        POSTGRES_START_REPLY_TIMEOUT_SECONDS
        if operation == "postgres_start"
        else HOST_REPLY_TIMEOUT_SECONDS
    )
    deadline = monotonic() + reply_timeout
    while monotonic() < deadline:
        if reply.is_file():
            result = json.loads(reply.read_text(encoding="utf-8"))
            if result == {"complete": True}:
                return
            if isinstance(result, dict) and result.get("complete") is False:
                pytest.fail(
                    f"host fault operation {operation} failed: {result.get('error')}; "
                    f"docker_status={result.get('docker_status')}; "
                    f"health_status={result.get('health_status')}; "
                    f"last_probe_exit={result.get('last_probe_exit')}"
                )
            pytest.fail(f"invalid host fault reply for operation {operation}")
        sleep(HOST_REPLY_POLL_SECONDS)
    pytest.fail(f"host did not complete disposable-stack operation {operation}")
