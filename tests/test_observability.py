"""Actual log/metrics serialization excludes secrets and content on error paths."""

import json
import logging
import stat
import subprocess
import sys
from pathlib import Path
from typing import cast
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.exc import SQLAlchemyError

from arbiter.config import RedisSettings
from arbiter.governance.capacity import CapacityGate
from arbiter.governance.rate import RateDenied, RateGate, RateUnavailable
from arbiter.main import create_app
from arbiter.observability import OperationalMetrics, SafeFormatter, metrics_server, read_metrics
from arbiter.operations import clearance, migrate, provision
from arbiter.operations.security_checks import SENTINELS
from arbiter.persistence.workload import KeyBinding


def assert_clean(value: str) -> None:
    assert all(sentinel not in value for sentinel in SENTINELS)


def test_actual_python_warning_output_uses_safe_formatter() -> None:
    result = subprocess.run(  # noqa: S603 -- fixed interpreter/module; inert generated sentinel
        [
            sys.executable,
            "-c",
            "import warnings; from arbiter.observability import configure_logging; "
            "configure_logging(); warnings.warn('SENTINEL_'+'PROMPT_CONTENT')",
        ],
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    assert result.returncode == 0
    assert_clean(result.stdout + result.stderr)
    assert '"level": "WARNING"' in result.stderr


def test_uvicorn_startup_tracebacks_are_sanitized(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ARBITER_OIDC_ISSUER", SENTINELS[4])
    root = Path(__file__).resolve().parents[1]
    result = subprocess.run(  # noqa: S603 -- fixed Python module and checked-in config
        [
            sys.executable,
            "-m",
            "uvicorn",
            "arbiter.main:create_app",
            "--factory",
            "--log-config",
            str(root / "deploy/logging.json"),
            "--no-access-log",
        ],
        capture_output=True,
        text=True,
        timeout=20,
        check=False,
    )
    assert result.returncode != 0
    assert_clean(result.stdout + result.stderr)
    assert '"event": "runtime_log"' in result.stderr


def test_framework_validation_does_not_echo_rejected_input() -> None:
    app = create_app()

    @app.get("/fixture-validation")
    def fixture_validation(count: int) -> dict[str, int]:
        return {"count": count}

    # No lifespan required to exercise the actual framework validation handler.
    client = TestClient(app)
    response = client.get("/fixture-validation", params={"count": SENTINELS[0]})
    assert response.status_code == 422
    assert_clean(response.text)
    assert response.json()["error"] == {"code": "invalid_fields", "message": "Invalid request"}


@pytest.mark.parametrize(
    "logger_name", ["uvicorn.error", "httpx", "sqlalchemy.engine", "unexpected"]
)
def test_formatter_discards_message_args_extras_and_chained_traceback(logger_name: str) -> None:
    try:
        raise RuntimeError(" ".join(SENTINELS))
    except RuntimeError:
        record = logging.LogRecord(
            logger_name, logging.ERROR, SENTINELS[0], 1, "%s", (SENTINELS[1],), sys.exc_info()
        )
        record.__dict__["request"] = SENTINELS[2]
        record.stack_info = SENTINELS[3]
        output = SafeFormatter().format(record)
    assert_clean(output)
    assert set(json.loads(output)) == {"event", "component", "level", "exception"}


class HostileLogValue:
    def __str__(self) -> str:
        raise AssertionError(SENTINELS[2])

    def __repr__(self) -> str:
        raise AssertionError(SENTINELS[0])


@pytest.mark.parametrize(
    "field", ["name", "levelname", "exc_info", "stack_info", "module", "extra"]
)
@pytest.mark.parametrize("kind", ["none", "bytes", "dict", "list", "hostile"], ids=range(5))
def test_malformed_log_records_never_enter_raw_handler_error(
    capsys: pytest.CaptureFixture[str], field: str, kind: str
) -> None:
    record = logging.LogRecord(
        "httpx", logging.ERROR, "inert", 1, SENTINELS[2], (SENTINELS[0],), None
    )
    values: dict[str, object] = {
        "none": None,
        "bytes": SENTINELS[2].encode(),
        "dict": {"secret": HostileLogValue()},
        "list": [HostileLogValue()],
        "hostile": HostileLogValue(),
    }
    record.__dict__[field] = values[kind]
    handler = logging.StreamHandler()
    handler.setFormatter(SafeFormatter())
    # emit exercises the real handleError fallback if formatting were to raise.
    handler.emit(record)
    output = capsys.readouterr()
    assert_clean(output.out + output.err)
    event = json.loads(output.err)
    assert event["event"] == "runtime_log"
    assert event["component"] in {"httpx", "other"}
    assert event["level"] in {"ERROR", "OTHER"}
    assert type(event["exception"]) is bool
    assert len(output.err) < 128


def test_formatter_internal_failure_emits_fixed_record(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    record = logging.LogRecord("httpx", logging.ERROR, "inert", 1, SENTINELS[2], (), None)

    def broken(*args: object, **kwargs: object) -> str:
        raise RuntimeError(SENTINELS[0])

    with monkeypatch.context() as scoped:
        scoped.setattr("arbiter.observability.json.dumps", broken)
        handler = logging.StreamHandler()
        handler.setFormatter(SafeFormatter())
        handler.emit(record)
    output = capsys.readouterr()
    assert_clean(output.out + output.err)
    assert json.loads(output.err) == {
        "event": "runtime_log",
        "component": "other",
        "level": "OTHER",
        "exception": True,
    }


def test_private_metrics_export_has_bounded_dimensions_and_no_identifiers(tmp_path: Path) -> None:
    metrics = OperationalMetrics()
    for forbidden in (*SENTINELS, "request_id", "tenant_id", "native_tag"):
        with pytest.raises(ValueError):
            metrics.record(forbidden, "success")
        with pytest.raises(ValueError):
            metrics.record("execution", forbidden)
        with pytest.raises(ValueError):
            metrics.redis(forbidden)
    metrics.record("execution", "denied", 0.5)
    metrics.redis("barrier")
    gate = CapacityGate(2)
    binding = KeyBinding(uuid4(), uuid4(), ("inference:write",))
    claim = gate.try_acquire(binding, uuid4())
    assert claim is not None
    gate.quarantine(claim)
    sock = tmp_path / "metrics.sock"
    with metrics_server(
        lambda: {**metrics.output(), "capacity": gate.operational_snapshot()}, sock
    ):
        assert stat.S_IMODE(sock.stat().st_mode) == 0o600
        report = read_metrics(sock)
        wire = json.dumps(report)
        assert_clean(wire)
        assert all(
            value not in wire for value in ("request_id", "tenant_id", "key_id", "native_tag")
        )
        assert report["redis_last_observation"] == "barrier"
        assert report["capacity"] == {
            "limit": 2,
            "occupied": 1,
            "quarantined": 1,
            "recovery_ready": False,
            "saturated": False,
        }
        assert str(binding.tenant_id) not in wire and str(binding.key_id) not in wire
        assert {row["outcome"] for row in cast(list[dict[str, object]], report["operations"])} <= {
            "success",
            "denied",
            "unavailable",
            "deadline",
            "unknown",
            "failure",
            "rejected_input",
            "definite_failure",
            "invalid_response",
        }
    assert not sock.exists()


@pytest.mark.parametrize(
    "decision,state",
    [(1, "healthy"), (-1, "denied"), (-2, "denied"), (-3, "barrier"), (-4, "unavailable")],
)
def test_actual_rate_reply_exports_only_bounded_state(
    monkeypatch: pytest.MonkeyPatch,
    decision: int,
    state: str,
) -> None:
    import socket

    from arbiter.observability import metrics

    client, server = socket.socketpair()
    with client, server:
        server.sendall(f":{decision}\r\n".encode())
        monkeypatch.setattr(socket, "create_connection", lambda *args, **kwargs: client)
        action = RateGate(RedisSettings())
        binding = KeyBinding(uuid4(), uuid4(), ("inference:write",))
        if decision == 1:
            action.admit(binding, 1, 1)
        else:
            with pytest.raises(RateDenied if decision in {-1, -2} else RateUnavailable):
                action.admit(binding, 1, 1)
    assert metrics.output()["redis_last_observation"] == state


def test_unknown_or_symlink_socket_is_not_removed(tmp_path: Path) -> None:
    existing = tmp_path / "existing"
    existing.write_text("inert-fixture")
    sock = tmp_path / "metrics.sock"
    sock.symlink_to(existing)
    with pytest.raises(OSError), metrics_server(lambda: {}, sock):
        pass
    assert existing.read_text() == "inert-fixture" and sock.is_symlink()


@pytest.mark.parametrize("command", ["clearance", "provision", "migration"])
def test_operator_failures_do_not_echo_input_or_driver_details(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    command: str,
) -> None:
    if command == "clearance":
        monkeypatch.setattr(sys, "argv", ["clearance", "--tenant", SENTINELS[0]])
        action = clearance.main
    elif command == "provision":

        def action() -> None:
            provision.main([SENTINELS[0]])
    else:

        def fail() -> None:
            raise SQLAlchemyError(" ".join(SENTINELS))

        monkeypatch.setattr(migrate, "migrate", fail)
        action = migrate.main
    with pytest.raises(SystemExit) as failure:
        action()
    captured = capsys.readouterr()
    assert_clean(str(failure.value) + captured.out + captured.err)
