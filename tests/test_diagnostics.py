"""Negative protocol tests and opt-in checks against real foundation dependencies."""

import os
import socket
from time import monotonic

import pytest
from sqlalchemy import create_engine
from sqlalchemy.pool import NullPool

from arbiter.config import DatabaseSettings, RedisSettings
from arbiter.operations.diagnostics import (
    FoundationReport,
    _reply,
    main,
    postgres_foundation,
    redis_foundation,
)


@pytest.mark.parametrize("postgres,redis", [(True, True), (False, True), (True, False)])
def test_healthy_foundation_never_claims_admission_readiness(postgres: bool, redis: bool) -> None:
    report = FoundationReport(postgres=postgres, redis=redis)
    assert report.foundation_ready is (postgres and redis)
    assert report.output()["ready"] is False
    assert report.output()["unimplemented_gates"] == [
        "identity",
        "enforcement",
        "recovery",
        "model_readiness",
    ]


@pytest.mark.parametrize(
    "wire",
    [b"-ERR private server detail\r\n", b"$65537\r\n", b"$-1\r\n", b"$x\r\n", b"+" * 128],
)
def test_invalid_or_oversized_protocol_replies_are_rejected(wire: bytes) -> None:
    client, server = socket.socketpair()
    with client, server:
        server.sendall(wire)
        with pytest.raises(ValueError):
            _reply(client, monotonic() + 1)


def test_protocol_deadline_is_absolute() -> None:
    client, server = socket.socketpair()
    with client, server, pytest.raises(TimeoutError):
        _reply(client, monotonic() - 1)


def test_cli_does_not_print_exception_details(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def fail() -> FoundationReport:
        raise RuntimeError("private diagnostic detail")

    monkeypatch.setattr("arbiter.operations.diagnostics.diagnose", fail)
    with pytest.raises(SystemExit) as failure:
        main()
    assert str(failure.value) == "foundation diagnostics failed"
    assert capsys.readouterr().out == ""


@pytest.mark.skipif(os.environ.get("ARBITER_TEST_DATABASE") != "1", reason="real PostgreSQL")
@pytest.mark.parametrize("role", ["runtime", "operator"])
def test_catalog_diagnostics_require_runtime_authority(role: str) -> None:
    settings = DatabaseSettings()
    # Selecting a role is test-only; the diagnostic command always uses runtime.
    engine = create_engine(
        settings.url("runtime").set(
            username=f"arbiter_{role}",
            password=settings.password(
                "runtime" if role == "runtime" else "operator"
            ).get_secret_value(),
        ),
        poolclass=NullPool,
        hide_parameters=True,
    )
    try:
        assert postgres_foundation(engine) is (role == "runtime")
    finally:
        engine.dispose()


@pytest.mark.skipif(os.environ.get("ARBITER_TEST_REDIS") != "1", reason="real Redis")
def test_real_redis_foundation_configuration() -> None:
    assert redis_foundation(RedisSettings()) is True


def test_unreachable_redis_fails_closed() -> None:
    # Hold an unlistened socket to avoid a race with another local listener.
    with socket.socket() as unused:
        unused.bind(("127.0.0.1", 0))
        settings = RedisSettings(host="127.0.0.1", port=unused.getsockname()[1])
        assert redis_foundation(settings) is False
