"""Real PostgreSQL/Redis observability leakage proof without governance shortcuts."""

import io
import logging
import os
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.exc import SQLAlchemyError
from test_chat_transport import _headers, _request, _service
from test_observability import assert_clean
from test_provider_binding import bind
from test_provider_binding import binding_store as binding_store
from test_rate_admission import redis_ready as redis_ready
from test_reservation_transactions import ReservationStore

from arbiter.governance.rate import RateUnavailable
from arbiter.main import create_app
from arbiter.observability import SafeFormatter
from arbiter.operations.registry import ModelApproval
from arbiter.operations.security_checks import SENTINELS
from arbiter.providers.port import ProviderDeadline, ProviderResult, ProviderUnavailable

pytest_plugins = ("test_migrations",)
_REAL = pytest.mark.skipif(
    any(
        os.environ.get(name) != "1"
        for name in ("ARBITER_TEST_DATABASE", "ARBITER_TEST_MIGRATIONS", "ARBITER_TEST_REDIS")
    ),
    reason="real disposable PostgreSQL and Redis",
)


@_REAL
@pytest.mark.parametrize(
    "mode", ["success", "provider_error", "deadline", "redis", "database", "auth", "invalid"]
)
def test_real_chat_error_paths_emit_no_content(
    binding_store: tuple[ReservationStore, ModelApproval],
    redis_ready: None,
    monkeypatch: pytest.MonkeyPatch,
    mode: str,
) -> None:
    store, proof = binding_store
    bind(store, proof, 1, "fixture:one")
    actor = store.actor()
    service, provider, _, gate = _service(store)

    def generate(*args: object, **kwargs: object) -> ProviderResult:
        logging.getLogger("httpx").error(" ".join(SENTINELS), exc_info=True)
        if mode == "provider_error":
            raise ProviderUnavailable()
        if mode == "deadline":
            raise ProviderDeadline()
        return ProviderResult(SENTINELS[3], None, None, "stop")

    monkeypatch.setattr(provider, "generate", generate)
    if mode == "redis":

        def no_redis(*args: object, **kwargs: object) -> None:
            raise RateUnavailable(SENTINELS[5])

        monkeypatch.setattr("arbiter.governance.rate.RateGate.admit", no_redis)
    if mode == "database":

        def no_database(*args: object, **kwargs: object) -> None:
            raise SQLAlchemyError(SENTINELS[4])

        monkeypatch.setattr(service, "execute", no_database)
    app = create_app(chat_service=service)
    output = io.StringIO()
    handler = logging.StreamHandler(output)
    handler.setFormatter(SafeFormatter())
    logging.getLogger().addHandler(handler)
    try:
        with TestClient(app, raise_server_exceptions=False) as client:
            response = client.post(
                "/v1/chat/completions",
                headers=_headers(
                    SENTINELS[0] if mode == "auth" else actor.credential.get_secret_value()
                ),
                json={"invalid": SENTINELS[2]}
                if mode == "invalid"
                else _request(store.alias, SENTINELS[2]),
            )
            expected = {
                "success": 200,
                "provider_error": 503,
                "deadline": 504,
                "redis": 503,
                "database": 503,
                "auth": 401,
                "invalid": 422,
            }[mode]
            assert response.status_code == expected
            if mode != "success":
                assert_clean(response.text)
            if mode == "deadline":
                assert response.json()["error"]["code"] == "provider_deadline"
                assert gate.operational_snapshot()["quarantined"] == 1
                assert store.totals(actor) == (1, 0, 10, 0)
            for route in ("/health/live", "/health/ready"):
                assert_clean(client.get(route).text)
        assert_clean(output.getvalue())
        root = os.environ.get("ARBITER_TEST_EXIT_CONTROL")
        if root:
            (Path(root).parent / ("leakage-" + mode + ".log")).write_text(output.getvalue())
    finally:
        logging.getLogger().removeHandler(handler)
