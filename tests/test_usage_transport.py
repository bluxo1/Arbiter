"""Offline usage/request metadata boundary tests; real-PostgreSQL cases are DB-gated."""

import base64
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast
from uuid import UUID, uuid4

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from arbiter.identity.context import TenantContext
from arbiter.main import create_app
from arbiter.operations.usage import (
    InvalidUsageQuery,
    ManagementUsage,
    aligned_selector,
    current_window,
)
from arbiter.persistence.identity import InaccessibleTenant
from arbiter.transport.usage import router as usage_router

TENANT = uuid4()
NOW = datetime.now(UTC)
# Fixed past selector: aligned and historical forever once the date has passed.
DAY_START = datetime(2026, 9, 28, tzinfo=UTC)
MONTH_START = datetime(2026, 9, 1, tzinfo=UTC)
# Current windows track the wall clock; routes compute them from the real time.
CURRENT_DAY = NOW.replace(hour=0, minute=0, second=0, microsecond=0)
CURRENT_MONTH = NOW.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
AUTH = {"Authorization": "Bearer fixture-management-token"}


@pytest.fixture
def secret_directory(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    directory = tmp_path / "secrets"
    directory.mkdir()
    (directory / "db_runtime_password").write_text("inert-test-password-" + "x" * 32)
    # The real lifespan also requires the maintenance credential at startup.
    (directory / "db_maintenance_password").write_text("inert-maintenance-password-" + "x" * 32)
    key_file = directory / "audit_cursor_key"
    key_file.write_bytes(base64.b64encode(bytes(32)))
    monkeypatch.setenv("ARBITER_AUDIT_KEY_FILE", str(key_file))
    pepper_file = directory / "api_key_pepper"
    pepper_file.write_bytes(base64.b64encode(bytes(32)))
    monkeypatch.setenv("ARBITER_KEYS_PEPPER_FILE", str(pepper_file))
    fingerprint_file = directory / "request_fingerprint_key"
    fingerprint_file.write_bytes(base64.b64encode(bytes(32)))
    monkeypatch.setenv("ARBITER_FINGERPRINT_KEY_FILE", str(fingerprint_file))
    monkeypatch.setenv("ARBITER_KEYS_PEPPER_VERSION", "1")
    monkeypatch.setenv("ARBITER_OIDC_ISSUER", "https://fixture.invalid/issuer")
    monkeypatch.setenv("ARBITER_OIDC_AUDIENCE", "arbiter-api")
    monkeypatch.setenv("ARBITER_OIDC_JWKS_URL", "https://fixture.invalid/keys")
    monkeypatch.delenv("ARBITER_OIDC_CA_FILE", raising=False)
    monkeypatch.setenv("ARBITER_DB_SECRET_DIRECTORY", str(directory))
    return directory


def test_production_routes_wired_fail_closed(secret_directory: Path) -> None:
    app = create_app()
    with TestClient(app) as client:
        assert client.get("/health/live").json() == {"status": "ok"}
        assert client.get("/health/ready").status_code == 503
        # Metadata routes exist; unwired dependencies fail closed without leaking.
        assert client.get("/v1/usage").status_code in {401, 503}
        assert client.get(f"/v1/requests/{uuid4()}").status_code in {401, 503}
        assert client.get("/v1/tenants/00000000-0000-0000-0000-000000000000/usage").status_code in {
            401,
            503,
        }
        assert client.get(
            f"/v1/tenants/00000000-0000-0000-0000-000000000000/requests/{uuid4()}"
        ).status_code in {401, 503}


def test_post_metadata_routes_rejected(secret_directory: Path) -> None:
    with TestClient(create_app()) as client:
        assert client.post("/v1/usage").status_code == 405
        assert client.post(f"/v1/requests/{uuid4()}").status_code == 405
        assert (
            client.post("/v1/tenants/00000000-0000-0000-0000-000000000000/usage").status_code == 405
        )


def test_aligned_selector_rules() -> None:
    unit, start = aligned_selector("day", "2026-09-28T00:00:00Z")
    assert (unit, start) == ("day", DAY_START)
    unit, start = aligned_selector("month", "2026-09-01T05:30:00+05:30")
    assert (unit, start) == ("month", MONTH_START)
    for window, start_text in (
        ("week", "2026-09-28T00:00:00Z"),
        ("day", "2026-09-28T12:00:00Z"),
        ("month", "2026-09-28T00:00:00Z"),
        ("day", "2026-09-28T00:00:00"),
        ("day", "not-a-timestamp"),
        ("day", "2999-01-01T00:00:00Z"),
        ("month", "2999-01-01T00:00:00Z"),
    ):
        with pytest.raises(InvalidUsageQuery):
            aligned_selector(window, start_text)


def test_current_window_bounds() -> None:
    now = datetime(2026, 9, 28, 15, 30, 45, tzinfo=UTC)
    assert current_window("day", now) == DAY_START
    assert current_window("month", now) == MONTH_START


class FakeStore:
    """Acts as the scoped transaction; serves canned rows and asserts tenant binding."""

    def __init__(self) -> None:
        self.context = TenantContext(TENANT)
        self.totals: dict[tuple[UUID, datetime], SimpleNamespace] = {}
        self.requests: dict[UUID, SimpleNamespace] = {}

    def connection(self) -> "FakeConnection":
        return FakeConnection(self)


class FakeConnection:
    def __init__(self, store: FakeStore) -> None:
        self._store = store

    def execute(
        self, statement: Any, parameters: dict[str, object] | None = None
    ) -> SimpleNamespace:
        params: dict[str, object] = dict(parameters or {})
        assert params["tenant"] == TENANT, "queries must bind the scoped tenant"
        sql = str(statement)
        if "FROM arbiter.requests" in sql:
            row = self._store.requests.get(cast(UUID, params["request"]))
        else:
            key = (cast(UUID, params["tenant"]), cast(datetime, params["start"]))
            row = self._store.totals.get(key)
        return SimpleNamespace(one_or_none=lambda: row)


class FakeManagementAccess:
    """Stands in for ManagementAccess; the callback runs with the fake scoped store."""

    def __init__(self, store: FakeStore) -> None:
        self.store = store

    async def run(
        self, token: Any, selector: Any, operation: Any, *, require_admin: bool = False
    ) -> Any:
        del token, selector, require_admin
        return operation(None, self.store)


class RejectingAccess:
    """Mirrors the sanitized absence ManagementAccess returns for inaccessible tenants."""

    async def run(
        self, token: Any, selector: Any, operation: Any, *, require_admin: bool = False
    ) -> Any:
        del token, selector, operation, require_admin
        raise InaccessibleTenant()


def metadata_app(access: object) -> FastAPI:
    app = FastAPI()
    app.state.management_usage = ManagementUsage(access)  # type: ignore[arg-type]
    app.include_router(usage_router)
    return app


def unknown_request_row(request_id: UUID) -> SimpleNamespace:
    return SimpleNamespace(
        id=request_id,
        state="unknown",
        outcome="unknown",
        credit_charge=10,
        input_tokens=None,
        output_tokens=None,
        model_alias="fixture-4b",
        policy_revision=2,
        created_at=datetime(2026, 9, 28, 10, 0, tzinfo=UTC),
        dispatched_at=datetime(2026, 9, 28, 10, 0, 5, tzinfo=UTC),
        finished_at=None,
    )


def seeded_store(request_id: UUID) -> FakeStore:
    store = FakeStore()
    # Clock-aligned current windows plus a fixed past window for historical reads.
    for day, month in ((CURRENT_DAY, CURRENT_MONTH), (DAY_START, MONTH_START)):
        store.totals[(TENANT, day)] = SimpleNamespace(window_start=day, committed=3, reserved=1)
        store.totals[(TENANT, month)] = SimpleNamespace(
            window_start=month, committed=30, reserved=2
        )
    store.requests[request_id] = unknown_request_row(request_id)
    return store


def test_management_current_and_historical_usage(secret_directory: Path) -> None:
    client = TestClient(metadata_app(FakeManagementAccess(seeded_store(uuid4()))))
    selector = f"/v1/tenants/{TENANT}/usage"

    current = client.get(selector, headers=AUTH)
    assert current.status_code == 200
    assert current.headers["cache-control"] == "no-store"
    payload = current.json()
    windows = {item["window"]: item for item in payload["data"]}
    assert windows["day"]["committed"] == 3 and windows["day"]["reserved"] == 1
    assert windows["month"]["committed"] == 30 and windows["month"]["reserved"] == 2
    assert windows["day"]["window_start"].startswith(CURRENT_DAY.strftime("%Y-%m-%dT%H:%M:%S"))
    assert list(windows["day"]) == ["window", "window_start", "committed", "reserved"]

    historical = client.get(
        f"{selector}?window=day&window_start=2026-09-28T00:00:00Z", headers=AUTH
    )
    assert historical.status_code == 200
    data = historical.json()["data"]
    assert len(data) == 1 and data[0]["committed"] == 3

    absent_window = client.get(
        f"{selector}?window=day&window_start=2026-09-27T00:00:00Z", headers=AUTH
    )
    assert absent_window.status_code == 200
    assert absent_window.json()["data"][0]["committed"] == 0
    assert absent_window.json()["data"][0]["reserved"] == 0


def test_management_request_status_shape_and_denials(secret_directory: Path) -> None:
    request_id = uuid4()
    client = TestClient(metadata_app(FakeManagementAccess(seeded_store(request_id))))
    base = f"/v1/tenants/{TENANT}/requests"

    found = client.get(f"{base}/{request_id}", headers=AUTH)
    assert found.status_code == 200
    assert found.headers["cache-control"] == "no-store"
    body = found.json()["data"]
    assert body["state"] == "unknown" and body["outcome"] == "unknown"
    assert body["input_tokens"] is None and body["output_tokens"] is None
    assert body["credit_charge"] == 10 and body["finished_at"] is None
    # Content-free projection: no internal materialized fields leak.
    assert set(body) == {
        "id",
        "state",
        "outcome",
        "credit_charge",
        "input_tokens",
        "output_tokens",
        "model_alias",
        "policy_revision",
        "created_at",
        "dispatched_at",
        "finished_at",
    }

    missing = client.get(f"{base}/{uuid4()}", headers=AUTH)
    assert missing.status_code == 404
    assert missing.json()["error"]["code"] == "not_found"

    unauthorized = TestClient(metadata_app(RejectingAccess()))
    response = unauthorized.get(f"{base}/{request_id}", headers=AUTH)
    assert response.status_code == 404
    assert response.json()["error"]["code"] == "not_found"
    usage_denied = unauthorized.get(f"/v1/tenants/{TENANT}/usage", headers=AUTH)
    assert usage_denied.status_code == 404

    unauthenticated = TestClient(metadata_app(FakeManagementAccess(seeded_store(request_id))))
    assert unauthenticated.get(f"{base}/{request_id}").status_code == 401


def test_management_query_validation(secret_directory: Path) -> None:
    client = TestClient(metadata_app(FakeManagementAccess(seeded_store(uuid4()))))
    selector = f"/v1/tenants/{TENANT}/usage"
    assert client.get("/v1/tenants/not-a-uuid/usage", headers=AUTH).status_code == 422
    assert (
        client.get(
            f"/v1/tenants/{TENANT}/requests/{uuid4()}?page_size=10", headers=AUTH
        ).status_code
        == 422
    )
    assert client.get(f"{selector}?window=day", headers=AUTH).status_code == 422
    assert (
        client.get(f"{selector}?window_start=2026-09-28T00:00:00Z", headers=AUTH).status_code == 422
    )
    assert (
        client.get(
            f"{selector}?window=day&window_start=2026-09-28T00:00:00Z&extra=1",
            headers=AUTH,
        ).status_code
        == 422
    )
    assert (
        client.get(
            f"{selector}?window=week&window_start=2026-09-28T00:00:00Z", headers=AUTH
        ).status_code
        == 422
    )
    assert (
        client.get(
            f"{selector}?window=day&window_start=2026-09-28T12:00:00Z", headers=AUTH
        ).status_code
        == 422
    )
    assert (
        client.get(
            f"{selector}?window=day&window_start=2999-01-01T00:00:00Z", headers=AUTH
        ).status_code
        == 422
    )
    assert (
        client.get(
            f"{selector}?window=day&window_start=2026-09-28T00:00:00Z&window=month",
            headers=AUTH,
        ).status_code
        == 422
    )


def test_management_terminal_success_shape(secret_directory: Path) -> None:
    request_id = uuid4()
    store = seeded_store(request_id)
    store.requests[request_id] = SimpleNamespace(
        id=request_id,
        state="succeeded",
        outcome="succeeded",
        credit_charge=10,
        input_tokens=12,
        output_tokens=256,
        model_alias="fixture-4b",
        policy_revision=2,
        created_at=datetime(2026, 9, 28, 10, 0, tzinfo=UTC),
        dispatched_at=datetime(2026, 9, 28, 10, 0, 5, tzinfo=UTC),
        finished_at=datetime(2026, 9, 28, 10, 0, 9, tzinfo=UTC),
    )
    client = TestClient(metadata_app(FakeManagementAccess(store)))
    body = client.get(f"/v1/tenants/{TENANT}/requests/{request_id}", headers=AUTH).json()["data"]
    assert body["state"] == "succeeded" and body["input_tokens"] == 12
    assert body["output_tokens"] == 256
