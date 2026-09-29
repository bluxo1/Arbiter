"""Real-PostgreSQL usage metadata evidence; skipped without provisioned restricted roles."""

import os
from collections.abc import Iterator
from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

import pytest
from sqlalchemy import text
from sqlalchemy.engine import Engine
from test_tenant_isolation import credential_engine, set_context

from arbiter.config import DatabaseSettings
from arbiter.identity.context import TenantContext
from arbiter.operations.policy import PolicyInput, PolicyService
from arbiter.operations.provision import MemberInput, ProvisioningService
from arbiter.persistence.tenant import runtime_engine, tenant_transaction
from arbiter.persistence.usage import UsageRepository

pytestmark = pytest.mark.skipif(
    os.environ.get("ARBITER_TEST_DATABASE") != "1",
    reason="requires provisioned real PostgreSQL",
)

DAY_START = datetime(2026, 9, 28, tzinfo=UTC)
MONTH_START = datetime(2026, 9, 1, tzinfo=UTC)

AUDIT_INSERT = text("""
    INSERT INTO arbiter.audit_events
    (id, tenant_id, actor_type, actor_reference, actor_membership_id, action,
     target_id, policy_revision, outcome)
    VALUES (:audit, :tenant, 'member', :reference, :member,
            'api_key_created', :key, 2, 'succeeded')
""")
KEY_INSERT = text("""
    INSERT INTO arbiter.api_keys
    (id, tenant_id, public_id, label, verifier, pepper_version, scopes, created_at,
     expires_at, created_by_membership_id, creation_audit_id)
    VALUES (:key, :tenant, :public, 'usage-fixture', :verifier, 1, ARRAY['usage:read'],
        CURRENT_TIMESTAMP, CURRENT_TIMESTAMP + interval '1 day', :member, :audit)
""")
QUOTA_INSERT = text("""
    INSERT INTO arbiter.quota_windows (id, tenant_id, window_start, committed, reserved)
    VALUES (:id, :tenant, :start, :committed, :reserved)
""")
BUDGET_INSERT = text("""
    INSERT INTO arbiter.budget_windows (id, tenant_id, window_start, committed, reserved)
    VALUES (:id, :tenant, :start, :committed, :reserved)
""")
REQUEST_INSERT = text("""
    INSERT INTO arbiter.requests
    (id, tenant_id, key_id, idempotency_key, payload_hmac, fingerprint_version,
     policy_revision, model_id, model_revision, model_alias, model_adapter,
     model_digest, context_cap, output_cap, credit_charge, quota_window_id,
     budget_window_id, quota_start, budget_start, created_at,
     reservation_id, reserve_event_id)
    VALUES (:request, :tenant, :key, :idempotency, :hmac, 1, 2, :model, 1,
        :alias, 'ollama', :digest, 4096, 256, 10, :quota, :budget,
        :day, :month, :created_at, :reservation, :event)
""")
RESERVATION_INSERT = text("""
    INSERT INTO arbiter.reservations
    (id, tenant_id, request_id, quota_window_id, budget_window_id, request_count, credits)
    VALUES (:reservation, :tenant, :request, :quota, :budget, 1, 10)
""")
EVENT_INSERT = text("""
    INSERT INTO arbiter.accounting_events
    (id, tenant_id, request_id, reservation_id, quota_window_id, budget_window_id,
     request_count, credits, kind)
    VALUES (:event, :tenant, :request, :reservation, :quota, :budget, 1, 10, 'reserve')
""")


@pytest.fixture(scope="module")
def store() -> Iterator[dict[str, Any]]:
    engines = {role: credential_engine(role) for role in ("runtime", "operator", "migration")}
    request_a = uuid4()
    model, alias = uuid4(), "usage-fixture-" + uuid4().hex
    try:
        with engines["migration"].begin() as connection:
            connection.execute(
                text("""
                    INSERT INTO arbiter.provider_models
                    (id, alias, adapter, model_digest, context_cap, output_cap,
                     credit_charge, revision, active)
                    VALUES (:id, :alias, 'ollama', :digest, 4096, 256, 10, 1, true)
                """),
                {"id": model, "alias": alias, "digest": "sha256:" + "a" * 64},
            )
        service = ProvisioningService(engines["operator"])
        tenant_a = service.create_tenant().tenant_id
        tenant_b = service.create_tenant().tenant_id
        for index, tenant in enumerate((tenant_a, tenant_b)):
            member = service.create_member(
                tenant, MemberInput("https://usage.fixture.invalid", uuid4().hex, "admin")
            ).object_id
            PolicyService(engines["operator"]).set_policy(
                tenant, PolicyInput(concurrency=2, aliases=(alias,))
            )
            if index != 0:
                continue
            key, audit, quota, budget = (uuid4() for _ in range(4))
            values: dict[str, Any] = {
                "request": request_a,
                "tenant": tenant,
                "key": key,
                "audit": audit,
                "member": member,
                "reference": str(member),
                "public": uuid4().hex,
                "verifier": b"v" * 32,
                "quota": quota,
                "budget": budget,
                "model": model,
                "alias": alias,
                "digest": "sha256:" + "a" * 64,
                "idempotency": "usage-fixture-idempotency-0001",
                "hmac": b"x" * 32,
                "day": DAY_START,
                "month": MONTH_START,
                "created_at": datetime(2026, 9, 28, 1, tzinfo=UTC),
                "reservation": uuid4(),
                "event": uuid4(),
            }
            with engines["migration"].begin() as connection:
                set_context(connection, tenant)
                connection.execute(AUDIT_INSERT, values)
                connection.execute(KEY_INSERT, values)
                connection.execute(
                    QUOTA_INSERT,
                    {
                        "id": quota,
                        "tenant": tenant,
                        "start": DAY_START,
                        "committed": 7,
                        "reserved": 1,
                    },
                )
                connection.execute(
                    BUDGET_INSERT,
                    {
                        "id": budget,
                        "tenant": tenant,
                        "start": MONTH_START,
                        "committed": 70,
                        "reserved": 10,
                    },
                )
                connection.execute(REQUEST_INSERT, values)
                connection.execute(RESERVATION_INSERT, values)
                connection.execute(EVENT_INSERT, values)
        yield {
            "engines": engines,
            "tenant_a": tenant_a,
            "tenant_b": tenant_b,
            "request_a": request_a,
        }
    finally:
        # Accepted evidence is immutable: retain this synthetic fixture in the isolated DB.
        # No table-owner bypass or unlogged deletion of accounting history.
        for engine in engines.values():
            engine.dispose()


def test_totals_read_own_window_only(store: dict[str, Any]) -> None:
    engine: Engine = runtime_engine(DatabaseSettings())
    try:
        with tenant_transaction(engine, TenantContext(store["tenant_a"])) as scoped:
            totals = UsageRepository(scoped).totals("day", DAY_START)
            assert (totals.committed, totals.reserved) == (7, 1)
        with tenant_transaction(engine, TenantContext(store["tenant_b"])) as scoped:
            totals = UsageRepository(scoped).totals("day", DAY_START)
            assert (totals.committed, totals.reserved) == (0, 0)
    finally:
        engine.dispose()


def test_request_status_is_tenant_scoped_without_existence_disclosure(
    store: dict[str, Any],
) -> None:
    engine: Engine = runtime_engine(DatabaseSettings())
    try:
        with tenant_transaction(engine, TenantContext(store["tenant_a"])) as scoped:
            status = UsageRepository(scoped).request_status(store["request_a"])
            assert status is not None and status.state == "reserved"
        with tenant_transaction(engine, TenantContext(store["tenant_b"])) as scoped:
            assert UsageRepository(scoped).request_status(store["request_a"]) is None
    finally:
        engine.dispose()


def test_absent_tenant_context_denies_metadata_reads(store: dict[str, Any]) -> None:
    with store["engines"]["runtime"].begin() as connection:
        for statement in (
            "SELECT id FROM arbiter.requests",
            "SELECT id FROM arbiter.quota_windows",
            "SELECT id FROM arbiter.budget_windows",
        ):
            assert connection.execute(text(statement)).all() == []


def test_pooled_connection_context_reset_between_tenants(store: dict[str, Any]) -> None:
    engine: Engine = runtime_engine(DatabaseSettings())
    try:
        with tenant_transaction(engine, TenantContext(store["tenant_a"])) as scoped:
            pid: int = scoped.connection().execute(text("SELECT pg_backend_pid()")).scalar_one()
        with engine.connect() as connection:
            assert connection.execute(text("SELECT pg_backend_pid()")).scalar_one() == pid
            assert connection.execute(text("SELECT id FROM arbiter.requests")).all() == []
        with tenant_transaction(engine, TenantContext(store["tenant_b"])) as scoped:
            assert scoped.connection().execute(text("SELECT pg_backend_pid()")).scalar_one() == pid
            assert UsageRepository(scoped).request_status(store["request_a"]) is None
    finally:
        engine.dispose()
