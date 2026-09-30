"""Focused capacity ownership, restart reconciliation and operator clearance."""

import os
import sys
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import datetime
from uuid import UUID, uuid4

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine
from sqlalchemy.exc import DBAPIError, SQLAlchemyError
from test_reservation_release import evidence
from test_reservation_transactions import Actor, ReservationStore, reserve
from test_reservation_transactions import store as store
from test_tenant_isolation import set_context

from arbiter.config import DatabaseSettings
from arbiter.governance.capacity import CapacityGate, CapacityLease, CapacityService
from arbiter.governance.dispatch import DispatchConflict, DispatchService
from arbiter.governance.release import ReleaseConflict, ReleaseService
from arbiter.governance.reservation import ReservationDenied
from arbiter.identity.context import TenantContext
from arbiter.operations.maintenance import MaintenanceService, MaintenanceUnavailable
from arbiter.persistence.maintenance import candidates, clear_unknown, maintenance_engine
from arbiter.persistence.reservation import ReservationResult
from arbiter.persistence.tenant import tenant_transaction
from arbiter.persistence.workload import KeyBinding
from arbiter.providers.double import DeterministicProvider


@pytest.fixture(scope="module")
def discovery_engine() -> Iterator[Engine]:
    engine = maintenance_engine(DatabaseSettings())
    try:
        yield engine
    finally:
        engine.dispose()


def scope_maintenance(monkeypatch: pytest.MonkeyPatch, tenant_id: UUID) -> None:
    """Keep retained fault-injection rows from other test tenants out of this sweep."""
    from arbiter.operations import maintenance

    original = candidates
    monkeypatch.setattr(
        maintenance,
        "candidates",
        lambda engine, kind: tuple(
            item for item in original(engine, kind) if item.tenant_id == tenant_id
        ),
    )


def aged_reservation(
    store: ReservationStore, actor: Actor, age_seconds: int
) -> tuple[ReservationResult, UUID]:
    """Owner-only historical fixture with valid immutable window/accounting links."""
    source_result = reserve(store, actor)
    source = source_result.request_id
    request, reservation, event = uuid4(), uuid4(), uuid4()
    with store.migration.begin() as connection:
        set_context(connection, actor.tenant)
        created: datetime = connection.execute(
            text("SELECT clock_timestamp()-(:age * interval '1 second')"),
            {"age": age_seconds},
        ).scalar_one()
        day, month = connection.execute(
            text("""
                SELECT date_trunc('day',CAST(:created AS timestamptz) AT TIME ZONE 'UTC')
                    AT TIME ZONE 'UTC',
                    date_trunc('month',CAST(:created AS timestamptz) AT TIME ZONE 'UTC')
                    AT TIME ZONE 'UTC'
            """),
            {"created": created},
        ).one()
        quota, budget = uuid4(), uuid4()
        values = {
            "tenant": actor.tenant,
            "source": source,
            "request": request,
            "reservation": reservation,
            "event": event,
            "quota": quota,
            "budget": budget,
            "created": created,
            "day": day,
            "month": month,
            "idem": uuid4().hex,
        }
        connection.execute(
            text("""
                INSERT INTO arbiter.quota_windows(id,tenant_id,window_start)
                VALUES (:quota,:tenant,:day) ON CONFLICT (tenant_id,window_start) DO NOTHING
            """),
            values,
        )
        connection.execute(
            text("""
                INSERT INTO arbiter.budget_windows(id,tenant_id,window_start)
                VALUES (:budget,:tenant,:month) ON CONFLICT (tenant_id,window_start) DO NOTHING
            """),
            values,
        )
        values["quota"] = connection.execute(
            text(
                "SELECT id FROM arbiter.quota_windows WHERE tenant_id=:tenant AND window_start=:day"
            ),
            values,
        ).scalar_one()
        values["budget"] = connection.execute(
            text(
                "SELECT id FROM arbiter.budget_windows "
                "WHERE tenant_id=:tenant AND window_start=:month"
            ),
            values,
        ).scalar_one()
        connection.execute(
            text(
                "UPDATE arbiter.quota_windows SET reserved=reserved+1 "
                "WHERE tenant_id=:tenant AND id=:quota"
            ),
            values,
        )
        connection.execute(
            text(
                "UPDATE arbiter.budget_windows SET reserved=reserved+10 "
                "WHERE tenant_id=:tenant AND id=:budget"
            ),
            values,
        )
        connection.execute(
            text("""
                INSERT INTO arbiter.requests
                    (id,tenant_id,key_id,idempotency_key,payload_hmac,fingerprint_version,
                     policy_revision,model_id,model_revision,model_alias,model_adapter,model_digest,
                     context_cap,output_cap,credit_charge,quota_window_id,budget_window_id,
                     quota_start,budget_start,reservation_id,reserve_event_id,created_at)
                SELECT :request,tenant_id,key_id,:idem,payload_hmac,fingerprint_version,
                    policy_revision,model_id,model_revision,model_alias,model_adapter,model_digest,
                    context_cap,output_cap,credit_charge,:quota,:budget,:day,:month,
                    :reservation,:event,:created
                FROM arbiter.requests WHERE tenant_id=:tenant AND id=:source
            """),
            values,
        )
        connection.execute(
            text("""
                INSERT INTO arbiter.reservations
                    (id,tenant_id,request_id,quota_window_id,budget_window_id,
                     request_count,credits)
                VALUES (:reservation,:tenant,:request,:quota,:budget,1,10)
            """),
            values,
        )
        connection.execute(
            text("""
                INSERT INTO arbiter.accounting_events
                    (id,tenant_id,request_id,reservation_id,quota_window_id,budget_window_id,
                     request_count,credits,kind)
                VALUES (:event,:tenant,:request,:reservation,:quota,:budget,1,10,'reserve')
            """),
            values,
        )
    return source_result, request


def test_dispatch_claim_cannot_be_freed_by_handler_and_unknown_is_quarantined() -> None:
    gate = CapacityGate(1)
    binding = KeyBinding(uuid4(), uuid4(), ("inference:write",))
    request = uuid4()
    claim = gate.try_acquire(binding, request)
    assert claim is not None
    gate.transfer_after_dispatch(claim)
    assert not gate.release(claim)
    assert not gate.release_reserved_identity(claim.identity)
    gate.quarantine(claim)
    gate.set_recovery_ready(True)
    assert not gate.ready and gate.occupied == 1
    assert gate.try_acquire(binding, uuid4()) is None
    assert gate.release_cleared_unknown(claim.identity)
    assert not gate.release_cleared_unknown(claim.identity)
    assert gate.occupied == 0


def test_restart_rebuilds_effective_claim_without_automatic_release() -> None:
    old = CapacityGate(2)
    binding = KeyBinding(uuid4(), uuid4(), ("inference:write",))
    request = uuid4()
    claim = old.try_acquire(binding, request)
    assert claim is not None
    old.transfer_after_dispatch(claim)
    current = CapacityGate(2)
    current.set_recovery_ready(False)
    assert current.try_acquire(binding, uuid4()) is None
    current.restore_unknown(claim.identity)
    current.restore_unknown(claim.identity)
    assert current.occupied == 1 and not current.ready
    assert not current.release(claim)
    assert current.release_cleared_unknown(claim.identity)
    assert current.occupied == 0


def test_reconciliation_failure_closes_recovery_gate(monkeypatch: pytest.MonkeyPatch) -> None:
    from arbiter.operations import maintenance

    engine = create_engine("sqlite://")
    try:
        gate = CapacityGate(1)
        service = MaintenanceService(engine, engine, gate)
        monkeypatch.setattr(maintenance, "candidates", lambda _engine, _kind: ())
        assert service.run_once().recovery_ready

        def unavailable(_engine: Engine, _kind: str) -> tuple[object, ...]:
            raise SQLAlchemyError("simulated outage")

        monkeypatch.setattr(maintenance, "candidates", unavailable)
        with pytest.raises(MaintenanceUnavailable):
            service.run_once()
        assert not service.recovery_ready
        assert gate.try_acquire(KeyBinding(uuid4(), uuid4(), ("inference:write",)), uuid4()) is None
    finally:
        engine.dispose()


def test_quarantine_during_unknown_scan_cannot_reopen_readiness(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from arbiter.operations import maintenance

    engine = create_engine("sqlite://")
    try:
        gate = CapacityGate(2)
        service = MaintenanceService(engine, engine, gate)
        identity = (uuid4(), uuid4(), uuid4())

        def concurrent_unknown(_engine: Engine, kind: str) -> tuple[object, ...]:
            if kind == "unknown":
                gate.restore_unknown(identity)
            return ()

        monkeypatch.setattr(maintenance, "candidates", concurrent_unknown)
        assert not service.run_once().recovery_ready
        assert not gate.ready and gate.occupied == 1
    finally:
        engine.dispose()


def test_operator_cli_requires_provider_stopped_attestation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from arbiter.operations import clearance

    monkeypatch.setattr(
        sys,
        "argv",
        ["clearance", "--tenant", str(uuid4()), "--request", str(uuid4())],
    )
    with pytest.raises(SystemExit) as refused:
        clearance.main()
    assert refused.value.code == 2


@pytest.mark.skipif(os.environ.get("ARBITER_TEST_DATABASE") != "1", reason="real PostgreSQL")
@pytest.mark.parametrize("age,eligible", [(29, False), (30, True), (31, True)])
def test_stale_reservation_threshold_and_durable_release(
    store: ReservationStore,
    discovery_engine: Engine,
    monkeypatch: pytest.MonkeyPatch,
    age: int,
    eligible: bool,
) -> None:
    actor = store.actor()
    scope_maintenance(monkeypatch, actor.tenant)
    source, old = aged_reservation(store, actor, age)
    match = {item.request_id for item in candidates(discovery_engine, "stale")}
    assert (old in match) is eligible
    binding = KeyBinding(actor.key, actor.tenant, ("inference:write",))
    if eligible:
        gate = CapacityGate(2)
        claim = gate.try_acquire(binding, old)
        assert claim is not None
        result = MaintenanceService(store.runtime, discovery_engine, gate).run_once()
        assert result.released >= 1
        assert old not in gate._owners
        assert evidence(store, actor, old)[0:2] == ("released", "reservation_expired")
        assert evidence(store, actor, old)[7:] == (1, 1)
    else:
        with pytest.raises(ReleaseConflict):
            ReleaseService(store.runtime).release(binding, old, "reservation_expired")
        assert evidence(store, actor, old)[0] == "reserved"
        assert ReleaseService(store.runtime).release(binding, old, "cancelled").changed
    assert (
        ReleaseService(store.runtime).release(binding, source.request_id, "cancelled").state
        == "released"
    )


@pytest.mark.skipif(os.environ.get("ARBITER_TEST_DATABASE") != "1", reason="real PostgreSQL")
def test_stale_maintenance_race_with_late_handler_releases_once(
    store: ReservationStore, discovery_engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    actor = store.actor()
    scope_maintenance(monkeypatch, actor.tenant)
    source, old = aged_reservation(store, actor, 31)
    gate = CapacityGate(2)
    binding = KeyBinding(actor.key, actor.tenant, ("inference:write",))
    claim = gate.try_acquire(binding, old)
    assert claim is not None
    lease = CapacityLease(
        replace(source, request_id=old), binding, claim, gate, ReleaseService(store.runtime)
    )
    maintenance = MaintenanceService(store.runtime, discovery_engine, gate)
    with ThreadPoolExecutor(max_workers=2) as pool:
        late = pool.submit(lease.release_before_dispatch, "cancelled")
        sweep = pool.submit(maintenance.run_once)
        assert late.result().state == "released"
        sweep.result()
    assert old not in gate._owners
    assert evidence(store, actor, old)[0] == "released"
    assert evidence(store, actor, old)[7:] == (1, 1)
    assert store.totals(actor) == (0, 1, 0, 10)
    ReleaseService(store.runtime).release(binding, source.request_id, "cancelled")


@pytest.mark.skipif(os.environ.get("ARBITER_TEST_DATABASE") != "1", reason="real PostgreSQL")
def test_restart_marks_dispatched_unknown_keeps_charge_and_requires_clearance(
    store: ReservationStore,
    discovery_engine: Engine,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    actor, gate = store.actor(concurrency=1), CapacityGate(2)
    scope_maintenance(monkeypatch, actor.tenant)
    original = store.request("private maintenance marker")
    lease = CapacityService(
        store.service(), ReleaseService(store.runtime), gate
    ).reserve_and_acquire(actor.credential, uuid4().hex, original)
    DispatchService(store.runtime).authorize(lease)
    assert not gate.release(lease._claim)
    assert store.totals(actor) == (1, 0, 10, 0)
    restarted = CapacityGate(2)
    maintenance = MaintenanceService(store.runtime, discovery_engine, restarted)
    first = maintenance.run_once()
    assert first.marked_unknown == 1 and first.unresolved_unknown == 1
    assert not first.recovery_ready and restarted.occupied >= 1
    assert store.totals(actor) == (1, 0, 10, 0)
    with pytest.raises(ReservationDenied) as occupied:
        store.service().reserve(actor.credential, uuid4().hex, original)
    assert occupied.value.code == "tenant_capacity"
    provider = DeterministicProvider(store.model, "sha256:" + "d" * 64, 256)
    with pytest.raises(DispatchConflict):
        DispatchService(store.runtime).run_double_once(lease, original, provider, store.fingerprint)
    assert provider.calls == ()
    with tenant_transaction(store.runtime, TenantContext(actor.tenant)) as tx:
        row = (
            tx.connection()
            .execute(
                text(
                    "SELECT state,outcome,input_tokens,output_tokens FROM arbiter.requests "
                    "WHERE tenant_id=:tenant AND id=:request"
                ),
                {"tenant": actor.tenant, "request": lease.result.request_id},
            )
            .one()
        )
        assert tuple(row) == ("unknown", "unknown", None, None)
        audit = (
            tx.connection()
            .execute(
                text(
                    "SELECT action,actor_type FROM arbiter.audit_events "
                    "WHERE tenant_id=:tenant AND request_id=:request "
                    "AND action='request_finalized'"
                ),
                {"tenant": actor.tenant, "request": lease.result.request_id},
            )
            .one()
        )
        assert tuple(audit) == ("request_finalized", "api_key")
    assert maintenance.run_once().marked_unknown == 0
    repeated_restart_gate = CapacityGate(2)
    repeated_restart = MaintenanceService(store.runtime, discovery_engine, repeated_restart_gate)
    assert repeated_restart.run_once().marked_unknown == 0
    assert not repeated_restart.recovery_ready and repeated_restart_gate.occupied == 1
    with pytest.raises(DBAPIError):
        clear_unknown(store.operator, uuid4(), lease.result.request_id)
    assert not maintenance.recovery_ready
    assert clear_unknown(store.operator, actor.tenant, lease.result.request_id)
    assert not clear_unknown(store.operator, actor.tenant, lease.result.request_id)
    with tenant_transaction(store.runtime, TenantContext(actor.tenant)) as tx:
        finished_at: datetime | None = (
            tx.connection()
            .execute(
                text(
                    "SELECT finished_at FROM arbiter.requests "
                    "WHERE tenant_id=:tenant AND id=:request"
                ),
                {"tenant": actor.tenant, "request": lease.result.request_id},
            )
            .scalar_one()
        )
        assert finished_at is not None
    after_clearance = store.service().reserve(actor.credential, uuid4().hex, original)
    assert after_clearance.state == "reserved"
    ReleaseService(store.runtime).release(
        KeyBinding(actor.key, actor.tenant, ("inference:write",)),
        after_clearance.request_id,
        "cancelled",
    )
    second = maintenance.run_once()
    assert second.recovered_capacity >= 1
    assert second.recovery_ready
    assert (actor.tenant, actor.key, lease.result.request_id) not in restarted._owners
    assert maintenance.run_once().recovered_capacity == 0
    assert repeated_restart.run_once().recovered_capacity == 1
    assert repeated_restart.recovery_ready and repeated_restart_gate.occupied == 0
    assert store.totals(actor) == (1, 0, 10, 0)
    with tenant_transaction(store.runtime, TenantContext(actor.tenant)) as tx:
        actions = (
            tx.connection()
            .execute(
                text(
                    "SELECT action,actor_type FROM arbiter.audit_events "
                    "WHERE tenant_id=:tenant AND request_id=:request "
                    "AND action='unknown_capacity_cleared'"
                ),
                {"tenant": actor.tenant, "request": lease.result.request_id},
            )
            .all()
        )
        assert [tuple(row) for row in actions] == [("unknown_capacity_cleared", "operator")]
        payload: str = (
            tx.connection()
            .execute(
                text(
                    "SELECT jsonb_agg(to_jsonb(a))::text FROM arbiter.audit_events a "
                    "WHERE a.tenant_id=:tenant AND a.request_id=:request"
                ),
                {"tenant": actor.tenant, "request": lease.result.request_id},
            )
            .scalar_one()
        )
        assert "private maintenance marker" not in payload


@pytest.mark.skipif(os.environ.get("ARBITER_TEST_DATABASE") != "1", reason="real PostgreSQL")
def test_new_reservation_is_not_stale_and_concurrent_maintenance_is_idempotent(
    store: ReservationStore,
    discovery_engine: Engine,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    actor, gate = store.actor(), CapacityGate(2)
    scope_maintenance(monkeypatch, actor.tenant)
    lease = CapacityService(
        store.service(), ReleaseService(store.runtime), gate
    ).reserve_and_acquire(actor.credential, uuid4().hex, store.request())
    assert all(
        item.request_id != lease.result.request_id for item in candidates(discovery_engine, "stale")
    )
    a, b = (
        MaintenanceService(store.runtime, discovery_engine, gate),
        MaintenanceService(store.runtime, discovery_engine, gate),
    )
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = [future.result() for future in (pool.submit(a.run_once), pool.submit(b.run_once))]
    assert all(result.released == 0 for result in results)
    assert store.totals(actor) == (0, 1, 0, 10)
    assert lease.release_before_dispatch().changed
    assert lease._claim.identity not in gate._owners


@pytest.mark.skipif(os.environ.get("ARBITER_TEST_DATABASE") != "1", reason="real PostgreSQL")
def test_operator_cannot_clear_reserved_or_cross_tenant_unknown(store: ReservationStore) -> None:
    actor, other = store.actor(), store.actor()
    lease = CapacityService(
        store.service(), ReleaseService(store.runtime), CapacityGate()
    ).reserve_and_acquire(actor.credential, uuid4().hex, store.request())
    with pytest.raises(DBAPIError):
        clear_unknown(store.operator, actor.tenant, lease.result.request_id)
    with pytest.raises(DBAPIError):
        clear_unknown(store.operator, other.tenant, lease.result.request_id)
    assert lease.release_before_dispatch().changed
