"""Real PostgreSQL evidence for the deterministic post-dispatch lifecycle."""

import os
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from threading import Barrier
from uuid import UUID, uuid4

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.pool import NullPool
from test_provider_contract import Scenario, ScriptedProvider
from test_reservation_release import fault
from test_reservation_transactions import Actor, ReservationStore
from test_reservation_transactions import store as store

from arbiter.config import DatabaseSettings
from arbiter.governance.capacity import (
    CapacityGate,
    CapacityLease,
    CapacityOwnershipError,
    CapacityService,
)
from arbiter.governance.dispatch import DispatchConflict, DispatchService, TerminalUnavailable
from arbiter.governance.fingerprint import ReservationInput
from arbiter.governance.release import ReleaseService
from arbiter.identity.context import TenantContext
from arbiter.persistence.tenant import tenant_transaction
from arbiter.persistence.terminal import TerminalRepository
from arbiter.persistence.workload import KeyBinding
from arbiter.providers.double import DeterministicProvider, DoubleMode
from arbiter.providers.port import ProviderRequest, ProviderResult

pytestmark = pytest.mark.skipif(
    os.environ.get("ARBITER_TEST_DATABASE") != "1", reason="requires real PostgreSQL"
)
DIGEST = "sha256:" + "d" * 64


def prepared(
    store: ReservationStore,
) -> tuple[Actor, CapacityGate, CapacityLease, ReservationInput]:
    actor, gate = store.actor(), CapacityGate(1)
    original = store.request("private deterministic prompt marker")
    lease = CapacityService(
        store.service(), ReleaseService(store.runtime), gate
    ).reserve_and_acquire(actor.credential, uuid4().hex, original)
    DispatchService(store.runtime).authorize(lease)
    return actor, gate, lease, original


def double(store: ReservationStore, mode: DoubleMode = "success") -> DeterministicProvider:
    return DeterministicProvider(store.model, DIGEST, 256, mode=mode)


def row(store: ReservationStore, actor: Actor, request_id: UUID) -> tuple[object, ...]:
    with tenant_transaction(store.runtime, TenantContext(actor.tenant)) as transaction:
        return tuple(
            transaction.connection()
            .execute(
                text("""
                    SELECT r.state,r.outcome,r.finished_at,r.input_tokens,r.output_tokens,
                        r.terminal_audit_id,
                        (SELECT count(*) FROM arbiter.audit_events a
                            WHERE a.tenant_id=r.tenant_id AND a.request_id=r.id
                                AND a.action='request_finalized')
                    FROM arbiter.requests r WHERE r.tenant_id=:tenant AND r.id=:request
                """),
                {"tenant": actor.tenant, "request": request_id},
            )
            .one()
        )


def test_success_one_call_after_committed_marker_and_content_free(
    store: ReservationStore, caplog: pytest.LogCaptureFixture
) -> None:
    actor, gate, lease, original = prepared(store)
    provider = double(store)
    assert store.totals(actor) == (1, 0, 10, 0)
    completed = DispatchService(store.runtime).run_double_once(
        lease, original, provider, store.fingerprint
    )
    assert completed.state == completed.outcome == "succeeded"
    assert completed.assistant_text == "fixture response"
    assert provider.calls == (lease.result.request_id,)
    state = row(store, actor, lease.result.request_id)
    assert state[0:2] == ("succeeded", "succeeded")
    assert state[2] is not None and state[3:5] == (4, 2)
    assert state[5] is not None and state[6] == 1
    assert store.totals(actor) == (1, 0, 10, 0)
    assert gate.occupied == 0
    with tenant_transaction(store.runtime, TenantContext(actor.tenant)) as transaction:
        payload: str = (
            transaction.connection()
            .execute(
                text("""
                SELECT jsonb_agg(to_jsonb(x))::text FROM (
                    SELECT to_jsonb(r) AS body FROM arbiter.requests r WHERE r.tenant_id=:tenant
                    UNION ALL SELECT to_jsonb(a) FROM arbiter.audit_events a
                        WHERE a.tenant_id=:tenant
                    UNION ALL SELECT to_jsonb(e) FROM arbiter.accounting_events e
                        WHERE e.tenant_id=:tenant
                ) x
            """),
                {"tenant": actor.tenant},
            )
            .scalar_one()
        )
    assert "private deterministic prompt marker" not in payload
    assert "fixture response" not in payload
    assert "private deterministic prompt marker" not in caplog.text
    assert "fixture response" not in caplog.text
    with pytest.raises((CapacityOwnershipError, DispatchConflict)):
        DispatchService(store.runtime).run_double_once(lease, original, provider, store.fingerprint)
    assert provider.calls == (lease.result.request_id,)


@pytest.mark.parametrize(
    "scenario,state,occupied",
    [
        ("success", "succeeded", 0),
        ("unavailable", "unknown", 1),
        ("deadline", "unknown", 1),
        ("malformed", "unknown", 1),
        ("oversized", "unknown", 1),
        ("unknown_model", "failed", 0),
        ("ambiguous", "unknown", 1),
    ],
)
def test_independent_provider_uses_existing_dispatch_ownership(
    store: ReservationStore, scenario: Scenario, state: str, occupied: int
) -> None:
    actor, gate, lease, original = prepared(store)
    provider = ScriptedProvider(store.model, DIGEST, 256, scenario)
    completed = DispatchService(store.runtime).run_double_once(
        lease, original, provider, store.fingerprint
    )
    assert completed.state == state
    assert provider.calls == (lease.result.request_id,)
    assert row(store, actor, lease.result.request_id)[0] == state
    assert store.totals(actor) == (1, 0, 10, 0)
    assert gate.occupied == occupied
    with pytest.raises((CapacityOwnershipError, DispatchConflict)):
        DispatchService(store.runtime).run_double_once(lease, original, provider, store.fingerprint)
    assert provider.calls == (lease.result.request_id,)


@pytest.mark.parametrize("body", ["oversized", "malformed"])
def test_dispatch_rejects_invalid_returned_provider_result(
    store: ReservationStore, body: str
) -> None:
    actor, gate, lease, original = prepared(store)

    class InvalidResultProvider(ScriptedProvider):
        def generate(self, request: ProviderRequest, deadline: datetime) -> ProviderResult:
            super().generate(request, deadline)
            if body == "oversized":
                return ProviderResult("x" * 1048577)
            return ProviderResult("fixture response", finish_reason="invalid")

    provider = InvalidResultProvider(store.model, DIGEST, 256, "success")
    completed = DispatchService(store.runtime).run_double_once(
        lease, original, provider, store.fingerprint
    )
    assert completed.state == "unknown"
    assert provider.calls == (lease.result.request_id,)
    assert row(store, actor, lease.result.request_id)[0] == "unknown"
    assert store.totals(actor) == (1, 0, 10, 0)
    assert gate.occupied == 1


@pytest.mark.parametrize(
    "mode,expected_state,expected_outcome,capacity",
    [
        ("definite_failure", "failed", "provider_failure", 0),
        ("deadline", "unknown", "unknown", 1),
        ("malformed", "unknown", "unknown", 1),
        ("ambiguous", "unknown", "unknown", 1),
    ],
)
def test_provider_classification_retains_charges_and_safe_capacity(
    store: ReservationStore,
    mode: DoubleMode,
    expected_state: str,
    expected_outcome: str,
    capacity: int,
) -> None:
    actor, gate, lease, original = prepared(store)
    provider = double(store, mode)
    completed = DispatchService(store.runtime).run_double_once(
        lease, original, provider, store.fingerprint
    )
    assert (completed.state, completed.outcome) == (expected_state, expected_outcome)
    assert provider.calls == (lease.result.request_id,)
    state = row(store, actor, lease.result.request_id)
    assert state[0:2] == (expected_state, expected_outcome)
    assert state[3:5] == (None, None) and state[5] is not None and state[6] == 1
    assert (state[2] is None) == (expected_state == "unknown")
    assert store.totals(actor) == (1, 0, 10, 0) and gate.occupied == capacity
    with tenant_transaction(store.runtime, TenantContext(actor.tenant)) as transaction:
        assert (
            TerminalRepository(transaction).finalize(
                lease._binding,
                lease.result.request_id,
                expected_state,
                expected_outcome,
                None,
                None,
            )
            is False
        )
    assert row(store, actor, lease.result.request_id)[6] == 1
    with pytest.raises((CapacityOwnershipError, DispatchConflict)):
        DispatchService(store.runtime).run_double_once(lease, original, provider, store.fingerprint)
    assert len(provider.calls) == 1


def test_known_zero_telemetry_is_distinct_from_unknown(store: ReservationStore) -> None:
    actor, gate, lease, original = prepared(store)
    provider = DeterministicProvider(store.model, DIGEST, 256, input_tokens=0, output_tokens=0)
    DispatchService(store.runtime).run_double_once(lease, original, provider, store.fingerprint)
    assert row(store, actor, lease.result.request_id)[3:5] == (0, 0)
    assert gate.occupied == 0


def test_invalid_token_telemetry_is_unknown_without_fabricated_counts(
    store: ReservationStore,
) -> None:
    actor, gate, lease, original = prepared(store)
    provider = DeterministicProvider(store.model, DIGEST, 256, input_tokens=4, output_tokens=257)
    completed = DispatchService(store.runtime).run_double_once(
        lease, original, provider, store.fingerprint
    )
    assert completed.state == "unknown"
    assert row(store, actor, lease.result.request_id)[3:5] == (None, None)
    assert store.totals(actor) == (1, 0, 10, 0) and gate.occupied == 1


def test_no_transaction_is_held_across_provider_call(store: ReservationStore) -> None:
    actor, gate, lease, original = prepared(store)

    class ObservingDouble(DeterministicProvider):
        def generate(self, request: ProviderRequest, deadline: datetime) -> ProviderResult:
            with store.runtime.begin() as connection:
                assert (
                    connection.execute(
                        text("SELECT NULLIF(current_setting('arbiter.tenant_id',true),'')")
                    ).scalar_one()
                    is None
                )
            return super().generate(request, deadline)

    provider = ObservingDouble(store.model, DIGEST, 256)
    DispatchService(store.runtime).run_double_once(lease, original, provider, store.fingerprint)
    assert provider.calls == (lease.result.request_id,)
    assert store.totals(actor) == (1, 0, 10, 0) and gate.occupied == 0


def test_mismatched_transient_content_cannot_reach_double(store: ReservationStore) -> None:
    actor, gate, lease, _ = prepared(store)
    provider = double(store)
    with pytest.raises(DispatchConflict):
        DispatchService(store.runtime).run_double_once(
            lease, store.request("different content"), provider, store.fingerprint
        )
    assert provider.calls == () and gate.occupied == 1
    assert row(store, actor, lease.result.request_id)[0] == "dispatched"


def test_unregistered_double_identity_never_generates(store: ReservationStore) -> None:
    actor, gate, lease, original = prepared(store)
    provider = DeterministicProvider(uuid4(), DIGEST, 256)
    completed = DispatchService(store.runtime).run_double_once(
        lease, original, provider, store.fingerprint
    )
    assert completed.state == "failed" and completed.outcome == "provider_failure"
    assert provider.calls == () and gate.occupied == 0
    assert row(store, actor, lease.result.request_id)[0] == "failed"
    assert store.totals(actor) == (1, 0, 10, 0)


def test_concurrent_handlers_make_one_double_call(store: ReservationStore) -> None:
    actor, gate, lease, original = prepared(store)
    provider = double(store)
    service = DispatchService(store.runtime)

    def run() -> str:
        try:
            return service.run_double_once(lease, original, provider, store.fingerprint).state
        except (CapacityOwnershipError, DispatchConflict):
            return "duplicate_denied"

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = [future.result() for future in (pool.submit(run), pool.submit(run))]
    assert sorted(results) == ["duplicate_denied", "succeeded"]
    assert provider.calls == (lease.result.request_id,)
    assert row(store, actor, lease.result.request_id)[6] == 1
    assert gate.occupied == 0 and store.totals(actor) == (1, 0, 10, 0)


def test_reserved_released_and_rejected_capacity_never_call_provider(
    store: ReservationStore,
) -> None:
    actor, gate = store.actor(), CapacityGate(2)
    original = store.request()
    provider = double(store)
    binding = KeyBinding(actor.key, actor.tenant, ("inference:write",))
    for reason in (None, "cancelled", "rejected_capacity"):
        result = store.service().reserve(actor.credential, uuid4().hex, original)
        claim = gate.try_acquire(binding, result.request_id)
        assert claim is not None
        lease = CapacityLease(result, binding, claim, gate, ReleaseService(store.runtime))
        if reason == "cancelled":
            ReleaseService(store.runtime).release(binding, result.request_id, "cancelled")
        elif reason == "rejected_capacity":
            ReleaseService(store.runtime).release(binding, result.request_id, "rejected_capacity")
        with pytest.raises(DispatchConflict):
            DispatchService(store.runtime).run_double_once(
                lease, original, provider, store.fingerprint
            )
        if reason is None:
            lease.release_before_dispatch()
        else:
            gate.release(claim)
    assert provider.calls == () and gate.occupied == 0


def test_concurrent_terminalization_is_idempotent_and_does_not_double_release(
    store: ReservationStore,
) -> None:
    actor, gate, lease, _ = prepared(store)
    barrier = Barrier(2)
    binding = lease._binding

    def finish() -> bool:
        engine = create_engine(
            DatabaseSettings().url("runtime"), hide_parameters=True, poolclass=NullPool
        )
        try:
            barrier.wait(timeout=5)
            with tenant_transaction(engine, TenantContext(actor.tenant)) as transaction:
                return TerminalRepository(transaction).finalize(
                    binding, lease.result.request_id, "succeeded", "succeeded", 4, 2
                )
        finally:
            engine.dispose()

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = [future.result() for future in (pool.submit(finish), pool.submit(finish))]
    assert sorted(results) == [False, True]
    assert row(store, actor, lease.result.request_id)[6] == 1
    assert lease._release_after_terminal(lease.result.request_id, "succeeded") is True
    assert lease._release_after_terminal(lease.result.request_id, "succeeded") is False
    assert gate.occupied == 0 and store.totals(actor) == (1, 0, 10, 0)
    with (
        pytest.raises(DBAPIError) as stale,
        tenant_transaction(store.runtime, TenantContext(actor.tenant)) as transaction,
    ):
        TerminalRepository(transaction).finalize(
            binding, lease.result.request_id, "failed", "provider_failure", None, None
        )
    assert getattr(stale.value.orig, "sqlstate", None) == "TL002"


def test_crash_after_provider_completion_before_persistence_does_not_retry(
    store: ReservationStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    actor, gate, lease, original = prepared(store)
    provider = double(store)

    def crashed(*args: object, **kwargs: object) -> bool:
        raise RuntimeError("synthetic persistence interruption")

    monkeypatch.setattr(TerminalRepository, "finalize", crashed)
    with pytest.raises(TerminalUnavailable):
        DispatchService(store.runtime).run_double_once(lease, original, provider, store.fingerprint)
    assert provider.calls == (lease.result.request_id,)
    assert row(store, actor, lease.result.request_id)[0] == "dispatched"
    assert store.totals(actor) == (1, 0, 10, 0) and gate.occupied == 1
    with pytest.raises(DispatchConflict):
        DispatchService(store.runtime).run_double_once(lease, original, provider, store.fingerprint)
    assert len(provider.calls) == 1


@pytest.mark.parametrize("table,operation", [("requests", "UPDATE"), ("audit_events", "INSERT")])
def test_terminal_mutation_and_audit_rollback_together(
    store: ReservationStore, table: str, operation: str
) -> None:
    actor, gate, lease, original = prepared(store)
    provider = double(store)
    with fault(store, actor, table, operation), pytest.raises(TerminalUnavailable):
        DispatchService(store.runtime).run_double_once(lease, original, provider, store.fingerprint)
    state = row(store, actor, lease.result.request_id)
    assert state[0] == "dispatched" and state[5:7] == (None, 0)
    assert store.totals(actor) == (1, 0, 10, 0) and gate.occupied == 1
    assert len(provider.calls) == 1


def test_cross_tenant_terminal_access_and_runtime_privileges(store: ReservationStore) -> None:
    first, gate, lease, _ = prepared(store)
    other = store.actor()
    with tenant_transaction(store.runtime, TenantContext(other.tenant)) as transaction:
        assert (
            TerminalRepository(transaction).dispatched_snapshot(
                KeyBinding(other.key, other.tenant, ("inference:write",)), lease.result.request_id
            )
            is None
        )
    with (
        pytest.raises(DBAPIError) as foreign,
        tenant_transaction(store.runtime, TenantContext(other.tenant)) as transaction,
    ):
        TerminalRepository(transaction).finalize(
            KeyBinding(other.key, other.tenant, ("inference:write",)),
            lease.result.request_id,
            "succeeded",
            "succeeded",
            None,
            None,
        )
    assert getattr(foreign.value.orig, "sqlstate", None) == "TL001"
    with pytest.raises(DBAPIError) as missing, store.runtime.begin() as connection:
        connection.execute(
            text(
                "SELECT * FROM arbiter.finalize_dispatched(:tenant,:key,:request,'unknown',"
                "'unknown',NULL,NULL)"
            ),
            {"tenant": first.tenant, "key": first.key, "request": lease.result.request_id},
        )
    assert getattr(missing.value.orig, "sqlstate", None) == "42501"
    with pytest.raises(DBAPIError) as denied, store.runtime.begin() as connection:
        connection.execute(text("SET ROLE arbiter_terminal_writer"))
    assert getattr(denied.value.orig, "sqlstate", None) == "42501"
    with pytest.raises(DBAPIError) as direct, store.runtime.begin() as connection:
        connection.execute(
            text("UPDATE arbiter.requests SET state='unknown' WHERE id=:request"),
            {"request": lease.result.request_id},
        )
    assert getattr(direct.value.orig, "sqlstate", None) == "42501"
    with store.migration.connect() as connection:
        assert (
            connection.execute(
                text("""
                SELECT rolcanlogin,rolsuper,rolbypassrls,rolcreaterole,rolcreatedb,
                    rolinherit,rolreplication FROM pg_roles
                WHERE rolname='arbiter_terminal_writer'
            """)
            ).one()
            == (False,) * 7
        )
        assert connection.execute(
            text("""
                SELECT pg_get_userbyid(proowner),prosecdef,proconfig FROM pg_proc
                WHERE oid='arbiter.finalize_dispatched(uuid,uuid,uuid,text,text,bigint,bigint)'
                    ::regprocedure
            """)
        ).one() == ("arbiter_terminal_writer", True, ["search_path=pg_catalog"])
    assert gate.occupied == 1


def test_pooled_connections_clear_terminal_tenant_context(store: ReservationStore) -> None:
    first, first_gate, first_lease, first_input = prepared(store)
    second, second_gate, second_lease, second_input = prepared(store)
    backend_ids: list[int] = []
    for actor, gate, lease, original in (
        (first, first_gate, first_lease, first_input),
        (second, second_gate, second_lease, second_input),
    ):
        DispatchService(store.runtime).run_double_once(
            lease, original, double(store), store.fingerprint
        )
        with store.runtime.begin() as connection:
            backend_ids.append(connection.execute(text("SELECT pg_backend_pid()")).scalar_one())
            assert (
                connection.execute(
                    text("SELECT NULLIF(current_setting('arbiter.tenant_id',true),'')")
                ).scalar_one()
                is None
            )
            assert connection.execute(text("SELECT id FROM arbiter.requests")).all() == []
        assert gate.occupied == 0 and store.totals(actor) == (1, 0, 10, 0)
    assert backend_ids[0] == backend_ids[1]
