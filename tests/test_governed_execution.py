"""Full internal Phase 3 path against real PostgreSQL, Redis and the provider double."""

import asyncio
import os
import socket
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from threading import Barrier
from uuid import UUID, uuid4

import pytest
from sqlalchemy import text
from test_rate_admission import redis_ready as redis_ready
from test_reservation_transactions import Actor, ReservationStore
from test_reservation_transactions import store as store

from arbiter.config import RedisSettings
from arbiter.governance.capacity import CapacityGate, CapacityLease, CapacityUnavailable, _Claim
from arbiter.governance.dispatch import (
    DispatchAuthorized,
    DispatchRejected,
    DispatchService,
    DispatchUnavailable,
    TerminalUnavailable,
)
from arbiter.governance.execution import GovernedExecutionService
from arbiter.governance.rate import RateDenied, RateGate, RateUnavailable
from arbiter.governance.release import ReleaseConflict, ReleaseService, ReleaseUnavailable
from arbiter.governance.reservation import (
    IdempotencyConflict,
    RequestAlreadyAdmitted,
    ReservationDenied,
)
from arbiter.identity.context import TenantContext
from arbiter.operations.policy import PolicyInput, PolicyService
from arbiter.operations.provision import ProvisioningService
from arbiter.persistence.dispatch import DispatchDecision, DispatchRepository
from arbiter.persistence.tenant import tenant_transaction
from arbiter.persistence.terminal import TerminalRepository
from arbiter.persistence.workload import KeyBinding
from arbiter.providers.double import DeterministicProvider, DoubleMode
from arbiter.providers.port import ProviderRequest, ProviderResult

pytestmark = pytest.mark.skipif(
    os.environ.get("ARBITER_TEST_DATABASE") != "1" or os.environ.get("ARBITER_TEST_REDIS") != "1",
    reason="real PostgreSQL and Redis",
)
DIGEST = "sha256:" + "d" * 64


def pipeline(
    store: ReservationStore,
    provider: DeterministicProvider,
    capacity: CapacityGate,
    rate: RateGate | None = None,
) -> GovernedExecutionService:
    return GovernedExecutionService(
        store.runtime,
        store.verifier,
        store.fingerprint,
        rate or RateGate(RedisSettings()),
        provider,
        capacity,
    )


def double(store: ReservationStore, mode: DoubleMode = "success") -> DeterministicProvider:
    return DeterministicProvider(store.model, DIGEST, 256, mode=mode)


def evidence(store: ReservationStore, actor: Actor, request_id: UUID) -> tuple[str, int, int]:
    with tenant_transaction(store.runtime, TenantContext(actor.tenant)) as transaction:
        row = (
            transaction.connection()
            .execute(
                text("""
                    SELECT r.state,
                        (SELECT count(*) FROM arbiter.accounting_events e
                         WHERE e.tenant_id=r.tenant_id AND e.request_id=r.id
                           AND e.kind='commit'),
                        (SELECT count(*) FROM arbiter.audit_events a
                         WHERE a.tenant_id=r.tenant_id AND a.request_id=r.id
                           AND a.action='request_finalized')
                    FROM arbiter.requests r WHERE r.tenant_id=:tenant AND r.id=:request
                """),
                {"tenant": actor.tenant, "request": request_id},
            )
            .one()
        )
    return row.state, row[1], row[2]


def test_success_duplicates_and_exactly_once(
    store: ReservationStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    actor, capacity, provider = store.actor(), CapacityGate(1), double(store)
    actual_rate = RateGate.admit
    decisions: list[KeyBinding] = []

    def counted_rate(gate: RateGate, binding: KeyBinding, tenant: int, key: int) -> None:
        decisions.append(binding)
        actual_rate(gate, binding, tenant, key)

    monkeypatch.setattr(RateGate, "admit", counted_rate)
    service = pipeline(store, provider, capacity)
    idem, request = uuid4().hex, store.request()
    result = service.execute(actor.credential, idem, request)
    assert (result.state, result.outcome, result.assistant_text) == (
        "succeeded",
        "succeeded",
        "fixture response",
    )
    assert provider.calls == (result.request_id,)
    assert evidence(store, actor, result.request_id) == ("succeeded", 1, 1)
    assert store.totals(actor) == (1, 0, 10, 0) and capacity.occupied == 0
    assert len(decisions) == 1
    with pytest.raises(RequestAlreadyAdmitted) as matching:
        service.execute(actor.credential, idem, request)
    assert (matching.value.request_id, matching.value.state) == (result.request_id, "succeeded")
    with pytest.raises(IdempotencyConflict):
        service.execute(actor.credential, idem, store.request("conflicting body"))
    assert provider.calls == (result.request_id,)
    assert evidence(store, actor, result.request_id) == ("succeeded", 1, 1)
    assert store.totals(actor) == (1, 0, 10, 0) and capacity.occupied == 0
    assert len(decisions) == 1


def test_concurrent_matching_first_attempts_dispatch_once(
    store: ReservationStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    actor, capacity, provider = store.actor(), CapacityGate(2), double(store)
    service = pipeline(store, provider, capacity)
    idem, request = uuid4().hex, store.request()
    barrier = Barrier(2)
    actual = RateGate.admit

    def admit_together(gate: RateGate, binding: KeyBinding, tenant: int, key: int) -> None:
        barrier.wait(timeout=10)
        actual(gate, binding, tenant, key)

    monkeypatch.setattr(RateGate, "admit", admit_together)

    def run() -> tuple[str, UUID]:
        try:
            result = service.execute(actor.credential, idem, request)
            return result.state, result.request_id
        except RequestAlreadyAdmitted as duplicate:
            return "duplicate", duplicate.request_id

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = [future.result() for future in (pool.submit(run), pool.submit(run))]
    assert sorted(state for state, _ in results) == ["duplicate", "succeeded"]
    assert results[0][1] == results[1][1]
    assert provider.calls == (results[0][1],)
    assert evidence(store, actor, results[0][1]) == ("succeeded", 1, 1)
    assert store.totals(actor) == (1, 0, 10, 0) and capacity.occupied == 0


def test_redis_denial_precedes_provider_and_postgres(store: ReservationStore) -> None:
    actor, capacity, provider = store.actor(), CapacityGate(2), double(store)
    PolicyService(store.operator).set_policy(
        actor.tenant,
        PolicyInput(tenant_rate=0, key_rate=0, aliases=(store.alias,), concurrency=2),
    )
    before = store.counts(actor)
    with pytest.raises(RateDenied):
        pipeline(store, provider, capacity).execute(actor.credential, uuid4().hex, store.request())
    assert store.counts(actor) == before and provider.calls == () and capacity.occupied == 0


def test_redis_unavailable_fails_closed_in_full_path(store: ReservationStore) -> None:
    actor, capacity, provider = store.actor(), CapacityGate(1), double(store)
    before = store.counts(actor)
    with socket.socket() as unused:
        unused.bind(("127.0.0.1", 0))
        rate = RateGate(RedisSettings(host="127.0.0.1", port=unused.getsockname()[1]))
        with pytest.raises(RateUnavailable):
            pipeline(store, provider, capacity, rate).execute(
                actor.credential, uuid4().hex, store.request()
            )
    assert store.counts(actor) == before and provider.calls == () and capacity.occupied == 0


@pytest.mark.parametrize(
    "limit,code", [("quota", "quota_exhausted"), ("budget", "budget_exhausted")]
)
def test_postgres_denial_never_calls_provider(
    store: ReservationStore, limit: str, code: str
) -> None:
    actor = store.actor(
        quota=0 if limit == "quota" else 1000, budget=0 if limit == "budget" else 10000
    )
    capacity, provider = CapacityGate(1), double(store)
    before = store.counts(actor)
    with pytest.raises(ReservationDenied) as denied:
        pipeline(store, provider, capacity).execute(actor.credential, uuid4().hex, store.request())
    assert denied.value.code == code
    assert store.counts(actor) == before and provider.calls == () and capacity.occupied == 0


def test_capacity_denial_releases_reservation_without_provider(store: ReservationStore) -> None:
    actor, capacity, provider = store.actor(), CapacityGate(0), double(store)
    with pytest.raises(CapacityUnavailable):
        pipeline(store, provider, capacity).execute(actor.credential, uuid4().hex, store.request())
    assert provider.calls == () and capacity.occupied == 0
    assert store.totals(actor) == (0, 0, 0, 0)


def test_dispatch_failure_releases_before_transfer(
    store: ReservationStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    actor, capacity, provider = store.actor(), CapacityGate(1), double(store)

    actual = DispatchRepository.authorize

    def fail(
        repository: DispatchRepository, binding: KeyBinding, request: UUID
    ) -> DispatchDecision:
        actual(repository, binding, request)
        raise RuntimeError("synthetic dispatch transaction failure")

    monkeypatch.setattr(DispatchRepository, "authorize", fail)
    with pytest.raises(DispatchUnavailable):
        pipeline(store, provider, capacity).execute(actor.credential, uuid4().hex, store.request())
    assert provider.calls == () and capacity.occupied == 0
    assert store.totals(actor) == (0, 0, 0, 0)


def test_suspension_between_reservation_and_dispatch_rejects(
    store: ReservationStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    actor, capacity, provider = store.actor(), CapacityGate(1), double(store)
    actual = DispatchService.authorize

    def suspend_then_authorize(
        service: DispatchService, lease: CapacityLease
    ) -> DispatchAuthorized:
        ProvisioningService(store.operator).set_tenant_status(actor.tenant, "suspended")
        return actual(service, lease)

    monkeypatch.setattr(DispatchService, "authorize", suspend_then_authorize)
    with pytest.raises(DispatchRejected):
        pipeline(store, provider, capacity).execute(actor.credential, uuid4().hex, store.request())
    assert provider.calls == () and capacity.occupied == 0
    assert store.totals(actor) == (0, 0, 0, 0)


@pytest.mark.parametrize(
    "mode,state,occupied",
    [
        ("success", "succeeded", 0),
        ("definite_failure", "failed", 0),
        ("deadline", "unknown", 1),
        ("malformed", "unknown", 1),
        ("ambiguous", "unknown", 1),
    ],
)
def test_full_provider_outcomes_keep_committed_accounting(
    store: ReservationStore, mode: DoubleMode, state: str, occupied: int
) -> None:
    actor, capacity, provider = store.actor(), CapacityGate(1), double(store, mode)
    idem = uuid4().hex
    service = pipeline(store, provider, capacity)
    result = service.execute(actor.credential, idem, store.request())
    assert result.state == state and provider.calls == (result.request_id,)
    assert evidence(store, actor, result.request_id) == (state, 1, 1)
    assert store.totals(actor) == (1, 0, 10, 0) and capacity.occupied == occupied
    with pytest.raises(RequestAlreadyAdmitted):
        service.execute(actor.credential, idem, store.request())
    assert provider.calls == (result.request_id,) and capacity.occupied == occupied
    if state == "unknown":
        assert not capacity.ready


def test_terminalization_failure_keeps_capacity_and_charge(
    store: ReservationStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    actor, capacity, provider = store.actor(), CapacityGate(1), double(store)
    idem = uuid4().hex
    service = pipeline(store, provider, capacity)

    def fail(*_args: object) -> bool:
        raise RuntimeError("synthetic terminal interruption")

    with monkeypatch.context() as patch:
        patch.setattr(TerminalRepository, "finalize", fail)
        with pytest.raises(TerminalUnavailable):
            service.execute(actor.credential, idem, store.request())
    assert len(provider.calls) == 1 and capacity.occupied == 1 and not capacity.ready
    assert evidence(store, actor, provider.calls[0]) == ("dispatched", 1, 0)
    assert store.totals(actor) == (1, 0, 10, 0)
    with pytest.raises(RequestAlreadyAdmitted):
        service.execute(actor.credential, idem, store.request())
    assert len(provider.calls) == 1


def test_cancellation_before_dispatch_releases_once(
    store: ReservationStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    actor, capacity, provider = store.actor(), CapacityGate(1), double(store)

    def cancel(_service: DispatchService, _lease: CapacityLease) -> None:
        raise asyncio.CancelledError()

    monkeypatch.setattr(DispatchService, "authorize", cancel)
    with pytest.raises(asyncio.CancelledError):
        pipeline(store, provider, capacity).execute(actor.credential, uuid4().hex, store.request())
    assert provider.calls == () and capacity.occupied == 0
    assert store.totals(actor) == (0, 0, 0, 0)


def test_cancellation_after_dispatch_quarantines_without_refund(store: ReservationStore) -> None:
    class CancellingDouble(DeterministicProvider):
        def generate(self, request: ProviderRequest, deadline: datetime) -> ProviderResult:
            super().generate(request, deadline)
            raise asyncio.CancelledError()

    actor, capacity = store.actor(), CapacityGate(1)
    provider = CancellingDouble(store.model, DIGEST, 256)
    idem, service = uuid4().hex, pipeline(store, provider, capacity)
    with pytest.raises(asyncio.CancelledError):
        service.execute(actor.credential, idem, store.request())
    assert len(provider.calls) == 1 and capacity.occupied == 1 and not capacity.ready
    assert evidence(store, actor, provider.calls[0]) == ("unknown", 1, 1)
    assert store.totals(actor) == (1, 0, 10, 0)
    with pytest.raises(RequestAlreadyAdmitted):
        service.execute(actor.credential, idem, store.request())
    assert len(provider.calls) == 1


@pytest.mark.parametrize("point", ["before_transfer", "after_transfer"])
def test_interruption_after_dispatch_commit_cannot_release_capacity(
    store: ReservationStore, monkeypatch: pytest.MonkeyPatch, point: str
) -> None:
    actor, capacity, provider = store.actor(), CapacityGate(1), double(store)
    actual = DispatchService.authorize

    def commit_then_cancel(service: DispatchService, lease: CapacityLease) -> None:
        actual(service, lease)
        raise asyncio.CancelledError()

    if point == "before_transfer":

        def cancel_transfer(_lease: CapacityLease) -> None:
            raise asyncio.CancelledError()

        monkeypatch.setattr(CapacityLease, "_transfer_after_dispatch", cancel_transfer)
    else:
        monkeypatch.setattr(DispatchService, "authorize", commit_then_cancel)
    idem, service = uuid4().hex, pipeline(store, provider, capacity)
    with pytest.raises(asyncio.CancelledError):
        service.execute(actor.credential, idem, store.request())
    assert provider.calls == () and capacity.occupied == 1 and not capacity.ready
    with pytest.raises(RequestAlreadyAdmitted) as duplicate:
        service.execute(actor.credential, idem, store.request())
    assert evidence(store, actor, duplicate.value.request_id) == ("unknown", 1, 1)
    assert store.totals(actor) == (1, 0, 10, 0)


def test_unconfirmed_predispatch_release_retains_handler_claim(
    store: ReservationStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    actor, capacity, provider = store.actor(), CapacityGate(1), double(store)
    captured: list[CapacityLease] = []

    def cancel(_service: DispatchService, lease: CapacityLease) -> None:
        captured.append(lease)
        raise asyncio.CancelledError()

    def unavailable(*_args: object) -> None:
        raise ReleaseUnavailable()

    with monkeypatch.context() as patch:
        patch.setattr(DispatchService, "authorize", cancel)
        patch.setattr(ReleaseService, "release", unavailable)
        with pytest.raises(asyncio.CancelledError):
            pipeline(store, provider, capacity).execute(
                actor.credential, uuid4().hex, store.request()
            )
    assert provider.calls == () and capacity.occupied == 1
    assert store.totals(actor) == (0, 1, 0, 10)
    assert captured[0].release_before_dispatch().changed
    assert capacity.occupied == 0 and store.totals(actor) == (0, 0, 0, 0)


def test_provider_observes_dispatch_commit_and_transferred_capacity(
    store: ReservationStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    actor, capacity = store.actor(), CapacityGate(1)
    actual = DispatchService.authorize
    captured: list[CapacityLease] = []

    def authorize(service: DispatchService, lease: CapacityLease) -> DispatchAuthorized:
        result = actual(service, lease)
        captured.append(lease)
        return result

    class ObservingDouble(DeterministicProvider):
        def generate(self, request: ProviderRequest, deadline: datetime) -> ProviderResult:
            lease = captured[0]
            assert evidence(store, actor, request.correlation) == ("dispatched", 1, 0)
            assert store.totals(actor) == (1, 0, 10, 0)
            assert capacity.release(lease._claim) is False
            with pytest.raises(ReleaseConflict):
                lease.release_before_dispatch()
            assert lease.owns() and capacity.occupied == 1
            # With the one-connection fixture pool, this also proves no database
            # transaction spans the provider invocation.
            with store.runtime.begin() as connection:
                assert (
                    connection.execute(
                        text("SELECT NULLIF(current_setting('arbiter.tenant_id',true),'')")
                    ).scalar_one()
                    is None
                )
            return super().generate(request, deadline)

    monkeypatch.setattr(DispatchService, "authorize", authorize)
    provider = ObservingDouble(store.model, DIGEST, 256)
    result = pipeline(store, provider, capacity).execute(
        actor.credential, uuid4().hex, store.request()
    )
    assert provider.calls == (result.request_id,) and capacity.occupied == 0
    assert evidence(store, actor, result.request_id) == ("succeeded", 1, 1)


def test_successful_terminal_capacity_cannot_be_released_twice(
    store: ReservationStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    actor, capacity, provider = store.actor(), CapacityGate(1), double(store)
    actual = CapacityGate.release_terminal
    releases: list[bool] = []

    def record(gate: CapacityGate, claim: _Claim) -> bool:
        result = actual(gate, claim)
        releases.append(result)
        return result

    monkeypatch.setattr(CapacityGate, "release_terminal", record)
    idem, service = uuid4().hex, pipeline(store, provider, capacity)
    result = service.execute(actor.credential, idem, store.request())
    assert releases == [True] and capacity.occupied == 0
    with pytest.raises(RequestAlreadyAdmitted):
        service.execute(actor.credential, idem, store.request())
    assert releases == [True] and provider.calls == (result.request_id,)
    assert evidence(store, actor, result.request_id) == ("succeeded", 1, 1)
