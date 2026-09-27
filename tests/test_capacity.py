"""Process-local slot ownership and real-PostgreSQL pre-dispatch cleanup."""

import asyncio
import os
from concurrent.futures import ThreadPoolExecutor
from threading import Event
from uuid import UUID, uuid4

import pytest
from sqlalchemy import text
from test_reservation_release import evidence, mark_dispatched_fixture
from test_reservation_transactions import ReservationStore
from test_reservation_transactions import store as store

from arbiter.governance.capacity import (
    CapacityGate,
    CapacityOwnershipError,
    CapacityService,
    CapacityUnavailable,
    _Claim,
)
from arbiter.governance.release import ReleaseConflict, ReleaseService, ReleaseUnavailable
from arbiter.identity.context import TenantContext
from arbiter.persistence.tenant import tenant_transaction
from arbiter.persistence.workload import KeyBinding


def _binding() -> KeyBinding:
    return KeyBinding(uuid4(), uuid4(), ("inference:write",))


def test_default_and_limit_validation() -> None:
    assert CapacityGate().limit == 2
    for invalid in (-1, True, 2147483648, 1.5, "2"):
        with pytest.raises(ValueError):
            CapacityGate(invalid)  # type: ignore[arg-type]
    assert CapacityGate(0).try_acquire(_binding(), uuid4()) is None


def test_limit_immediate_rejection_and_exact_release() -> None:
    gate = CapacityGate(2)
    first, second, third = _binding(), _binding(), _binding()
    a = gate.try_acquire(first, uuid4())
    b = gate.try_acquire(second, uuid4())
    assert a is not None and b is not None and gate.occupied == 2
    assert gate.try_acquire(third, uuid4()) is None
    assert gate.occupied == 2
    assert gate.release(a) is True
    assert gate.release(a) is False
    assert gate.occupied == 1
    assert gate.release(b) is True
    assert gate.occupied == 0


def test_no_queueing_while_held() -> None:
    gate = CapacityGate(1)
    owner = gate.try_acquire(_binding(), uuid4())
    assert owner is not None
    completed = Event()
    attempted = Event()

    def contender() -> bool:
        attempted.set()
        denied = gate.try_acquire(_binding(), uuid4()) is None
        completed.set()
        return denied

    with ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(contender)
        try:
            assert attempted.wait(2) and completed.wait(2)
            assert future.result() is True
            assert gate.occupied == 1
        finally:
            assert gate.release(owner)


def test_concurrent_acquisition_race_and_no_underflow() -> None:
    gate = CapacityGate(2)
    start = Event()
    bindings = [_binding() for _ in range(64)]

    def contender(index: int) -> _Claim | None:
        assert start.wait(5)
        return gate.try_acquire(bindings[index], uuid4())

    with ThreadPoolExecutor(max_workers=64) as pool:
        futures = [pool.submit(contender, index) for index in range(64)]
        start.set()
        claims = [future.result() for future in futures]
    owners = [claim for claim in claims if claim is not None]
    assert len(owners) == gate.occupied == 2
    with ThreadPoolExecutor(max_workers=32) as pool:
        releases = list(pool.map(gate.release, [owners[0]] * 32))
    assert sum(releases) == 1 and gate.occupied == 1
    assert gate.release(owners[1]) and gate.occupied == 0
    assert not gate.release(owners[0]) and gate.occupied == 0


def test_duplicate_and_stale_claim_cannot_release_new_owner() -> None:
    gate = CapacityGate(1)
    binding, request = _binding(), uuid4()
    old = gate.try_acquire(binding, request)
    assert old is not None
    with pytest.raises(CapacityOwnershipError):
        gate.try_acquire(binding, request)
    assert gate.release(old)
    current = gate.try_acquire(binding, request)
    assert current is not None
    assert not gate.release(old)
    assert gate.occupied == 1
    assert gate.release(current)


def test_restart_creates_no_recovery_claim() -> None:
    old_process = CapacityGate()
    old_claim = old_process.try_acquire(_binding(), uuid4())
    assert old_claim is not None
    new_process = CapacityGate()
    assert new_process.occupied == 0
    assert not new_process.release(old_claim)
    # Empty local state says nothing about durable dispatched/unknown work.
    assert old_process.occupied == 1


def test_stale_claim_cannot_prepare() -> None:
    gate = CapacityGate(1)
    # The gate itself rejects a stale owner before a later handler can prepare.
    binding, request = _binding(), uuid4()
    old = gate.try_acquire(binding, request)
    assert old is not None and gate.release(old)
    current = gate.try_acquire(binding, request)
    assert current is not None and not gate.owns(old) and gate.owns(current)
    assert gate.release(current)


@pytest.mark.skipif(os.environ.get("ARBITER_TEST_DATABASE") != "1", reason="real PostgreSQL")
def test_reservation_precedes_global_acquisition_and_rejection_is_durable(
    store: ReservationStore,
) -> None:
    gate = CapacityGate(2)
    service = CapacityService(store.service(), ReleaseService(store.runtime), gate)
    a, b, denied_actor = store.actor(), store.actor(), store.actor()
    a_lease = service.reserve_and_acquire(a.credential, uuid4().hex, store.request())
    b_lease = service.reserve_and_acquire(b.credential, uuid4().hex, store.request())
    assert gate.occupied == 2
    with pytest.raises(CapacityUnavailable) as denied:
        service.reserve_and_acquire(denied_actor.credential, uuid4().hex, store.request())
    assert denied.value.status_code == 503
    assert gate.occupied == 2
    assert store.totals(denied_actor) == (0, 0, 0, 0)
    assert store.counts(denied_actor) == (1, 1, 1, 1, 2, 1)
    with tenant_transaction(store.runtime, TenantContext(denied_actor.tenant)) as tx:
        rejected_id: UUID = (
            tx.connection()
            .execute(
                text(
                    "SELECT id FROM arbiter.requests "
                    "WHERE tenant_id=:tenant AND state='rejected_capacity'"
                ),
                {"tenant": denied_actor.tenant},
            )
            .scalar_one()
        )
    assert evidence(store, denied_actor, rejected_id)[7:] == (1, 1)
    assert a_lease.release_before_dispatch().changed
    assert b_lease.release_before_dispatch().changed
    assert gate.occupied == 0


@pytest.mark.skipif(os.environ.get("ARBITER_TEST_DATABASE") != "1", reason="real PostgreSQL")
def test_slot_acquisition_observes_committed_reservation(
    store: ReservationStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    actor = store.actor()
    gate = CapacityGate(1)
    original = gate.try_acquire
    observed = False

    def inspect_before_acquire(binding: KeyBinding, request_id: UUID) -> object:
        nonlocal observed
        assert binding.tenant_id == actor.tenant and binding.key_id == actor.key
        assert store.counts(actor) == (1, 1, 1, 1, 1, 1)
        assert store.totals(actor) == (0, 1, 0, 10)
        observed = True
        return original(binding, request_id)

    monkeypatch.setattr(gate, "try_acquire", inspect_before_acquire)
    lease = CapacityService(
        store.service(), ReleaseService(store.runtime), gate
    ).reserve_and_acquire(actor.credential, uuid4().hex, store.request())
    assert observed and gate.occupied == 1
    assert lease.release_before_dispatch().changed and gate.occupied == 0


@pytest.mark.skipif(os.environ.get("ARBITER_TEST_DATABASE") != "1", reason="real PostgreSQL")
def test_independent_tenants_share_gate_and_cannot_release_each_other(
    store: ReservationStore,
) -> None:
    gate = CapacityGate(1)
    service = CapacityService(store.service(), ReleaseService(store.runtime), gate)
    a, b = store.actor(), store.actor()
    lease = service.reserve_and_acquire(a.credential, uuid4().hex, store.request())
    with pytest.raises(CapacityUnavailable):
        service.reserve_and_acquire(b.credential, uuid4().hex, store.request())
    assert gate.occupied == 1 and store.totals(b) == (0, 0, 0, 0)
    assert lease.release_before_dispatch().changed
    other = service.reserve_and_acquire(b.credential, uuid4().hex, store.request())
    assert gate.occupied == 1
    assert not gate.release(lease._claim)
    assert gate.occupied == 1
    assert other.release_before_dispatch().changed


@pytest.mark.skipif(os.environ.get("ARBITER_TEST_DATABASE") != "1", reason="real PostgreSQL")
def test_pre_dispatch_failure_and_cancellation_leave_no_slot(store: ReservationStore) -> None:
    gate = CapacityGate()
    service = CapacityService(store.service(), ReleaseService(store.runtime), gate)
    for exception in (RuntimeError("preparation failed"), asyncio.CancelledError()):
        actor = store.actor()
        lease = service.reserve_and_acquire(actor.credential, uuid4().hex, store.request())

        def fail(error: BaseException = exception) -> None:
            raise error

        with pytest.raises(type(exception)):
            lease.prepare(fail)
        assert gate.occupied == 0 and store.totals(actor) == (0, 0, 0, 0)
        assert evidence(store, actor, lease.result.request_id)[0] == "released"
        assert lease.release_before_dispatch().changed is False
        assert gate.occupied == 0
        called = False

        def stale_action() -> None:
            nonlocal called
            called = True

        with pytest.raises(CapacityOwnershipError):
            lease.prepare(stale_action)
        assert not called


@pytest.mark.skipif(os.environ.get("ARBITER_TEST_DATABASE") != "1", reason="real PostgreSQL")
def test_release_failure_keeps_slot_until_postgres_confirms(
    store: ReservationStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    gate = CapacityGate(1)
    actor = store.actor()
    lease = CapacityService(
        store.service(), ReleaseService(store.runtime), gate
    ).reserve_and_acquire(actor.credential, uuid4().hex, store.request())
    actual = lease._releaser.release

    def fail(*_args: object) -> None:
        raise ReleaseUnavailable()

    monkeypatch.setattr(lease._releaser, "release", fail)
    with pytest.raises(ReleaseUnavailable):
        lease.release_before_dispatch()
    assert gate.occupied == 1 and store.totals(actor) == (0, 1, 0, 10)
    monkeypatch.setattr(lease._releaser, "release", actual)
    assert lease.release_before_dispatch().changed
    assert gate.occupied == 0 and store.totals(actor) == (0, 0, 0, 0)


@pytest.mark.skipif(os.environ.get("ARBITER_TEST_DATABASE") != "1", reason="real PostgreSQL")
def test_dispatched_fixture_cannot_free_capacity(store: ReservationStore) -> None:
    gate = CapacityGate(1)
    actor = store.actor()
    lease = CapacityService(
        store.service(), ReleaseService(store.runtime), gate
    ).reserve_and_acquire(actor.credential, uuid4().hex, store.request())
    # Owner-only test fixture for a committed marker; no application dispatch exists.
    with store.migration.begin() as connection:
        mark_dispatched_fixture(connection, actor, lease.result.request_id)
    with pytest.raises(ReleaseConflict):
        lease.release_before_dispatch()
    assert gate.occupied == 1 and store.totals(actor) == (1, 0, 10, 0)
