"""Real PostgreSQL and Redis integration at the authenticated admission boundary."""

import os
import socket
from time import monotonic, sleep
from uuid import uuid4

import pytest
from test_reservation_transactions import ReservationStore

from arbiter.config import RedisSettings
from arbiter.governance.admission import RateGovernedReservationService
from arbiter.governance.capacity import CapacityGate, CapacityService
from arbiter.governance.rate import RateDenied, RateGate, RateUnavailable
from arbiter.governance.release import ReleaseService
from arbiter.governance.reservation import (
    IdempotencyConflict,
    RequestAlreadyAdmitted,
    ReservationDenied,
    ReservationUnavailable,
)
from arbiter.operations.policy import PolicyInput, PolicyService
from arbiter.persistence.workload import KeyBinding
from arbiter.providers.double import DeterministicProvider

pytestmark = pytest.mark.skipif(
    os.environ.get("ARBITER_TEST_DATABASE") != "1" or os.environ.get("ARBITER_TEST_REDIS") != "1",
    reason="real PostgreSQL and Redis",
)
pytest_plugins = ("test_reservation_transactions",)


@pytest.fixture(scope="module", autouse=True)
def redis_ready() -> None:
    gate = RateGate(RedisSettings())
    probe = KeyBinding(uuid4(), uuid4(), ("inference:write",))
    deadline = monotonic() + 65
    while monotonic() < deadline:
        try:
            gate.admit(probe, 0, 0)
        except RateDenied:
            return
        except RateUnavailable:
            sleep(0.2)
    pytest.fail("Redis recovery barrier did not become ready after 60 seconds")


def governed(store: ReservationStore, gate: RateGate | None = None) -> CapacityService:
    reservation = RateGovernedReservationService(
        store.runtime, store.verifier, store.fingerprint, gate or RateGate(RedisSettings())
    )
    return CapacityService(reservation, ReleaseService(store.runtime), CapacityGate(2))


def test_redis_denial_never_reaches_reservation_capacity_or_provider(
    store: ReservationStore,
) -> None:
    actor = store.actor()
    PolicyService(store.operator).set_policy(
        actor.tenant,
        PolicyInput(tenant_rate=1, key_rate=1, aliases=(store.alias,), concurrency=2),
    )
    service = governed(store)
    first = service.reserve_and_acquire(actor.credential, uuid4().hex, store.request())
    before = store.counts(actor)
    provider = DeterministicProvider(store.model, "sha256:" + "d" * 64, 256)
    with pytest.raises(RateDenied):
        service.reserve_and_acquire(actor.credential, uuid4().hex, store.request())
    assert store.counts(actor) == before
    assert provider.calls == ()
    assert first.owns()


def test_postgres_denial_keeps_redis_rate_consumption(store: ReservationStore) -> None:
    actor = store.actor(quota=0)
    PolicyService(store.operator).set_policy(
        actor.tenant,
        PolicyInput(
            tenant_rate=1, key_rate=1, daily_quota=0, aliases=(store.alias,), concurrency=2
        ),
    )
    service = governed(store)
    before = store.counts(actor)
    with pytest.raises(ReservationDenied) as rejected:
        service.reserve_and_acquire(actor.credential, uuid4().hex, store.request())
    assert rejected.value.code == "quota_exhausted"
    assert store.counts(actor) == before
    with pytest.raises(RateDenied):
        service.reserve_and_acquire(actor.credential, uuid4().hex, store.request())
    assert store.counts(actor) == before


def test_matching_and_conflicting_duplicates_are_checked_before_redis(
    store: ReservationStore,
) -> None:
    actor = store.actor()
    PolicyService(store.operator).set_policy(
        actor.tenant,
        PolicyInput(tenant_rate=1, key_rate=1, aliases=(store.alias,), concurrency=2),
    )
    service = governed(store)
    idem = uuid4().hex
    first = service.reserve_and_acquire(actor.credential, idem, store.request())
    with pytest.raises(RequestAlreadyAdmitted) as duplicate:
        service.reserve_and_acquire(actor.credential, idem, store.request())
    assert duplicate.value.request_id == first.result.request_id
    with pytest.raises(IdempotencyConflict):
        service.reserve_and_acquire(actor.credential, idem, store.request("different request"))
    with pytest.raises(RateDenied):
        service.reserve_and_acquire(actor.credential, uuid4().hex, store.request())


def test_unavailable_redis_cannot_write_postgres_or_acquire_capacity(
    store: ReservationStore,
) -> None:
    actor = store.actor()
    with socket.socket() as unused:
        unused.bind(("127.0.0.1", 0))
        gate = RateGate(RedisSettings(host="127.0.0.1", port=unused.getsockname()[1]))
        service = governed(store, gate)
        before = store.counts(actor)
        with pytest.raises(RateUnavailable):
            service.reserve_and_acquire(actor.credential, uuid4().hex, store.request())
        assert store.counts(actor) == before


def test_policy_change_during_redis_decision_cannot_admit_on_stale_limit(
    store: ReservationStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    actor = store.actor()
    PolicyService(store.operator).set_policy(
        actor.tenant,
        PolicyInput(tenant_rate=2, key_rate=2, aliases=(store.alias,), concurrency=2),
    )
    original = RateGate.admit

    def change_then_admit(
        gate: RateGate, binding: KeyBinding, tenant_limit: int, key_limit: int
    ) -> None:
        assert tenant_limit == key_limit == 2
        # This would block if admission held the PostgreSQL tenant lock across Redis.
        PolicyService(store.operator).set_policy(
            actor.tenant,
            PolicyInput(tenant_rate=1, key_rate=1, aliases=(store.alias,), concurrency=2),
        )
        original(gate, binding, tenant_limit, key_limit)

    monkeypatch.setattr(RateGate, "admit", change_then_admit)
    service = governed(store)
    before = store.counts(actor)
    with pytest.raises(ReservationUnavailable):
        service.reserve_and_acquire(actor.credential, uuid4().hex, store.request())
    assert store.counts(actor) == before
    monkeypatch.setattr(RateGate, "admit", original)
    with pytest.raises(RateDenied):
        service.reserve_and_acquire(actor.credential, uuid4().hex, store.request())
