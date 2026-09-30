"""Real service outages/restarts through the complete governed execution path."""

import os
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from threading import Barrier, Event
from time import monotonic, sleep
from uuid import uuid4

import pytest
from phase3_exit_host import request_host
from phase3_exit_support import (
    DIGEST,
    assert_unique,
    concurrent_engine,
    double,
    execute_service,
    policy,
    receipts,
    recovery,
    wait,
)
from test_rate_admission import redis_ready as redis_ready
from test_rate_governance import redis_int, wait_ready
from test_reservation_transactions import ReservationStore
from test_reservation_transactions import store as store

from arbiter.governance.capacity import CapacityGate
from arbiter.governance.dispatch import TerminalUnavailable
from arbiter.governance.rate import RateDenied, RateUnavailable
from arbiter.governance.reservation import RequestAlreadyAdmitted, ReservationUnavailable
from arbiter.persistence.maintenance import clear_unknown
from arbiter.providers.double import DeterministicProvider
from arbiter.providers.port import ProviderRequest, ProviderResult

pytestmark = pytest.mark.skipif(
    os.environ.get("ARBITER_TEST_DATABASE") != "1" or os.environ.get("ARBITER_TEST_REDIS") != "1",
    reason="requires real PostgreSQL and Redis",
)
host = pytest.mark.skipif(
    os.environ.get("ARBITER_TEST_EXIT_HOST") != "1",
    reason="requires scripts/verify-phase3.ps1 disposable-stack fault controller",
)


def test_paired_key_and_tenant_rate_denials_do_not_reserve_or_invoke_provider(
    store: ReservationStore,
) -> None:
    actor, other = store.actor(), store.actor()
    second_key = store.actor(existing=actor)
    policy(store, actor, tenant_rate=3, key_rate=2)
    policy(store, other, tenant_rate=3, key_rate=2)
    gate, provider = CapacityGate(2), double(store)
    service = execute_service(store, provider, gate)
    for _ in range(2):
        assert service.execute(actor.credential, uuid4().hex, store.request()).state == "succeeded"
    with pytest.raises(RateDenied):
        service.execute(actor.credential, uuid4().hex, store.request())
    assert service.execute(second_key.credential, uuid4().hex, store.request()).state == "succeeded"
    for identity in (actor, second_key):
        with pytest.raises(RateDenied):
            service.execute(identity.credential, uuid4().hex, store.request())
    assert service.execute(other.credential, uuid4().hex, store.request()).state == "succeeded"
    assert len(provider.calls) == 4 and len(receipts(store, actor)) == 3
    assert store.totals(actor) == (3, 0, 30, 0) and store.totals(other) == (1, 0, 10, 0)
    assert gate.occupied == 0


@host
def test_real_redis_outage_rejects_100_simultaneous_attempts_without_provider_calls(
    store: ReservationStore,
) -> None:
    actor, gate, provider = store.actor(), CapacityGate(128), double(store)
    policy(store, actor)
    request_host("redis_stop")
    try:
        with concurrent_engine() as engine, ThreadPoolExecutor(max_workers=100) as pool:
            service, start = execute_service(store, provider, gate, engine), Barrier(101)

            def attempt() -> None:
                start.wait(timeout=45)
                with pytest.raises(RateUnavailable):
                    service.execute(actor.credential, uuid4().hex, store.request())

            futures = [pool.submit(attempt) for _ in range(100)]
            start.wait(timeout=45)
            for future in futures:
                future.result(timeout=90)
        assert provider.calls == () and receipts(store, actor) == () and gate.occupied == 0
    finally:
        request_host("redis_start")
        wait_ready()


@pytest.mark.parametrize("loss", ["restart", "state_loss"])
@host
def test_entire_redis_recovery_barrier_blocks_full_pipeline(
    store: ReservationStore, loss: str
) -> None:
    actor, gate, provider = store.actor(), CapacityGate(2), double(store)
    service = execute_service(store, provider, gate)
    if loss == "restart":
        request_host("redis_restart")
    else:
        assert (
            redis_int(
                "return redis.call('DEL',KEYS[1],KEYS[2])",
                ("arbiter:rate:sentinel", "arbiter:rate:index"),
            )
            == 2
        )
    started = monotonic()
    with pytest.raises(RateUnavailable):
        service.execute(actor.credential, uuid4().hex, store.request())
    barrier = redis_int(
        "return tonumber(string.match(redis.call('GET',KEYS[1]),':([0-9]+)$'))",
        ("arbiter:rate:barrier",),
    )
    clock_script = (
        "local t=redis.call('TIME'); return tonumber(t[1])*1000+math.floor(tonumber(t[2])/1000)"
    )
    now = redis_int(clock_script)
    assert 59_000 <= barrier - now <= 60_000
    probes = 0
    # Check against Redis time, including a probe within the last second. No
    # clock mocks, accelerated TTLs or readiness PING substitutes are used.
    while redis_int(clock_script) < barrier - 50:
        with pytest.raises(RateUnavailable):
            service.execute(actor.credential, uuid4().hex, store.request())
        probes += 1
        assert provider.calls == () and receipts(store, actor) == ()
        assert (
            redis_int(
                "return tonumber(string.match(redis.call('GET',KEYS[1]),':([0-9]+)$'))",
                ("arbiter:rate:barrier",),
            )
            == barrier
        )
        sleep(0.2)
    wait_ready()
    assert monotonic() - started >= 59.9 and probes >= 100
    assert service.execute(actor.credential, uuid4().hex, store.request()).state == "succeeded"
    assert len(provider.calls) == 1 and gate.occupied == 0


@host
def test_real_postgresql_outage_before_reservation_has_no_provider_call(
    store: ReservationStore,
) -> None:
    actor, gate, provider = store.actor(), CapacityGate(1), double(store)
    request_host("postgres_stop")
    try:
        with concurrent_engine() as engine:
            with pytest.raises(ReservationUnavailable):
                execute_service(store, provider, gate, engine).execute(
                    actor.credential, uuid4().hex, store.request()
                )
        assert provider.calls == () and gate.occupied == 0
    finally:
        request_host("postgres_start")
        for engine in (store.runtime, store.operator, store.migration):
            engine.dispose()
    assert receipts(store, actor) == ()


@host
def test_real_postgresql_outage_after_provider_retains_charge_and_unknown_capacity(
    store: ReservationStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    entered, terminal = Event(), Event()

    class HeldDouble(DeterministicProvider):
        def generate(self, request: ProviderRequest, deadline: datetime) -> ProviderResult:
            result = super().generate(request, deadline)
            entered.set()
            wait(terminal)
            return result

    actor, gate, idem = store.actor(), CapacityGate(1), uuid4().hex
    provider = HeldDouble(store.model, DIGEST, 256)
    with concurrent_engine() as engine, ThreadPoolExecutor(max_workers=1) as pool:
        service = execute_service(store, provider, gate, engine)
        future = pool.submit(service.execute, actor.credential, idem, store.request())
        try:
            wait(entered)
            request_host("postgres_stop")
            terminal.set()
            with pytest.raises(TerminalUnavailable):
                future.result(timeout=45)
            assert len(provider.calls) == gate.occupied == 1 and not gate.ready
        finally:
            terminal.set()
            request_host("postgres_start")
            for fixture_engine in (store.runtime, store.operator, store.migration):
                fixture_engine.dispose()
    (row,) = receipts(store, actor)
    assert row.state == "dispatched" and row.commit_events == 1 and row.terminal_audits == 0
    restarted = CapacityGate(1)
    with recovery(store, restarted, monkeypatch, actor) as maintenance:
        assert maintenance.run_once().marked_unknown == 1
        assert maintenance.run_once().marked_unknown == 0 and restarted.occupied == 1
        with pytest.raises(RequestAlreadyAdmitted):
            execute_service(store, provider, restarted).execute(
                actor.credential, idem, store.request()
            )
        assert len(provider.calls) == 1 and store.totals(actor) == (1, 0, 10, 0)
        assert clear_unknown(store.operator, actor.tenant, row.request_id)
        assert maintenance.run_once().recovered_capacity == 1
        assert maintenance.run_once().recovered_capacity == 0 and restarted.occupied == 0
        assert store.totals(actor) == (1, 0, 10, 0)
    assert_unique(receipts(store, actor)[0])
