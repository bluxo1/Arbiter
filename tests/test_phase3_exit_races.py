"""Full governed execution against genuine PostgreSQL authority-lock races."""

import os
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from threading import Event
from uuid import UUID, uuid4

import pytest
from phase3_exit_support import (
    assert_blocked,
    assert_unique,
    concurrent_engine,
    double,
    execute_service,
    held_policy_change,
    observe_query,
    policy,
    receipts,
    wait,
)
from test_dispatch_authorization import held_authority_change
from test_rate_admission import redis_ready as redis_ready
from test_reservation_transactions import ReservationStore
from test_reservation_transactions import store as store

from arbiter.config import DatabaseRole
from arbiter.governance.capacity import CapacityGate, CapacityLease
from arbiter.governance.dispatch import DispatchAuthorized, DispatchRejected, DispatchService
from arbiter.governance.rate import RateGate
from arbiter.governance.reservation import ReservationUnavailable
from arbiter.identity.keys import InvalidKey
from arbiter.persistence.dispatch import DispatchDecision, DispatchRepository
from arbiter.persistence.workload import KeyBinding

pytestmark = pytest.mark.skipif(
    os.environ.get("ARBITER_TEST_DATABASE") != "1" or os.environ.get("ARBITER_TEST_REDIS") != "1",
    reason="requires real PostgreSQL and Redis",
)


@pytest.mark.parametrize("change", ["revoked", "suspended", "policy"])
def test_authority_commit_wins_full_execution_dispatch_race(
    store: ReservationStore, monkeypatch: pytest.MonkeyPatch, change: str
) -> None:
    actor, gate, provider = store.actor(), CapacityGate(1), double(store)
    reserved, dispatch = Event(), Event()
    actual = DispatchService.authorize

    def pause(service: DispatchService, lease: CapacityLease) -> DispatchAuthorized:
        reserved.set()
        wait(dispatch)
        return actual(service, lease)

    monkeypatch.setattr(DispatchService, "authorize", pause)
    with concurrent_engine() as engine, ThreadPoolExecutor(max_workers=1) as pool:
        with observe_query(engine, "arbiter.authorize_dispatch") as observation:
            future = pool.submit(
                execute_service(store, provider, gate, engine).execute,
                actor.credential,
                uuid4().hex,
                store.request(),
            )
            try:
                wait(reserved)
                mutation = (
                    held_policy_change(store, actor)
                    if change == "policy"
                    else (held_authority_change(store, actor, change))
                )
                with mutation:
                    dispatch.set()
                    assert_blocked(store, observation)
                    assert not future.done()
                with pytest.raises(DispatchRejected) as denied:
                    future.result(timeout=45)
                assert denied.value.reason == "authorization_changed"
            finally:
                dispatch.set()
    (row,) = receipts(store, actor)
    assert_unique(row)
    assert row.state == "released" and row.release_events == 1 and row.commit_events == 0
    assert provider.calls == () and gate.occupied == 0 and store.totals(actor) == (0, 0, 0, 0)


@pytest.mark.parametrize("change", ["revoked", "suspended"])
def test_dispatch_commit_wins_full_execution_authority_race(
    store: ReservationStore, monkeypatch: pytest.MonkeyPatch, change: str
) -> None:
    actor, gate, provider = store.actor(), CapacityGate(1), double(store)
    locked, commit = Event(), Event()
    actual = DispatchRepository.authorize

    def pause(
        repository: DispatchRepository, binding: KeyBinding, request: UUID
    ) -> DispatchDecision:
        result = actual(repository, binding, request)
        assert result.decision == "authorized"
        locked.set()
        wait(commit)
        return result

    monkeypatch.setattr(DispatchRepository, "authorize", pause)
    role: DatabaseRole = "runtime" if change == "revoked" else "operator"
    with concurrent_engine() as engine, concurrent_engine(role) as mutation_engine:
        changing = (
            replace(store, runtime=mutation_engine)
            if change == "revoked"
            else (replace(store, operator=mutation_engine))
        )

        def mutate() -> None:
            with held_authority_change(changing, actor, change):
                pass

        with ThreadPoolExecutor(max_workers=2) as pool:
            service = execute_service(store, provider, gate, engine)
            first = pool.submit(service.execute, actor.credential, uuid4().hex, store.request())
            try:
                wait(locked)
                with observe_query(
                    mutation_engine, "arbiter.revoke_api_key", "FROM arbiter.tenants"
                ) as observation:
                    mutation = pool.submit(mutate)
                    assert_blocked(store, observation)
                    assert not mutation.done()
                    commit.set()
                    mutation.result(timeout=45)
                assert first.result(timeout=45).state == "succeeded"
            finally:
                commit.set()
            with pytest.raises(InvalidKey):
                service.execute(actor.credential, uuid4().hex, store.request())
    (row,) = receipts(store, actor)
    assert_unique(row)
    assert row.commit_events == row.terminal_audits == 1 and provider.calls == (row.request_id,)
    assert store.totals(actor) == (1, 0, 10, 0) and gate.occupied == 0


def test_policy_revision_changes_after_rate_preflight_before_reservation(
    store: ReservationStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    actor, gate, provider = store.actor(), CapacityGate(1), double(store)
    admitted, reserve = Event(), Event()
    actual = RateGate.admit

    def pause(gate: RateGate, binding: KeyBinding, tenant: int, key: int) -> None:
        actual(gate, binding, tenant, key)
        admitted.set()
        wait(reserve)

    monkeypatch.setattr(RateGate, "admit", pause)
    with concurrent_engine() as engine, ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(
            execute_service(store, provider, gate, engine).execute,
            actor.credential,
            uuid4().hex,
            store.request(),
        )
        try:
            wait(admitted)
            policy(store, actor)
        finally:
            reserve.set()
        with pytest.raises(ReservationUnavailable) as denied:
            future.result(timeout=45)
        assert denied.value.code == "unavailable"
    assert receipts(store, actor) == () and provider.calls == () and gate.occupied == 0
