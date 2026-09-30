"""Deterministic governed-pipeline races and accounting/capacity exit assertions."""

import ast
import os
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from pathlib import Path
from threading import Barrier, Event
from typing import Any
from uuid import UUID, uuid4

import pytest
from fastapi.routing import APIRoute
from phase3_exit_support import (
    DIGEST,
    assert_blocked,
    assert_unique,
    concurrent_engine,
    double,
    execute_service,
    observe_query,
    policy,
    receipts,
    recovery,
    wait,
)
from test_rate_admission import redis_ready as redis_ready
from test_reservation_release import fault
from test_reservation_transactions import ReservationStore
from test_reservation_transactions import store as store

from arbiter.governance.capacity import CapacityGate, CapacityLease
from arbiter.governance.dispatch import (
    DispatchService,
    DispatchUnavailable,
    TerminalUnavailable,
)
from arbiter.governance.rate import RateGate
from arbiter.governance.release import ReleaseService
from arbiter.governance.reservation import (
    IdempotencyConflict,
    RequestAlreadyAdmitted,
    ReservationDenied,
)
from arbiter.main import create_app
from arbiter.persistence.dispatch import DispatchDecision, DispatchRepository
from arbiter.persistence.maintenance import clear_unknown
from arbiter.persistence.terminal import TerminalRepository
from arbiter.persistence.workload import KeyBinding
from arbiter.providers.double import DeterministicProvider, DoubleMode
from arbiter.providers.port import ProviderAmbiguous, ProviderRequest, ProviderResult

pytestmark = pytest.mark.skipif(
    os.environ.get("ARBITER_TEST_DATABASE") != "1" or os.environ.get("ARBITER_TEST_REDIS") != "1",
    reason="requires real PostgreSQL and Redis",
)


@pytest.mark.parametrize("allocation", ["quota", "budget"])
def test_zero_allocation_with_100_simultaneous_execute_attempts(
    store: ReservationStore, allocation: str
) -> None:
    actor = store.actor()
    policy(
        store,
        actor,
        quota=0 if allocation == "quota" else 1000,
        budget=0 if allocation == "budget" else 10000,
    )
    gate, provider = CapacityGate(128), double(store)
    start = Barrier(101)
    with concurrent_engine() as engine, ThreadPoolExecutor(max_workers=100) as pool:
        service = execute_service(store, provider, gate, engine)

        def attempt() -> str:
            start.wait(timeout=45)
            with pytest.raises(ReservationDenied) as rejected:
                service.execute(actor.credential, uuid4().hex, store.request())
            return rejected.value.code

        futures = [pool.submit(attempt) for _ in range(100)]
        start.wait(timeout=45)
        assert [future.result(timeout=90) for future in futures] == [
            f"{allocation}_exhausted"
        ] * 100
    assert provider.calls == () and gate.occupied == 0 and receipts(store, actor) == ()


@pytest.mark.parametrize("conflicting", [False, True])
def test_100_simultaneous_first_duplicates_execute_once(
    store: ReservationStore, monkeypatch: pytest.MonkeyPatch, conflicting: bool
) -> None:
    actor, gate, provider = store.actor(), CapacityGate(128), double(store)
    policy(store, actor)
    barrier = Barrier(100)
    actual = RateGate.admit
    idem = uuid4().hex

    def ready(gate: RateGate, binding: KeyBinding, tenant: int, key: int) -> None:
        # Every authenticated first preflight finishes before ANY reservation.
        # Each attempt then makes its real atomic Redis decision exactly once.
        barrier.wait(timeout=45)
        actual(gate, binding, tenant, key)

    monkeypatch.setattr(RateGate, "admit", ready)
    with concurrent_engine() as engine, ThreadPoolExecutor(max_workers=100) as pool:
        service = execute_service(store, provider, gate, engine)

        def attempt(index: int) -> str:
            try:
                request = store.request(str(index) if conflicting else "same bounded body")
                return service.execute(actor.credential, idem, request).state
            except (RequestAlreadyAdmitted, IdempotencyConflict) as rejected:
                return rejected.code

        futures = [pool.submit(attempt, index) for index in range(100)]
        results = [future.result(timeout=120) for future in futures]
    expected = "idempotency_conflict" if conflicting else "request_already_admitted"
    assert results.count("succeeded") == 1 and results.count(expected) == 99
    (row,) = receipts(store, actor)
    assert_unique(row)
    assert row.commit_events == row.dispatch_audits == row.terminal_audits == 1
    assert provider.calls == (row.request_id,)
    assert store.totals(actor) == (1, 0, 10, 0) and gate.occupied == 0


def test_duplicate_after_dispatch_commit_before_terminalization(
    store: ReservationStore,
) -> None:
    entered, complete = Event(), Event()

    class HeldDouble(DeterministicProvider):
        def generate(self, request: ProviderRequest, deadline: datetime) -> ProviderResult:
            result = super().generate(request, deadline)
            entered.set()
            wait(complete)
            return result

    actor, gate = store.actor(), CapacityGate(2)
    provider = HeldDouble(store.model, DIGEST, 256)
    idem, request = uuid4().hex, store.request()
    with concurrent_engine() as engine, ThreadPoolExecutor(max_workers=1) as pool:
        service = execute_service(store, provider, gate, engine)
        first = pool.submit(service.execute, actor.credential, idem, request)
        try:
            wait(entered)
            with pytest.raises(RequestAlreadyAdmitted) as duplicate:
                service.execute(actor.credential, idem, request)
            assert duplicate.value.state == "dispatched"
            with pytest.raises(IdempotencyConflict):
                service.execute(actor.credential, idem, store.request("different body"))
            assert provider.calls == (duplicate.value.request_id,)
            assert gate.occupied == 1 and store.totals(actor) == (1, 0, 10, 0)
        finally:
            complete.set()
        assert first.result(timeout=45).state == "succeeded"
    (row,) = receipts(store, actor)
    assert_unique(row)
    assert row.terminal_audits == 1 and gate.occupied == 0


def test_both_concurrent_first_attempts_fail_predispatch_release_once(
    store: ReservationStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    actor, gate, provider = store.actor(), CapacityGate(2), double(store)
    policy(store, actor)
    idem, preflight, duplicate_seen = uuid4().hex, Barrier(2), Event()
    actual = RateGate.admit

    def admit(gate: RateGate, binding: KeyBinding, tenant: int, key: int) -> None:
        preflight.wait(timeout=45)
        actual(gate, binding, tenant, key)

    def fail(
        _repository: DispatchRepository, _binding: KeyBinding, _request: UUID
    ) -> DispatchDecision:
        wait(duplicate_seen)
        raise RuntimeError("deterministic pre-dispatch failure")

    monkeypatch.setattr(RateGate, "admit", admit)
    monkeypatch.setattr(DispatchRepository, "authorize", fail)
    with concurrent_engine() as engine, ThreadPoolExecutor(max_workers=2) as pool:
        service = execute_service(store, provider, gate, engine)

        def attempt() -> str:
            try:
                service.execute(actor.credential, idem, store.request())
                pytest.fail("pre-dispatch failure unexpectedly succeeded")
            except RequestAlreadyAdmitted:
                duplicate_seen.set()
                return "duplicate"
            except DispatchUnavailable:
                return "unavailable"

        futures = [pool.submit(attempt) for _ in range(2)]
        assert sorted(future.result(timeout=60) for future in futures) == [
            "duplicate",
            "unavailable",
        ]
    (row,) = receipts(store, actor)
    assert_unique(row)
    assert row.state == "released" and row.release_events == 1 and row.commit_events == 0
    binding = KeyBinding(actor.key, actor.tenant, ("inference:write",))
    assert not ReleaseService(store.runtime).release(binding, row.request_id, "cancelled").changed
    assert receipts(store, actor) == (row,)
    assert provider.calls == () and gate.occupied == 0 and store.totals(actor) == (0, 0, 0, 0)


@pytest.mark.parametrize(
    "mode", ["success", "definite_failure", "deadline", "malformed", "ambiguous"]
)
def test_terminal_outcome_accounting_capacity_and_duplicate_evidence(
    store: ReservationStore, mode: DoubleMode
) -> None:
    actor, gate, provider = store.actor(), CapacityGate(1), double(store, mode)
    service, idem = execute_service(store, provider, gate), uuid4().hex
    result = service.execute(actor.credential, idem, store.request())
    (row,) = receipts(store, actor)
    assert_unique(row)
    assert row.commit_events == row.terminal_audits == 1 and row.release_events == 0
    assert provider.calls == (result.request_id,) and store.totals(actor) == (1, 0, 10, 0)
    assert gate.occupied == int(result.state == "unknown")
    with pytest.raises(RequestAlreadyAdmitted):
        service.execute(actor.credential, idem, store.request())
    assert receipts(store, actor) == (row,) and len(provider.calls) == 1


def test_real_terminal_write_failure_is_recovered_without_provider_retry(
    store: ReservationStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    entered, complete = Event(), Event()

    class HeldDouble(DeterministicProvider):
        def generate(self, request: ProviderRequest, deadline: datetime) -> ProviderResult:
            result = super().generate(request, deadline)
            entered.set()
            wait(complete)
            return result

    actor, gate = store.actor(), CapacityGate(1)
    provider = HeldDouble(store.model, DIGEST, 256)
    idem = uuid4().hex
    with concurrent_engine() as engine, ThreadPoolExecutor(max_workers=1) as pool:
        service = execute_service(store, provider, gate, engine)
        future = pool.submit(service.execute, actor.credential, idem, store.request())
        try:
            wait(entered)
            with fault(store, actor, "audit_events", "INSERT"):
                complete.set()
                with pytest.raises(TerminalUnavailable):
                    future.result(timeout=45)
        finally:
            complete.set()
    (row,) = receipts(store, actor)
    assert row.state == "dispatched" and row.commit_events == 1 and row.terminal_audits == 0
    assert gate.occupied == 1 and not gate.ready and len(provider.calls) == 1
    restarted = CapacityGate(1)
    with recovery(store, restarted, monkeypatch, actor) as maintenance:
        assert maintenance.run_once().marked_unknown == 1
        assert maintenance.run_once().marked_unknown == 0
        assert restarted.occupied == 1 and not restarted.ready
    with pytest.raises(RequestAlreadyAdmitted):
        execute_service(store, provider, restarted).execute(actor.credential, idem, store.request())
    assert len(provider.calls) == 1 and store.totals(actor) == (1, 0, 10, 0)
    assert_unique(receipts(store, actor)[0])


def test_mark_unknown_races_with_maintenance_terminalization(
    store: ReservationStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    actor, gate, provider = store.actor(), CapacityGate(1), double(store)
    entered, continue_handler = Event(), Event()
    maintenance_locked, commit_maintenance = Event(), Event()
    captured: list[CapacityLease] = []
    actual = TerminalRepository.finalize

    def hold_terminal(
        repository: TerminalRepository,
        binding: KeyBinding,
        request_id: UUID,
        state: str,
        outcome: str,
        input_tokens: int | None,
        output_tokens: int | None,
    ) -> bool:
        changed = actual(
            repository, binding, request_id, state, outcome, input_tokens, output_tokens
        )
        if not maintenance_locked.is_set():
            maintenance_locked.set()
            wait(commit_maintenance)
        return changed

    def interrupted(_service: DispatchService, lease: CapacityLease, *_args: object) -> None:
        captured.append(lease)
        entered.set()
        wait(continue_handler)
        raise RuntimeError("interrupted dispatched handler")

    monkeypatch.setattr(DispatchService, "run_double_once", interrupted)
    monkeypatch.setattr(TerminalRepository, "finalize", hold_terminal)
    idem = uuid4().hex
    with concurrent_engine() as engine, ThreadPoolExecutor(max_workers=2) as pool:
        future = pool.submit(
            execute_service(store, provider, gate, engine).execute,
            actor.credential,
            idem,
            store.request(),
        )
        try:
            wait(entered)
            with recovery(store, gate, monkeypatch, actor) as maintenance:
                with observe_query(engine, "arbiter.finalize_dispatched") as observation:
                    sweeping = pool.submit(maintenance.run_once)
                    wait(maintenance_locked)
                    continue_handler.set()
                    assert_blocked(store, observation)
                    assert not future.done()
                    commit_maintenance.set()
                    assert sweeping.result(timeout=45).marked_unknown == 1
                with pytest.raises(RuntimeError):
                    future.result(timeout=45)
                assert DispatchService(store.runtime).mark_unknown(captured[0]) is False
                assert maintenance.run_once().marked_unknown == 0
                assert gate.occupied == 1 and not gate.ready
                assert clear_unknown(store.operator, actor.tenant, captured[0].result.request_id)
                assert not clear_unknown(
                    store.operator, actor.tenant, captured[0].result.request_id
                )
                assert maintenance.run_once().recovered_capacity == 1
                assert maintenance.run_once().recovered_capacity == 0
                assert gate.occupied == 0
        finally:
            continue_handler.set()
            commit_maintenance.set()
    (row,) = receipts(store, actor)
    assert_unique(row)
    assert row.state == "unknown" and row.terminal_audits == 1
    assert provider.calls == () and store.totals(actor) == (1, 0, 10, 0)


def test_operator_clearance_releases_only_the_intended_reconstructed_claim(
    store: ReservationStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    actor, gate = store.actor(), CapacityGate(2)
    policy(store, actor)
    both_called, finish = Event(), Event()
    calls = Barrier(2)

    class AmbiguousDouble(DeterministicProvider):
        def generate(self, request: ProviderRequest, deadline: datetime) -> ProviderResult:
            super().generate(request, deadline)
            calls.wait(timeout=45)
            both_called.set()
            wait(finish)
            raise ProviderAmbiguous()

    provider = AmbiguousDouble(store.model, DIGEST, 256)
    with concurrent_engine() as engine, ThreadPoolExecutor(max_workers=2) as pool:
        service = execute_service(store, provider, gate, engine)
        futures = [
            pool.submit(service.execute, actor.credential, uuid4().hex, store.request())
            for _ in range(2)
        ]
        try:
            wait(both_called)
        finally:
            finish.set()
        assert [future.result(timeout=45).state for future in futures] == ["unknown", "unknown"]
    rows = receipts(store, actor)
    assert len(rows) == len(provider.calls) == gate.occupied == 2
    restarted = CapacityGate(2)
    with recovery(store, restarted, monkeypatch, actor) as maintenance:
        assert maintenance.run_once().unresolved_unknown == 2
        assert restarted.occupied == 2 and not restarted.ready
        assert clear_unknown(store.operator, actor.tenant, rows[0].request_id)
        assert not clear_unknown(store.operator, actor.tenant, rows[0].request_id)
        assert maintenance.run_once().recovered_capacity == 1
        assert restarted.occupied == 1 and not restarted.ready
        assert maintenance.run_once().recovered_capacity == 0
        assert clear_unknown(store.operator, actor.tenant, rows[1].request_id)
        assert maintenance.run_once().recovered_capacity == 1
        assert restarted.occupied == 0 and restarted.ready
    assert store.totals(actor) == (2, 0, 20, 0) and receipts(store, actor) == rows
    for row in rows:
        assert_unique(row)
        assert row.commit_events == row.terminal_audits == 1 and row.release_events == 0


def test_generation_calls_are_confined_to_dispatch_service() -> None:
    root = Path(__file__).resolve().parents[1] / "src" / "arbiter"
    sites: list[tuple[str, str]] = []
    for source in root.rglob("*.py"):
        module = ast.parse(source.read_text(encoding="utf-8"))
        for function in ast.walk(module):
            if isinstance(function, (ast.FunctionDef, ast.AsyncFunctionDef)):
                for node in ast.walk(function):
                    if (
                        isinstance(node, ast.Call)
                        and isinstance(node.func, ast.Attribute)
                        and node.func.attr == "generate"
                    ):
                        sites.append((source.relative_to(root).as_posix(), function.name))
    assert sites == [("governance/dispatch.py", "run_double_once")]


def test_only_health_management_and_metadata_http_routes_exist() -> None:
    allowed = {
        ("GET", "/health/live"),
        ("GET", "/health/ready"),
        ("GET", "/v1/usage"),
        ("GET", "/v1/requests/{request_id}"),
        ("GET", "/v1/tenants/{tenant_id}/usage"),
        ("GET", "/v1/tenants/{tenant_id}/requests/{request_id}"),
        ("GET", "/v1/tenants/{tenant_id}/audit"),
        ("GET", "/v1/tenants/{tenant_id}/models"),
        ("GET", "/v1/models"),
        ("GET", "/v1/tenants/{tenant_id}/keys"),
        ("POST", "/v1/tenants/{tenant_id}/keys"),
        ("POST", "/v1/tenants/{tenant_id}/keys/{key_id}/revoke"),
    }
    actual: set[tuple[str, str]] = set()

    def collect(route: Any, prefix: str = "") -> None:
        if isinstance(route, APIRoute):
            assert route.methods is not None
            actual.update((method, prefix + route.path) for method in route.methods)
        else:
            # Pinned FastAPI includes routers lazily. Inspect their original
            # routes too, including any route excluded from the OpenAPI schema.
            assert hasattr(route, "original_router")
            for child in route.original_router.routes:
                collect(child, prefix + route.include_context.prefix)

    for route in create_app().routes:
        collect(route)
    assert actual == allowed
