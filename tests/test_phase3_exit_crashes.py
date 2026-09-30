"""Actual process death at governed durable boundaries, followed by fresh recovery."""

import os
from collections.abc import Callable
from datetime import datetime
from multiprocessing import get_context
from multiprocessing.connection import Connection
from uuid import UUID, uuid4

import pytest
from phase3_exit_support import (
    DIGEST,
    assert_unique,
    concurrent_engine,
    double,
    execute_service,
    receipts,
    recovery,
    wait_stale,
)
from test_rate_admission import redis_ready as redis_ready
from test_reservation_transactions import Actor, ReservationStore
from test_reservation_transactions import store as store

from arbiter.governance.capacity import CapacityGate, CapacityLease
from arbiter.governance.dispatch import DispatchService
from arbiter.governance.reservation import RequestAlreadyAdmitted
from arbiter.persistence.dispatch import DispatchRepository
from arbiter.persistence.maintenance import clear_unknown
from arbiter.persistence.reservation import ReservationRepository
from arbiter.persistence.terminal import TerminalRepository
from arbiter.providers.double import DeterministicProvider
from arbiter.providers.port import ProviderRequest, ProviderResult

pytestmark = pytest.mark.skipif(
    os.environ.get("ARBITER_TEST_DATABASE") != "1" or os.environ.get("ARBITER_TEST_REDIS") != "1",
    reason="requires real PostgreSQL and Redis",
)

POINTS = (
    "before_reservation",
    "before_reservation_commit",
    "after_reservation",
    "after_capacity",
    "before_dispatch_commit",
    "after_dispatch_commit",
    "after_ownership_transfer",
    "during_provider",
    "after_provider_completion",
    "before_terminal_commit",
    "after_terminal_commit",
)


def crashed_worker(
    control: Connection, actor: Actor, model: UUID, alias: str, idem: str, point: str
) -> None:
    """A child exits without finally blocks, rollback helpers or handler cleanup."""
    provider_calls = 0

    def stop() -> None:
        control.send(("boundary", point, provider_calls))
        if not control.poll(60) or control.recv() != "crash":
            os._exit(98)
        os._exit(97)

    class WitnessDouble(DeterministicProvider):
        def generate(self, request: ProviderRequest, deadline: datetime) -> ProviderResult:
            nonlocal provider_calls
            result = super().generate(request, deadline)
            provider_calls += 1
            if point == "during_provider":
                stop()
            return result

    hooks: dict[str, tuple[type, str, bool]] = {
        "before_reservation": (ReservationRepository, "reserve_governed", False),
        "before_reservation_commit": (ReservationRepository, "reserve_governed", True),
        "after_reservation": (CapacityGate, "try_acquire", False),
        "after_capacity": (DispatchService, "authorize", False),
        "before_dispatch_commit": (DispatchRepository, "authorize", True),
        "after_dispatch_commit": (CapacityLease, "_transfer_after_dispatch", False),
        "after_ownership_transfer": (DispatchService, "run_double_once", False),
        "after_provider_completion": (TerminalRepository, "finalize", False),
        "before_terminal_commit": (TerminalRepository, "finalize", True),
        "after_terminal_commit": (CapacityLease, "_release_after_terminal", False),
    }
    try:
        with concurrent_engine() as engine, pytest.MonkeyPatch.context() as patch:
            if point in hooks:
                target, method, after = hooks[point]
                actual: Callable[..., object] = getattr(target, method)

                def intercept(*args: object, **kwargs: object) -> object:
                    if not after:
                        stop()
                    result = actual(*args, **kwargs)
                    if after:
                        stop()
                    return result

                patch.setattr(target, method, intercept)
            # These fixture keys match ReservationStore; credentials remain only
            # in memory. No prompt, result, credential or DB URL enters the pipe.
            fixture = ReservationStore(engine, engine, engine, model, alias)
            provider = WitnessDouble(model, DIGEST, 256)
            execute_service(fixture, provider, CapacityGate(1)).execute(
                actor.credential, idem, fixture.request()
            )
        control.send(("unexpected_completion", point, provider_calls))
    except BaseException as error:
        control.send(("error", type(error).__name__, provider_calls))
    os._exit(99)


@pytest.mark.parametrize("point", POINTS)
def test_process_crash_and_restart_at_every_durable_boundary(
    store: ReservationStore, monkeypatch: pytest.MonkeyPatch, point: str
) -> None:
    actor, idem = store.actor(), uuid4().hex
    context = get_context("spawn")
    parent, child = context.Pipe()
    worker = context.Process(
        target=crashed_worker, args=(child, actor, store.model, store.alias, idem, point)
    )
    worker.start()
    child.close()
    try:
        assert parent.poll(60), "child did not reach the selected crash boundary"
        message = parent.recv()
        called = int(
            point
            in {
                "during_provider",
                "after_provider_completion",
                "before_terminal_commit",
                "after_terminal_commit",
            }
        )
        assert message == ("boundary", point, called)
        before = receipts(store, actor)
        if point in {"before_reservation", "before_reservation_commit"}:
            assert before == ()
        else:
            (row,) = before
            expected = (
                "reserved"
                if point in {"after_reservation", "after_capacity", "before_dispatch_commit"}
                else "succeeded"
                if point == "after_terminal_commit"
                else "dispatched"
            )
            assert row.state == expected
            assert row.commit_events == int(expected != "reserved")
            assert row.terminal_audits == int(expected == "succeeded")
        parent.send("crash")
        worker.join(timeout=15)
        assert worker.exitcode == 97, "worker must die without executing cleanup"
    finally:
        if worker.is_alive():
            worker.terminate()
            worker.join(timeout=15)
        parent.close()
        worker.close()

    restarted = CapacityGate(1)
    no_reservation = point in {"before_reservation", "before_reservation_commit"}
    reserved = point in {"after_reservation", "after_capacity", "before_dispatch_commit"}
    if reserved:
        # Use the real expiration threshold; never edit immutable request times.
        wait_stale(store, actor)
    with recovery(store, restarted, monkeypatch, actor) as maintenance:
        result = maintenance.run_once()
        if no_reservation:
            assert receipts(store, actor) == ()
            assert result.released == result.marked_unknown == restarted.occupied == 0
        elif reserved:
            (row,) = receipts(store, actor)
            assert row.state == "released" and row.release_events == result.released == 1
            assert row.commit_events == row.terminal_audits == restarted.occupied == 0
            assert store.totals(actor) == (0, 0, 0, 0)
        elif point == "after_terminal_commit":
            assert receipts(store, actor) == before
            assert result.marked_unknown == restarted.occupied == 0
            assert store.totals(actor) == (1, 0, 10, 0)
        else:
            (row,) = receipts(store, actor)
            assert row.state == "unknown" and row.terminal_audits == 1
            assert result.marked_unknown == result.unresolved_unknown == restarted.occupied == 1
            assert not restarted.ready and store.totals(actor) == (1, 0, 10, 0)
        assert maintenance.run_once().released == maintenance.run_once().marked_unknown == 0
        provider = double(store)
        if not no_reservation:
            with pytest.raises(RequestAlreadyAdmitted):
                execute_service(store, provider, restarted).execute(
                    actor.credential, idem, store.request()
                )
            assert provider.calls == (), "recovery or duplicate must not retry the provider"
            (row,) = receipts(store, actor)
            assert_unique(row)
            if not reserved and point != "after_terminal_commit":
                assert clear_unknown(store.operator, actor.tenant, row.request_id)
                assert not clear_unknown(store.operator, actor.tenant, row.request_id)
                assert maintenance.run_once().recovered_capacity == 1
                assert maintenance.run_once().recovered_capacity == 0
                assert store.totals(actor) == (1, 0, 10, 0)
        assert restarted.occupied == 0 and restarted.ready
