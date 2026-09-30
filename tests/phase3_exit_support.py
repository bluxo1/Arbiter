"""Real-service evidence and scoped recovery helpers for the Phase 3 exit matrix."""

from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from threading import Event
from time import monotonic, sleep
from typing import Any
from uuid import UUID, uuid4

import pytest
from sqlalchemy import create_engine, event, text
from sqlalchemy.engine import Connection, Engine
from sqlalchemy.pool import NullPool
from test_reservation_transactions import Actor, ReservationStore

from arbiter.config import DatabaseRole, DatabaseSettings, RedisSettings
from arbiter.governance.capacity import CapacityGate
from arbiter.governance.execution import GovernedExecutionService
from arbiter.governance.rate import RateGate
from arbiter.identity.context import TenantContext
from arbiter.operations import maintenance
from arbiter.operations.maintenance import MaintenanceService
from arbiter.operations.policy import PolicyInput, PolicyService
from arbiter.persistence.maintenance import candidates, maintenance_engine
from arbiter.persistence.operator import OperatorRepository, operator_transaction
from arbiter.persistence.policy import PolicyRepository
from arbiter.persistence.tenant import tenant_transaction
from arbiter.providers.double import DeterministicProvider, DoubleMode

DIGEST = "sha256:" + "d" * 64
WAIT_SECONDS = 45


def wait(signal: Event) -> None:
    assert signal.wait(WAIT_SECONDS), "exit-matrix boundary was not reached"


def double(store: ReservationStore, mode: DoubleMode = "success") -> DeterministicProvider:
    return DeterministicProvider(store.model, DIGEST, 256, mode=mode)


def execute_service(
    store: ReservationStore,
    provider: DeterministicProvider,
    gate: CapacityGate,
    engine: Engine | None = None,
) -> GovernedExecutionService:
    return GovernedExecutionService(
        store.runtime if engine is None else engine,
        store.verifier,
        store.fingerprint,
        RateGate(RedisSettings()),
        provider,
        gate,
    )


@contextmanager
def concurrent_engine(
    role: DatabaseRole = "runtime", *, database: str | None = None
) -> Iterator[Engine]:
    # No connection pool serializes the attempts. The isolated test PostgreSQL
    # must have >=128 connections; these timeouts apply only to verification.
    engine = create_engine(
        DatabaseSettings().url(role).set(database=database)
        if database
        else DatabaseSettings().url(role),
        hide_parameters=True,
        poolclass=NullPool,
        connect_args={
            "connect_timeout": 15,
            "options": "-c statement_timeout=60000 -c lock_timeout=60000",
        },
    )
    try:
        yield engine
    finally:
        engine.dispose()


def policy(
    store: ReservationStore,
    actor: Actor,
    *,
    quota: int = 1000,
    budget: int = 10000,
    tenant_rate: int = 512,
    key_rate: int = 512,
) -> None:
    PolicyService(store.operator).set_policy(
        actor.tenant,
        PolicyInput(
            daily_quota=quota,
            monthly_budget=budget,
            tenant_rate=tenant_rate,
            key_rate=key_rate,
            concurrency=2,
            aliases=(store.alias,),
        ),
    )


@dataclass(frozen=True)
class Receipt:
    request_id: UUID
    state: str
    outcome: str | None
    reserve_events: int
    commit_events: int
    release_events: int
    dispatch_audits: int
    terminal_audits: int
    release_audits: int


def receipts(store: ReservationStore, actor: Actor) -> tuple[Receipt, ...]:
    with tenant_transaction(store.runtime, TenantContext(actor.tenant)) as transaction:
        rows = (
            transaction.connection()
            .execute(
                text("""
                SELECT r.id,r.state,r.outcome,
                    (SELECT count(*) FROM arbiter.accounting_events e
                     WHERE e.tenant_id=r.tenant_id AND e.request_id=r.id AND e.kind='reserve'),
                    (SELECT count(*) FROM arbiter.accounting_events e
                     WHERE e.tenant_id=r.tenant_id AND e.request_id=r.id AND e.kind='commit'),
                    (SELECT count(*) FROM arbiter.accounting_events e
                     WHERE e.tenant_id=r.tenant_id AND e.request_id=r.id AND e.kind='release'),
                    (SELECT count(*) FROM arbiter.audit_events a
                     WHERE a.tenant_id=r.tenant_id AND a.request_id=r.id
                       AND a.action='request_dispatched'),
                    (SELECT count(*) FROM arbiter.audit_events a
                     WHERE a.tenant_id=r.tenant_id AND a.request_id=r.id
                       AND a.action='request_finalized'),
                    (SELECT count(*) FROM arbiter.audit_events a
                     WHERE a.tenant_id=r.tenant_id AND a.request_id=r.id
                       AND a.action='request_released')
                FROM arbiter.requests r WHERE r.tenant_id=:tenant ORDER BY r.id
            """),
                {"tenant": actor.tenant},
            )
            .all()
        )
    return tuple(Receipt(*row) for row in rows)


def assert_unique(receipt: Receipt) -> None:
    assert receipt.reserve_events == 1
    assert receipt.commit_events in {0, 1}
    assert receipt.release_events in {0, 1}
    assert receipt.commit_events + receipt.release_events <= 1
    assert receipt.dispatch_audits == receipt.commit_events
    assert receipt.release_audits == receipt.release_events
    assert receipt.terminal_audits in {0, 1}


@contextmanager
def recovery(
    store: ReservationStore,
    gate: CapacityGate,
    monkeypatch: pytest.MonkeyPatch,
    *actors: Actor,
) -> Iterator[MaintenanceService]:
    tenants = {actor.tenant for actor in actors}
    discovery = maintenance_engine(DatabaseSettings())
    try:
        with monkeypatch.context() as patch:
            # The real restricted SQL discovery still runs. Scope only its UUID
            # output, keeping earlier retained verification tenants out of this sweep.
            patch.setattr(
                maintenance,
                "candidates",
                lambda engine, kind: tuple(
                    item for item in candidates(engine, kind) if item.tenant_id in tenants
                ),
            )
            yield MaintenanceService(store.runtime, discovery, gate)
    finally:
        discovery.dispose()


def wait_stale(store: ReservationStore, actor: Actor) -> None:
    deadline = monotonic() + 35
    while monotonic() < deadline:
        with tenant_transaction(store.runtime, TenantContext(actor.tenant)) as transaction:
            stale: bool = (
                transaction.connection()
                .execute(
                    text("""
                    SELECT bool_and(created_at<=clock_timestamp()-interval '30 seconds')
                    FROM arbiter.requests WHERE tenant_id=:tenant
                """),
                    {"tenant": actor.tenant},
                )
                .scalar_one()
            )
        if stale:
            return
        sleep(0.1)
    pytest.fail("real 30-second stale reservation threshold did not elapse")


@contextmanager
def held_policy_change(store: ReservationStore, actor: Actor) -> Iterator[None]:
    with operator_transaction(store.operator, actor.tenant) as transaction:
        operator = OperatorRepository(transaction)
        tenant = operator.lock_tenant()
        repository = PolicyRepository(transaction)
        repository.validate_limits(1000, 10000, 2)
        repository.validate_aliases((store.alias,))
        revision, policy_id = tenant.policy_revision + 1, uuid4()
        repository.advance_revision(tenant.policy_revision, revision)
        audit = operator.append_audit(
            action="tenant_policy_set",
            target_id=policy_id,
            revision=revision,
            correlation=uuid4(),
        )
        repository.insert(
            policy_id=policy_id,
            revision=revision,
            audit_id=audit,
            limits=(511, 511, 1000, 10000, 2),
            aliases=(store.alias,),
        )
        yield


@contextmanager
def observe_query(engine: Engine, *needles: str) -> Iterator[tuple[Event, list[int]]]:
    waiting, pids = Event(), []

    def observe(
        connection: Connection,
        _cursor: Any,
        statement: str,
        _parameters: Any,
        _context: Any,
        _executemany: bool,
    ) -> None:
        if any(needle in statement for needle in needles):
            driver: Any = connection.connection.driver_connection
            assert driver is not None
            pids.append(driver.info.backend_pid)
            waiting.set()

    event.listen(engine, "before_cursor_execute", observe)
    try:
        yield waiting, pids
    finally:
        event.remove(engine, "before_cursor_execute", observe)


def assert_blocked(store: ReservationStore, observation: tuple[Event, list[int]]) -> None:
    waiting, pids = observation
    wait(waiting)
    deadline = monotonic() + 5
    while monotonic() < deadline:
        with store.migration.connect() as probe:
            blocked: bool = probe.execute(
                text("SELECT cardinality(pg_blocking_pids(:pid))>0"), {"pid": pids[-1]}
            ).scalar_one()
        if blocked:
            return
        sleep(0.02)
    pytest.fail("contender did not block on the real PostgreSQL authority/terminal lock")
