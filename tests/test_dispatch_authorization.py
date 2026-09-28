"""Restricted PostgreSQL dispatch marker; never calls a provider."""

import os
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from dataclasses import replace
from datetime import datetime
from threading import Event
from time import monotonic, sleep
from typing import Any
from uuid import UUID, uuid4

import pytest
from sqlalchemy import create_engine, event, text
from sqlalchemy.engine import Connection
from sqlalchemy.exc import DBAPIError
from sqlalchemy.pool import NullPool
from test_reservation_release import fault
from test_reservation_transactions import Actor, ReservationStore, revoke_in_transaction
from test_reservation_transactions import store as store
from test_tenant_isolation import set_context

from arbiter.config import DatabaseRole, DatabaseSettings
from arbiter.governance.capacity import (
    CapacityGate,
    CapacityLease,
    CapacityOwnershipError,
    CapacityService,
    CapacityUnavailable,
)
from arbiter.governance.dispatch import (
    DispatchAuthorized,
    DispatchConflict,
    DispatchRejected,
    DispatchService,
    DispatchUnavailable,
)
from arbiter.governance.release import ReleaseConflict, ReleaseService
from arbiter.identity.context import TenantContext
from arbiter.operations.policy import PolicyInput, PolicyService
from arbiter.operations.provision import ProvisioningService
from arbiter.persistence.dispatch import DispatchRepository
from arbiter.persistence.operator import OperatorRepository, operator_transaction
from arbiter.persistence.tenant import tenant_transaction
from arbiter.persistence.workload import KeyBinding

pytestmark = pytest.mark.skipif(
    os.environ.get("ARBITER_TEST_DATABASE") != "1", reason="requires real PostgreSQL"
)


def acquire(store: ReservationStore, actor: Actor, gate: CapacityGate) -> CapacityLease:
    return CapacityService(
        store.service(), ReleaseService(store.runtime), gate
    ).reserve_and_acquire(actor.credential, uuid4().hex, store.request())


def evidence(store: ReservationStore, actor: Actor, request_id: UUID) -> tuple[object, ...]:
    with tenant_transaction(store.runtime, TenantContext(actor.tenant)) as tx:
        row = (
            tx.connection()
            .execute(
                text("""
                SELECT r.state,r.dispatched_at,r.dispatch_audit_id,s.disposition,
                    s.settlement_event_id,
                    (SELECT count(*) FROM arbiter.accounting_events e
                        WHERE e.tenant_id=r.tenant_id AND e.request_id=r.id AND e.kind='commit'),
                    (SELECT count(*) FROM arbiter.audit_events a
                        WHERE a.tenant_id=r.tenant_id AND a.request_id=r.id
                            AND a.action='request_dispatched')
                FROM arbiter.requests r JOIN arbiter.reservations s
                    ON s.tenant_id=r.tenant_id AND s.id=r.reservation_id
                WHERE r.tenant_id=:tenant AND r.id=:request
            """),
                {"tenant": actor.tenant, "request": request_id},
            )
            .one()
        )
        return tuple(row)


def test_authorization_commits_exactly_once_and_keeps_capacity(store: ReservationStore) -> None:
    actor, gate = store.actor(), CapacityGate(1)
    lease = acquire(store, actor, gate)
    before = evidence(store, actor, lease.result.request_id)
    assert before == ("reserved", None, None, "reserved", None, 0, 0)
    assert store.totals(actor) == (0, 1, 0, 10)
    assert DispatchService(store.runtime).authorize(lease) == DispatchAuthorized(
        lease.result.request_id
    )
    after = evidence(store, actor, lease.result.request_id)
    assert after[0] == "dispatched" and after[1] is not None and after[2] is not None
    assert after[3] == "committed" and after[4] is not None and after[5:] == (1, 1)
    assert store.totals(actor) == (1, 0, 10, 0)
    assert gate.occupied == 1
    with pytest.raises(DispatchConflict):
        DispatchService(store.runtime).authorize(lease)
    assert evidence(store, actor, lease.result.request_id) == after
    assert store.totals(actor) == (1, 0, 10, 0) and gate.occupied == 1
    with pytest.raises(ReleaseConflict):
        lease.release_before_dispatch()
    assert store.totals(actor) == (1, 0, 10, 0) and gate.occupied == 1


def test_runtime_has_no_direct_dispatch_mutation_or_owner_privileges(
    store: ReservationStore,
) -> None:
    actor, gate = store.actor(), CapacityGate(1)
    lease = acquire(store, actor, gate)
    with store.runtime.begin() as connection, pytest.raises(DBAPIError) as missing:
        connection.execute(
            text("SELECT * FROM arbiter.authorize_dispatch(:tenant,:key,:request)"),
            {"tenant": actor.tenant, "key": actor.key, "request": lease.result.request_id},
        )
    assert getattr(missing.value.orig, "sqlstate", None) == "42501"
    with store.runtime.begin() as connection, pytest.raises(DBAPIError) as denied:
        set_context(connection, actor.tenant)
        connection.execute(
            text("UPDATE arbiter.quota_windows SET committed=1 WHERE tenant_id=:tenant"),
            {"tenant": actor.tenant},
        )
    assert getattr(denied.value.orig, "sqlstate", None) == "42501"
    with store.migration.connect() as connection:
        assert (
            connection.execute(
                text("""
            SELECT rolcanlogin,rolsuper,rolbypassrls,rolcreaterole,rolcreatedb,rolinherit,
                rolreplication FROM pg_roles WHERE rolname='arbiter_dispatch_writer'
        """)
            ).one()
            == (False,) * 7
        )
        assert connection.execute(
            text("""
            SELECT pg_get_userbyid(proowner),prosecdef,proconfig FROM pg_proc
            WHERE oid='arbiter.authorize_dispatch(uuid,uuid,uuid)'::regprocedure
        """)
        ).one() == ("arbiter_dispatch_writer", True, ["search_path=pg_catalog"])
        assert (
            connection.execute(
                text("""
            SELECT count(*) FROM pg_auth_members
            WHERE member=(SELECT oid FROM pg_roles WHERE rolname='arbiter_runtime')
        """)
            ).scalar_one()
            == 0
        )
    lease.release_before_dispatch()


def test_concurrent_dispatch_attempts_commit_once(store: ReservationStore) -> None:
    actor, gate = store.actor(), CapacityGate(1)
    lease = acquire(store, actor, gate)
    service = DispatchService(store.runtime)
    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(service.authorize, lease) for _ in range(2)]
        outcomes: list[DispatchAuthorized | str] = []
        for future in futures:
            try:
                outcomes.append(future.result())
            except DispatchConflict:
                outcomes.append("conflict")
    assert outcomes.count("conflict") == 1
    assert sum(isinstance(item, DispatchAuthorized) for item in outcomes) == 1
    assert store.totals(actor) == (1, 0, 10, 0)
    assert evidence(store, actor, lease.result.request_id)[5:] == (1, 1)
    assert gate.occupied == 1


@pytest.mark.parametrize("change", ["revoked", "expired", "suspended", "policy", "model"])
def test_changed_authority_releases_before_dispatch(store: ReservationStore, change: str) -> None:
    actor, gate = store.actor(lifetime=10 if change == "expired" else 86400), CapacityGate(1)
    lease = acquire(store, actor, gate)
    if change == "revoked":
        with tenant_transaction(store.runtime, TenantContext(actor.tenant)) as tx:
            revoke_in_transaction(tx.connection(), actor)
    elif change == "expired":
        # Key expiry is intentionally immutable. Let a short-lived fixture expire.
        sleep(10.1)
    elif change == "suspended":
        ProvisioningService(store.operator).set_tenant_status(actor.tenant, "suspended")
    elif change == "policy":
        PolicyService(store.operator).set_policy(
            actor.tenant, PolicyInput(concurrency=2, aliases=(store.alias,), tenant_rate=59)
        )
    else:
        with store.migration.begin() as connection:
            connection.execute(
                text(
                    "UPDATE arbiter.provider_models SET revision=revision+1,active=false "
                    "WHERE id=:model"
                ),
                {"model": store.model},
            )
    with pytest.raises(DispatchRejected) as rejected:
        DispatchService(store.runtime).authorize(lease)
    assert rejected.value.reason == "authorization_changed"
    assert store.totals(actor) == (0, 0, 0, 0) and gate.occupied == 0
    row = evidence(store, actor, lease.result.request_id)
    assert row[0] == "released" and row[1] is None and row[5:] == (0, 0)
    if change == "model":
        with store.migration.begin() as connection:
            connection.execute(
                text(
                    "UPDATE arbiter.provider_models SET revision=revision+1,active=true "
                    "WHERE id=:model"
                ),
                {"model": store.model},
            )


@pytest.mark.parametrize(
    "table,operation",
    [
        ("quota_windows", "UPDATE"),
        ("budget_windows", "UPDATE"),
        ("requests", "UPDATE"),
        ("reservations", "UPDATE"),
        ("accounting_events", "INSERT"),
        ("audit_events", "INSERT"),
    ],
)
def test_rollback_at_every_mutation(store: ReservationStore, table: str, operation: str) -> None:
    actor, gate = store.actor(), CapacityGate(1)
    lease = acquire(store, actor, gate)
    before = evidence(store, actor, lease.result.request_id)
    with fault(store, actor, table, operation), pytest.raises(DispatchUnavailable):
        DispatchService(store.runtime).authorize(lease)
    assert evidence(store, actor, lease.result.request_id) == before
    assert store.totals(actor) == (0, 1, 0, 10) and gate.occupied == 1
    DispatchService(store.runtime).authorize(lease)
    assert store.totals(actor) == (1, 0, 10, 0) and gate.occupied == 1


def test_cross_tenant_and_stale_lease_do_not_dispatch(store: ReservationStore) -> None:
    actor, other, gate = store.actor(), store.actor(), CapacityGate(2)
    lease = acquire(store, actor, gate)
    other_lease = acquire(store, other, gate)
    with (
        pytest.raises(DBAPIError) as missing,
        tenant_transaction(store.runtime, TenantContext(actor.tenant)) as tx,
    ):
        DispatchRepository(tx).authorize(lease._binding, other_lease.result.request_id)
    assert getattr(missing.value.orig, "sqlstate", None) == "DA001"
    lease.release_before_dispatch()
    with pytest.raises(CapacityOwnershipError):
        DispatchService(store.runtime).authorize(lease)
    assert gate.occupied == 1 and store.totals(actor) == (0, 0, 0, 0)
    other_lease.release_before_dispatch()


def test_rejected_capacity_request_cannot_dispatch(store: ReservationStore) -> None:
    actor, other, gate = store.actor(), store.actor(), CapacityGate(1)
    first = acquire(store, actor, gate)
    with pytest.raises(CapacityUnavailable):
        acquire(store, other, gate)
    # Only a held lease can authorize. The rejected request has no owner claim.
    assert store.totals(other) == (0, 0, 0, 0)
    with tenant_transaction(store.runtime, TenantContext(other.tenant)) as transaction:
        rejected_id: UUID = (
            transaction.connection()
            .execute(
                text("""
            SELECT id FROM arbiter.requests WHERE tenant_id=:tenant
                AND key_id=:key AND state='rejected_capacity'
            ORDER BY created_at DESC LIMIT 1
        """),
                {"tenant": other.tenant, "key": other.key},
            )
            .scalar_one()
        )
    with (
        pytest.raises(DBAPIError) as denied,
        tenant_transaction(store.runtime, TenantContext(other.tenant)) as transaction,
    ):
        DispatchRepository(transaction).authorize(
            KeyBinding(other.key, other.tenant, ("inference:write",)), rejected_id
        )
    assert getattr(denied.value.orig, "sqlstate", None) == "DA002"
    first.release_before_dispatch()


def test_pool_reuse_never_carries_dispatch_tenant_context(store: ReservationStore) -> None:
    first, second, gate = store.actor(), store.actor(), CapacityGate(2)
    leases = [acquire(store, actor, gate) for actor in (first, second)]
    engine = create_engine(
        DatabaseSettings().url("runtime"),
        hide_parameters=True,
        pool_size=1,
        max_overflow=0,
        pool_reset_on_return="rollback",
    )
    try:
        pids: list[int] = []
        for lease in leases:
            DispatchService(engine).authorize(lease)
            with engine.begin() as connection:
                pids.append(connection.execute(text("SELECT pg_backend_pid()")).scalar_one())
                assert (
                    connection.execute(
                        text("SELECT NULLIF(current_setting('arbiter.tenant_id',true),'')")
                    ).scalar_one()
                    is None
                )
                assert connection.execute(text("SELECT id FROM arbiter.requests")).all() == []
        assert pids[0] == pids[1]
        assert store.totals(first) == store.totals(second) == (1, 0, 10, 0)
        assert gate.occupied == 2
    finally:
        engine.dispose()


@pytest.mark.parametrize("period", ["day", "month"])
def test_utc_window_change_releases_original_allocation(
    store: ReservationStore, period: str
) -> None:
    actor, gate = store.actor(), CapacityGate(1)
    source = acquire(store, actor, gate)
    source.release_before_dispatch()
    historical, reservation, accounting, quota, budget = (uuid4() for _ in range(5))
    values: dict[str, object] = {
        "tenant": actor.tenant,
        "source": source.result.request_id,
        "request": historical,
        "reservation": reservation,
        "event": accounting,
        "quota": quota,
        "budget": budget,
        "period": period,
        "idem": uuid4().hex,
    }
    with store.migration.begin() as connection:
        set_context(connection, actor.tenant)
        day: datetime = connection.execute(
            text("""
            SELECT date_trunc('day',clock_timestamp() AT TIME ZONE 'UTC') AT TIME ZONE 'UTC'
                - CASE WHEN :period='day' THEN interval '1 day' ELSE interval '32 days' END
        """),
            values,
        ).scalar_one()
        values["day"] = day
        month: datetime = connection.execute(
            text("""
            SELECT date_trunc('month',CAST(:day AS timestamptz) AT TIME ZONE 'UTC')
                AT TIME ZONE 'UTC'
        """),
            values,
        ).scalar_one()
        values["month"] = month
        connection.execute(
            text("""
            INSERT INTO arbiter.quota_windows(id,tenant_id,window_start,reserved)
            VALUES (:quota,:tenant,:day,1)
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
        values["budget"] = connection.execute(
            text("""
            SELECT id FROM arbiter.budget_windows
            WHERE tenant_id=:tenant AND window_start=:month
        """),
            values,
        ).scalar_one()
        connection.execute(
            text("""
            UPDATE arbiter.budget_windows SET reserved=reserved+10
            WHERE tenant_id=:tenant AND id=:budget
        """),
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
                :reservation,:event,CAST(:day AS timestamptz)+interval '12 hours'
            FROM arbiter.requests WHERE tenant_id=:tenant AND id=:source
        """),
            values,
        )
        connection.execute(
            text("""
            INSERT INTO arbiter.reservations
                (id,tenant_id,request_id,quota_window_id,budget_window_id,request_count,credits)
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
    claim = gate.try_acquire(source._binding, historical)
    assert claim is not None
    lease = CapacityLease(
        replace(source.result, request_id=historical),
        source._binding,
        claim,
        gate,
        ReleaseService(store.runtime),
    )
    with pytest.raises(DispatchRejected) as rejected:
        DispatchService(store.runtime).authorize(lease)
    assert rejected.value.reason == "admission_window_changed"
    assert gate.occupied == 0
    assert evidence(store, actor, historical)[0] == "released"
    with tenant_transaction(store.runtime, TenantContext(actor.tenant)) as tx:
        totals = (
            tx.connection()
            .execute(
                text("""
            SELECT q.committed,q.reserved,b.committed,b.reserved
            FROM arbiter.requests r JOIN arbiter.quota_windows q
                ON q.tenant_id=r.tenant_id AND q.id=r.quota_window_id
            JOIN arbiter.budget_windows b
                ON b.tenant_id=r.tenant_id AND b.id=r.budget_window_id
            WHERE r.tenant_id=:tenant AND r.id=:request
        """),
                {"tenant": actor.tenant, "request": historical},
            )
            .one()
        )
    assert tuple(totals) == (0, 0, 0, 0)


@contextmanager
def held_authority_change(store: ReservationStore, actor: Actor, change: str) -> Iterator[None]:
    if change == "revoked":
        with tenant_transaction(store.runtime, TenantContext(actor.tenant)) as tx:
            revoke_in_transaction(tx.connection(), actor)
            yield
    else:
        with operator_transaction(store.operator, actor.tenant) as tx:
            repository = OperatorRepository(tx)
            tenant = repository.lock_tenant()
            repository.set_status("suspended")
            repository.append_audit(
                action="tenant_suspended",
                target_id=actor.tenant,
                revision=tenant.policy_revision,
                correlation=uuid4(),
            )
            yield


@pytest.mark.parametrize("change", ["revoked", "suspended"])
def test_authority_commit_wins_real_dispatch_lock_race(
    store: ReservationStore, change: str
) -> None:
    actor, gate = store.actor(), CapacityGate(1)
    lease = acquire(store, actor, gate)
    waiting = Event()
    pids: list[int] = []

    def observe(
        connection: Connection,
        cursor: Any,
        statement: str,
        parameters: Any,
        context: Any,
        executemany: bool,
    ) -> None:
        if "arbiter.authorize_dispatch" in statement:
            driver: Any = connection.connection.driver_connection
            assert driver is not None
            pids.append(driver.info.backend_pid)
            waiting.set()

    contender = create_engine(
        DatabaseSettings().url("runtime"),
        hide_parameters=True,
        poolclass=NullPool,
        connect_args={"connect_timeout": 5, "options": "-c statement_timeout=5000"},
    )
    event.listen(contender, "before_cursor_execute", observe)
    try:
        with ThreadPoolExecutor(max_workers=1) as pool:
            with held_authority_change(store, actor, change):
                future = pool.submit(DispatchService(contender).authorize, lease)
                assert waiting.wait(5)
                deadline = monotonic() + 5
                while monotonic() < deadline:
                    with store.migration.connect() as probe:
                        blocked: bool = probe.execute(
                            text("SELECT cardinality(pg_blocking_pids(:pid))>0"),
                            {"pid": pids[-1]},
                        ).scalar_one()
                    if blocked:
                        break
                    sleep(0.02)
                else:
                    pytest.fail("dispatch did not wait on tenant admission lock")
                assert not future.done()
            with pytest.raises(DispatchRejected) as rejected:
                future.result(timeout=10)
        assert rejected.value.reason == "authorization_changed"
        assert store.totals(actor) == (0, 0, 0, 0)
        assert evidence(store, actor, lease.result.request_id)[0] == "released"
        assert gate.occupied == 0
    finally:
        event.remove(contender, "before_cursor_execute", observe)
        contender.dispose()


@pytest.mark.parametrize("change", ["revoked", "suspended"])
def test_dispatch_commit_wins_real_authority_lock_race(
    store: ReservationStore, change: str
) -> None:
    actor, gate = store.actor(), CapacityGate(1)
    lease = acquire(store, actor, gate)
    role: DatabaseRole = "runtime" if change == "revoked" else "operator"
    contender = create_engine(
        DatabaseSettings().url(role),
        hide_parameters=True,
        poolclass=NullPool,
        connect_args={"connect_timeout": 5, "options": "-c statement_timeout=5000"},
    )
    waiting = Event()
    pids: list[int] = []

    def observe(
        connection: Connection,
        cursor: Any,
        statement: str,
        parameters: Any,
        context: Any,
        executemany: bool,
    ) -> None:
        if "arbiter.revoke_api_key" in statement or "FROM arbiter.tenants" in statement:
            driver: Any = connection.connection.driver_connection
            assert driver is not None
            pids.append(driver.info.backend_pid)
            waiting.set()

    def mutate_authority() -> None:
        if change == "revoked":
            with tenant_transaction(contender, TenantContext(actor.tenant)) as transaction:
                revoke_in_transaction(transaction.connection(), actor)
        else:
            with operator_transaction(contender, actor.tenant) as transaction:
                repository = OperatorRepository(transaction)
                tenant = repository.lock_tenant()
                repository.set_status("suspended")
                repository.append_audit(
                    action="tenant_suspended",
                    target_id=actor.tenant,
                    revision=tenant.policy_revision,
                    correlation=uuid4(),
                )

    event.listen(contender, "before_cursor_execute", observe)
    try:
        with ThreadPoolExecutor(max_workers=1) as pool:
            with tenant_transaction(store.runtime, TenantContext(actor.tenant)) as transaction:
                result = DispatchRepository(transaction).authorize(
                    lease._binding, lease.result.request_id
                )
                assert result.decision == "authorized"
                future = pool.submit(mutate_authority)
                assert waiting.wait(5)
                deadline = monotonic() + 5
                while monotonic() < deadline:
                    with store.migration.connect() as probe:
                        blocked: bool = probe.execute(
                            text("SELECT cardinality(pg_blocking_pids(:pid))>0"),
                            {"pid": pids[-1]},
                        ).scalar_one()
                    if blocked:
                        break
                    sleep(0.02)
                else:
                    pytest.fail("authority mutation did not wait on dispatch tenant lock")
                assert not future.done()
            future.result(timeout=10)
        assert evidence(store, actor, lease.result.request_id)[0] == "dispatched"
        assert store.totals(actor) == (1, 0, 10, 0) and gate.occupied == 1
        with pytest.raises(ReleaseConflict):
            lease.release_before_dispatch()
    finally:
        event.remove(contender, "before_cursor_execute", observe)
        contender.dispose()
