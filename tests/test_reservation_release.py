"""Real PostgreSQL reserved-only settlement, fault injection and late-handler races.

Dispatch fixtures below are owner-only, deterministic predicate probes. They do
not implement application dispatch, invoke providers or establish pipeline readiness.
Accepted accounting/audit fixtures are retained in the isolated test database.
"""

import os
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from datetime import datetime
from threading import Event
from time import monotonic, sleep
from typing import Any
from uuid import UUID, uuid4

import pytest
from psycopg import sql
from sqlalchemy import create_engine, event, text
from sqlalchemy.engine import Connection, Engine
from sqlalchemy.exc import DBAPIError
from test_reservation_transactions import (
    Actor,
    ReservationStore,
    reserve,
    revoke_in_transaction,
)
from test_reservation_transactions import store as store
from test_tenant_isolation import postgres_error, set_context

from arbiter.config import DatabaseSettings
from arbiter.governance.release import (
    InvalidRelease,
    ReleaseConflict,
    ReleaseNotFound,
    ReleaseService,
    ReleaseUnavailable,
)
from arbiter.governance.reservation import IdempotencyConflict, RequestAlreadyAdmitted
from arbiter.identity.context import TenantContext
from arbiter.identity.keys import InvalidKey
from arbiter.operations.policy import PolicyInput, PolicyService
from arbiter.operations.provision import ProvisioningService
from arbiter.persistence.release import ReleaseReason, ReleaseRepository, ReleaseResult
from arbiter.persistence.tenant import tenant_transaction
from arbiter.persistence.workload import KeyBinding, resolve_key

pytestmark = pytest.mark.skipif(
    os.environ.get("ARBITER_TEST_DATABASE") != "1", reason="requires real PostgreSQL"
)
FUNCTION = "arbiter.release_request(uuid,uuid,uuid,text)"
RAW = text("SELECT * FROM arbiter.release_request(:tenant,:key,:request,:reason)")


def binding(actor: Actor) -> KeyBinding:
    # Test-only retained in-flight binding. Production callers retain resolve_key's result.
    return KeyBinding(actor.key, actor.tenant, ("inference:write", "usage:read"))


def release(
    store: ReservationStore,
    actor: Actor,
    request: UUID,
    reason: ReleaseReason = "cancelled",
    engine: Engine | None = None,
) -> ReleaseResult:
    return ReleaseService(store.runtime if engine is None else engine).release(
        binding(actor),
        request,
        reason,
    )


def evidence(store: ReservationStore, actor: Actor, request: UUID) -> tuple[Any, ...]:
    with tenant_transaction(store.runtime, TenantContext(actor.tenant)) as tx:
        return tuple(
            tx.connection()
            .execute(
                text("""
            SELECT r.state,r.outcome,r.dispatched_at,r.finished_at,r.release_audit_id,
                s.disposition,s.settlement_event_id,
                (SELECT count(*) FROM arbiter.accounting_events e WHERE e.tenant_id=r.tenant_id
                    AND e.request_id=r.id AND e.kind='release'),
                (SELECT count(*) FROM arbiter.audit_events a WHERE a.tenant_id=r.tenant_id
                    AND a.request_id=r.id AND a.action='request_released')
            FROM arbiter.requests r JOIN arbiter.reservations s
                ON s.tenant_id=r.tenant_id AND s.id=r.reservation_id AND s.tenant_id=:tenant
            WHERE r.tenant_id=:tenant AND r.id=:request
        """),
                {"tenant": actor.tenant, "request": request},
            )
            .one()
        )


@pytest.mark.parametrize(
    "reason,state",
    [
        ("cancelled", "released"),
        ("provider_unavailable", "released"),
        ("rejected_capacity", "rejected_capacity"),
    ],
)
def test_release_exactly_once_and_idempotency_retained(
    store: ReservationStore,
    reason: ReleaseReason,
    state: str,
) -> None:
    actor = store.actor()
    idem = uuid4().hex
    request = reserve(store, actor, idem=idem).request_id
    assert release(store, actor, request, reason) == ReleaseResult(request, state, reason, True)
    first = evidence(store, actor, request)
    assert first[0:3] == (state, reason, None)
    assert first[3] is not None and first[4] is not None
    assert first[5] == "released" and first[6] is not None and first[7:] == (1, 1)
    assert store.totals(actor) == (0, 0, 0, 0)
    # A different subsequent cleanup reason must not overwrite the first reason/time/evidence.
    assert release(store, actor, request, "rejected_capacity") == ReleaseResult(
        request,
        state,
        reason,
        False,
    )
    assert evidence(store, actor, request) == first
    with pytest.raises(RequestAlreadyAdmitted) as prior:
        reserve(store, actor, idem=idem)
    assert prior.value.request_id == request and prior.value.state == state
    with pytest.raises(IdempotencyConflict):
        store.service().reserve(
            actor.credential, idem, store.request("different synthetic payload")
        )
    reserve(store, actor)
    assert store.totals(actor) == (0, 1, 0, 10)


def test_concurrent_duplicates_have_one_release(store: ReservationStore) -> None:
    actor = store.actor()
    request = reserve(store, actor).request_id
    with ThreadPoolExecutor(max_workers=12) as pool:
        results = list(pool.map(lambda _: release(store, actor, request), range(48)))
    assert sum(result.changed for result in results) == 1
    assert {result.state for result in results} == {"released"}
    assert store.totals(actor) == (0, 0, 0, 0)
    assert evidence(store, actor, request)[7:] == (1, 1)


def test_restores_only_its_reservation_and_never_committed(store: ReservationStore) -> None:
    actor = store.actor()
    first, second = reserve(store, actor), reserve(store, actor)
    with store.migration.begin() as connection:
        set_context(connection, actor.tenant)
        # Explicit historical counter fixture, not fabricated API usage or dispatch.
        connection.execute(
            text("UPDATE arbiter.quota_windows SET committed=7 WHERE tenant_id=:t"),
            {"t": actor.tenant},
        )
        connection.execute(
            text("UPDATE arbiter.budget_windows SET committed=70 WHERE tenant_id=:t"),
            {"t": actor.tenant},
        )
    release(store, actor, first.request_id)
    assert store.totals(actor) == (7, 1, 70, 10)
    release(store, actor, first.request_id)
    assert store.totals(actor) == (7, 1, 70, 10)
    release(store, actor, second.request_id)
    assert store.totals(actor) == (7, 0, 70, 0)


@contextmanager
def fault(
    store: ReservationStore,
    actor: Actor,
    table: str,
    operation: str,
    *,
    deferred: bool = False,
) -> Iterator[None]:
    name = "release_fault_" + uuid4().hex
    identifier = sql.Identifier("arbiter", name)
    with store.migration.begin() as connection:
        connection.execute(
            text(
                sql.SQL("""
            CREATE FUNCTION {}() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $$
            BEGIN IF NEW.tenant_id={}::uuid THEN
                RAISE EXCEPTION 'synthetic release failure' USING ERRCODE='23514';
            END IF; RETURN NEW; END $$
        """)
                .format(identifier, sql.Literal(str(actor.tenant)))
                .as_string()
            )
        )
        connection.execute(
            text(sql.SQL("REVOKE ALL ON FUNCTION {}() FROM PUBLIC").format(identifier).as_string())
        )
        template = (
            "CREATE CONSTRAINT TRIGGER {} AFTER {} ON {} DEFERRABLE INITIALLY DEFERRED "
            "FOR EACH ROW EXECUTE FUNCTION {}()"
            if deferred
            else "CREATE TRIGGER {} AFTER {} ON {} FOR EACH ROW EXECUTE FUNCTION {}()"
        )
        connection.execute(
            text(
                sql.SQL(template)
                .format(
                    sql.Identifier(name),
                    sql.SQL(operation),
                    sql.Identifier("arbiter", table),
                    identifier,
                )
                .as_string()
            )
        )
    try:
        yield
    finally:
        with store.migration.begin() as connection:
            connection.execute(
                text(
                    sql.SQL("DROP TRIGGER {} ON {}")
                    .format(sql.Identifier(name), sql.Identifier("arbiter", table))
                    .as_string()
                )
            )
            connection.execute(
                text(sql.SQL("DROP FUNCTION {}() RESTRICT").format(identifier).as_string())
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
def test_rollback_after_every_release_mutation(
    store: ReservationStore,
    table: str,
    operation: str,
) -> None:
    actor = store.actor()
    request = reserve(store, actor).request_id
    before = evidence(store, actor, request)
    with fault(store, actor, table, operation), pytest.raises(ReleaseUnavailable) as failure:
        release(store, actor, request)
    assert str(failure.value) == "release unavailable"
    assert evidence(store, actor, request) == before
    assert store.totals(actor) == (0, 1, 0, 10)
    release(store, actor, request)
    assert evidence(store, actor, request)[7:] == (1, 1)


def test_commit_failure_cannot_return_success(store: ReservationStore) -> None:
    actor = store.actor()
    request = reserve(store, actor).request_id
    before = evidence(store, actor, request)
    with (
        fault(store, actor, "audit_events", "INSERT", deferred=True),
        pytest.raises(ReleaseUnavailable),
    ):
        release(store, actor, request)
    assert evidence(store, actor, request) == before
    assert store.totals(actor) == (0, 1, 0, 10)


@pytest.mark.parametrize("table", ["quota_windows", "budget_windows"])
def test_inconsistent_reserved_totals_fail_closed(store: ReservationStore, table: str) -> None:
    actor = store.actor()
    request = reserve(store, actor).request_id
    with store.migration.begin() as connection:
        set_context(connection, actor.tenant)
        connection.execute(
            text(
                sql.SQL("UPDATE {} SET reserved=0 WHERE tenant_id=:t")
                .format(sql.Identifier("arbiter", table))
                .as_string()
            ),
            {"t": actor.tenant},
        )
    before = evidence(store, actor, request)
    with pytest.raises(ReleaseUnavailable):
        release(store, actor, request)
    assert evidence(store, actor, request) == before


def test_retained_verified_binding_can_cleanup_after_revocation(store: ReservationStore) -> None:
    actor = store.actor()
    with store.runtime.begin() as connection:
        captured = resolve_key(connection, actor.candidate)
    request = reserve(store, actor).request_id
    with tenant_transaction(store.runtime, TenantContext(actor.tenant)) as tx:
        revoke_in_transaction(tx.connection(), actor)
    with pytest.raises(InvalidKey), store.runtime.begin() as connection:
        resolve_key(connection, actor.candidate)
    assert ReleaseService(store.runtime).release(captured, request, "authorization_changed").changed


@pytest.mark.parametrize(
    "misuse", ["foreign_request", "unknown_request", "foreign_key", "sibling_key"]
)
def test_inaccessible_references_indistinguishable(store: ReservationStore, misuse: str) -> None:
    actor, other = store.actor(), store.actor()
    request, foreign = reserve(store, actor).request_id, reserve(store, other).request_id
    selected = binding(actor)
    if misuse == "foreign_request":
        request = foreign
    elif misuse == "unknown_request":
        request = uuid4()
    elif misuse == "foreign_key":
        selected = KeyBinding(other.key, actor.tenant, ("inference:write",))
    else:
        selected = binding(store.actor(existing=actor))
    with pytest.raises(ReleaseNotFound) as failure:
        ReleaseService(store.runtime).release(selected, request, "cancelled")
    assert str(failure.value) == "request unavailable"
    assert store.totals(actor) == store.totals(other) == (0, 1, 0, 10)


@pytest.mark.parametrize("context", ["missing", "foreign"])
def test_raw_function_requires_matching_context(store: ReservationStore, context: str) -> None:
    actor, other = store.actor(), store.actor()
    request = reserve(store, actor).request_id
    with pytest.raises(DBAPIError) as failure, store.runtime.begin() as connection:
        if context == "foreign":
            set_context(connection, other.tenant)
        connection.execute(
            RAW,
            {"tenant": actor.tenant, "key": actor.key, "request": request, "reason": "cancelled"},
        )
    assert postgres_error(failure.value).sqlstate == "42501"
    assert store.totals(actor) == (0, 1, 0, 10)


@pytest.mark.parametrize(
    "change", ["revoked", "expired", "suspended", "policy", "model", "inactive"]
)
def test_changed_authority_releases_without_fresh_authentication(
    store: ReservationStore,
    change: str,
) -> None:
    actor = store.actor(lifetime=3 if change == "expired" else 86400)
    request = reserve(store, actor).request_id
    if change == "revoked":
        with tenant_transaction(store.runtime, TenantContext(actor.tenant)) as tx:
            revoke_in_transaction(tx.connection(), actor)
    elif change == "suspended":
        ProvisioningService(store.operator).set_tenant_status(actor.tenant, "suspended")
    elif change == "policy":
        PolicyService(store.operator).set_policy(actor.tenant, PolicyInput(aliases=(store.alias,)))
    elif change == "expired":
        deadline = monotonic() + 6
        while monotonic() < deadline:
            with store.migration.begin() as connection:
                set_context(connection, actor.tenant)
                expired: bool = connection.execute(
                    text("""
                    SELECT expires_at<=clock_timestamp() FROM arbiter.api_keys
                    WHERE tenant_id=:t AND id=:k
                """),
                    {"t": actor.tenant, "k": actor.key},
                ).scalar_one()
            if expired:
                break
            sleep(0.02)
        else:
            pytest.fail("key did not expire in database time")
    else:
        with store.migration.begin() as connection:
            # Owner-only model fixture; registry mutations via production CLI are separately gated.
            connection.execute(
                text("""
                UPDATE arbiter.provider_models SET revision=revision+1,active=:active WHERE id=:id
            """),
                {"id": store.model, "active": change != "inactive"},
            )
    try:
        result = release(store, actor, request, "authorization_changed")
        assert result.state == "released" and result.outcome == "authorization_changed"
        assert store.totals(actor) == (0, 0, 0, 0)
    finally:
        if change == "inactive":
            with store.migration.begin() as connection:
                connection.execute(
                    text("UPDATE arbiter.provider_models SET active=true WHERE id=:id"),
                    {"id": store.model},
                )


@pytest.mark.parametrize(
    "reason", ["authorization_changed", "admission_window_changed", "reservation_expired"]
)
def test_stale_reason_requires_real_locked_condition(
    store: ReservationStore, reason: ReleaseReason
) -> None:
    actor = store.actor()
    request = reserve(store, actor).request_id
    with pytest.raises(ReleaseConflict):
        release(store, actor, request, reason)
    assert store.totals(actor) == (0, 1, 0, 10)


@pytest.mark.parametrize(
    "period,reason",
    [
        ("day", "admission_window_changed"),
        ("month", "admission_window_changed"),
        ("month", "reservation_expired"),
    ],
)
def test_historical_window_release_uses_snapshot_not_current_windows(
    store: ReservationStore,
    period: str,
    reason: ReleaseReason,
) -> None:
    actor = store.actor()
    current = reserve(store, actor).request_id
    historical, reservation, accounting = uuid4(), uuid4(), uuid4()
    with store.migration.begin() as connection:
        set_context(connection, actor.tenant)
        values: dict[str, Any] = {
            "t": actor.tenant,
            "source": current,
            "id": historical,
            "s": reservation,
            "e": accounting,
            "q": uuid4(),
            "b": uuid4(),
            "period": period,
            "idem": uuid4().hex,
        }
        # Deterministic owner-only historical fixture. No production usage is fabricated.
        current_budget: UUID = connection.execute(
            text("""
            SELECT budget_window_id FROM arbiter.requests WHERE tenant_id=:t AND id=:source
        """),
            values,
        ).scalar_one()
        day: datetime = connection.execute(
            text("""
            SELECT date_trunc('day',clock_timestamp() AT TIME ZONE 'UTC') AT TIME ZONE 'UTC'
                - CASE WHEN :period='day' THEN interval '1 day' ELSE interval '32 days' END
        """),
            values,
        ).scalar_one()
        values["day"] = day
        connection.execute(
            text("""
            INSERT INTO arbiter.quota_windows(id,tenant_id,window_start,reserved)
            VALUES (:q,:t,:day,1)
        """),
            values,
        )
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
            INSERT INTO arbiter.budget_windows(id,tenant_id,window_start)
            VALUES (:b,:t,:month) ON CONFLICT (tenant_id,window_start) DO NOTHING
        """),
            values,
        )
        values["b"] = connection.execute(
            text("""
            SELECT id FROM arbiter.budget_windows WHERE tenant_id=:t AND window_start=:month
        """),
            values,
        ).scalar_one()
        connection.execute(
            text("""
            UPDATE arbiter.budget_windows SET reserved=reserved+10 WHERE tenant_id=:t AND id=:b
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
            SELECT :id,tenant_id,key_id,:idem,payload_hmac,fingerprint_version,
                policy_revision,model_id,model_revision,model_alias,model_adapter,model_digest,
                context_cap,output_cap,credit_charge,:q,:b,:day,:month,:s,:e,
                CAST(:day AS timestamptz)+interval '12 hours'
            FROM arbiter.requests WHERE tenant_id=:t AND id=:source
        """),
            values,
        )
        connection.execute(
            text("""
            INSERT INTO arbiter.reservations
                (id,tenant_id,request_id,quota_window_id,budget_window_id,request_count,credits)
            VALUES (:s,:t,:id,:q,:b,1,10)
        """),
            values,
        )
        connection.execute(
            text("""
            INSERT INTO arbiter.accounting_events
                (id,tenant_id,request_id,reservation_id,quota_window_id,budget_window_id,
                 request_count,credits,kind)
            VALUES (:e,:t,:id,:s,:q,:b,1,10,'reserve')
        """),
            values,
        )
    assert release(store, actor, historical, reason).outcome == reason
    with tenant_transaction(store.runtime, TenantContext(actor.tenant)) as tx:
        rows = (
            tx.connection()
            .execute(
                text("""
            SELECT r.id,q.committed,q.reserved,b.committed,b.reserved
            FROM arbiter.requests r JOIN arbiter.quota_windows q
                ON q.tenant_id=r.tenant_id AND q.id=r.quota_window_id
            JOIN arbiter.budget_windows b ON b.tenant_id=r.tenant_id AND b.id=r.budget_window_id
            WHERE r.tenant_id=:t ORDER BY r.id
        """),
                {"t": actor.tenant},
            )
            .all()
        )
        counters = {row[0]: tuple(row[1:]) for row in rows}
        assert counters[current] == (0, 1, 0, 10)
        assert counters[historical] == (0, 0, 0, 10 if values["b"] == current_budget else 0)
    assert evidence(store, actor, historical)[7:] == (1, 1)


def mark_dispatched_fixture(connection: Connection, actor: Actor, request: UUID) -> None:
    """Test-only conditional authorization marker under tenant/window locks; no provider."""
    set_context(connection, actor.tenant)
    values = {"t": actor.tenant, "k": actor.key, "id": request, "event": uuid4()}
    connection.execute(
        text("SELECT id FROM arbiter.tenants WHERE tenant_id=:t AND id=:t FOR UPDATE"), values
    )
    connection.execute(
        text("SELECT id FROM arbiter.api_keys WHERE tenant_id=:t AND id=:k FOR UPDATE"), values
    )
    connection.execute(
        text(
            "SELECT id FROM arbiter.tenant_policies WHERE tenant_id=:t "
            "ORDER BY revision DESC LIMIT 1 FOR SHARE"
        ),
        values,
    )
    connection.execute(
        text("""
            SELECT q.id FROM arbiter.quota_windows q JOIN arbiter.requests r
            ON r.tenant_id=q.tenant_id AND r.quota_window_id=q.id
            WHERE r.tenant_id=:t AND r.id=:id FOR UPDATE OF q
        """),
        values,
    )
    connection.execute(
        text("""
            SELECT b.id FROM arbiter.budget_windows b JOIN arbiter.requests r
            ON r.tenant_id=b.tenant_id AND r.budget_window_id=b.id
            WHERE r.tenant_id=:t AND r.id=:id FOR UPDATE OF b
        """),
        values,
    )
    row = connection.execute(
        text("""
        UPDATE arbiter.requests SET state='dispatched',dispatched_at=clock_timestamp()
        WHERE tenant_id=:t AND id=:id AND state='reserved' AND dispatched_at IS NULL RETURNING id
    """),
        values,
    ).one_or_none()
    if row is None:
        raise ReleaseConflict()
    connection.execute(
        text("""
        UPDATE arbiter.reservations SET disposition='committed',settlement_event_id=:event
        WHERE tenant_id=:t AND request_id=:id AND disposition='reserved'
    """),
        values,
    )
    connection.execute(
        text("""
        INSERT INTO arbiter.accounting_events
        (id,tenant_id,request_id,reservation_id,quota_window_id,budget_window_id,
            request_count,credits,kind)
        SELECT :event,tenant_id,id,reservation_id,quota_window_id,budget_window_id,
            1,credit_charge,'commit'
        FROM arbiter.requests WHERE tenant_id=:t AND id=:id
    """),
        values,
    )
    connection.execute(
        text(
            "UPDATE arbiter.quota_windows SET committed=committed+1,reserved=reserved-1 "
            "WHERE tenant_id=:t"
        ),
        values,
    )
    connection.execute(
        text(
            "UPDATE arbiter.budget_windows SET committed=committed+10,reserved=reserved-10 "
            "WHERE tenant_id=:t"
        ),
        values,
    )


def test_dispatched_requests_never_refunded(store: ReservationStore) -> None:
    actor = store.actor()
    request = reserve(store, actor).request_id
    with store.migration.begin() as connection:
        mark_dispatched_fixture(connection, actor, request)
    before = evidence(store, actor, request)
    with pytest.raises(ReleaseConflict):
        release(store, actor, request)
    assert evidence(store, actor, request) == before
    assert store.totals(actor) == (1, 0, 10, 0)


def test_released_state_cannot_be_resurrected_even_by_owner_dml(store: ReservationStore) -> None:
    actor = store.actor()
    request = reserve(store, actor).request_id
    release(store, actor, request)
    for statement in (
        "UPDATE arbiter.requests SET state='reserved',finished_at=NULL,outcome=NULL,"
        "release_audit_id=NULL WHERE tenant_id=:t AND id=:id",
        "UPDATE arbiter.requests SET state='dispatched',dispatched_at=clock_timestamp(),"
        "finished_at=NULL,outcome=NULL,release_audit_id=NULL WHERE tenant_id=:t AND id=:id",
        "UPDATE arbiter.reservations SET disposition='reserved',settlement_event_id=NULL "
        "WHERE tenant_id=:t AND request_id=:id",
    ):
        with pytest.raises(DBAPIError) as failure, store.migration.begin() as connection:
            set_context(connection, actor.tenant)
            connection.execute(text(statement), {"t": actor.tenant, "id": request})
        assert postgres_error(failure.value).sqlstate == "23514"
    assert store.totals(actor) == (0, 0, 0, 0)


@pytest.mark.parametrize("winner", ["release", "marker"])
def test_release_vs_late_marker_lock_race(store: ReservationStore, winner: str) -> None:
    actor = store.actor()
    request = reserve(store, actor).request_id
    waiting = Event()
    pids: list[int] = []
    loser_engine = store.migration if winner == "release" else store.runtime

    def observe(
        connection: Connection,
        cursor: Any,
        statement: str,
        parameters: Any,
        context: Any,
        executemany: bool,
    ) -> None:
        needle = "arbiter.tenants" if winner == "release" else "arbiter.release_request"
        if needle in statement:
            driver: Any = connection.connection.driver_connection
            assert driver is not None
            pids.append(driver.info.backend_pid)
            waiting.set()

    def loser() -> None:
        if winner == "release":
            with loser_engine.begin() as connection:
                mark_dispatched_fixture(connection, actor, request)
        else:
            release(store, actor, request)

    event.listen(loser_engine, "before_cursor_execute", observe)
    try:
        with ThreadPoolExecutor(max_workers=1) as pool:
            with (store.runtime if winner == "release" else store.migration).begin() as held:
                if winner == "release":
                    set_context(held, actor.tenant)
                    held.execute(
                        RAW,
                        {
                            "tenant": actor.tenant,
                            "key": actor.key,
                            "request": request,
                            "reason": "cancelled",
                        },
                    )
                else:
                    mark_dispatched_fixture(held, actor, request)
                future = pool.submit(loser)
                assert waiting.wait(5)
                deadline = monotonic() + 5
                while monotonic() < deadline:
                    with store.operator.connect() as probe:
                        blocked: bool = probe.execute(
                            text("SELECT cardinality(pg_blocking_pids(:pid))>0"), {"pid": pids[-1]}
                        ).scalar_one()
                    if blocked:
                        break
                    sleep(0.02)
                else:
                    pytest.fail("losing handler did not wait on the actual admission lock")
                assert not future.done()
            with pytest.raises(ReleaseConflict):
                future.result(timeout=10)
        assert store.totals(actor) == ((0, 0, 0, 0) if winner == "release" else (1, 0, 10, 0))
        assert evidence(store, actor, request)[7:] == ((1, 1) if winner == "release" else (0, 0))
    finally:
        event.remove(loser_engine, "before_cursor_execute", observe)


def test_runtime_privileges_and_exact_function_boundary(store: ReservationStore) -> None:
    actor = store.actor()
    for statement in (
        "SET ROLE arbiter_release_writer",
        "SET ROLE arbiter_migration",
        "UPDATE arbiter.requests SET state='released'",
        "UPDATE arbiter.reservations SET disposition='released'",
        "UPDATE arbiter.quota_windows SET reserved=0",
        "UPDATE arbiter.budget_windows SET committed=0",
        "UPDATE arbiter.accounting_events SET kind='release'",
        "DELETE FROM arbiter.audit_events",
    ):
        with pytest.raises(DBAPIError) as failure, store.runtime.begin() as connection:
            set_context(connection, actor.tenant)
            connection.execute(text(statement))
        assert postgres_error(failure.value).sqlstate == "42501"
    with store.runtime.connect() as connection:
        row = connection.execute(
            text("""
            SELECT r.rolcanlogin,r.rolsuper,r.rolbypassrls,r.rolinherit,
                p.prosecdef,p.proconfig,
                has_schema_privilege(r.oid,'arbiter','CREATE'),
                has_column_privilege(r.oid,'arbiter.quota_windows','committed','UPDATE'),
                has_column_privilege(r.oid,'arbiter.requests','dispatched_at','UPDATE')
            FROM pg_proc p JOIN pg_roles r ON r.oid=p.proowner WHERE p.oid=CAST(:fn AS regprocedure)
        """),
            {"fn": FUNCTION},
        ).one()
        assert tuple(row[:5]) == (False, False, False, False, True)
        assert row[5] == ["search_path=pg_catalog"] and tuple(row[6:]) == (False, False, False)
        acl = connection.execute(
            text("""
            SELECT pg_get_userbyid(a.grantee),a.privilege_type FROM pg_proc p,
                LATERAL aclexplode(p.proacl) a WHERE p.oid=CAST(:fn AS regprocedure)
        """),
            {"fn": FUNCTION},
        ).all()
        assert set(acl) == {("arbiter_runtime", "EXECUTE"), ("arbiter_release_writer", "EXECUTE")}
    with store.operator.connect() as connection:
        assert (
            connection.execute(
                text("SELECT has_function_privilege(current_user,:fn,'EXECUTE')"), {"fn": FUNCTION}
            ).scalar_one()
            is False
        )


def test_pool_context_is_reset_and_repository_rejects_foreign_scope(
    store: ReservationStore,
) -> None:
    actors = [store.actor(), store.actor()]
    requests = [reserve(store, actor).request_id for actor in actors]
    engine = create_engine(
        DatabaseSettings().url("runtime"),
        hide_parameters=True,
        pool_size=1,
        max_overflow=0,
        pool_reset_on_return="rollback",
    )
    try:
        pids: list[int] = []
        for index in (0, 1, 0):
            release(store, actors[index], requests[index], engine=engine)
            with engine.begin() as connection:
                pids.append(connection.execute(text("SELECT pg_backend_pid()")).scalar_one())
                assert (
                    connection.execute(
                        text("SELECT NULLIF(current_setting('arbiter.tenant_id',true),'')")
                    ).scalar_one()
                    is None
                )
                assert connection.execute(text("SELECT id FROM arbiter.requests")).all() == []
            with pytest.raises(ReleaseNotFound):
                release(store, actors[index], requests[1 - index], engine=engine)
        assert len(set(pids)) == 1
        with tenant_transaction(engine, TenantContext(actors[0].tenant)) as tx:
            with pytest.raises(RuntimeError, match="binding mismatch"):
                ReleaseRepository(tx).release(binding(actors[1]), requests[1], "cancelled")
        with tenant_transaction(engine, TenantContext(actors[0].tenant)) as tx:
            repository = ReleaseRepository(tx)
            tx.connection().execute(
                text("SELECT set_config('arbiter.tenant_id',:t,true)"), {"t": str(actors[1].tenant)}
            )
            with pytest.raises(RuntimeError, match="context changed"):
                repository.release(binding(actors[0]), requests[0], "cancelled")
        with pytest.raises(RuntimeError, match="closed"):
            repository.release(binding(actors[0]), requests[0], "cancelled")
        with engine.begin() as connection:
            connection.execute(
                text("SELECT set_config('arbiter.tenant_id',:tenant,false)"),
                {"tenant": str(actors[0].tenant)},
            )
            poisoned: int = connection.execute(text("SELECT pg_backend_pid()")).scalar_one()
        with pytest.raises(ReleaseUnavailable):
            release(store, actors[1], requests[1], engine=engine)
        with engine.begin() as connection:
            assert connection.execute(text("SELECT pg_backend_pid()")).scalar_one() != poisoned
    finally:
        engine.dispose()


def test_release_evidence_is_content_free_and_immutable(
    store: ReservationStore, caplog: pytest.LogCaptureFixture
) -> None:
    actor = store.actor()
    request = reserve(store, actor).request_id
    release(store, actor, request)
    with tenant_transaction(store.runtime, TenantContext(actor.tenant)) as tx:
        row = (
            tx.connection()
            .execute(
                text("""
            SELECT a.actor_api_key_id,a.policy_revision,a.target_id,a.request_id,
                to_jsonb(a)::text,e.kind,e.credits,e.request_count,
                r.finished_at=a.occurred_at AND a.occurred_at=e.occurred_at
            FROM arbiter.requests r JOIN arbiter.audit_events a ON a.tenant_id=r.tenant_id
                AND a.id=r.release_audit_id JOIN arbiter.reservations s
                ON s.tenant_id=r.tenant_id AND s.id=r.reservation_id
            JOIN arbiter.accounting_events e
                ON e.tenant_id=s.tenant_id AND e.id=s.settlement_event_id
            WHERE r.tenant_id=:tenant AND r.id=:request
        """),
                {"tenant": actor.tenant, "request": request},
            )
            .one()
        )
        assert tuple(row[:4]) == (actor.key, 2, request, request)
        assert tuple(row[5:]) == ("release", 10, 1, True)
        for forbidden in (
            actor.credential.get_secret_value(),
            actor.candidate.verifier.get_secret_value().hex(),
            "synthetic reservation input",
            "model_digest",
            "provider_url",
        ):
            assert forbidden not in row[4] and forbidden not in caplog.text, "content/secret leaked"
    for table in ("accounting_events", "audit_events"):
        for operation in ("UPDATE", "DELETE"):
            statement = (
                sql.SQL("UPDATE {} SET occurred_at=clock_timestamp() WHERE tenant_id=:t")
                if operation == "UPDATE"
                else sql.SQL("DELETE FROM {} WHERE tenant_id=:t")
            )
            engine = store.runtime if table == "audit_events" else store.migration
            with pytest.raises(DBAPIError) as failure, engine.begin() as connection:
                set_context(connection, actor.tenant)
                connection.execute(
                    text(statement.format(sql.Identifier("arbiter", table)).as_string()),
                    {"t": actor.tenant},
                )
            assert postgres_error(failure.value).sqlstate == "42501"


def test_invalid_reason_is_sanitized(store: ReservationStore) -> None:
    actor = store.actor()
    request = reserve(store, actor).request_id
    # Exercise the SQL boundary as well as typed application validation.
    with pytest.raises(DBAPIError) as failure, store.runtime.begin() as connection:
        set_context(connection, actor.tenant)
        connection.execute(
            RAW,
            {
                "tenant": actor.tenant,
                "key": actor.key,
                "request": request,
                "reason": "provider_failure",
            },
        )
    assert postgres_error(failure.value).sqlstate == "22023"
    with pytest.raises(InvalidRelease):
        ReleaseService(store.runtime).release(binding(actor), request, "invalid")  # type: ignore[arg-type]
    assert store.totals(actor) == (0, 1, 0, 10)
