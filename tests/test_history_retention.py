"""Real PostgreSQL history eligibility, authority, FK and serialization proofs."""

import os
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from threading import Barrier, Event
from time import monotonic, sleep
from uuid import UUID, uuid4

import pytest
from psycopg import sql
from sqlalchemy import event, text
from sqlalchemy.engine import Connection
from sqlalchemy.exc import DBAPIError
from test_migrations import migrate_to
from test_provider_binding import binding_store as binding_store
from test_request_retention import age, completed
from test_reservation_transactions import Actor, ReservationStore
from test_tenant_isolation import postgres_error, set_context

from arbiter.identity.context import TenantContext
from arbiter.operations.registry import ModelApproval
from arbiter.operations.retention import RetentionService
from arbiter.persistence.maintenance import clear_unknown
from arbiter.persistence.operator import OperatorAccessDenied, operator_transaction
from arbiter.persistence.tenant import tenant_transaction

pytestmark = pytest.mark.skipif(
    os.environ.get("ARBITER_TEST_DATABASE") != "1"
    or os.environ.get("ARBITER_TEST_MIGRATIONS") != "1",
    reason="requires real PostgreSQL and a disposable migrated database",
)
pytest_plugins = ("test_migrations",)
AS_OF = datetime(2020, 1, 1, tzinfo=UTC)


def window(store: ReservationStore, actor: Actor, kind: str, start: datetime) -> UUID:
    assert kind in {"quota_windows", "budget_windows"}
    identifier = uuid4()
    with store.migration.begin() as connection:
        set_context(connection, actor.tenant)
        connection.execute(
            text(
                sql.SQL(
                    "INSERT INTO {} (id,tenant_id,window_start,committed,reserved) "
                    "VALUES (:id,:tenant,:start,77,9)"
                )
                .format(sql.Identifier("arbiter", kind))
                .as_string()
            ),
            {"id": identifier, "tenant": actor.tenant, "start": start},
        )
    return identifier


def audit(store: ReservationStore, actor: Actor, occurred: datetime) -> UUID:
    identifier = uuid4()
    with operator_transaction(store.operator, actor.tenant) as tx:
        tx.connection().execute(
            text("""
            INSERT INTO arbiter.audit_events (id,tenant_id,actor_type,actor_reference,
                action,target_id,policy_revision,occurred_at,outcome)
            VALUES (:id,:tenant,'operator','arbiter_operator','retention_fixture',:target,
                2,:at,'succeeded')
        """),
            {"id": identifier, "tenant": actor.tenant, "target": uuid4(), "at": occurred},
        )
    return identifier


def exists(store: ReservationStore, actor: Actor, table: str, identifier: UUID) -> bool:
    assert table in {"quota_windows", "budget_windows", "audit_events", "api_keys", "requests"}
    with tenant_transaction(store.runtime, TenantContext(actor.tenant)) as tx:
        return bool(
            tx.connection()
            .execute(
                text(
                    sql.SQL("SELECT count(*) FROM {} WHERE tenant_id=:tenant AND id=:id")
                    .format(sql.Identifier("arbiter", table))
                    .as_string()
                ),
                {"tenant": actor.tenant, "id": identifier},
            )
            .scalar_one()
        )


def age_audits(store: ReservationStore, actor: Actor, occurred: datetime) -> None:
    # Owner-only historical fixture; restore the insert-only cleanup audit guard.
    with store.migration.begin() as connection:
        set_context(connection, actor.tenant)
        connection.execute(
            text("ALTER TABLE arbiter.audit_events DISABLE TRIGGER retention_audit_guard")
        )
        connection.execute(
            text("UPDATE arbiter.audit_events SET occurred_at=:at WHERE tenant_id=:tenant"),
            {"tenant": actor.tenant, "at": occurred},
        )
        connection.execute(
            text("ALTER TABLE arbiter.audit_events ENABLE TRIGGER retention_audit_guard")
        )


@pytest.mark.parametrize(
    "kind,start,boundary",
    [
        ("quota_windows", datetime(2018, 1, 30, tzinfo=UTC), datetime(2019, 2, 28, tzinfo=UTC)),
        ("budget_windows", datetime(2018, 1, 1, tzinfo=UTC), datetime(2019, 3, 1, tzinfo=UTC)),
    ],
)
@pytest.mark.parametrize("offset,removed", [(-1, 0), (0, 1), (1, 1)])
def test_calendar_close_boundary_inclusive_and_counters_unchanged(
    binding_store: tuple[ReservationStore, ModelApproval],
    kind: str,
    start: datetime,
    boundary: datetime,
    offset: int,
    removed: int,
) -> None:
    store, _ = binding_store
    actor = store.actor()
    identifier = window(store, actor, kind, start)
    with operator_transaction(store.operator, actor.tenant) as tx:
        tx.connection().execute(text("SET LOCAL TIME ZONE 'America/New_York'"))
        # UTC calendar eligibility is independent of the caller session's time zone.
        result = (
            tx.connection()
            .execute(
                text("SELECT * FROM arbiter.retire_history(:tenant,:at,:op,100)"),
                {
                    "tenant": actor.tenant,
                    "at": boundary + timedelta(microseconds=offset),
                    "op": uuid4(),
                },
            )
            .one()
        )
    assert getattr(result, kind + "_removed") == removed
    assert exists(store, actor, kind, identifier) == (removed == 0)
    if not removed:
        with tenant_transaction(store.runtime, TenantContext(actor.tenant)) as tx:
            row = (
                tx.connection()
                .execute(
                    text(
                        sql.SQL(
                            "SELECT committed,reserved FROM {} WHERE tenant_id=:tenant AND id=:id"
                        )
                        .format(sql.Identifier("arbiter", kind))
                        .as_string()
                    ),
                    {"tenant": actor.tenant, "id": identifier},
                )
                .one()
            )
            assert tuple(row) == (77, 9)


@pytest.mark.parametrize("kind", ["quota_windows", "budget_windows"])
def test_recent_window_cannot_be_deleted(
    binding_store: tuple[ReservationStore, ModelApproval], kind: str
) -> None:
    store, _ = binding_store
    actor = store.actor()
    start = datetime.now(UTC).replace(hour=0, minute=0, second=0, microsecond=0)
    if kind == "budget_windows":
        start = start.replace(day=1)
    identifier = window(store, actor, kind, start)
    result = RetentionService(store.operator).retire_history(actor.tenant)
    assert getattr(result, kind + "_removed") == 0 and exists(store, actor, kind, identifier)


@pytest.mark.parametrize("offset,removed", [(-1, 0), (0, 1), (1, 1)])
def test_standalone_audit_90_day_boundary(
    binding_store: tuple[ReservationStore, ModelApproval], offset: int, removed: int
) -> None:
    store, _ = binding_store
    actor = store.actor()
    identifier = audit(store, actor, AS_OF - timedelta(days=90))
    result = RetentionService(store.operator).retire_history(
        actor.tenant, as_of=AS_OF + timedelta(microseconds=offset)
    )
    assert result.standalone_audits_removed == removed
    assert exists(store, actor, "audit_events", identifier) == (removed == 0)
    assert exists(store, actor, "audit_events", result.audit_id)


@pytest.mark.parametrize(
    "state,mode",
    [
        ("reserved", "success"),
        ("dispatched", "success"),
        ("unknown", "deadline"),
        ("cleared_unknown", "deadline"),
        ("succeeded", "success"),
    ],
)
def test_retained_graph_protects_windows_and_request_audits(
    binding_store: tuple[ReservationStore, ModelApproval],
    state: str,
    mode: str,
) -> None:
    store, _ = binding_store
    actor = store.actor()
    # Select a typed known double mode rather than passing caller-controlled provider options.
    identifier = completed(
        store,
        actor,
        state="unknown" if state == "cleared_unknown" else state,
        mode="deadline" if mode == "deadline" else "success",
    )
    if state == "cleared_unknown":
        assert clear_unknown(store.operator, actor.tenant, identifier)
    age(store, actor, identifier, AS_OF)
    age_audits(store, actor, AS_OF - timedelta(days=100))
    totals = store.totals(actor)
    result = RetentionService(store.operator).retire_history(actor.tenant)
    assert result.quota_windows_removed == result.budget_windows_removed == 0
    assert store.totals(actor) == totals and exists(store, actor, "requests", identifier)
    with tenant_transaction(store.runtime, TenantContext(actor.tenant)) as tx:
        assert (
            tx.connection()
            .execute(
                text(
                    "SELECT count(*) FROM arbiter.audit_events "
                    "WHERE tenant_id=:tenant AND action LIKE 'request_%'"
                ),
                {"tenant": actor.tenant},
            )
            .scalar_one()
            >= 1
        )
    if state == "succeeded":
        assert (
            RetentionService(store.operator).run_once(actor.tenant, actor.key).requests_removed == 1
        )
        later = RetentionService(store.operator).retire_history(actor.tenant)
        assert later.quota_windows_removed == later.budget_windows_removed == 1


def test_inbound_fk_and_future_reference_protect_standalone_audits(
    binding_store: tuple[ReservationStore, ModelApproval],
) -> None:
    store, _ = binding_store
    actor = store.actor()
    age_audits(store, actor, AS_OF - timedelta(days=100))
    # Key-creation and policy evidence remain referenced even though neither is request evidence.
    with tenant_transaction(store.runtime, TenantContext(actor.tenant)) as tx:
        protected: list[UUID] = list(
            tx.connection()
            .execute(
                text(
                    "SELECT id FROM arbiter.audit_events WHERE "
                    "tenant_id=:tenant AND action IN ('api_key_created','tenant_policy_set')"
                ),
                {"tenant": actor.tenant},
            )
            .scalars()
        )
    identifier = audit(store, actor, AS_OF - timedelta(days=100))
    with store.migration.begin() as connection:
        set_context(connection, actor.tenant)
        connection.execute(
            text(
                "CREATE TABLE arbiter.future_retention_reference (tenant_id uuid NOT NULL,"
                "audit_id uuid NOT NULL,FOREIGN KEY (tenant_id,audit_id) "
                "REFERENCES arbiter.audit_events(tenant_id,id))"
            )
        )
        connection.execute(
            text("GRANT SELECT ON arbiter.future_retention_reference TO arbiter_retention_writer")
        )
        connection.execute(
            text("INSERT INTO arbiter.future_retention_reference VALUES (:tenant,:id)"),
            {"tenant": actor.tenant, "id": identifier},
        )
    RetentionService(store.operator).retire_history(actor.tenant)
    assert protected and all(
        exists(store, actor, "audit_events", i) for i in [*protected, identifier]
    )


def test_cleanup_evidence_lifetime_and_fresh_summary(
    binding_store: tuple[ReservationStore, ModelApproval],
) -> None:
    store, _ = binding_store
    actor = store.actor()
    first = RetentionService(store.operator).retire_history(actor.tenant)
    assert (
        RetentionService(store.operator).retire_history(actor.tenant).standalone_audits_removed == 0
    )
    assert exists(store, actor, "audit_events", first.audit_id)
    age_audits(store, actor, AS_OF - timedelta(days=90))
    before = RetentionService(store.operator).retire_history(
        actor.tenant, as_of=AS_OF - timedelta(microseconds=1)
    )
    assert before.standalone_audits_removed == 0
    at = RetentionService(store.operator).retire_history(actor.tenant, as_of=AS_OF)
    assert at.standalone_audits_removed >= 2 and not exists(
        store, actor, "audit_events", first.audit_id
    )
    assert exists(store, actor, "audit_events", at.audit_id) and exists(
        store, actor, "audit_events", before.audit_id
    )
    with tenant_transaction(store.runtime, TenantContext(actor.tenant)) as tx:
        row = (
            tx.connection()
            .execute(
                text("SELECT * FROM arbiter.audit_events WHERE tenant_id=:tenant AND id=:id"),
                {"tenant": actor.tenant, "id": at.audit_id},
            )
            .one()
        )
        assert row.actor_reference == "arbiter_operator" and row.outcome == "succeeded"
        assert row.request_id == row.target_id and row.occurred_at > AS_OF
        assert set(row.retention_summary) == {
            "as_of",
            "quota_windows",
            "budget_windows",
            "standalone_audits",
        }


def test_failure_rolls_back_all_deletions_and_audit(
    binding_store: tuple[ReservationStore, ModelApproval],
) -> None:
    store, _ = binding_store
    actor = store.actor()
    identifier = window(store, actor, "quota_windows", datetime(2018, 1, 1, tzinfo=UTC))
    old = audit(store, actor, AS_OF - timedelta(days=100))
    with store.migration.begin() as connection:
        connection.execute(
            text(
                "CREATE TABLE arbiter.unreadable_reference "
                "(audit_id uuid REFERENCES arbiter.audit_events(id))"
            )
        )
    # Unknown future authority without SELECT permission fails closed, after the window deletion.
    with pytest.raises(DBAPIError) as failed:
        RetentionService(store.operator).retire_history(actor.tenant)
    assert postgres_error(failed.value).sqlstate == "42501"
    assert exists(store, actor, "quota_windows", identifier) and exists(
        store, actor, "audit_events", old
    )
    with tenant_transaction(store.runtime, TenantContext(actor.tenant)) as tx:
        assert (
            tx.connection()
            .execute(
                text(
                    "SELECT count(*) FROM arbiter.audit_events WHERE tenant_id=:tenant "
                    "AND action='retention_cleaned'"
                ),
                {"tenant": actor.tenant},
            )
            .scalar_one()
            == 0
        )


def test_fresh_cleanup_audit_failure_rolls_back_completed_deletions(
    binding_store: tuple[ReservationStore, ModelApproval],
) -> None:
    store, _ = binding_store
    actor = store.actor()
    identifier = window(store, actor, "quota_windows", datetime(2018, 1, 1, tzinfo=UTC))
    old = audit(store, actor, AS_OF - timedelta(days=100))

    def snapshot() -> tuple[list[str], list[str]]:
        with tenant_transaction(store.runtime, TenantContext(actor.tenant)) as tx:
            return (
                list(
                    tx.connection()
                    .execute(
                        text(
                            "SELECT row_to_json(q)::text FROM arbiter.quota_windows q "
                            "WHERE tenant_id=:tenant ORDER BY id"
                        ),
                        {"tenant": actor.tenant},
                    )
                    .scalars()
                ),
                list(
                    tx.connection()
                    .execute(
                        text(
                            "SELECT row_to_json(a)::text FROM arbiter.audit_events a "
                            "WHERE tenant_id=:tenant ORDER BY id"
                        ),
                        {"tenant": actor.tenant},
                    )
                    .scalars()
                ),
            )

    before = snapshot()
    with store.migration.begin() as connection:
        connection.execute(
            text("""
                CREATE FUNCTION arbiter.test_reject_cleanup_audit() RETURNS trigger
                LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog AS $$
                BEGIN
                    IF NEW.action='retention_cleaned' THEN
                        -- Observe actual DELETE effects in the cleanup transaction, not
                        -- just its claimed counts, before rejecting its final INSERT.
                        IF EXISTS (SELECT 1 FROM arbiter.quota_windows
                            WHERE tenant_id=NEW.tenant_id AND id=TG_ARGV[0]::uuid)
                            OR EXISTS (SELECT 1 FROM arbiter.audit_events
                            WHERE tenant_id=NEW.tenant_id AND id=TG_ARGV[1]::uuid)
                            OR NEW.retention_summary->>'quota_windows' IS DISTINCT FROM '1'
                            OR NEW.retention_summary->>'standalone_audits' IS DISTINCT FROM '1'
                        THEN
                            RAISE EXCEPTION 'cleanup deletions not completed'
                                USING ERRCODE='P5001';
                        END IF;
                        RAISE EXCEPTION 'cleanup audit rejected after completed deletions'
                            USING ERRCODE='P5002';
                    END IF;
                    RETURN NEW;
                END $$
            """)
        )
        connection.execute(
            text(
                sql.SQL(
                    "CREATE TRIGGER zz_test_reject_cleanup_audit BEFORE INSERT "
                    "ON arbiter.audit_events FOR EACH ROW EXECUTE FUNCTION "
                    "arbiter.test_reject_cleanup_audit({},{})"
                )
                .format(sql.Literal(str(identifier)), sql.Literal(str(old)))
                .as_string()
            )
        )
    try:
        with pytest.raises(DBAPIError) as failed:
            RetentionService(store.operator).retire_history(actor.tenant)
        error = postgres_error(failed.value)
        assert error.sqlstate == "P5002"
        assert error.diag.message_primary == "cleanup audit rejected after completed deletions"
        assert exists(store, actor, "quota_windows", identifier)
        assert exists(store, actor, "audit_events", old)
        # Exact full-row equality also proves counters and all audit evidence survived,
        # and that no new retention_cleaned record or partial cleanup was committed.
        assert snapshot() == before
    finally:
        with store.migration.begin() as connection:
            connection.execute(
                text("DROP TRIGGER zz_test_reject_cleanup_audit ON arbiter.audit_events")
            )
            connection.execute(text("DROP FUNCTION arbiter.test_reject_cleanup_audit()"))


def test_security_rls_and_api_keys_remain_durable(
    binding_store: tuple[ReservationStore, ModelApproval],
) -> None:
    store, _ = binding_store
    actor, foreign = store.actor(), store.actor()
    identifier = window(store, actor, "quota_windows", datetime(2018, 1, 1, tzinfo=UTC))
    with pytest.raises(OperatorAccessDenied):
        RetentionService(store.runtime).retire_history(actor.tenant)
    with pytest.raises(DBAPIError):
        with operator_transaction(store.operator, foreign.tenant) as tx:
            tx.connection().execute(
                text("SELECT * FROM arbiter.retire_history(:tenant,NULL,:op,100)"),
                {"tenant": actor.tenant, "op": uuid4()},
            )
    with pytest.raises(DBAPIError):
        with store.operator.begin() as connection:
            connection.execute(
                text("SELECT * FROM arbiter.retire_history(:tenant,NULL,:op,100)"),
                {"tenant": actor.tenant, "op": uuid4()},
            )
    for statement in (
        "SELECT * FROM arbiter.retire_history(NULL,NULL,NULL,100)",
        "DELETE FROM arbiter.quota_windows",
        "DELETE FROM arbiter.budget_windows",
        "DELETE FROM arbiter.audit_events",
        "UPDATE arbiter.audit_events SET outcome='succeeded'",
        "TRUNCATE arbiter.audit_events CASCADE",
        "UPDATE arbiter.accounting_events SET credits=credits",
        "DELETE FROM arbiter.api_keys",
    ):
        with pytest.raises(DBAPIError) as denied:
            with tenant_transaction(store.runtime, TenantContext(actor.tenant)) as tx:
                tx.connection().execute(text(statement))
        assert postgres_error(denied.value).sqlstate == "42501"
    RetentionService(store.operator).retire_history(foreign.tenant)
    assert exists(store, actor, "quota_windows", identifier)
    assert exists(store, actor, "api_keys", actor.key)
    with store.migration.begin() as connection:
        set_context(connection, actor.tenant)
        connection.execute(
            text(
                "UPDATE arbiter.api_keys SET revoked_at=clock_timestamp() WHERE tenant_id=:tenant "
                "AND id=:key"
            ),
            {"tenant": actor.tenant, "key": actor.key},
        )
    RetentionService(store.operator).retire_history(actor.tenant)
    assert exists(store, actor, "api_keys", actor.key)
    with pytest.raises(DBAPIError):
        with store.migration.begin() as connection:
            set_context(connection, actor.tenant)
            connection.execute(
                text("UPDATE arbiter.api_keys SET revoked_at=NULL WHERE tenant_id=:tenant"),
                {"tenant": actor.tenant},
            )
    with store.migration.begin() as connection:
        assert not connection.execute(
            text(
                "SELECT has_table_privilege('arbiter_retention_writer','arbiter.api_keys','DELETE')"
            )
        ).scalar_one()


@pytest.mark.parametrize("other", ["history", "retirement", "admission", "revocation"])
def test_tenant_first_serialization_with_other_transactions(
    binding_store: tuple[ReservationStore, ModelApproval],
    other: str,
) -> None:
    store, _ = binding_store
    actor = store.actor()
    identifier = completed(store, actor)
    age(store, actor, identifier, AS_OF)
    age_audits(store, actor, AS_OF - timedelta(days=100))
    if other == "history":
        window(store, actor, "quota_windows", datetime(2018, 1, 1, tzinfo=UTC))
    start = Barrier(3)
    captured = Event()
    pids: list[int] = []

    def capture(
        connection: Connection,
        _cursor: object,
        statement: str,
        _parameters: object,
        _context: object,
        _many: bool,
    ) -> None:
        if any(
            name in statement
            for name in (
                "arbiter.retire_history(",
                "arbiter.retire_requests(",
                "arbiter.reserve_request(",
                "arbiter.revoke_api_key(",
            )
        ):
            pids.append(connection.exec_driver_sql("SELECT pg_backend_pid()").scalar_one())
            if len(pids) >= 2:
                captured.set()

    for engine in (store.runtime, store.operator):
        event.listen(engine, "before_cursor_execute", capture)

    def history() -> int:
        start.wait(timeout=10)
        return RetentionService(store.operator).retire_history(actor.tenant).quota_windows_removed

    def competing() -> int:
        start.wait(timeout=10)
        if other == "history":
            return (
                RetentionService(store.operator).retire_history(actor.tenant).quota_windows_removed
            )
        if other == "retirement":
            return (
                RetentionService(store.operator).run_once(actor.tenant, actor.key).requests_removed
            )
        if other == "admission":
            store.service().reserve(actor.credential, uuid4().hex, store.request())
            return 0
        with tenant_transaction(store.runtime, TenantContext(actor.tenant)) as tx:
            principal: UUID = (
                tx.connection()
                .execute(
                    text(
                        "SELECT principal_id FROM arbiter.memberships "
                        "WHERE tenant_id=:tenant AND id=:member"
                    ),
                    {"tenant": actor.tenant, "member": actor.member},
                )
                .scalar_one()
            )
            tx.connection().execute(
                text(
                    "SELECT * FROM arbiter.revoke_api_key"
                    "(:tenant,:member,:principal,:key,:audit,:request)"
                ),
                {
                    "tenant": actor.tenant,
                    "member": actor.member,
                    "principal": principal,
                    "key": actor.key,
                    "audit": uuid4(),
                    "request": uuid4(),
                },
            ).one()
        return 0

    try:
        with ThreadPoolExecutor(max_workers=2) as pool:
            with store.migration.begin() as blocker:
                set_context(blocker, actor.tenant)
                blocker.execute(
                    text("SELECT id FROM arbiter.tenants WHERE tenant_id=:tenant FOR UPDATE"),
                    {"tenant": actor.tenant},
                )
                blocker_pid: int = blocker.exec_driver_sql("SELECT pg_backend_pid()").scalar_one()
                jobs = [pool.submit(history), pool.submit(competing)]
                start.wait(timeout=10)
                assert captured.wait(timeout=10)
                deadline = monotonic() + 10
                with store.migration.begin() as observer:

                    def waits_for_tenant_lock(pid: int) -> bool:
                        pending = [pid]
                        seen: set[int] = set()
                        while pending:
                            current = pending.pop()
                            if current in seen:
                                continue
                            seen.add(current)
                            blockers: list[int] = observer.execute(
                                text("SELECT pg_blocking_pids(:pid)"), {"pid": current}
                            ).scalar_one()
                            if blocker_pid in blockers:
                                return True
                            pending.extend(blockers)
                        return False

                    while True:
                        # PostgreSQL can queue a tuple waiter behind the first waiter;
                        # both must transitively depend on the held tenant row.
                        if len(pids) == 2 and all(waits_for_tenant_lock(pid) for pid in pids):
                            break
                        assert monotonic() < deadline, "workers did not block on the tenant lock"
                        sleep(0.02)
            results = [job.result(timeout=20) for job in jobs]
        if other == "history":
            assert sum(results) == 1
            assert (
                RetentionService(store.operator).retire_history(actor.tenant).quota_windows_removed
                == 0
            )
        elif other == "retirement":
            assert results[1] == 1
            final = RetentionService(store.operator).retire_history(actor.tenant)
            assert results[0] + final.quota_windows_removed == 1
            assert not exists(store, actor, "requests", identifier)
        else:
            assert results[0] == 0
            assert exists(store, actor, "requests", identifier)
    finally:
        for engine in (store.runtime, store.operator):
            event.remove(engine, "before_cursor_execute", capture)


def test_batch_bound_and_invalid_cleanup_time_are_enforced(
    binding_store: tuple[ReservationStore, ModelApproval],
) -> None:
    store, _ = binding_store
    actor = store.actor()
    first = window(store, actor, "quota_windows", datetime(2018, 1, 1, tzinfo=UTC))
    second = window(store, actor, "quota_windows", datetime(2018, 1, 2, tzinfo=UTC))
    for limit in (0, 101, None):
        with pytest.raises(DBAPIError) as invalid:
            with operator_transaction(store.operator, actor.tenant) as tx:
                tx.connection().execute(
                    text("SELECT * FROM arbiter.retire_history(:tenant,:at,:op,:limit)"),
                    {"tenant": actor.tenant, "at": AS_OF, "op": uuid4(), "limit": limit},
                )
        assert postgres_error(invalid.value).sqlstate == "22023"
    with pytest.raises(DBAPIError) as future:
        RetentionService(store.operator).retire_history(
            actor.tenant, as_of=datetime.now(UTC) + timedelta(days=1)
        )
    assert postgres_error(future.value).sqlstate == "22023"
    assert exists(store, actor, "quota_windows", first)
    assert exists(store, actor, "quota_windows", second)
    assert (
        RetentionService(store.operator).retire_history(actor.tenant, limit=1).quota_windows_removed
        == 1
    )
    assert not exists(store, actor, "quota_windows", first)
    assert exists(store, actor, "quota_windows", second)
    assert (
        RetentionService(store.operator).retire_history(actor.tenant, limit=1).quota_windows_removed
        == 1
    )
    assert (
        RetentionService(store.operator).retire_history(actor.tenant, limit=1).quota_windows_removed
        == 0
    )


def test_downgrade_preserves_retained_cleanup_evidence(
    binding_store: tuple[ReservationStore, ModelApproval],
) -> None:
    store, _ = binding_store
    actor = store.actor()
    result = RetentionService(store.operator).retire_history(actor.tenant)
    migrate_to(store.migration, "0020_request_retention", downgrade=True)
    assert exists(store, actor, "audit_events", result.audit_id)
    with pytest.raises(DBAPIError):
        migrate_to(store.migration, "0019_reserved_provider_binding", downgrade=True)
    migrate_to(store.migration, "head")
    assert exists(store, actor, "audit_events", result.audit_id)
