"""Real PostgreSQL evidence; SQLite/mocks are never isolation evidence."""

import os
from collections.abc import Iterator, Sequence
from dataclasses import dataclass
from uuid import UUID, uuid4

import psycopg
import pytest
from retention_cleanup import delete_fixture_audits
from sqlalchemy import create_engine, event, text
from sqlalchemy.engine import Connection, Engine
from sqlalchemy.exc import DBAPIError
from sqlalchemy.pool import QueuePool

from arbiter.config import DatabaseRole, DatabaseSettings
from arbiter.identity.context import TenantContext
from arbiter.persistence.repositories import AuditRepository, MembershipRepository, TenantRepository
from arbiter.persistence.tenant import runtime_engine, tenant_transaction

pytestmark = pytest.mark.skipif(
    os.environ.get("ARBITER_TEST_DATABASE") != "1", reason="requires provisioned real PostgreSQL"
)

AUDIT_INSERT = text("""
    INSERT INTO arbiter.audit_events
    (id, tenant_id, actor_type, actor_reference, actor_membership_id,
     action, target_id, policy_revision, outcome)
    VALUES (:id, :tenant, 'member', 'test-fixture', :member,
            'fixture', :member, 1, 'succeeded')
""")


def set_context(connection: Connection, tenant_id: UUID) -> None:
    connection.execute(
        text("SELECT set_config('arbiter.tenant_id', :tenant, true)"), {"tenant": str(tenant_id)}
    )


def audit_values(tenant_id: UUID, member_id: UUID) -> dict[str, UUID]:
    return {"id": uuid4(), "tenant": tenant_id, "member": member_id}


def postgres_error(error: DBAPIError) -> psycopg.Error:
    assert isinstance(error.orig, psycopg.Error)
    return error.orig


def credential_engine(role: DatabaseRole) -> Engine:
    return create_engine(
        DatabaseSettings().url(role),
        hide_parameters=True,
        pool_size=1,
        max_overflow=0,
        pool_timeout=5,
        connect_args={"connect_timeout": 5, "options": "-c statement_timeout=5000"},
    )


@dataclass(frozen=True)
class Store:
    runtime: Engine
    operator: Engine
    migration: Engine
    tenant_a: UUID
    tenant_b: UUID
    member_a: UUID
    member_b: UUID
    principal_a: UUID
    principal_b: UUID
    audit_a: UUID
    audit_b: UUID


@pytest.fixture(scope="module")
def store() -> Iterator[Store]:
    value = Store(
        credential_engine("runtime"),
        credential_engine("operator"),
        credential_engine("migration"),
        *(uuid4() for _ in range(8)),
    )
    try:
        with value.operator.begin() as connection:
            for principal in (value.principal_a, value.principal_b):
                connection.execute(
                    text("INSERT INTO arbiter.principals (id, issuer, subject) VALUES (:id,:i,:s)"),
                    {"id": principal, "i": "https://fixture.invalid", "s": str(principal)},
                )
        for tenant, member, principal, audit in (
            (value.tenant_a, value.member_a, value.principal_a, value.audit_a),
            (value.tenant_b, value.member_b, value.principal_b, value.audit_b),
        ):
            with value.operator.begin() as connection:
                set_context(connection, tenant)
                connection.execute(
                    text("INSERT INTO arbiter.tenants (id) VALUES (:id)"), {"id": tenant}
                )
                connection.execute(
                    text("""
                        INSERT INTO arbiter.memberships (id, tenant_id, principal_id, role)
                        VALUES (:id, :tenant, :principal, 'member')
                    """),
                    {"id": member, "tenant": tenant, "principal": principal},
                )
                connection.execute(AUDIT_INSERT, {"id": audit, "tenant": tenant, "member": member})
        yield value
    finally:
        # Cleanup only this fixture's random IDs; migration ownership remains FORCE-scoped.
        with value.migration.begin() as connection:
            for tenant in (value.tenant_a, value.tenant_b):
                set_context(connection, tenant)
                delete_fixture_audits(connection, tenant)
                connection.execute(
                    text("DELETE FROM arbiter.memberships WHERE tenant_id=:tenant"),
                    {"tenant": tenant},
                )
                connection.execute(
                    text("DELETE FROM arbiter.tenants WHERE tenant_id=:tenant"),
                    {"tenant": tenant},
                )
            connection.execute(
                text("DELETE FROM arbiter.principals WHERE id IN (:a,:b)"),
                {"a": value.principal_a, "b": value.principal_b},
            )
        for engine in (value.runtime, value.operator, value.migration):
            engine.dispose()


@pytest.mark.parametrize("role", ["runtime", "operator", "migration"])
def test_missing_context_denies_reads_including_forced_owner(store: Store, role: str) -> None:
    engine = getattr(store, role)
    with engine.begin() as connection:
        assert (
            connection.execute(
                text("SELECT NULLIF(current_setting('arbiter.tenant_id', true), '')")
            ).scalar()
            is None
        )
        for statement in (
            "SELECT id FROM arbiter.tenants",
            "SELECT id FROM arbiter.memberships",
            "SELECT id FROM arbiter.audit_events",
        ):
            assert connection.execute(text(statement)).all() == []


def test_missing_context_denies_inserts_and_filters_updates(store: Store) -> None:
    with store.runtime.begin() as connection, pytest.raises(DBAPIError) as failure:
        connection.execute(AUDIT_INSERT, audit_values(store.tenant_a, store.member_a))
    assert postgres_error(failure.value).sqlstate == "42501"
    with store.operator.begin() as connection:
        assert (
            connection.execute(
                text("UPDATE arbiter.memberships SET role='admin' WHERE id=:id"),
                {"id": store.member_a},
            ).rowcount
            == 0
        )


@pytest.mark.parametrize("reverse", [False, True])
def test_cross_tenant_reads_joins_and_repositories(store: Store, reverse: bool) -> None:
    tenant, member, other_member, audit = (
        (store.tenant_b, store.member_b, store.member_a, store.audit_b)
        if reverse
        else (store.tenant_a, store.member_a, store.member_b, store.audit_a)
    )
    with tenant_transaction(store.runtime, TenantContext(tenant)) as transaction:
        connection = transaction.connection()
        assert connection.execute(text("SELECT id FROM arbiter.tenants")).scalars().all() == [
            tenant
        ]
        assert connection.execute(text("SELECT id FROM arbiter.memberships")).scalars().all() == [
            member
        ]
        assert connection.execute(text("SELECT id FROM arbiter.audit_events")).scalars().all() == [
            audit
        ]
        assert connection.execute(
            text("""
            SELECT a.id, m.id FROM arbiter.audit_events a
            JOIN arbiter.memberships m ON a.actor_membership_id=m.id
        """)
        ).all() == [(audit, member)]
        current = TenantRepository(transaction).get()
        assert current is not None and current.id == tenant
        memberships = MembershipRepository(transaction)
        assert memberships.get(member) is not None
        assert memberships.get(other_member) is None
        events = AuditRepository(transaction).list_with_actor()
        assert [event.id for event in events] == [audit]
        assert events[0].actor_role == "member"
        assert events[0].occurred_at.tzinfo is not None


def test_runtime_can_append_own_audit_but_not_another_tenant(store: Store) -> None:
    with store.runtime.connect() as connection:
        with connection.begin() as transaction:
            set_context(connection, store.tenant_a)
            assert (
                connection.execute(
                    AUDIT_INSERT, audit_values(store.tenant_a, store.member_a)
                ).rowcount
                == 1
            )
            transaction.rollback()
    with store.runtime.begin() as connection, pytest.raises(DBAPIError) as failure:
        set_context(connection, store.tenant_a)
        connection.execute(AUDIT_INSERT, audit_values(store.tenant_b, store.member_b))
    assert postgres_error(failure.value).sqlstate == "42501"


def test_scoped_operator_cannot_modify_other_tenant(store: Store) -> None:
    with store.operator.connect() as connection, connection.begin() as transaction:
        set_context(connection, store.tenant_a)
        assert (
            connection.execute(
                text("UPDATE arbiter.memberships SET role='admin' WHERE id=:id"),
                {"id": store.member_b},
            ).rowcount
            == 0
        )
        assert (
            connection.execute(
                text("UPDATE arbiter.memberships SET role='admin' WHERE id=:id"),
                {"id": store.member_a},
            ).rowcount
            == 1
        )
        transaction.rollback()


def test_repository_append_derives_tenant_and_shares_transaction(store: Store) -> None:
    with pytest.raises(ValueError, match="abort audit transaction"):
        with tenant_transaction(store.runtime, TenantContext(store.tenant_a)) as transaction:
            repository = AuditRepository(transaction)
            for actor in (store.member_b, uuid4()):
                with pytest.raises(ValueError, match="inaccessible audit actor"):
                    repository.append_member_event(
                        actor_membership_id=actor,
                        action="fixture",
                        target_id=store.member_a,
                        policy_revision=1,
                        outcome="succeeded",
                    )
            event_id = repository.append_member_event(
                actor_membership_id=store.member_a,
                action="fixture",
                target_id=store.member_a,
                policy_revision=1,
                outcome="succeeded",
            )
            assert event_id in [event.id for event in repository.list_with_actor()]
            raise ValueError("abort audit transaction")
    with tenant_transaction(store.runtime, TenantContext(store.tenant_a)) as transaction:
        assert event_id not in [
            event.id for event in AuditRepository(transaction).list_with_actor()
        ]


def test_repositories_scope_sql_independently_of_rls(store: Store) -> None:
    observed: list[tuple[str, object]] = []

    def observe(
        connection: Connection,
        cursor: object,
        statement: str,
        parameters: object,
        execution_context: object,
        executemany: bool,
    ) -> None:
        if "FROM arbiter." in statement or "INSERT INTO arbiter." in statement:
            observed.append((" ".join(statement.split()), parameters))

    event.listen(store.runtime, "before_cursor_execute", observe)
    try:
        with pytest.raises(ValueError, match="abort SQL scope fixture"):
            with tenant_transaction(store.runtime, TenantContext(store.tenant_a)) as transaction:
                TenantRepository(transaction).get()
                MembershipRepository(transaction).get(store.member_b)
                repository = AuditRepository(transaction)
                repository.list_with_actor()
                repository.append_member_event(
                    actor_membership_id=store.member_a,
                    action="fixture",
                    target_id=store.member_a,
                    policy_revision=1,
                    outcome="succeeded",
                )
                raise ValueError("abort SQL scope fixture")
    finally:
        event.remove(store.runtime, "before_cursor_execute", observe)
    assert len(observed) == 5
    for statement, parameters in observed:
        assert isinstance(parameters, dict)
        assert parameters["tenant"] == store.tenant_a
        if statement.startswith("SELECT"):
            assert (
                "WHERE tenant_id=%(tenant)s" in statement
                or "WHERE a.tenant_id=%(tenant)s" in statement
            )
        else:
            assert "INSERT INTO arbiter.audit_events" in statement
            assert "tenant_id" in statement and "%(tenant)s" in statement
        if "JOIN arbiter.memberships" in statement:
            assert "m.tenant_id=a.tenant_id" in statement
            assert "m.tenant_id=%(tenant)s" in statement


def test_composite_reference_rejects_hidden_and_nonexistent_members_equally(store: Store) -> None:
    for member in (store.member_b, uuid4()):
        with store.runtime.begin() as connection, pytest.raises(DBAPIError) as failure:
            set_context(connection, store.tenant_a)
            connection.execute(AUDIT_INSERT, audit_values(store.tenant_a, member))
        assert postgres_error(failure.value).sqlstate == "23503"
        assert postgres_error(failure.value).diag.constraint_name == "audit_actor_membership_fk"


def test_null_tenant_ownership_is_rejected(store: Store) -> None:
    with store.runtime.begin() as connection, pytest.raises(DBAPIError) as failure:
        set_context(connection, store.tenant_a)
        connection.execute(AUDIT_INSERT, {"id": uuid4(), "tenant": None, "member": store.member_a})
    # RLS rejects NULL before the NOT NULL check; catalog verification covers both layers.
    assert postgres_error(failure.value).sqlstate == "42501"


@pytest.mark.parametrize(
    "statement",
    [
        "UPDATE arbiter.audit_events SET outcome='denied'",
        "DELETE FROM arbiter.audit_events",
        "TRUNCATE arbiter.audit_events",
        "SELECT * FROM arbiter.principals",
        "INSERT INTO arbiter.tenants (id) VALUES (gen_random_uuid())",
        "UPDATE arbiter.memberships SET role='admin'",
        "ALTER TABLE arbiter.memberships DISABLE ROW LEVEL SECURITY",
        "ALTER TABLE arbiter.memberships NO FORCE ROW LEVEL SECURITY",
        "CREATE POLICY bypass ON arbiter.memberships USING (true)",
        "SET ROLE arbiter_operator",
        "SET ROLE arbiter_migration",
        "SET ROLE arbiter_bootstrap",
        "ALTER ROLE arbiter_runtime BYPASSRLS",
    ],
)
def test_runtime_cannot_escalate_or_mutate_restricted_records(store: Store, statement: str) -> None:
    with store.runtime.begin() as connection, pytest.raises(DBAPIError) as failure:
        set_context(connection, store.tenant_a)
        connection.execute(text(statement))
    assert postgres_error(failure.value).sqlstate == "42501"


def test_row_security_off_does_not_bypass_rls(store: Store) -> None:
    with store.runtime.begin() as connection, pytest.raises(DBAPIError) as failure:
        set_context(connection, store.tenant_a)
        connection.execute(text("SET LOCAL row_security = off"))
        connection.execute(text("SELECT id FROM arbiter.memberships"))
    assert postgres_error(failure.value).sqlstate == "42501"


def test_invalid_context_fails_closed(store: Store) -> None:
    with store.runtime.begin() as connection, pytest.raises(DBAPIError) as failure:
        connection.execute(text("SELECT set_config('arbiter.tenant_id', 'invalid-uuid', true)"))
        connection.execute(text("SELECT id FROM arbiter.memberships"))
    assert postgres_error(failure.value).sqlstate == "22P02"


def test_tenant_and_object_identity_are_immutable(store: Store) -> None:
    with store.operator.begin() as connection, pytest.raises(DBAPIError) as failure:
        set_context(connection, store.tenant_a)
        connection.execute(
            text("UPDATE arbiter.memberships SET tenant_id=:other WHERE id=:id"),
            {"other": store.tenant_b, "id": store.member_a},
        )
    assert postgres_error(failure.value).sqlstate == "42501"
    with store.migration.begin() as connection, pytest.raises(DBAPIError) as failure:
        set_context(connection, store.tenant_a)
        connection.execute(
            text("UPDATE arbiter.memberships SET tenant_id=:other WHERE id=:id"),
            {"other": store.tenant_b, "id": store.member_a},
        )
    assert postgres_error(failure.value).sqlstate == "42501"
    with store.migration.begin() as connection, pytest.raises(DBAPIError) as failure:
        set_context(connection, store.tenant_a)
        connection.execute(
            text("UPDATE arbiter.memberships SET id=:other WHERE id=:id"),
            {"other": uuid4(), "id": store.member_a},
        )
    # The existing FK may reject first; use an unreferenced row to exercise the trigger below.
    assert postgres_error(failure.value).sqlstate in {"23503", "23514"}
    with store.migration.begin() as connection, pytest.raises(DBAPIError) as failure:
        set_context(connection, store.tenant_a)
        connection.execute(
            text("UPDATE arbiter.audit_events SET id=:other WHERE id=:id"),
            {"other": uuid4(), "id": store.audit_a},
        )
    assert postgres_error(failure.value).sqlstate == "23514"


@pytest.mark.parametrize("rollback", [False, True])
def test_single_connection_pool_clears_context_after_commit_and_rollback(
    store: Store, rollback: bool
) -> None:
    with tenant_transaction(store.runtime, TenantContext(store.tenant_a)) as transaction:
        pid: int = transaction.connection().execute(text("SELECT pg_backend_pid()")).scalar_one()
    if rollback:
        with pytest.raises(ValueError, match="abort fixture"):
            with tenant_transaction(store.runtime, TenantContext(store.tenant_a)) as transaction:
                assert (
                    transaction.connection().execute(text("SELECT pg_backend_pid()")).scalar_one()
                    == pid
                )
                raise ValueError("abort fixture")
    with store.runtime.begin() as connection:
        assert connection.execute(text("SELECT pg_backend_pid()")).scalar_one() == pid
        assert (
            connection.execute(
                text("SELECT NULLIF(current_setting('arbiter.tenant_id', true), '')")
            ).scalar_one()
            is None
        )
        assert connection.execute(text("SELECT id FROM arbiter.memberships")).all() == []
    with tenant_transaction(store.runtime, TenantContext(store.tenant_b)) as transaction:
        assert transaction.connection().execute(text("SELECT pg_backend_pid()")).scalar_one() == pid
        assert MembershipRepository(transaction).get(store.member_a) is None
        assert MembershipRepository(transaction).get(store.member_b) is not None
    with store.runtime.begin() as connection:
        assert connection.execute(text("SELECT id FROM arbiter.memberships")).all() == []


def test_repositories_reject_expired_or_changed_transaction(store: Store) -> None:
    with tenant_transaction(store.runtime, TenantContext(store.tenant_a)) as transaction:
        repository = MembershipRepository(transaction)
        transaction.connection().execute(
            text("SELECT set_config('arbiter.tenant_id', :tenant, true)"),
            {"tenant": str(store.tenant_b)},
        )
        with pytest.raises(RuntimeError, match="context changed"):
            repository.get(store.member_b)
    with pytest.raises(RuntimeError, match="transaction is closed"):
        repository.get(store.member_a)


def test_session_scope_poison_is_rejected_and_connection_discarded(store: Store) -> None:
    # Deliberate hostile fixture only: production must never set session-wide context.
    with store.runtime.begin() as connection:
        old_pid: int = connection.execute(text("SELECT pg_backend_pid()")).scalar_one()
        connection.execute(
            text("SELECT set_config('arbiter.tenant_id', :tenant, false)"),
            {"tenant": str(store.tenant_a)},
        )
    with pytest.raises(RuntimeError, match="unexpected session tenant context"):
        with tenant_transaction(store.runtime, TenantContext(store.tenant_b)):
            pytest.fail("poisoned session was accepted")
    with store.runtime.begin() as connection:
        assert connection.execute(text("SELECT pg_backend_pid()")).scalar_one() != old_pid
        assert connection.execute(text("SELECT id FROM arbiter.memberships")).all() == []


def test_policy_and_grant_catalog_matches_security_contract(store: Store) -> None:
    with store.migration.begin() as connection:
        rows = connection.execute(
            text("""
            SELECT relname, relrowsecurity, relforcerowsecurity, pg_get_userbyid(relowner)
            FROM pg_class JOIN pg_namespace ON pg_namespace.oid=relnamespace
            WHERE nspname='arbiter' AND relkind='r' ORDER BY relname
        """)
        ).all()
        assert rows == [
            ("accounting_events", True, True, "arbiter_migration"),
            ("api_keys", True, True, "arbiter_migration"),
            ("audit_events", True, True, "arbiter_migration"),
            ("budget_windows", True, True, "arbiter_migration"),
            ("capacity_clearances", True, True, "arbiter_migration"),
            ("dispatched_provider_bindings", True, True, "arbiter_migration"),
            ("idempotency_tombstones", True, True, "arbiter_migration"),
            ("memberships", True, True, "arbiter_migration"),
            ("model_registry_journal", False, False, "arbiter_migration"),
            ("principals", False, False, "arbiter_migration"),
            ("provider_model_bindings", False, False, "arbiter_migration"),
            ("provider_models", False, False, "arbiter_migration"),
            ("quota_windows", True, True, "arbiter_migration"),
            ("requests", True, True, "arbiter_migration"),
            ("reservations", True, True, "arbiter_migration"),
            ("tenant_policies", True, True, "arbiter_migration"),
            ("tenants", True, True, "arbiter_migration"),
        ]
        assert (
            connection.execute(
                text("""
            SELECT count(*) FROM information_schema.columns
            WHERE table_schema='arbiter' AND column_name='tenant_id' AND is_nullable='NO'
        """)
            ).scalar_one()
            == 13
        )
        assert (
            connection.execute(
                text("""
            SELECT count(*) FROM pg_policies WHERE schemaname='arbiter'
                AND policyname='tenant_ownership' AND permissive='RESTRICTIVE'
                AND qual IS NOT NULL AND with_check IS NOT NULL
        """)
            ).scalar_one()
            == 10
        )
        assert (
            connection.execute(
                text("""
            SELECT count(*) FROM pg_policies WHERE schemaname='arbiter'
                AND policyname='maintenance_clearance_access'
                AND tablename='capacity_clearances'
        """)
            ).scalar_one()
            == 1
        )
        assert (
            connection.execute(
                text("""
            SELECT count(*) FROM pg_class c, LATERAL aclexplode(c.relacl) a
            WHERE c.relnamespace='arbiter'::regnamespace
                AND c.relname='capacity_clearances'
                AND a.grantee=(SELECT oid FROM pg_roles WHERE rolname='arbiter_runtime')
        """)
            ).scalar_one()
            == 0
        )
        assert (
            connection.execute(
                text("""
            SELECT count(*) FROM pg_auth_members
            WHERE member=(SELECT oid FROM pg_roles WHERE rolname='arbiter_runtime')
        """)
            ).scalar_one()
            == 0
        )
        assert connection.execute(
            text("""
            SELECT rolsuper, rolbypassrls FROM pg_roles WHERE rolname='arbiter_runtime'
        """)
        ).one() == (False, False)
        assert (
            connection.execute(
                text("""
            SELECT prosecdef FROM pg_proc JOIN pg_namespace n ON n.oid=pronamespace
            WHERE n.nspname='arbiter' AND proname='reject_ownership_change'
        """)
            ).scalar_one()
            is False
        )


def test_production_pool_factory_uses_only_runtime_credentials() -> None:
    engine = runtime_engine(DatabaseSettings())
    try:
        assert engine.url.username == "arbiter_runtime"
        assert isinstance(engine.pool, QueuePool) and engine.pool.size() == 2
        with tenant_transaction(engine, TenantContext(uuid4())) as transaction:
            assert (
                transaction.connection().execute(text("SELECT current_user")).scalar_one()
                == "arbiter_runtime"
            )
            assert TenantRepository(transaction).get() is None
    finally:
        engine.dispose()


@pytest.mark.parametrize("failure_stage", ["deferred_fk", "enable"])
def test_fixture_audit_cleanup_failure_cannot_commit_a_disabled_guard(
    store: Store, failure_stage: str
) -> None:
    def fail_enable(*args: object) -> None:
        if args[2] == "ALTER TABLE arbiter.audit_events ENABLE TRIGGER retention_delete_guard":
            raise RuntimeError("fixture guard restoration interrupted")

    with store.migration.begin() as connection:
        set_context(connection, store.tenant_a)
        before: Sequence[UUID] = (
            connection.execute(text("SELECT id FROM arbiter.audit_events ORDER BY id"))
            .scalars()
            .all()
        )
        if failure_stage == "deferred_fk":
            # This table is created and dropped in this transaction; it never persists.
            connection.execute(
                text("""
                    CREATE TABLE arbiter.fixture_audit_cleanup_reference (
                        tenant_id uuid NOT NULL, audit_id uuid NOT NULL,
                        FOREIGN KEY (tenant_id,audit_id)
                            REFERENCES arbiter.audit_events(tenant_id,id)
                            DEFERRABLE INITIALLY DEFERRED
                    )
                """)
            )
            connection.execute(
                text("INSERT INTO arbiter.fixture_audit_cleanup_reference VALUES (:tenant,:id)"),
                {"tenant": store.tenant_a, "id": store.audit_a},
            )
            with pytest.raises(DBAPIError) as failure:
                delete_fixture_audits(connection, store.tenant_a)
            assert postgres_error(failure.value).sqlstate == "23503"
            connection.execute(text("SET CONSTRAINTS ALL IMMEDIATE"))
            connection.execute(text("DROP TABLE arbiter.fixture_audit_cleanup_reference"))
        else:
            event.listen(connection, "before_cursor_execute", fail_enable)
            try:
                with pytest.raises(RuntimeError, match="fixture guard restoration interrupted"):
                    delete_fixture_audits(connection, store.tenant_a)
            finally:
                event.remove(connection, "before_cursor_execute", fail_enable)
        assert (
            connection.execute(text("SELECT id FROM arbiter.audit_events ORDER BY id"))
            .scalars()
            .all()
            == before
        )
        # Catch the helper failure, then deliberately commit the outer transaction.
    with store.migration.begin() as connection:
        assert (
            connection.execute(
                text("""
                SELECT tgenabled FROM pg_trigger
                WHERE tgrelid='arbiter.audit_events'::regclass
                    AND tgname='retention_delete_guard'
            """)
            ).scalar_one()
            == "O"
        )
    with store.migration.begin() as connection, pytest.raises(DBAPIError) as denied:
        set_context(connection, store.tenant_a)
        connection.execute(
            text("DELETE FROM arbiter.audit_events WHERE tenant_id=:tenant"),
            {"tenant": store.tenant_a},
        )
    assert postgres_error(denied.value).sqlstate == "42501"
