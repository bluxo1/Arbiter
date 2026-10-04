"""Explicitly privileged checks on newly created, disposable PostgreSQL databases.

Never downgrade the application database. The bootstrap secret is mounted only
for this dedicated test invocation, never into the API or ordinary isolation tests.
"""

import os
from collections.abc import Iterator
from uuid import uuid4

import psycopg
import pytest
from alembic import command
from alembic.config import Config
from psycopg import sql
from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine
from sqlalchemy.exc import DBAPIError
from sqlalchemy.pool import NullPool
from test_accounting_persistence import bundle_values, insert_bundle
from test_reservation_transactions import ReservationStore
from test_tenant_isolation import postgres_error, set_context

from arbiter.config import DatabaseSettings
from arbiter.governance.capacity import CapacityGate, CapacityService
from arbiter.governance.dispatch import DispatchService
from arbiter.governance.release import ReleaseService
from arbiter.persistence.workload import KeyBinding
from arbiter.providers.double import DeterministicProvider

pytestmark = pytest.mark.skipif(
    os.environ.get("ARBITER_TEST_MIGRATIONS") != "1",
    reason="requires explicit bootstrap credential and disposable database permission",
)


@pytest.fixture
def disposable_database() -> Iterator[Engine]:
    settings = DatabaseSettings()
    name = f"arbiter_migration_test_{uuid4().hex}"
    # PostgreSQL requires CREATE/DROP DATABASE outside a transaction. These are
    # administrative operations, never autocommit tenant queries.
    with psycopg.connect(
        host=settings.host,
        port=settings.port,
        dbname=settings.name,
        user="arbiter_bootstrap",
        password=settings.password("bootstrap").get_secret_value(),
        connect_timeout=5,
        autocommit=True,
    ) as admin:
        admin.execute(sql.SQL("CREATE DATABASE {}").format(sql.Identifier(name)))
        engine = create_engine(
            settings.url("migration").set(database=name),
            poolclass=NullPool,
            hide_parameters=True,
            connect_args={"connect_timeout": 5, "options": "-c statement_timeout=10000"},
        )
        try:
            admin.execute(
                sql.SQL("REVOKE ALL ON DATABASE {} FROM PUBLIC").format(sql.Identifier(name))
            )
            admin.execute(
                sql.SQL("GRANT CONNECT, CREATE ON DATABASE {} TO arbiter_migration").format(
                    sql.Identifier(name)
                )
            )
            admin.execute(
                sql.SQL(
                    "GRANT CONNECT ON DATABASE {} TO "
                    "arbiter_runtime, arbiter_operator, arbiter_maintenance"
                ).format(sql.Identifier(name))
            )
            with psycopg.connect(
                host=settings.host,
                port=settings.port,
                dbname=name,
                user="arbiter_bootstrap",
                password=settings.password("bootstrap").get_secret_value(),
                connect_timeout=5,
            ) as initial:
                initial.execute("REVOKE ALL ON SCHEMA public FROM PUBLIC")
                initial.execute("GRANT USAGE, CREATE ON SCHEMA public TO arbiter_migration")
            yield engine
        finally:
            engine.dispose()
            # Only this freshly generated database name can be dropped, without FORCE.
            admin.execute(sql.SQL("DROP DATABASE {}").format(sql.Identifier(name)))


def migrate_to(engine: Engine, revision: str, *, downgrade: bool = False) -> None:
    with engine.begin() as connection:
        config = Config("alembic.ini")
        config.attributes["connection"] = connection
        if downgrade:
            command.downgrade(config, revision)
        else:
            command.upgrade(config, revision)


def test_history_retention_upgrade_privileges_and_round_trip(disposable_database: Engine) -> None:
    migrate_to(disposable_database, "0020_request_retention")
    migrate_to(disposable_database, "head")
    with disposable_database.begin() as connection:
        assert (
            connection.execute(text("SELECT version_num FROM public.alembic_version")).scalar_one()
            == "0021_history_retention"
        )
        row = connection.execute(
            text(
                "SELECT prosecdef,proconfig,pg_get_userbyid(proowner) AS owner FROM pg_proc "
                "WHERE oid='arbiter.retire_history(uuid,timestamptz,uuid,integer)'::regprocedure"
            )
        ).one()
        assert row.prosecdef and row.owner == "arbiter_retention_writer"
        assert row.proconfig == ["search_path=pg_catalog"]
        assert not connection.execute(
            text(
                "SELECT EXISTS (SELECT 1 FROM pg_proc p,"
                "LATERAL aclexplode(COALESCE(p.proacl,acldefault('f',p.proowner))) a "
                "WHERE p.oid='arbiter.retire_history(uuid,timestamptz,uuid,integer)'::regprocedure "
                "AND a.grantee=0 AND a.privilege_type='EXECUTE')"
            )
        ).scalar_one()
        for role in ("arbiter_runtime", "arbiter_maintenance"):
            assert not connection.execute(
                text(
                    "SELECT has_function_privilege(:role,"
                    "'arbiter.retire_history(uuid,timestamptz,uuid,integer)','EXECUTE')"
                ),
                {"role": role},
            ).scalar_one()
        assert connection.execute(
            text(
                "SELECT has_function_privilege('arbiter_operator',"
                "'arbiter.retire_history(uuid,timestamptz,uuid,integer)','EXECUTE')"
            )
        ).scalar_one()
        for table in (
            "quota_windows",
            "budget_windows",
            "audit_events",
            "api_keys",
            "tenant_policies",
        ):
            assert connection.execute(
                text(
                    "SELECT relrowsecurity AND relforcerowsecurity FROM pg_class "
                    "WHERE oid=CAST(:table AS regclass)"
                ),
                {"table": "arbiter." + table},
            ).scalar_one()
            assert not connection.execute(
                text("SELECT has_table_privilege('arbiter_runtime',:table,'DELETE,TRUNCATE')"),
                {"table": "arbiter." + table},
            ).scalar_one()
        for table in ("quota_windows", "budget_windows"):
            assert connection.execute(
                text("SELECT has_table_privilege('arbiter_retention_writer',:table,'DELETE')"),
                {"table": "arbiter." + table},
            ).scalar_one()
            assert not connection.execute(
                text(
                    "SELECT has_table_privilege('arbiter_retention_writer',"
                    ":table,'UPDATE,TRUNCATE,INSERT')"
                ),
                {"table": "arbiter." + table},
            ).scalar_one()
        assert not connection.execute(
            text(
                "SELECT has_table_privilege('arbiter_retention_writer','arbiter.api_keys','DELETE')"
            )
        ).scalar_one()
        assert (
            connection.execute(
                text(
                    "SELECT count(*) FROM pg_constraint WHERE contype='f' AND confdeltype='c' "
                    "AND confrelid IN ('arbiter.quota_windows'::regclass,"
                    "'arbiter.budget_windows'::regclass,'arbiter.audit_events'::regclass)"
                )
            ).scalar_one()
            == 0
        )
    migrate_to(disposable_database, "0020_request_retention", downgrade=True)
    with disposable_database.begin() as connection:
        assert (
            connection.execute(
                text(
                    "SELECT to_regprocedure"
                    "('arbiter.retire_history(uuid,timestamptz,uuid,integer)')"
                )
            ).scalar_one()
            is None
        )
        assert not connection.execute(
            text(
                "SELECT has_table_privilege('arbiter_retention_writer',"
                "'arbiter.quota_windows','DELETE')"
            )
        ).scalar_one()
    migrate_to(disposable_database, "head")


def test_retention_migration_from_previous_grants_rls_and_round_trip(
    disposable_database: Engine,
) -> None:
    migrate_to(disposable_database, "0019_reserved_provider_binding")
    migrate_to(disposable_database, "0020_request_retention")
    with disposable_database.begin() as connection:
        assert (
            connection.execute(text("SELECT version_num FROM public.alembic_version")).scalar_one()
            == "0020_request_retention"
        )
        assert connection.execute(
            text(
                "SELECT relrowsecurity AND relforcerowsecurity FROM pg_class "
                "WHERE oid='arbiter.idempotency_tombstones'::regclass"
            )
        ).scalar_one()
        assert (
            connection.execute(
                text(
                    "SELECT pg_get_userbyid(proowner) FROM pg_proc WHERE "
                    "oid='arbiter.retire_requests(uuid,uuid,timestamptz,uuid,integer)'::regprocedure"
                )
            ).scalar_one()
            == "arbiter_retention_writer"
        )
        for role in ("arbiter_runtime", "arbiter_maintenance"):
            assert not connection.execute(
                text(
                    "SELECT "
                    "has_function_privilege(:role,'arbiter.retire_requests(uuid,uuid,timestamptz,uuid,integer)','EXECUTE')"
                ),
                {"role": role},
            ).scalar_one()
        for table in (
            "requests",
            "reservations",
            "accounting_events",
            "audit_events",
            "idempotency_tombstones",
        ):
            assert not connection.execute(
                text("SELECT has_table_privilege('arbiter_runtime',:table,'DELETE,TRUNCATE')"),
                {"table": "arbiter." + table},
            ).scalar_one()
        for table in ("quota_windows", "budget_windows"):
            assert not connection.execute(
                text(
                    "SELECT "
                    "has_table_privilege('arbiter_retention_writer',:table,'INSERT,UPDATE,DELETE,TRUNCATE')"
                ),
                {"table": "arbiter." + table},
            ).scalar_one()
        assert (
            connection.execute(
                text(
                    "SELECT count(*) FROM pg_auth_members WHERE member=(SELECT oid "
                    "FROM pg_roles WHERE rolname='arbiter_retention_writer')"
                )
            ).scalar_one()
            == 0
        )
        assert connection.execute(
            text(
                "SELECT NOT rolcanlogin AND NOT rolbypassrls AND NOT rolsuper "
                "FROM pg_roles WHERE rolname='arbiter_retention_writer'"
            )
        ).scalar_one()
        for function in ("rate_preflight_live", "reserve_request_live"):
            signature = (
                f"arbiter.{function}(uuid,uuid,text,bytea,integer,text,bytea,integer,text,integer)"
            )
            assert not connection.execute(
                text("SELECT has_function_privilege('arbiter_runtime',:function,'EXECUTE')"),
                {"function": signature},
            ).scalar_one()
    migrate_to(disposable_database, "0019_reserved_provider_binding", downgrade=True)
    migrate_to(disposable_database, "head")


def test_maintenance_recovery_migration_restricts_discovery_and_round_trips(
    disposable_database: Engine,
) -> None:
    engine = disposable_database
    migrate_to(engine, "head")
    with engine.begin() as connection:
        assert connection.execute(
            text("SELECT version_num FROM public.alembic_version")
        ).scalar_one() == ("0021_history_retention")
        assert connection.execute(
            text("""
                SELECT c.relrowsecurity AND c.relforcerowsecurity
                FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
                WHERE n.nspname='arbiter' AND c.relname='capacity_clearances'
            """)
        ).scalar_one()
        assert (
            connection.execute(
                text("""
                SELECT pg_get_userbyid(proowner) FROM pg_proc
                WHERE oid='arbiter.maintenance_candidates(text)'::regprocedure
            """)
            ).scalar_one()
            == "arbiter_maintenance_worker"
        )
    settings = DatabaseSettings()
    runtime, maintenance = (
        create_engine(
            settings.url(role).set(database=engine.url.database),
            poolclass=NullPool,
            hide_parameters=True,
        )
        for role in ("runtime", "maintenance")
    )
    try:
        with runtime.connect() as connection:
            assert not connection.execute(
                text(
                    "SELECT has_function_privilege(current_user, "
                    "'arbiter.maintenance_candidates(text)', 'EXECUTE')"
                )
            ).scalar_one()
            assert not connection.execute(
                text(
                    "SELECT has_table_privilege(current_user, "
                    "'arbiter.capacity_clearances', 'SELECT,INSERT')"
                )
            ).scalar_one()
        with maintenance.connect() as connection:
            assert (
                connection.execute(
                    text("SELECT count(*) FROM arbiter.maintenance_candidates('unknown')")
                ).scalar_one()
                == 0
            )
            assert not connection.execute(
                text("SELECT has_table_privilege(current_user, 'arbiter.requests', 'SELECT')")
            ).scalar_one()
    finally:
        runtime.dispose()
        maintenance.dispose()
    migrate_to(engine, "0016_rate_preflight", downgrade=True)
    migrate_to(engine, "head")


def test_dispatch_upgrade_preserves_reservation_and_refuses_lossy_downgrade(
    disposable_database: Engine,
) -> None:
    engine = disposable_database
    migrate_to(engine, "0013_undispatched_release")
    settings = DatabaseSettings()
    runtime, operator = (
        create_engine(
            settings.url(role).set(database=engine.url.database),
            poolclass=NullPool,
            hide_parameters=True,
        )
        for role in ("runtime", "operator")
    )
    model, alias = uuid4(), "dispatch-migration-" + uuid4().hex
    store = ReservationStore(runtime, operator, engine, model, alias)
    try:
        with engine.begin() as connection:
            connection.execute(
                text("""
                INSERT INTO arbiter.provider_models
                    (id,alias,adapter,model_digest,context_cap,output_cap,credit_charge,
                     revision,active)
                VALUES (:id,:alias,'ollama',:digest,4096,256,10,1,true)
            """),
                {"id": model, "alias": alias, "digest": "sha256:" + "d" * 64},
            )
        actor = store.actor()
        gate = CapacityGate(1)
        lease = CapacityService(store.service(), ReleaseService(runtime), gate).reserve_and_acquire(
            actor.credential, uuid4().hex, store.request()
        )
        assert store.totals(actor) == (0, 1, 0, 10)
        migrate_to(engine, "head")
        with engine.begin() as connection:
            set_context(connection, actor.tenant)
            assert connection.execute(
                text("""
                SELECT state,dispatch_audit_id FROM arbiter.requests
                WHERE tenant_id=:tenant AND id=:request
            """),
                {"tenant": actor.tenant, "request": lease.result.request_id},
            ).one() == ("reserved", None)
        DispatchService(runtime).authorize(lease)
        assert store.totals(actor) == (1, 0, 10, 0) and gate.occupied == 1
        with pytest.raises(DBAPIError) as failure:
            migrate_to(engine, "0013_undispatched_release", downgrade=True)
        assert postgres_error(failure.value).sqlstate == "23514"
        with engine.begin() as connection:
            assert (
                connection.execute(
                    text("SELECT version_num FROM public.alembic_version")
                ).scalar_one()
                == "0021_history_retention"
            )
            set_context(connection, actor.tenant)
            assert connection.execute(
                text("""
                SELECT state,dispatch_audit_id IS NOT NULL FROM arbiter.requests
                WHERE tenant_id=:tenant AND id=:request
            """),
                {"tenant": actor.tenant, "request": lease.result.request_id},
            ).one() == ("dispatched", True)
    finally:
        runtime.dispose()
        operator.dispose()


def test_terminal_upgrade_preserves_dispatched_request_and_refuses_evidence_loss(
    disposable_database: Engine,
) -> None:
    engine = disposable_database
    migrate_to(engine, "0014_dispatch_authorization")
    settings = DatabaseSettings()
    runtime, operator = (
        create_engine(
            settings.url(role).set(database=engine.url.database),
            poolclass=NullPool,
            hide_parameters=True,
        )
        for role in ("runtime", "operator")
    )
    model, alias = uuid4(), "terminal-migration-" + uuid4().hex
    store = ReservationStore(runtime, operator, engine, model, alias)
    try:
        with engine.begin() as connection:
            connection.execute(
                text("""
                INSERT INTO arbiter.provider_models
                    (id,alias,adapter,model_digest,context_cap,output_cap,credit_charge,
                     revision,active)
                VALUES (:id,:alias,'ollama',:digest,4096,256,10,1,true)
            """),
                {"id": model, "alias": alias, "digest": "sha256:" + "d" * 64},
            )
        actor, gate, original = store.actor(), CapacityGate(1), store.request()
        lease = CapacityService(store.service(), ReleaseService(runtime), gate).reserve_and_acquire(
            actor.credential, uuid4().hex, original
        )
        DispatchService(runtime).authorize(lease)
        with engine.begin() as connection:
            set_context(connection, actor.tenant)
            previous: str = connection.execute(
                text("""
                SELECT to_jsonb(r)::text FROM arbiter.requests r
                WHERE tenant_id=:tenant AND id=:request
            """),
                {"tenant": actor.tenant, "request": lease.result.request_id},
            ).scalar_one()
        migrate_to(engine, "head")
        with engine.begin() as connection:
            set_context(connection, actor.tenant)
            assert (
                connection.execute(
                    text("""
                SELECT (to_jsonb(r)-ARRAY['terminal_audit_id','terminal_action'])::text
                FROM arbiter.requests r WHERE tenant_id=:tenant AND id=:request
            """),
                    {"tenant": actor.tenant, "request": lease.result.request_id},
                ).scalar_one()
                == previous
            )
        result = DispatchService(runtime).run_double_once(
            lease,
            original,
            DeterministicProvider(model, "sha256:" + "d" * 64, 256),
            store.fingerprint,
        )
        assert result.state == "succeeded" and store.totals(actor) == (1, 0, 10, 0)
        assert gate.occupied == 0
        with pytest.raises(DBAPIError) as failure:
            migrate_to(engine, "0014_dispatch_authorization", downgrade=True)
        assert postgres_error(failure.value).sqlstate == "23514"
        with engine.begin() as connection:
            assert (
                connection.execute(
                    text("SELECT version_num FROM public.alembic_version")
                ).scalar_one()
                == "0021_history_retention"
            )
    finally:
        runtime.dispose()
        operator.dispose()


def test_release_upgrade_preserves_reservation_and_refuses_lossy_downgrade(
    disposable_database: Engine,
) -> None:
    engine = disposable_database
    migrate_to(engine, "0012_reservation_transactions")
    settings = DatabaseSettings()
    runtime, operator = (
        create_engine(
            settings.url(role).set(database=engine.url.database),
            poolclass=NullPool,
            hide_parameters=True,
        )
        for role in ("runtime", "operator")
    )
    model, alias = uuid4(), "reserve-fixture-" + uuid4().hex
    store = ReservationStore(runtime, operator, engine, model, alias)
    try:
        with engine.begin() as connection:
            connection.execute(
                text("""
                INSERT INTO arbiter.provider_models
                (id,alias,adapter,model_digest,context_cap,output_cap,credit_charge,revision,active)
                VALUES (:id,:alias,'ollama',:digest,4096,256,10,1,true)
            """),
                {"id": model, "alias": alias, "digest": "sha256:" + "d" * 64},
            )
        actor = store.actor()
        result = store.service().reserve(actor.credential, uuid4().hex, store.request())
        with engine.begin() as connection:
            set_context(connection, actor.tenant)
            before: str = connection.execute(
                text("""
                SELECT to_jsonb(r)::text FROM arbiter.requests r WHERE tenant_id=:t AND id=:id
            """),
                {"t": actor.tenant, "id": result.request_id},
            ).scalar_one()
        # A nonempty 0012 reservation remains representable on a safe round trip.
        migrate_to(engine, "head")
        migrate_to(engine, "0012_reservation_transactions", downgrade=True)
        migrate_to(engine, "head")
        with engine.begin() as connection:
            set_context(connection, actor.tenant)
            row = connection.execute(
                text("""
                SELECT release_audit_id,
                    (to_jsonb(r)-ARRAY['release_audit_id','release_action',
                        'dispatch_audit_id','dispatch_action',
                        'terminal_audit_id','terminal_action'])::text
                FROM arbiter.requests r WHERE tenant_id=:t AND id=:id
            """),
                {"t": actor.tenant, "id": result.request_id},
            ).one()
            assert row[0] is None and row[1] == before
        released = ReleaseService(runtime).release(
            KeyBinding(actor.key, actor.tenant, ("inference:write",)),
            result.request_id,
            "cancelled",
        )
        assert released.changed and store.totals(actor) == (0, 0, 0, 0)
        with pytest.raises(DBAPIError) as failure:
            migrate_to(engine, "0012_reservation_transactions", downgrade=True)
        assert postgres_error(failure.value).sqlstate == "23514"
        with engine.begin() as connection:
            assert (
                connection.execute(
                    text("SELECT version_num FROM public.alembic_version")
                ).scalar_one()
                == "0021_history_retention"
            )
            set_context(connection, actor.tenant)
            assert connection.execute(
                text("""
                SELECT state,release_audit_id IS NOT NULL FROM arbiter.requests
                WHERE tenant_id=:t AND id=:id
            """),
                {"t": actor.tenant, "id": result.request_id},
            ).one() == ("released", True)
    finally:
        runtime.dispose()
        operator.dispose()


def test_reservation_upgrade_preserves_legacy_evidence_and_blocks_lossy_downgrade(
    disposable_database: Engine,
) -> None:
    engine = disposable_database
    migrate_to(engine, "0011_accounting_foundation")
    settings = DatabaseSettings()
    runtime, operator = (
        create_engine(
            settings.url(role).set(database=engine.url.database),
            poolclass=NullPool,
            hide_parameters=True,
        )
        for role in ("runtime", "operator")
    )
    model, alias = uuid4(), "reserve-fixture-" + uuid4().hex
    store = ReservationStore(runtime, operator, engine, model, alias)
    try:
        with engine.begin() as connection:
            connection.execute(
                text("""
                INSERT INTO arbiter.provider_models
                (id,alias,adapter,model_digest,context_cap,output_cap,credit_charge,revision,active)
                VALUES (:id,:alias,'ollama',:digest,4096,256,10,1,true)
            """),
                {"id": model, "alias": alias, "digest": "sha256:" + "d" * 64},
            )
        actor = store.actor()
        with engine.begin() as connection:
            set_context(connection, actor.tenant)
            day, month = connection.execute(
                text("""
                SELECT date_trunc('day',CURRENT_TIMESTAMP AT TIME ZONE 'UTC') AT TIME ZONE 'UTC',
                    date_trunc('month',CURRENT_TIMESTAMP AT TIME ZONE 'UTC') AT TIME ZONE 'UTC'
            """)
            ).one()
            quota, budget = uuid4(), uuid4()
            connection.execute(
                text("""
                INSERT INTO arbiter.quota_windows(id,tenant_id,window_start,reserved)
                VALUES (:id,:tenant,:start,1)
            """),
                {"id": quota, "tenant": actor.tenant, "start": day},
            )
            connection.execute(
                text("""
                INSERT INTO arbiter.budget_windows(id,tenant_id,window_start,reserved)
                VALUES (:id,:tenant,:start,10)
            """),
                {"id": budget, "tenant": actor.tenant, "start": month},
            )
            values = bundle_values(actor.tenant, actor.key, quota, budget, day, month)
            values.update({"model": model, "alias": alias})
            insert_bundle(connection, values)
            legacy: str = connection.execute(
                text("""
                SELECT to_jsonb(r)::text FROM arbiter.requests r WHERE tenant_id=:tenant AND id=:id
            """),
                {"tenant": actor.tenant, "id": values["request"]},
            ).scalar_one()
        migrate_to(engine, "head")
        with engine.begin() as connection:
            set_context(connection, actor.tenant)
            assert (
                connection.execute(
                    text("""
                SELECT reservation_audit_id FROM arbiter.requests WHERE tenant_id=:tenant AND id=:id
            """),
                    {"tenant": actor.tenant, "id": values["request"]},
                ).scalar_one()
                is None
            )
            after: str = connection.execute(
                text("""
                SELECT (to_jsonb(r)-ARRAY[
                    'reservation_audit_id','audit_action','audit_outcome',
                    'release_audit_id','release_action',
                    'dispatch_audit_id','dispatch_action',
                    'terminal_audit_id','terminal_action'])::text
                FROM arbiter.requests r WHERE tenant_id=:tenant AND id=:id
            """),
                {"tenant": actor.tenant, "id": values["request"]},
            ).scalar_one()
            assert legacy == after
        assert store.counts(actor) == (1, 1, 1, 1, 1, 0)
        store.service().reserve(actor.credential, uuid4().hex, store.request())
        assert store.counts(actor) == (1, 1, 2, 2, 2, 1)
        # Context-free FORCE RLS must not hide key-audits from the downgrade safety check.
        with pytest.raises(DBAPIError) as failure:
            migrate_to(engine, "0011_accounting_foundation", downgrade=True)
        assert postgres_error(failure.value).sqlstate == "23514"
        assert store.counts(actor) == (1, 1, 2, 2, 2, 1)
        with engine.begin() as connection:
            assert (
                connection.execute(
                    text("SELECT version_num FROM public.alembic_version")
                ).scalar_one()
                == "0021_history_retention"
            )
    finally:
        runtime.dispose()
        operator.dispose()


@pytest.mark.parametrize("previous", ["0008_tenant_policies", "0009_model_catalog"])
def test_registry_upgrade_preserves_legacy_configuration_without_fabricating_audit(
    disposable_database: Engine, previous: str
) -> None:
    engine = disposable_database
    object_id = uuid4()
    migrate_to(engine, previous)
    with engine.begin() as connection:
        connection.execute(
            text("""
            INSERT INTO arbiter.provider_models
                (id,alias,adapter,model_digest,context_cap,output_cap,credit_charge,revision,active)
            VALUES (:id,'legacy-fixture','ollama',:digest,4096,256,10,4,false)
        """),
            {"id": object_id, "digest": "sha256:" + "a" * 64},
        )
    migrate_to(engine, "head")
    with engine.begin() as connection:
        assert connection.execute(
            text(
                "SELECT id,revision,active,journal_id FROM arbiter.provider_models "
                "WHERE alias='legacy-fixture'"
            )
        ).one() == (object_id, 4, False, None)
        assert (
            connection.execute(
                text("SELECT count(*) FROM arbiter.model_registry_journal")
            ).scalar_one()
            == 0
        )


@pytest.mark.parametrize(
    "previous",
    [
        None,
        "0001_foundation",
        "0002_tenant_isolation",
        "0003_operator_audit",
        "0004_identity_lookup",
        "0005_api_key_creation",
        "0006_api_key_revocation",
        "0007_workload_key_lookup",
        "0008_tenant_policies",
        "0009_model_catalog",
        "0010_model_registry",
        "0011_accounting_foundation",
        "0012_reservation_transactions",
        "0013_undispatched_release",
        "0014_dispatch_authorization",
        "0015_terminal_lifecycle",
    ],
)
def test_migration_empty_and_previous_then_repeat_and_round_trip(
    disposable_database: Engine, previous: str | None
) -> None:
    engine = disposable_database
    if previous is not None:
        migrate_to(engine, previous)
        with engine.begin() as connection:
            assert connection.execute(
                text("SELECT count(*) FROM pg_tables WHERE schemaname='arbiter'")
            ).scalar_one() == (
                0
                if previous == "0001_foundation"
                else 13
                if previous
                in {
                    "0011_accounting_foundation",
                    "0012_reservation_transactions",
                    "0013_undispatched_release",
                    "0014_dispatch_authorization",
                    "0015_terminal_lifecycle",
                }
                else 8
                if previous == "0010_model_registry"
                else 7
                if previous in {"0008_tenant_policies", "0009_model_catalog"}
                else 5
                if previous
                in {"0005_api_key_creation", "0006_api_key_revocation", "0007_workload_key_lookup"}
                else 4
            )
    migrate_to(engine, "head")
    migrate_to(engine, "head")
    with engine.begin() as connection:
        assert (
            connection.execute(text("SELECT version_num FROM public.alembic_version")).scalar_one()
            == "0021_history_retention"
        )
        assert (
            connection.execute(
                text("SELECT count(*) FROM pg_tables WHERE schemaname='arbiter'")
            ).scalar_one()
            == 17
        )
        assert (
            connection.execute(
                text("""
            SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
            WHERE n.nspname='arbiter' AND c.relrowsecurity AND c.relforcerowsecurity
        """)
            ).scalar_one()
            == 13
        )
        assert (
            connection.execute(
                text("""
            SELECT count(*) FROM pg_policies WHERE schemaname='arbiter'
                AND policyname='runtime_audit_actor' AND permissive='RESTRICTIVE'
                AND cmd='INSERT' AND with_check IS NOT NULL
        """)
            ).scalar_one()
            == 1
        )
    # Safe only because this database is disposable and all tenant tables are empty.
    migrate_to(engine, "0001_foundation", downgrade=True)
    migrate_to(engine, "head")
    migrate_to(engine, "base", downgrade=True)
    with engine.begin() as connection:
        assert (
            connection.execute(
                text("SELECT count(*) FROM pg_namespace WHERE nspname='arbiter'")
            ).scalar_one()
            == 0
        )
    migrate_to(engine, "head")


@pytest.mark.parametrize(
    "previous",
    [
        "0002_tenant_isolation",
        "0003_operator_audit",
        "0004_identity_lookup",
        "0005_api_key_creation",
        "0006_api_key_revocation",
        "0007_workload_key_lookup",
        "0008_tenant_policies",
        "0009_model_catalog",
        "0010_model_registry",
        "0011_accounting_foundation",
        "0012_reservation_transactions",
    ],
)
def test_upgrade_preserves_existing_tenant_and_audit(
    disposable_database: Engine,
    previous: str,
) -> None:
    engine = disposable_database
    tenant, event = uuid4(), uuid4()
    migrate_to(engine, previous)
    with engine.begin() as connection:
        connection.execute(
            text("SELECT set_config('arbiter.tenant_id', :tenant, true)"), {"tenant": str(tenant)}
        )
        connection.execute(
            text("INSERT INTO arbiter.tenants (id,status) VALUES (:tenant,'suspended')"),
            {"tenant": tenant},
        )
        connection.execute(
            text("""
            INSERT INTO arbiter.audit_events
                (id,tenant_id,actor_type,actor_reference,action,target_id,policy_revision,outcome)
            VALUES (:event,:tenant,'operator','arbiter_operator','tenant_suspended',
                    :tenant,1,'succeeded')
        """),
            {"event": event, "tenant": tenant},
        )
    migrate_to(engine, "head")
    with engine.begin() as connection:
        connection.execute(
            text("SELECT set_config('arbiter.tenant_id', :tenant, true)"), {"tenant": str(tenant)}
        )
        assert connection.execute(
            text("SELECT id,status FROM arbiter.tenants WHERE tenant_id=:tenant"),
            {"tenant": tenant},
        ).one() == (tenant, "suspended")
        assert connection.execute(
            text("""
            SELECT id,actor_type,action,target_id FROM arbiter.audit_events
            WHERE tenant_id=:tenant
        """),
            {"tenant": tenant},
        ).one() == (event, "operator", "tenant_suspended", tenant)
        for table in (
            "quota_windows",
            "budget_windows",
            "requests",
            "reservations",
            "accounting_events",
        ):
            # Fixed migration-owned identifiers, and authenticated tenant value always bound.
            query = (
                sql.SQL("SELECT count(*) FROM {} WHERE tenant_id=:tenant")
                .format(sql.Identifier("arbiter", table))
                .as_string()
            )
            assert connection.execute(text(query), {"tenant": tenant}).scalar_one() == 0


def test_revocation_upgrade_and_downgrade_preserve_existing_key_state(
    disposable_database: Engine,
) -> None:
    engine = disposable_database
    tenant, principal, member, key, audit = (uuid4() for _ in range(5))
    migrate_to(engine, "0005_api_key_creation")
    with engine.begin() as connection:
        connection.execute(
            text("SELECT set_config('arbiter.tenant_id',:tenant,true)"), {"tenant": str(tenant)}
        )
        connection.execute(text("INSERT INTO arbiter.tenants (id) VALUES (:id)"), {"id": tenant})
        connection.execute(
            text(
                "INSERT INTO arbiter.principals (id,issuer,subject) "
                "VALUES (:id,'https://fixture.invalid','migration-preservation')"
            ),
            {"id": principal},
        )
        connection.execute(
            text(
                "INSERT INTO arbiter.memberships (id,tenant_id,principal_id,role) "
                "VALUES (:id,:tenant,:principal,'admin')"
            ),
            {"id": member, "tenant": tenant, "principal": principal},
        )
        connection.execute(
            text("""
                INSERT INTO arbiter.audit_events (id,tenant_id,actor_type,actor_reference,
                    actor_membership_id,action,target_id,policy_revision,outcome)
                VALUES (:audit,:tenant,'member',:reference,:member,'api_key_created',
                        :key,1,'succeeded')
            """),
            {
                "audit": audit,
                "tenant": tenant,
                "reference": str(member),
                "member": member,
                "key": key,
            },
        )
        connection.execute(
            text("""
                INSERT INTO arbiter.api_keys (id,tenant_id,public_id,label,verifier,pepper_version,
                    scopes,created_at,expires_at,revoked_at,created_by_membership_id,creation_audit_id)
                VALUES (:key,:tenant,:public,'preserved',decode(repeat('ab',32),'hex'),1,
                    ARRAY['usage:read'],now()-interval '60 days',now()-interval '30 days',
                    now()-interval '40 days',:member,:audit)
            """),
            {"key": key, "tenant": tenant, "public": key.hex, "member": member, "audit": audit},
        )
        before = connection.execute(
            text("SELECT * FROM arbiter.api_keys WHERE tenant_id=:tenant"), {"tenant": tenant}
        ).one()
    for revision, downgrade in (("head", False), ("0005_api_key_creation", True), ("head", False)):
        migrate_to(engine, revision, downgrade=downgrade)
        with engine.begin() as connection:
            connection.execute(
                text("SELECT set_config('arbiter.tenant_id',:tenant,true)"), {"tenant": str(tenant)}
            )
            assert (
                connection.execute(
                    text("SELECT * FROM arbiter.api_keys WHERE tenant_id=:tenant"),
                    {"tenant": tenant},
                ).one()
                == before
            )
            assert connection.execute(
                text("SELECT action,target_id FROM arbiter.audit_events WHERE tenant_id=:tenant"),
                {"tenant": tenant},
            ).one() == ("api_key_created", key)
            assert (
                connection.execute(
                    text(
                        "SELECT has_column_privilege('arbiter_runtime',"
                        "'arbiter.api_keys','revoked_at','UPDATE')"
                    )
                ).scalar_one()
                is False
            )
