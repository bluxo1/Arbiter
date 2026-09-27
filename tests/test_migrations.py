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
from sqlalchemy.pool import NullPool

from arbiter.config import DatabaseSettings

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
                sql.SQL("GRANT CONNECT ON DATABASE {} TO arbiter_runtime, arbiter_operator").format(
                    sql.Identifier(name)
                )
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


@pytest.mark.parametrize(
    "previous",
    [
        None,
        "0001_foundation",
        "0002_tenant_isolation",
        "0003_operator_audit",
        "0004_identity_lookup",
        "0005_api_key_creation",
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
                else 5
                if previous == "0005_api_key_creation"
                else 4
            )
    migrate_to(engine, "head")
    migrate_to(engine, "head")
    with engine.begin() as connection:
        assert (
            connection.execute(text("SELECT version_num FROM public.alembic_version")).scalar_one()
            == "0006_api_key_revocation"
        )
        assert (
            connection.execute(
                text("SELECT count(*) FROM pg_tables WHERE schemaname='arbiter'")
            ).scalar_one()
            == 5
        )
        assert (
            connection.execute(
                text("""
            SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
            WHERE n.nspname='arbiter' AND c.relrowsecurity AND c.relforcerowsecurity
        """)
            ).scalar_one()
            == 4
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
