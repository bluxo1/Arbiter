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


@pytest.mark.parametrize("previous", [None, "0001_foundation"])
def test_migration_empty_and_previous_then_repeat_and_round_trip(
    disposable_database: Engine, previous: str | None
) -> None:
    engine = disposable_database
    if previous is not None:
        migrate_to(engine, previous)
        with engine.begin() as connection:
            assert (
                connection.execute(
                    text("SELECT count(*) FROM pg_tables WHERE schemaname='arbiter'")
                ).scalar_one()
                == 0
            )
    migrate_to(engine, "head")
    migrate_to(engine, "head")
    with engine.begin() as connection:
        assert (
            connection.execute(text("SELECT version_num FROM public.alembic_version")).scalar_one()
            == "0002_tenant_isolation"
        )
        assert (
            connection.execute(
                text("SELECT count(*) FROM pg_tables WHERE schemaname='arbiter'")
            ).scalar_one()
            == 4
        )
        assert (
            connection.execute(
                text("""
            SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
            WHERE n.nspname='arbiter' AND c.relrowsecurity AND c.relforcerowsecurity
        """)
            ).scalar_one()
            == 3
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
