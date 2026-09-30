"""Opt-in checks against the real Compose PostgreSQL restricted roles."""

import os

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.pool import NullPool

from arbiter.config import DatabaseRole, DatabaseSettings


@pytest.mark.parametrize("search_path,code", [(None, "3F000"), ("arbiter", "42501")])
def test_runtime_cannot_run_actual_alembic_upgrade(search_path: str | None, code: str) -> None:
    engine = create_engine(
        DatabaseSettings().url("runtime"), poolclass=NullPool, hide_parameters=True
    )
    try:
        with engine.begin() as connection, pytest.raises(DBAPIError) as failure:
            if search_path is not None:
                # Also prove denial when the caller selects a visible runtime schema.
                connection.execute(text("SET LOCAL search_path = arbiter, pg_catalog"))
            config = Config("alembic.ini")
            config.attributes["connection"] = connection
            command.upgrade(config, "head")
        assert getattr(failure.value.orig, "sqlstate", None) == code
        assert failure.value.statement is not None
        assert "CREATE TABLE alembic_version" in failure.value.statement
    finally:
        engine.dispose()


pytestmark = pytest.mark.skipif(
    os.environ.get("ARBITER_TEST_DATABASE") != "1", reason="requires provisioned real PostgreSQL"
)


@pytest.mark.parametrize("role", ["runtime", "operator"])
def test_restricted_role_privileges(role: DatabaseRole) -> None:
    engine = create_engine(DatabaseSettings().url(role), poolclass=NullPool, hide_parameters=True)
    try:
        with engine.connect() as connection:
            flags = connection.execute(
                text(
                    "SELECT rolsuper, rolbypassrls, rolcreatedb, rolcreaterole "
                    "FROM pg_roles WHERE rolname = current_user"
                )
            ).one()
            assert tuple(flags) == (False, False, False, False)
        for statement in (
            "CREATE TABLE arbiter.forbidden_probe (id integer)",
            "CREATE TABLE public.forbidden_probe (id integer)",
            "CREATE SCHEMA forbidden_probe",
            "SET ROLE arbiter_migration",
            "SET ROLE arbiter_bootstrap",
            "SELECT * FROM public.alembic_version",
        ):
            with engine.begin() as connection, pytest.raises(DBAPIError) as failure:
                connection.execute(text(statement))
            assert getattr(failure.value.orig, "sqlstate", None) == "42501"
    finally:
        engine.dispose()


def test_only_migration_role_owns_schema_and_version_marker() -> None:
    engine = create_engine(DatabaseSettings().url("migration"), poolclass=NullPool)
    try:
        with engine.connect() as connection:
            assert (
                connection.execute(text("SELECT version_num FROM public.alembic_version")).scalar()
                == "0017_maintenance_recovery"
            )
            assert (
                connection.execute(
                    text(
                        "SELECT pg_get_userbyid(nspowner) FROM pg_namespace "
                        "WHERE nspname = 'arbiter'"
                    )
                ).scalar()
                == "arbiter_migration"
            )
            assert (
                connection.execute(
                    text("SELECT count(*) FROM pg_tables WHERE schemaname = 'arbiter'")
                ).scalar()
                == 14
            )
    finally:
        engine.dispose()
