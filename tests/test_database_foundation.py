"""Opt-in checks against the real Compose PostgreSQL restricted roles."""

import os

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.pool import NullPool

from arbiter.config import DatabaseRole, DatabaseSettings

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
                == "0001_foundation"
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
                == 0
            )
    finally:
        engine.dispose()
