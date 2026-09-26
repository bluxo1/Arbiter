"""Provision fixed PostgreSQL roles before migrations, using only a local command."""

import psycopg
from psycopg import sql

from arbiter.config import DatabaseRole, DatabaseSettings

ROLES: tuple[DatabaseRole, ...] = ("migration", "operator", "runtime")


def bootstrap(settings: DatabaseSettings) -> None:
    with psycopg.connect(
        host=settings.host,
        port=settings.port,
        dbname=settings.name,
        user="arbiter_bootstrap",
        password=settings.password("bootstrap").get_secret_value(),
        connect_timeout=5,
        options="-c statement_timeout=5000 -c lock_timeout=5000",
    ) as connection:
        # Password-bearing utility statements must never appear in server statement logs.
        connection.execute(
            "SELECT set_config('log_statement', 'none', true), "
            "set_config('log_min_error_statement', 'panic', true)"
        )
        for role in ROLES:
            name = f"arbiter_{role}"
            exists = connection.execute(
                "SELECT 1 FROM pg_roles WHERE rolname = %s", (name,)
            ).fetchone()
            if exists is None:
                connection.execute(sql.SQL("CREATE ROLE {}").format(sql.Identifier(name)))
            membership = connection.execute(
                "SELECT 1 FROM pg_auth_members m JOIN pg_roles r ON r.oid = m.member "
                "WHERE r.rolname = %s LIMIT 1",
                (name,),
            ).fetchone()
            if membership is not None:
                raise ValueError("unexpected database role membership")
            # Utility statements do not support bound password parameters. Literal quoting
            # here is psycopg's escaping, never string interpolation into SQL.
            connection.execute(
                sql.SQL(
                    "ALTER ROLE {} WITH LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE "
                    "NOINHERIT NOREPLICATION NOBYPASSRLS PASSWORD {}"
                ).format(
                    sql.Identifier(name), sql.Literal(settings.password(role).get_secret_value())
                )
            )
        connection.execute(
            sql.SQL("REVOKE ALL ON DATABASE {} FROM PUBLIC").format(sql.Identifier(settings.name))
        )
        connection.execute("REVOKE ALL ON SCHEMA public FROM PUBLIC")
        connection.execute("GRANT USAGE, CREATE ON SCHEMA public TO arbiter_migration")
        connection.execute(
            sql.SQL(
                "GRANT CONNECT ON DATABASE {} TO arbiter_migration, arbiter_operator, "
                "arbiter_runtime"
            ).format(sql.Identifier(settings.name))
        )
        connection.execute(
            sql.SQL("GRANT CREATE ON DATABASE {} TO arbiter_migration").format(
                sql.Identifier(settings.name)
            )
        )
        # No automatic grants on future tables: every tenant migration owns its RLS/grants.


def main() -> None:
    try:
        bootstrap(DatabaseSettings())
    except (OSError, ValueError, psycopg.Error) as error:
        raise SystemExit(f"database bootstrap failed ({type(error).__name__})") from None
    print("database roles provisioned")


if __name__ == "__main__":
    main()
