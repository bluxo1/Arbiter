"""Provision fixed PostgreSQL roles before migrations, using only a local command."""

import psycopg
from psycopg import sql

from arbiter.config import DatabaseRole, DatabaseSettings

ROLES: tuple[DatabaseRole, ...] = ("migration", "operator", "runtime")
LOOKUP_ROLE = "arbiter_identity_lookup"
KEY_ROLE = "arbiter_key_writer"
KEY_LOOKUP_ROLE = "arbiter_key_lookup"


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
            memberships = connection.execute(
                "SELECT parent.rolname FROM pg_auth_members m "
                "JOIN pg_roles r ON r.oid = m.member JOIN pg_roles parent ON parent.oid=m.roleid "
                "WHERE r.rolname = %s",
                (name,),
            ).fetchall()
            allowed = {LOOKUP_ROLE, KEY_ROLE, KEY_LOOKUP_ROLE} if role == "migration" else set()
            if any(row[0] not in allowed for row in memberships):
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
        # A non-login owner for the one pre-context membership lookup. Runtime/operator
        # cannot SET ROLE to it. Only the trusted migration role can manage its function.
        if (
            connection.execute("SELECT 1 FROM pg_roles WHERE rolname=%s", (LOOKUP_ROLE,)).fetchone()
            is None
        ):
            connection.execute("CREATE ROLE arbiter_identity_lookup")
        if (
            connection.execute(
                "SELECT 1 FROM pg_auth_members WHERE member=(SELECT oid FROM pg_roles "
                "WHERE rolname=%s)",
                (LOOKUP_ROLE,),
            ).fetchone()
            is not None
        ):
            raise ValueError("unexpected identity lookup owner membership")
        connection.execute(
            "ALTER ROLE arbiter_identity_lookup WITH NOLOGIN NOSUPERUSER NOCREATEDB "
            "NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS PASSWORD NULL"
        )
        connection.execute(
            "GRANT arbiter_identity_lookup TO arbiter_migration WITH INHERIT FALSE, SET TRUE"
        )
        if (
            connection.execute("SELECT 1 FROM pg_roles WHERE rolname=%s", (KEY_ROLE,)).fetchone()
            is None
        ):
            connection.execute("CREATE ROLE arbiter_key_writer")
        if (
            connection.execute(
                "SELECT 1 FROM pg_auth_members WHERE member="
                "(SELECT oid FROM pg_roles WHERE rolname=%s)",
                (KEY_ROLE,),
            ).fetchone()
            is not None
        ):
            raise ValueError("unexpected key writer owner membership")
        connection.execute(
            "ALTER ROLE arbiter_key_writer WITH NOLOGIN NOSUPERUSER NOCREATEDB "
            "NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS PASSWORD NULL"
        )
        connection.execute(
            "GRANT arbiter_key_writer TO arbiter_migration WITH INHERIT FALSE, SET TRUE"
        )
        if (
            connection.execute(
                "SELECT 1 FROM pg_roles WHERE rolname=%s", (KEY_LOOKUP_ROLE,)
            ).fetchone()
            is None
        ):
            connection.execute("CREATE ROLE arbiter_key_lookup")
        if (
            connection.execute(
                "SELECT 1 FROM pg_auth_members WHERE member="
                "(SELECT oid FROM pg_roles WHERE rolname=%s)",
                (KEY_LOOKUP_ROLE,),
            ).fetchone()
            is not None
        ):
            raise ValueError("unexpected key lookup owner membership")
        connection.execute(
            "ALTER ROLE arbiter_key_lookup WITH NOLOGIN NOSUPERUSER NOCREATEDB "
            "NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS PASSWORD NULL"
        )
        connection.execute(
            "GRANT arbiter_key_lookup TO arbiter_migration WITH INHERIT FALSE, SET TRUE"
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
