"""Explicit migration command; never run during API startup."""

from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine
from sqlalchemy.pool import NullPool

from arbiter.config import DatabaseSettings


def migrate() -> None:
    engine = create_engine(
        DatabaseSettings().url("migration"),
        poolclass=NullPool,
        hide_parameters=True,
        connect_args={"connect_timeout": 5, "options": "-c lock_timeout=5000"},
    )
    try:
        with engine.begin() as connection:
            config = Config("alembic.ini")
            config.attributes["connection"] = connection
            command.upgrade(config, "head")
    finally:
        engine.dispose()


def main() -> None:
    try:
        migrate()
    except Exception as error:
        # Driver exceptions can contain connection details; do not print their bodies.
        raise SystemExit(f"migration failed ({type(error).__name__})") from None
    print("database migrations applied")


if __name__ == "__main__":
    main()
