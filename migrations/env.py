"""Alembic receives a credentialed connection from the explicit command only."""

from alembic import context
from sqlalchemy.engine import Connection

connection = context.config.attributes.get("connection")
if not isinstance(connection, Connection):
    raise RuntimeError("use python -m arbiter.operations.migrate")

context.configure(connection=connection)
with context.begin_transaction():
    context.run_migrations()
