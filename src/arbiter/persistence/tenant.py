"""Scoped transactions for trusted services; this module does not authenticate callers.

Never construct TenantContext from an unchecked HTTP selector. Identity services
verify identity and active membership first; local operators authenticate separately.
Synchronous persistence must run outside the FastAPI event loop.
"""

from collections.abc import Iterator
from contextlib import contextmanager

from sqlalchemy import create_engine, text
from sqlalchemy.engine import Connection, Engine, Transaction

from arbiter.config import DatabaseSettings
from arbiter.identity.context import TenantContext


class TenantTransaction:
    """Repositories can use this capability only during its original transaction."""

    def __init__(
        self, connection: Connection, transaction: Transaction, context: TenantContext
    ) -> None:
        self._connection = connection
        self._transaction = transaction
        self._context = context

    @property
    def context(self) -> TenantContext:
        return self._context

    def connection(self) -> Connection:
        if not self._transaction.is_active or self._connection.closed:
            raise RuntimeError("tenant transaction is closed")
        # Detect accidental changes before a repository can operate with mismatched authority.
        current: str | None = self._connection.execute(
            text("SELECT NULLIF(current_setting('arbiter.tenant_id', true), '')")
        ).scalar_one()
        if current != str(self._context.tenant_id):
            raise RuntimeError("tenant transaction context changed")
        return self._connection


def runtime_engine(settings: DatabaseSettings) -> Engine:
    return create_engine(
        settings.url("runtime"),
        hide_parameters=True,
        pool_size=2,
        max_overflow=0,
        pool_timeout=5,
        pool_pre_ping=True,
        pool_reset_on_return="rollback",
        connect_args={
            "connect_timeout": 5,
            "options": "-c statement_timeout=5000 -c lock_timeout=5000 "
            "-c idle_in_transaction_session_timeout=10000",
        },
    )


@contextmanager
def tenant_transaction(engine: Engine, context: TenantContext) -> Iterator[TenantTransaction]:
    if not isinstance(context, TenantContext):
        raise TypeError("trusted tenant context is required")
    with engine.connect() as connection:
        with connection.begin() as transaction:
            yield bind_tenant_transaction(connection, transaction, context)


def bind_tenant_transaction(
    connection: Connection, transaction: Transaction, context: TenantContext
) -> TenantTransaction:
    """Bind an already-open transaction after a trusted service establishes authority."""
    if not isinstance(context, TenantContext):
        raise TypeError("trusted tenant context is required")
    if not transaction.is_active or connection.get_transaction() is not transaction:
        raise RuntimeError("active tenant transaction is required")
    inherited: str | None = connection.execute(
        text("SELECT NULLIF(current_setting('arbiter.tenant_id', true), '')")
    ).scalar_one()
    if inherited is not None:
        connection.invalidate()
        raise RuntimeError("unexpected session tenant context")
    connection.execute(
        text("SELECT set_config('arbiter.tenant_id', :tenant_id, true)"),
        {"tenant_id": str(context.tenant_id)},
    )
    return TenantTransaction(connection, transaction, context)
