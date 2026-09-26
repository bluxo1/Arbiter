"""Separately credentialed local operator access; never imported by HTTP transport."""

from collections.abc import Iterator
from contextlib import contextmanager
from uuid import UUID, uuid4

from sqlalchemy import create_engine, text
from sqlalchemy.engine import Connection, Engine

from arbiter.config import DatabaseSettings
from arbiter.identity.context import TenantContext
from arbiter.persistence.repositories import TenantRecord
from arbiter.persistence.tenant import TenantTransaction, bind_tenant_transaction


class OperatorAccessDenied(PermissionError):
    pass


class ProvisioningNotFound(ValueError):
    pass


def require_operator(connection: Connection) -> None:
    if connection.execute(text("SELECT current_user, session_user")).one() != (
        "arbiter_operator",
        "arbiter_operator",
    ):
        raise OperatorAccessDenied("local operator credential required")


def operator_engine(settings: DatabaseSettings) -> Engine:
    return create_engine(
        settings.url("operator"),
        hide_parameters=True,
        pool_size=1,
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
def operator_transaction(engine: Engine, tenant_id: UUID) -> Iterator[TenantTransaction]:
    with engine.connect() as connection:
        with connection.begin() as transaction:
            # Authenticate the separately held DB credential before establishing tenant scope.
            require_operator(connection)
            yield bind_tenant_transaction(connection, transaction, TenantContext(tenant_id))


class OperatorRepository:
    def __init__(self, transaction: TenantTransaction) -> None:
        self._transaction = transaction

    def _connection(self) -> Connection:
        connection = self._transaction.connection()
        require_operator(connection)
        return connection

    def create_tenant(self) -> None:
        self._connection().execute(
            text("INSERT INTO arbiter.tenants (id) VALUES (:tenant)"),
            {"tenant": self._transaction.context.tenant_id},
        )

    def lock_tenant(self) -> TenantRecord:
        row = (
            self._connection()
            .execute(
                text("""
                SELECT id, status, policy_revision FROM arbiter.tenants
                WHERE tenant_id=:tenant AND id=:tenant FOR UPDATE
            """),
                {"tenant": self._transaction.context.tenant_id},
            )
            .one_or_none()
        )
        if row is None:
            raise ProvisioningNotFound("tenant unavailable")
        return TenantRecord(row.id, row.status, row.policy_revision)

    def set_status(self, status: str) -> None:
        result = self._connection().execute(
            text(
                "UPDATE arbiter.tenants SET status=:status WHERE tenant_id=:tenant AND id=:tenant"
            ),
            {"status": status, "tenant": self._transaction.context.tenant_id},
        )
        if result.rowcount != 1:
            raise ProvisioningNotFound("tenant unavailable")

    def create_member(self, *, issuer: str, subject: str, role: str, object_id: UUID) -> None:
        connection = self._connection()
        # Exact opaque identity pair; no token verification or global-directory enumeration.
        connection.execute(
            text("""
                INSERT INTO arbiter.principals (id, issuer, subject) VALUES (:id, :issuer, :subject)
                ON CONFLICT (issuer, subject) DO NOTHING
            """),
            {"id": uuid4(), "issuer": issuer, "subject": subject},
        )
        principal: UUID = connection.execute(
            text("SELECT id FROM arbiter.principals WHERE issuer=:issuer AND subject=:subject"),
            {"issuer": issuer, "subject": subject},
        ).scalar_one()
        connection.execute(
            text("""
                INSERT INTO arbiter.memberships (id, tenant_id, principal_id, role)
                VALUES (:id, :tenant, :principal, :role)
            """),
            {
                "id": object_id,
                "tenant": self._transaction.context.tenant_id,
                "principal": principal,
                "role": role,
            },
        )

    def append_audit(
        self, *, action: str, target_id: UUID, revision: int, correlation: UUID
    ) -> UUID:
        object_id = uuid4()
        self._connection().execute(
            text("""
                INSERT INTO arbiter.audit_events
                (id, tenant_id, actor_type, actor_reference, action, target_id,
                 policy_revision, request_id, outcome)
                VALUES (:id, :tenant, 'operator', 'arbiter_operator', :action, :target,
                        :revision, :correlation, 'succeeded')
            """),
            {
                "id": object_id,
                "tenant": self._transaction.context.tenant_id,
                "action": action,
                "target": target_id,
                "revision": revision,
                "correlation": correlation,
            },
        )
        return object_id
