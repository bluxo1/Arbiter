"""Opaque candidate discovery and operator clearance; no request content is read."""

from dataclasses import dataclass
from typing import Literal
from uuid import UUID

from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine

from arbiter.config import DatabaseSettings
from arbiter.persistence.operator import operator_transaction


@dataclass(frozen=True, slots=True)
class MaintenanceCandidate:
    tenant_id: UUID
    key_id: UUID
    request_id: UUID
    cleared: bool

    @property
    def identity(self) -> tuple[UUID, UUID, UUID]:
        return self.tenant_id, self.key_id, self.request_id


def maintenance_engine(settings: DatabaseSettings) -> Engine:
    """A separate read-only login that can execute only opaque candidate discovery."""
    return create_engine(
        settings.url("maintenance"),
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


def candidates(
    engine: Engine, kind: Literal["stale", "restart", "unknown"]
) -> tuple[MaintenanceCandidate, ...]:
    """Only the restricted function may enumerate UUIDs across tenant scopes."""
    with engine.begin() as connection:
        rows = connection.execute(
            text(
                "SELECT tenant_id,key_id,request_id,cleared "
                "FROM arbiter.maintenance_candidates(:kind)"
            ),
            {"kind": kind},
        ).all()
    return tuple(MaintenanceCandidate(*row) for row in rows)


def clear_unknown(engine: Engine, tenant_id: UUID, request_id: UUID) -> bool:
    with operator_transaction(engine, tenant_id) as transaction:
        changed: bool = (
            transaction.connection()
            .execute(
                text("SELECT arbiter.clear_unknown_capacity(:tenant,:request)"),
                {"tenant": tenant_id, "request": request_id},
            )
            .scalar_one()
        )
    return changed
