"""Explicit local operator batches; no runtime scheduler or provider authority."""

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

from sqlalchemy import text
from sqlalchemy.engine import Engine

from arbiter.persistence.operator import operator_transaction


@dataclass(frozen=True, slots=True)
class RetentionResult:
    requests_removed: int
    reservations_removed: int
    accounting_removed: int
    audits_removed: int
    bindings_removed: int
    clearances_removed: int
    tombstones_removed: int
    audit_id: UUID


@dataclass(frozen=True, slots=True)
class HistoryRetentionResult:
    quota_windows_removed: int
    budget_windows_removed: int
    standalone_audits_removed: int
    audit_id: UUID


class RetentionService:
    def __init__(self, engine: Engine) -> None:
        self._engine = engine

    def run_once(
        self, tenant_id: UUID, key_id: UUID, *, cutoff: datetime | None = None, limit: int = 100
    ) -> RetentionResult:
        if type(limit) is not int or not 1 <= limit <= 100:
            raise ValueError("invalid retention batch size")
        cutoff = cutoff or datetime.now(UTC) - timedelta(days=90)
        if cutoff.tzinfo is None or cutoff.utcoffset() is None:
            raise ValueError("aware retention cutoff required")
        with operator_transaction(self._engine, tenant_id) as transaction:
            row = (
                transaction.connection()
                .execute(
                    text(
                        "SELECT * FROM arbiter.retire_requests"
                        "(:tenant,:key,:cutoff,:operation,:limit)"
                    ),
                    {
                        "tenant": tenant_id,
                        "key": key_id,
                        "cutoff": cutoff,
                        "operation": uuid4(),
                        "limit": limit,
                    },
                )
                .one()
            )
        return RetentionResult(*row)

    def retire_history(
        self, tenant_id: UUID, *, as_of: datetime | None = None, limit: int = 100
    ) -> HistoryRetentionResult:
        if type(limit) is not int or not 1 <= limit <= 100:
            raise ValueError("invalid retention batch size")
        if as_of is not None and (as_of.tzinfo is None or as_of.utcoffset() is None):
            raise ValueError("aware cleanup time required")
        with operator_transaction(self._engine, tenant_id) as transaction:
            row = (
                transaction.connection()
                .execute(
                    text("SELECT * FROM arbiter.retire_history(:tenant,:as_of,:operation,:limit)"),
                    {"tenant": tenant_id, "as_of": as_of, "operation": uuid4(), "limit": limit},
                )
                .one()
            )
        return HistoryRetentionResult(*row)
