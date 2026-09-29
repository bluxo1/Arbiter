"""Read-only authoritative usage/request metadata; no state derivation or mutation."""

from dataclasses import dataclass
from datetime import datetime
from typing import Literal
from uuid import UUID

from sqlalchemy import text
from sqlalchemy.engine import Connection

from arbiter.persistence.tenant import TenantTransaction

UsageUnit = Literal["day", "month"]


@dataclass(frozen=True, slots=True)
class UsageTotals:
    """One stored window; a missing row is an authoritative zero-allocation state."""

    unit: UsageUnit
    window_start: datetime
    committed: int
    reserved: int


@dataclass(frozen=True, slots=True)
class RequestStatus:
    """Projection of the stored request row; token counts are nullable on purpose."""

    id: UUID
    state: str
    outcome: str | None
    credit_charge: int
    input_tokens: int | None
    output_tokens: int | None
    model_alias: str
    policy_revision: int
    created_at: datetime
    dispatched_at: datetime | None
    finished_at: datetime | None


# Static statements only; no caller-controlled identifiers enter SQL text.
_TOTALS_STATEMENTS = {
    "day": text(
        "SELECT window_start, committed, reserved FROM arbiter.quota_windows "
        "WHERE tenant_id=:tenant AND window_start=:start"
    ),
    "month": text(
        "SELECT window_start, committed, reserved FROM arbiter.budget_windows "
        "WHERE tenant_id=:tenant AND window_start=:start"
    ),
}
_REQUEST_STATEMENT = text("""
    SELECT id, state, outcome, credit_charge, input_tokens, output_tokens,
        model_alias, policy_revision, created_at, dispatched_at, finished_at
    FROM arbiter.requests
    WHERE tenant_id=:tenant AND id=:request
""")


class UsageRepository:
    def __init__(self, transaction: TenantTransaction) -> None:
        self._transaction = transaction

    def _connection(self) -> Connection:
        return self._transaction.connection()

    def totals(self, unit: UsageUnit, window_start: datetime) -> UsageTotals:
        if unit not in ("day", "month"):
            raise ValueError("usage unit must be day or month")
        row = (
            self._connection()
            .execute(
                _TOTALS_STATEMENTS[unit],
                {"tenant": self._transaction.context.tenant_id, "start": window_start},
            )
            .one_or_none()
        )
        if row is None:
            # Authoritative absence: no allocation activity created this window.
            return UsageTotals(unit, window_start, 0, 0)
        return UsageTotals(unit, row.window_start, row.committed, row.reserved)

    def request_status(self, request_id: UUID) -> RequestStatus | None:
        row = (
            self._connection()
            .execute(
                _REQUEST_STATEMENT,
                {"tenant": self._transaction.context.tenant_id, "request": request_id},
            )
            .one_or_none()
        )
        if row is None:
            # Same absence for foreign and nonexistent objects; no existence disclosure.
            return None
        return RequestStatus(
            row.id,
            row.state,
            row.outcome,
            row.credit_charge,
            row.input_tokens,
            row.output_tokens,
            row.model_alias,
            row.policy_revision,
            row.created_at,
            row.dispatched_at,
            row.finished_at,
        )
