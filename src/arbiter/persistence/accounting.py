"""Read-only tenant accounting persistence; no admission, transitions or HTTP surface.

Later writers must hold tenant, key, policy, quota and budget locks in that order,
then registry locks when required, and bind evidence in the same transaction.
This module deliberately grants no writer/dispatch capability.
"""

from dataclasses import dataclass
from datetime import datetime
from typing import Literal
from uuid import UUID

from sqlalchemy import text

from arbiter.persistence.tenant import TenantTransaction


@dataclass(frozen=True, slots=True)
class AllocationWindow:
    id: UUID
    window_start: datetime
    committed: int
    reserved: int


@dataclass(frozen=True, slots=True)
class RequestMetadata:
    id: UUID
    state: str
    model_alias: str
    credit_charge: int
    input_tokens: int | None
    output_tokens: int | None
    outcome: str | None
    disposition: str


@dataclass(frozen=True, slots=True)
class AccountingEvidence:
    id: UUID
    kind: str
    request_count: int
    credits: int
    occurred_at: datetime


class AccountingRepository:
    def __init__(self, transaction: TenantTransaction) -> None:
        self._transaction = transaction

    def window(self, kind: Literal["quota", "budget"], start: datetime) -> AllocationWindow | None:
        if kind not in {"quota", "budget"} or start.tzinfo is None:
            raise ValueError("invalid allocation window selector")
        # Fixed server-owned statements; caller values are always bound.
        query = (
            "SELECT id,window_start,committed,reserved FROM arbiter.quota_windows "
            "WHERE tenant_id=:tenant AND window_start=:start"
            if kind == "quota"
            else "SELECT id,window_start,committed,reserved FROM arbiter.budget_windows "
            "WHERE tenant_id=:tenant AND window_start=:start"
        )
        row = (
            self._transaction.connection()
            .execute(text(query), {"tenant": self._transaction.context.tenant_id, "start": start})
            .one_or_none()
        )
        return None if row is None else AllocationWindow(*row)

    def request(self, identifier: UUID) -> RequestMetadata | None:
        row = (
            self._transaction.connection()
            .execute(
                text("""
                SELECT r.id,r.state,r.model_alias,r.credit_charge,r.input_tokens,r.output_tokens,
                       r.outcome,s.disposition
                FROM arbiter.requests r JOIN arbiter.reservations s
                    ON s.tenant_id=r.tenant_id AND s.id=r.reservation_id AND s.tenant_id=:tenant
                WHERE r.tenant_id=:tenant AND r.id=:id
            """),
                {"tenant": self._transaction.context.tenant_id, "id": identifier},
            )
            .one_or_none()
        )
        return None if row is None else RequestMetadata(*row)

    def evidence(self, identifier: UUID) -> tuple[AccountingEvidence, ...]:
        rows = self._transaction.connection().execute(
            text("""
                SELECT id,kind,request_count,credits,occurred_at FROM arbiter.accounting_events
                WHERE tenant_id=:tenant AND request_id=:id ORDER BY occurred_at,id
            """),
            {"tenant": self._transaction.context.tenant_id, "id": identifier},
        )
        return tuple(AccountingEvidence(*row) for row in rows)
