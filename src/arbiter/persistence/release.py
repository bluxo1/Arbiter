"""Reserved-only cleanup within an already authenticated in-flight tenant binding."""

from dataclasses import dataclass
from typing import Literal
from uuid import UUID

from sqlalchemy import text

from arbiter.persistence.tenant import TenantTransaction
from arbiter.persistence.workload import KeyBinding

ReleaseReason = Literal[
    "cancelled",
    "provider_unavailable",
    "rejected_capacity",
    "authorization_changed",
    "admission_window_changed",
    "reservation_expired",
]


@dataclass(frozen=True, slots=True)
class ReleaseResult:
    request_id: UUID
    state: str
    outcome: str
    changed: bool


class ReleaseRepository:
    def __init__(self, transaction: TenantTransaction) -> None:
        self._transaction = transaction

    def release(
        self, binding: KeyBinding, request_id: UUID, reason: ReleaseReason
    ) -> ReleaseResult:
        if binding.tenant_id != self._transaction.context.tenant_id:
            raise RuntimeError("release binding mismatch")
        row = (
            self._transaction.connection()
            .execute(
                text("""
                SELECT request_id,state,outcome,changed
                FROM arbiter.release_request(:tenant,:key,:request,:reason)
            """),
                {
                    "tenant": binding.tenant_id,
                    "key": binding.key_id,
                    "request": request_id,
                    "reason": reason,
                },
            )
            .one()
        )
        return ReleaseResult(*row)
