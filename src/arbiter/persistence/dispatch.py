"""Scoped dispatch decision; all mutations remain in a single PostgreSQL capability."""

from dataclasses import dataclass
from uuid import UUID

from sqlalchemy import text

from arbiter.persistence.tenant import TenantTransaction
from arbiter.persistence.workload import KeyBinding


@dataclass(frozen=True, slots=True)
class DispatchDecision:
    request_id: UUID
    decision: str


class DispatchRepository:
    def __init__(self, transaction: TenantTransaction) -> None:
        self._transaction = transaction

    def authorize(self, binding: KeyBinding, request_id: UUID) -> DispatchDecision:
        if binding.tenant_id != self._transaction.context.tenant_id:
            raise RuntimeError("dispatch binding mismatch")
        row = (
            self._transaction.connection()
            .execute(
                text(
                    "SELECT request_id,decision FROM "
                    "arbiter.authorize_dispatch(:tenant,:key,:request)"
                ),
                {"tenant": binding.tenant_id, "key": binding.key_id, "request": request_id},
            )
            .one()
        )
        return DispatchDecision(*row)
