"""Tenant-scoped dispatch snapshot and restricted terminal transition."""

from dataclasses import dataclass
from uuid import UUID

from sqlalchemy import text

from arbiter.persistence.tenant import TenantTransaction
from arbiter.persistence.workload import KeyBinding


@dataclass(frozen=True, slots=True)
class DispatchedSnapshot:
    model_id: UUID
    model_alias: str
    model_digest: str
    output_cap: int
    payload_hmac: bytes
    fingerprint_version: int


class TerminalRepository:
    def __init__(self, transaction: TenantTransaction) -> None:
        self._transaction = transaction

    def dispatched_snapshot(
        self, binding: KeyBinding, request_id: UUID
    ) -> DispatchedSnapshot | None:
        if binding.tenant_id != self._transaction.context.tenant_id:
            raise RuntimeError("terminal binding mismatch")
        row = (
            self._transaction.connection()
            .execute(
                text("""
                SELECT r.model_id,r.model_alias,r.model_digest,r.output_cap,
                    r.payload_hmac,r.fingerprint_version
                FROM arbiter.requests r JOIN arbiter.reservations s
                    ON s.tenant_id=r.tenant_id AND s.id=r.reservation_id
                WHERE r.tenant_id=:tenant AND r.key_id=:key AND r.id=:request
                    AND r.state='dispatched' AND r.dispatch_audit_id IS NOT NULL
                    AND r.terminal_audit_id IS NULL AND s.disposition='committed'
                    AND s.settlement_event_id IS NOT NULL
            """),
                {"tenant": binding.tenant_id, "key": binding.key_id, "request": request_id},
            )
            .one_or_none()
        )
        if row is None:
            return None
        return DispatchedSnapshot(
            row.model_id,
            row.model_alias,
            row.model_digest,
            row.output_cap,
            bytes(row.payload_hmac),
            row.fingerprint_version,
        )

    def finalize(
        self,
        binding: KeyBinding,
        request_id: UUID,
        state: str,
        outcome: str,
        input_tokens: int | None,
        output_tokens: int | None,
    ) -> bool:
        if binding.tenant_id != self._transaction.context.tenant_id:
            raise RuntimeError("terminal binding mismatch")
        row = (
            self._transaction.connection()
            .execute(
                text("""
                SELECT request_id,changed FROM arbiter.finalize_dispatched(
                    :tenant,:key,:request,:state,:outcome,:input,:output)
            """),
                {
                    "tenant": binding.tenant_id,
                    "key": binding.key_id,
                    "request": request_id,
                    "state": state,
                    "outcome": outcome,
                    "input": input_tokens,
                    "output": output_tokens,
                },
            )
            .one()
        )
        if row.request_id != request_id:
            raise RuntimeError("terminal request mismatch")
        return bool(row.changed)
