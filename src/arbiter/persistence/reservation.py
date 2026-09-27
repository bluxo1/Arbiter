"""One authenticated, scoped database capability; no direct allocation DML."""

from dataclasses import dataclass
from uuid import UUID

from sqlalchemy import text

from arbiter.governance.fingerprint import PayloadFingerprint
from arbiter.identity.keys import InvalidKey, KeyCandidate
from arbiter.persistence.tenant import TenantTransaction
from arbiter.persistence.workload import KeyBinding


@dataclass(frozen=True, slots=True)
class ReservationResult:
    request_id: UUID
    state: str
    model_alias: str
    credit_charge: int
    policy_revision: int
    model_revision: int
    duplicate: bool


class ReservationRepository:
    def __init__(self, transaction: TenantTransaction) -> None:
        self._transaction = transaction

    def reserve(
        self,
        binding: KeyBinding,
        candidate: KeyCandidate,
        idempotency: str,
        fingerprint: PayloadFingerprint,
        alias: str,
        output_cap: int,
    ) -> ReservationResult:
        if binding.tenant_id != self._transaction.context.tenant_id:
            raise InvalidKey()
        row = (
            self._transaction.connection()
            .execute(
                text("""
            SELECT request_id,state,model_alias,credit_charge,
                policy_revision,model_revision,duplicate
            FROM arbiter.reserve_request(:tenant,:key,:public,:candidate,:pepper,
                :idempotency,:fingerprint,:version,:alias,:output)
        """),
                {
                    "tenant": self._transaction.context.tenant_id,
                    "key": binding.key_id,
                    "public": candidate.public_id,
                    "candidate": candidate.verifier.get_secret_value(),
                    "pepper": candidate.pepper_version,
                    "idempotency": idempotency,
                    "fingerprint": fingerprint.digest.get_secret_value(),
                    "version": fingerprint.version,
                    "alias": alias,
                    "output": output_cap,
                },
            )
            .one()
        )
        return ReservationResult(*row)
