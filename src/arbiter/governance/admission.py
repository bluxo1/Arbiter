"""Internal rate-governed reservation seam; no public inference entry point."""

from uuid import UUID

from pydantic import SecretStr
from sqlalchemy import text
from sqlalchemy.engine import Engine
from sqlalchemy.exc import DBAPIError, SQLAlchemyError

from arbiter.governance.fingerprint import Fingerprinter, ReservationInput, validate_idempotency
from arbiter.governance.rate import RateGate
from arbiter.governance.reservation import (
    RequestAlreadyAdmitted,
    ReservationService,
    ReservationUnavailable,
    ReservedBinding,
    _database_error,
)
from arbiter.identity.context import TenantContext
from arbiter.identity.keys import KeyVerifier
from arbiter.identity.workload import MissingScope
from arbiter.persistence.reservation import ReservationRepository
from arbiter.persistence.tenant import bind_tenant_transaction, tenant_transaction
from arbiter.persistence.workload import resolve_key


class RateGovernedReservationService(ReservationService):
    """Read before Redis; start the durable reservation transaction only after it.

    The read-only preflight checks current authority, model and committed
    idempotency state. The locked reservation capability repeats those checks
    and rejects a policy revision change after Redis. Concurrent first attempts
    for the same idempotency key can conservatively consume two Redis entries;
    PostgreSQL still creates at most one reservation and dispatch marker.
    """

    def __init__(
        self, engine: Engine, verifier: KeyVerifier, fingerprinter: Fingerprinter, gate: RateGate
    ) -> None:
        super().__init__(engine, verifier, fingerprinter)
        self._gate = gate

    def reserve_for_capacity(
        self, credential: SecretStr, idempotency: str, request: ReservationInput
    ) -> ReservedBinding:
        validate_idempotency(idempotency)
        fingerprint = self._fingerprinter.compute(request)
        candidate = self._verifier.candidate(credential)
        try:
            with self._engine.connect() as connection, connection.begin() as transaction:
                inherited: str | None = connection.execute(
                    text("SELECT NULLIF(current_setting('arbiter.tenant_id',true),'')")
                ).scalar_one()
                if inherited is not None:
                    connection.invalidate()
                    raise ReservationUnavailable()
                binding = resolve_key(connection, candidate)
                if "inference:write" not in binding.scopes:
                    raise MissingScope()
                scoped = bind_tenant_transaction(
                    connection, transaction, TenantContext(binding.tenant_id)
                )
                row = (
                    scoped.connection()
                    .execute(
                        text("""
                        SELECT tenant_rate,key_rate,policy_revision,duplicate_id,duplicate_state
                        FROM arbiter.rate_preflight(:tenant,:key,:public,:candidate,:pepper,
                            :idempotency,:fingerprint,:version,:alias,:output)
                    """),
                        {
                            "tenant": binding.tenant_id,
                            "key": binding.key_id,
                            "public": candidate.public_id,
                            "candidate": candidate.verifier.get_secret_value(),
                            "pepper": candidate.pepper_version,
                            "idempotency": idempotency,
                            "fingerprint": fingerprint.digest.get_secret_value(),
                            "version": fingerprint.version,
                            "alias": request.model_alias,
                            "output": request.max_output_tokens,
                        },
                    )
                    .one()
                )
                if row.duplicate_id is not None:
                    if not isinstance(row.duplicate_id, UUID) or not isinstance(
                        row.duplicate_state, str
                    ):
                        raise ReservationUnavailable()
                    raise RequestAlreadyAdmitted(row.duplicate_id, row.duplicate_state)
                if (
                    type(row.tenant_rate) is not int
                    or type(row.key_rate) is not int
                    or type(row.policy_revision) is not int
                    or row.tenant_rate < 0
                    or row.key_rate < 0
                    or row.policy_revision < 1
                ):
                    raise ReservationUnavailable()
                tenant_limit = row.tenant_rate
                key_limit = row.key_rate
                policy_revision = row.policy_revision
            # No PostgreSQL transaction or row lock spans this Redis call.
            self._gate.admit(binding, tenant_limit, key_limit)
            with tenant_transaction(self._engine, TenantContext(binding.tenant_id)) as scoped:
                result = ReservationRepository(scoped).reserve_governed(
                    binding,
                    candidate,
                    idempotency,
                    fingerprint,
                    request.model_alias,
                    request.max_output_tokens,
                    policy_revision,
                )
                if result.duplicate:
                    raise RequestAlreadyAdmitted(result.request_id, result.state)
            return ReservedBinding(result, binding)
        except DBAPIError as error:
            raise _database_error(error) from None
        except (SQLAlchemyError, RuntimeError):
            raise ReservationUnavailable() from None
