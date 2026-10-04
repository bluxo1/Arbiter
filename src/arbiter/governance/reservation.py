"""PostgreSQL reservation only, called off the event loop.

This is an internal transaction component, not the complete admission pipeline:
it does not enforce Redis rate, obtain provider capacity or authorize dispatch.
Success is returned only after the transaction and deferred constraints commit.
"""

import json
from dataclasses import dataclass
from uuid import UUID

import psycopg
from pydantic import SecretStr
from sqlalchemy import text
from sqlalchemy.engine import Engine
from sqlalchemy.exc import DBAPIError, SQLAlchemyError

from arbiter.governance.fingerprint import (
    Fingerprinter,
    InvalidReservation,
    ReservationInput,
    validate_idempotency,
)
from arbiter.identity.context import TenantContext
from arbiter.identity.keys import InvalidKey, KeyVerifier
from arbiter.identity.workload import MissingScope
from arbiter.persistence.models import ModelRepository
from arbiter.persistence.reservation import ReservationRepository, ReservationResult
from arbiter.persistence.tenant import bind_tenant_transaction
from arbiter.persistence.workload import KeyBinding, resolve_key


class ReservationDenied(Exception):
    status_code = 429

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__("reservation denied")


class ModelDenied(ReservationDenied):
    status_code = 403

    def __init__(self) -> None:
        super().__init__("model_denied")


class IdempotencyConflict(Exception):
    code = "idempotency_conflict"
    status_code = 409

    def __init__(self) -> None:
        super().__init__("idempotency conflict")


class RequestAlreadyAdmitted(Exception):
    code = "request_already_admitted"
    status_code = 409

    def __init__(self, request_id: UUID, state: str) -> None:
        self.request_id = request_id
        self.state = state
        self.status_url = f"/v1/requests/{request_id}"
        super().__init__("request already admitted")


class ReservationUnavailable(Exception):
    code = "unavailable"
    status_code = 503

    def __init__(self) -> None:
        super().__init__("reservation unavailable")


@dataclass(frozen=True, slots=True)
class ReservedBinding:
    """Internal receipt after a committed reservation; never an HTTP response."""

    result: ReservationResult
    binding: KeyBinding


def _database_error(error: DBAPIError) -> Exception:
    code = getattr(error.orig, "sqlstate", None)
    if code == "AR001":
        return InvalidKey()
    if code == "AR002":
        return MissingScope()
    if code == "AR003":
        return IdempotencyConflict()
    if code == "AR009":
        try:
            if not isinstance(error.orig, psycopg.Error):
                raise ValueError("invalid retained receipt")
            detail = json.loads(error.orig.diag.message_detail or "")
            identifier = UUID(detail["request_id"])
            state = detail["state"]
            if state not in {"succeeded", "failed", "released", "rejected_capacity"}:
                raise ValueError("invalid retained state")
        except (AttributeError, TypeError, ValueError, KeyError):
            return ReservationUnavailable()
        return RequestAlreadyAdmitted(identifier, state)
    if code == "AR004":
        return ModelDenied()
    if code in {"AR005", "AR006", "AR007"}:
        return ReservationDenied(
            {"AR005": "quota_exhausted", "AR006": "budget_exhausted", "AR007": "tenant_capacity"}[
                code
            ]
        )
    if code == "22023":
        return InvalidReservation()
    return ReservationUnavailable()


class ReservationService:
    def __init__(self, engine: Engine, verifier: KeyVerifier, fingerprinter: Fingerprinter) -> None:
        self._engine = engine
        self._verifier = verifier
        self._fingerprinter = fingerprinter

    def reserve(
        self,
        credential: SecretStr,
        idempotency: str,
        request: ReservationInput,
    ) -> ReservationResult:
        return self.reserve_for_capacity(credential, idempotency, request).result

    def reserve_for_capacity(
        self,
        credential: SecretStr,
        idempotency: str,
        request: ReservationInput,
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
                # Design step 1 precedes idempotency. Policies allow at most 32 aliases;
                # this existing public projection grants no native registry access.
                models = ModelRepository(scoped).list_page(page_size=32, after=None)
                model = next((item for item in models if item.alias == request.model_alias), None)
                if model is None:
                    raise ModelDenied()
                if request.max_output_tokens > model.output_cap:
                    raise InvalidReservation()
                # The capability repeats locked validation for any NEW reservation.
                result = ReservationRepository(scoped).reserve(
                    binding,
                    candidate,
                    idempotency,
                    fingerprint,
                    request.model_alias,
                    request.max_output_tokens,
                )
                if result.duplicate:
                    raise RequestAlreadyAdmitted(result.request_id, result.state)
            return ReservedBinding(result, binding)
        except DBAPIError as error:
            raise _database_error(error) from None
        except (SQLAlchemyError, RuntimeError):
            raise ReservationUnavailable() from None
