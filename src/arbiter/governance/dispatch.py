"""Internal dispatch and deterministic Phase 3 terminal lifecycle; no HTTP route."""

import hmac
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from time import monotonic
from uuid import UUID

from sqlalchemy.engine import Engine
from sqlalchemy.exc import DBAPIError, SQLAlchemyError

from arbiter.governance.capacity import CapacityLease, CapacityOwnershipError
from arbiter.governance.fingerprint import Fingerprinter, ReservationInput
from arbiter.identity.context import TenantContext
from arbiter.observability import metrics
from arbiter.persistence.dispatch import DispatchRepository
from arbiter.persistence.release import ReleaseRepository, ReleaseResult
from arbiter.persistence.tenant import tenant_transaction
from arbiter.persistence.terminal import TerminalRepository
from arbiter.providers.port import (
    ProviderAmbiguous,
    ProviderDeadline,
    ProviderDefiniteFailure,
    ProviderMalformed,
    ProviderModelUnavailable,
    ProviderOversizedResponse,
    ProviderPort,
    ProviderRejectedInput,
    ProviderRequest,
    ProviderResult,
    ProviderUnavailable,
)


def _provider_metric(error: Exception) -> str:
    """Provider type classification only; never a durable lifecycle decision."""
    if isinstance(error, (ProviderModelUnavailable, ProviderUnavailable)):
        return "unavailable"
    if isinstance(error, ProviderRejectedInput):
        return "rejected_input"
    if isinstance(error, ProviderDefiniteFailure):
        return "definite_failure"
    if isinstance(error, ProviderDeadline):
        return "deadline"
    if isinstance(error, ProviderMalformed):
        return "invalid_response"
    if isinstance(error, ProviderAmbiguous):
        return "unknown"
    return "failure"


@dataclass(frozen=True, slots=True)
class DispatchAuthorized:
    request_id: UUID


class DispatchNotFound(Exception):
    code = "not_found"
    status_code = 404


class DispatchConflict(Exception):
    code = "request_not_reserved"
    status_code = 409


class DispatchRejected(Exception):
    code = "authorization_changed"
    status_code = 409

    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__("dispatch rejected before authorization")


class DispatchUnavailable(Exception):
    code = "unavailable"
    status_code = 503


class TerminalUnavailable(Exception):
    code = "unavailable"
    status_code = 503


@dataclass(frozen=True, slots=True)
class ProviderCompletion:
    request_id: UUID
    state: str
    outcome: str
    assistant_text: str | None = field(default=None, repr=False)
    input_tokens: int | None = None
    output_tokens: int | None = None
    public_error: str | None = None
    model_alias: str | None = None
    charged_credits: int | None = None


def _valid_result(value: object, output_cap: int) -> ProviderResult:
    if not isinstance(value, ProviderResult):
        raise ProviderMalformed()
    if type(value.assistant_text) is not str:
        raise ProviderMalformed()
    try:
        if len(value.assistant_text.encode("utf-8")) > 1048576:
            raise ProviderOversizedResponse()
    except UnicodeError:
        raise ProviderMalformed() from None
    if type(value.finish_reason) is not str or value.finish_reason not in {"stop", "length"}:
        raise ProviderMalformed()
    for count in (value.input_tokens, value.output_tokens):
        if count is not None and (type(count) is not int or not 0 <= count <= 9223372036854775807):
            raise ProviderMalformed()
    if value.output_tokens is not None and value.output_tokens > output_cap:
        raise ProviderMalformed()
    return value


class DispatchService:
    def __init__(self, engine: Engine) -> None:
        self._engine = engine

    def authorize(self, lease: CapacityLease) -> DispatchAuthorized:
        if not isinstance(lease, CapacityLease) or not lease.owns():
            raise CapacityOwnershipError()
        binding = lease._binding
        request_id = lease.result.request_id
        released: ReleaseResult | None = None
        decision = ""
        try:
            with tenant_transaction(self._engine, TenantContext(binding.tenant_id)) as transaction:
                outcome = DispatchRepository(transaction).authorize(binding, request_id)
                decision = outcome.decision
                if outcome.request_id != request_id:
                    raise DispatchUnavailable()
                if decision in {"authorization_changed", "admission_window_changed"}:
                    if decision == "authorization_changed":
                        released = ReleaseRepository(transaction).release(
                            binding, request_id, "authorization_changed"
                        )
                    else:
                        released = ReleaseRepository(transaction).release(
                            binding, request_id, "admission_window_changed"
                        )
                elif decision != "authorized":
                    raise DispatchUnavailable()
            # Database commit, including deferred audit/accounting checks, has completed.
            if released is not None:
                lease._release_after_confirmed(released)
                raise DispatchRejected(decision)
            lease._transfer_after_dispatch()
            return DispatchAuthorized(request_id)
        except DBAPIError as error:
            code = getattr(error.orig, "sqlstate", None)
            if code == "DA001":
                raise DispatchNotFound() from None
            if code == "DA002":
                raise DispatchConflict() from None
            raise DispatchUnavailable() from None
        except (SQLAlchemyError, RuntimeError):
            raise DispatchUnavailable() from None

    def run_double_once(
        self,
        lease: CapacityLease,
        original: ReservationInput,
        provider: ProviderPort,
        fingerprinter: Fingerprinter,
        *,
        deadline: datetime | None = None,
    ) -> ProviderCompletion:
        """Call one provider port after an already-committed dispatch marker.

        The original bounded content remains transient. A process-local one-shot claim
        and the durable dispatched-state check prevent duplicate calls in this process;
        restart recovery never calls this method automatically.
        """
        if (
            not isinstance(lease, CapacityLease)
            or not lease.owns()
            or not isinstance(original, ReservationInput)
            or not isinstance(provider, ProviderPort)
            or not isinstance(fingerprinter, Fingerprinter)
        ):
            raise CapacityOwnershipError()
        binding = lease._binding
        request_id = lease.result.request_id
        try:
            with tenant_transaction(self._engine, TenantContext(binding.tenant_id)) as transaction:
                snapshot = TerminalRepository(transaction).dispatched_snapshot(binding, request_id)
        except (DBAPIError, SQLAlchemyError, RuntimeError):
            raise TerminalUnavailable() from None
        if snapshot is None:
            raise DispatchConflict()
        fingerprint = fingerprinter.compute(original)
        if (
            snapshot.model_alias != original.model_alias
            or original.max_output_tokens > snapshot.output_cap
            or fingerprint.version != snapshot.fingerprint_version
            or not hmac.compare_digest(fingerprint.digest.get_secret_value(), snapshot.payload_hmac)
        ):
            raise DispatchConflict()
        transient = ProviderRequest(
            snapshot.model_id,
            snapshot.model_digest,
            request_id,
            original.messages,
            original.max_output_tokens,
        )
        # Governed execution passes its server-owned deadline from admission.
        # The default preserves direct internal Phase 3 test callers.
        if deadline is None:
            deadline = datetime.now(UTC) + timedelta(seconds=120)
        validation_outcome = "succeeded"
        validation_metric = "success"
        public_error: str | None = None
        try:
            if deadline <= datetime.now(UTC):
                raise ProviderDeadline()
            # Validation is explicitly non-inferencing. A known local mismatch
            # cannot have reached generation and is a definite failed attempt.
            provider.validate(transient)
        except ProviderDeadline as error:
            validation_metric = _provider_metric(error)
            validation_outcome = "unknown"
            public_error = "provider_deadline"
        except ProviderModelUnavailable as error:
            validation_metric = _provider_metric(error)
            validation_outcome = "failed"
            public_error = "model_unavailable"
        except (ProviderRejectedInput, ProviderDefiniteFailure) as error:
            validation_metric = _provider_metric(error)
            validation_outcome = "failed"
            public_error = "provider_failure"
        except ProviderUnavailable as error:
            validation_metric = _provider_metric(error)
            # Validation cannot initiate work, but it cannot establish readiness.
            validation_outcome = "failed"
            public_error = "provider_unavailable"
        except Exception as error:
            validation_metric = _provider_metric(error)
            # An undocumented adapter failure after the dispatch marker is
            # conservatively quarantined; it cannot cause a provider call.
            validation_outcome = "unknown"
            public_error = "provider_outcome_unknown"
        metrics.record("provider_validation", validation_metric)
        if not lease._claim_provider_once():
            raise DispatchConflict()
        text_value: str | None = None
        input_tokens: int | None = None
        output_tokens: int | None = None
        if validation_outcome == "failed":
            state, outcome = "failed", "provider_failure"
        elif validation_outcome == "unknown":
            state, outcome = "unknown", "unknown"
        elif deadline <= datetime.now(UTC):
            state, outcome = "unknown", "unknown"
            public_error = "provider_deadline"
        else:
            provider_started = monotonic()
            provider_metric = "success"
            try:
                # There is no open PostgreSQL transaction during this call.
                response = _valid_result(
                    provider.generate(transient, deadline), transient.max_output_tokens
                )
                state, outcome = "succeeded", "succeeded"
                text_value = response.assistant_text
                input_tokens, output_tokens = response.input_tokens, response.output_tokens
            except ProviderModelUnavailable as error:
                provider_metric = _provider_metric(error)
                state, outcome = "failed", "provider_failure"
                public_error = "model_unavailable"
            except ProviderDefiniteFailure as error:
                provider_metric = _provider_metric(error)
                state, outcome = "failed", "provider_failure"
                public_error = "provider_failure"
            except ProviderDeadline as error:
                provider_metric = _provider_metric(error)
                state, outcome = "unknown", "unknown"
                public_error = "provider_deadline"
            except ProviderOversizedResponse as error:
                provider_metric = _provider_metric(error)
                state, outcome = "unknown", "unknown"
                public_error = "provider_oversized"
            except ProviderMalformed as error:
                provider_metric = _provider_metric(error)
                state, outcome = "unknown", "unknown"
                public_error = "provider_malformed"
            except ProviderUnavailable as error:
                provider_metric = _provider_metric(error)
                state, outcome = "unknown", "unknown"
                public_error = "provider_unavailable"
            except Exception as error:
                provider_metric = _provider_metric(error)
                # Deadline, malformed output and all inconclusive failures stay charged
                # and quarantined. The exception object/body is never logged or stored.
                state, outcome = "unknown", "unknown"
                public_error = "provider_outcome_unknown"
            metrics.record(
                "provider",
                provider_metric,
                monotonic() - provider_started,
            )
        if state == "unknown":
            # Close local recovery admission before the unknown terminal commit.
            # A concurrent maintenance scan cannot reopen a quarantined gate.
            lease._quarantine_unknown()
        try:
            with tenant_transaction(self._engine, TenantContext(binding.tenant_id)) as transaction:
                changed = TerminalRepository(transaction).finalize(
                    binding, request_id, state, outcome, input_tokens, output_tokens
                )
        except (DBAPIError, SQLAlchemyError, RuntimeError):
            # The provider has already been called; never retry it. Keep capacity.
            raise TerminalUnavailable() from None
        if not changed:
            raise DispatchConflict()
        if state in {"succeeded", "failed"}:
            lease._release_after_terminal(request_id, state)
        return ProviderCompletion(
            request_id, state, outcome, text_value, input_tokens, output_tokens, public_error
        )

    def mark_unknown(self, lease: CapacityLease) -> bool:
        """Quarantine interrupted dispatched work without invoking the provider."""
        if not isinstance(lease, CapacityLease) or not lease.owns():
            raise CapacityOwnershipError()
        binding = lease._binding
        request_id = lease.result.request_id
        lease._quarantine_unknown()
        try:
            with tenant_transaction(self._engine, TenantContext(binding.tenant_id)) as transaction:
                return TerminalRepository(transaction).finalize(
                    binding, request_id, "unknown", "unknown", None, None
                )
        except (DBAPIError, SQLAlchemyError, RuntimeError):
            # A failed commit keeps the claim quarantined. Recovery will settle
            # any remaining dispatched row; it must never call the provider.
            raise TerminalUnavailable() from None
