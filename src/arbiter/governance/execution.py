"""Synchronous governed execution; provider selection follows durable dispatch."""

from collections.abc import Callable
from dataclasses import replace
from datetime import UTC, datetime, timedelta

from pydantic import SecretStr
from sqlalchemy.engine import Engine
from sqlalchemy.exc import SQLAlchemyError

from arbiter.governance.admission import RateGovernedReservationService
from arbiter.governance.capacity import (
    CapacityGate,
    CapacityLease,
    CapacityService,
    process_capacity,
)
from arbiter.governance.dispatch import DispatchService, ProviderCompletion
from arbiter.governance.fingerprint import Fingerprinter, ReservationInput
from arbiter.governance.rate import RateGate
from arbiter.governance.release import ReleaseConflict, ReleaseService
from arbiter.identity.context import TenantContext
from arbiter.identity.keys import KeyVerifier
from arbiter.persistence.provider_binding import (
    PinnedModelIdentity,
    ProviderBindingUnavailable,
    TrustedProviderSelection,
    dispatched_ollama_binding,
    reserved_binding_available,
)
from arbiter.persistence.tenant import tenant_transaction
from arbiter.persistence.terminal import TerminalRepository
from arbiter.providers.double import DeterministicProvider
from arbiter.providers.port import ProviderPort


class InferenceDeadline(Exception):
    code = "provider_deadline"
    status_code = 504


class GovernedExecutionService:
    """Join the established admission, dispatch and terminal capabilities once.

    Call off the event loop. No HTTP route or arbitrary provider adapter can
    construct a different execution path through this service.
    """

    def __init__(
        self,
        engine: Engine,
        verifier: KeyVerifier,
        fingerprinter: Fingerprinter,
        rate: RateGate,
        provider: DeterministicProvider | None,
        capacity: CapacityGate = process_capacity,
        *,
        provider_factory: Callable[[TrustedProviderSelection], ProviderPort] | None = None,
    ) -> None:
        if provider is not None and not isinstance(provider, DeterministicProvider):
            raise TypeError("internal test provider must be deterministic")
        self._engine = engine
        self._capacity = CapacityService(
            RateGovernedReservationService(engine, verifier, fingerprinter, rate),
            ReleaseService(engine),
            capacity,
        )
        self._dispatch = DispatchService(engine)
        self._fingerprinter = fingerprinter
        self._provider = provider
        self._provider_factory = provider_factory

    def _require_reserved_binding(self, lease: CapacityLease) -> None:
        binding = lease._binding
        try:
            with tenant_transaction(self._engine, TenantContext(binding.tenant_id)) as transaction:
                available = reserved_binding_available(
                    transaction, binding, lease.result.request_id, lease.result.model_revision
                )
        except (SQLAlchemyError, RuntimeError):
            raise ProviderBindingUnavailable() from None
        if not available:
            raise ProviderBindingUnavailable()

    def _selected_provider(self, lease: CapacityLease) -> ProviderPort:
        binding = lease._binding
        try:
            with tenant_transaction(self._engine, TenantContext(binding.tenant_id)) as transaction:
                snapshot = TerminalRepository(transaction).dispatched_snapshot(
                    binding, lease.result.request_id
                )
                if snapshot is None:
                    raise ProviderBindingUnavailable()
                selected = dispatched_ollama_binding(
                    transaction,
                    binding,
                    lease.result.request_id,
                    PinnedModelIdentity(
                        snapshot.model_id, snapshot.model_digest, lease.result.model_revision
                    ),
                )
        except (SQLAlchemyError, RuntimeError, ValueError):
            raise ProviderBindingUnavailable() from None
        provider = (
            self._provider_factory(selected) if self._provider_factory else selected.provider()
        )
        if not isinstance(provider, ProviderPort):
            raise ProviderBindingUnavailable()
        return provider

    def execute(
        self, credential: SecretStr, idempotency: str, request: ReservationInput
    ) -> ProviderCompletion:
        deadline = datetime.now(UTC) + timedelta(seconds=120)
        lease = self._capacity.reserve_and_acquire(credential, idempotency, request)
        dispatched = False
        try:
            if self._provider is None:
                self._require_reserved_binding(lease)
            if deadline <= datetime.now(UTC):
                raise InferenceDeadline()
            self._dispatch.authorize(lease)
            dispatched = True
            provider = (
                self._provider if self._provider is not None else self._selected_provider(lease)
            )
            if self._provider is None:
                completed = self._dispatch.run_double_once(
                    lease, request, provider, self._fingerprinter, deadline=deadline
                )
            else:
                # Preserve the established deterministic Phase 3 seam. Only
                # production chat passes the admission-owned absolute deadline.
                completed = self._dispatch.run_double_once(
                    lease, request, provider, self._fingerprinter
                )
            return replace(
                completed,
                model_alias=lease.result.model_alias,
                charged_credits=lease.result.credit_charge,
            )
        except BaseException as error:
            self._cleanup(lease, dispatched, isinstance(error, ProviderBindingUnavailable))
            raise

    def _cleanup(
        self, lease: CapacityLease, dispatched: bool, binding_missing: bool = False
    ) -> None:
        if not lease.owns():
            return
        if not dispatched:
            try:
                lease.release_before_dispatch(
                    "provider_unavailable" if binding_missing else "cancelled"
                )
                return
            except ReleaseConflict:
                # A durable marker won even if authorize did not return after
                # commit. Reserved-only cleanup cannot refund or free its claim.
                dispatched = True
            except BaseException:
                # Retain the handler's claim until a durable release is confirmed;
                # existing maintenance can reconcile the reserved state later.
                return
        if dispatched:
            try:
                self._dispatch.mark_unknown(lease)
            except BaseException:
                # mark_unknown quarantines before writing. Keep the original
                # failure, the claim and recovery evidence if that commit fails.
                return
