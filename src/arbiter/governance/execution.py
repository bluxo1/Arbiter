"""Synchronous, internal Phase 3 governed execution with the provider double."""

from pydantic import SecretStr
from sqlalchemy.engine import Engine

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
from arbiter.identity.keys import KeyVerifier
from arbiter.providers.double import DeterministicProvider


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
        provider: DeterministicProvider,
        capacity: CapacityGate = process_capacity,
    ) -> None:
        if not isinstance(provider, DeterministicProvider):
            raise TypeError("internal execution requires the deterministic provider double")
        self._capacity = CapacityService(
            RateGovernedReservationService(engine, verifier, fingerprinter, rate),
            ReleaseService(engine),
            capacity,
        )
        self._dispatch = DispatchService(engine)
        self._fingerprinter = fingerprinter
        self._provider = provider

    def execute(
        self, credential: SecretStr, idempotency: str, request: ReservationInput
    ) -> ProviderCompletion:
        lease = self._capacity.reserve_and_acquire(credential, idempotency, request)
        dispatched = False
        try:
            self._dispatch.authorize(lease)
            dispatched = True
            return self._dispatch.run_double_once(
                lease, request, self._provider, self._fingerprinter
            )
        except BaseException:
            self._cleanup(lease, dispatched)
            raise

    def _cleanup(self, lease: CapacityLease, dispatched: bool) -> None:
        if not lease.owns():
            return
        if not dispatched:
            try:
                lease.release_before_dispatch()
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
