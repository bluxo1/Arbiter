"""One process-local, nonqueueing capacity gate after durable reservation.

This module does not authorize dispatch or infer durable accounting from slots.
The dispatch commit transfers a claim from its handler to supervised work.
Unknown claims are quarantined until audited operator clearance.
"""

from collections.abc import Callable
from dataclasses import dataclass
from threading import Lock
from typing import Literal
from uuid import UUID

from pydantic import SecretStr

from arbiter.governance.fingerprint import ReservationInput
from arbiter.governance.release import ReleaseService
from arbiter.governance.reservation import ReservationService
from arbiter.persistence.release import ReleaseResult
from arbiter.persistence.reservation import ReservationResult
from arbiter.persistence.workload import KeyBinding


class CapacityUnavailable(Exception):
    code = "unavailable"
    status_code = 503

    def __init__(self) -> None:
        super().__init__("capacity unavailable")


class CapacityOwnershipError(Exception):
    def __init__(self) -> None:
        super().__init__("capacity ownership mismatch")


OwnedReleaseReason = Literal[
    "cancelled",
    "provider_unavailable",
    "authorization_changed",
    "admission_window_changed",
    "reservation_expired",
]


@dataclass(frozen=True, slots=True)
class _Claim:
    identity: tuple[UUID, UUID, UUID]
    nonce: object


class CapacityGate:
    """Atomically count only this process's claimed slots; never wait for one."""

    def __init__(self, limit: int = 2) -> None:
        if isinstance(limit, bool) or not isinstance(limit, int) or not 0 <= limit <= 2147483647:
            raise ValueError("invalid global capacity")
        self.limit = limit
        self._lock = Lock()
        self._owners: dict[tuple[UUID, UUID, UUID], object] = {}
        self._provider_started: set[tuple[UUID, UUID, UUID]] = set()
        self._dispatched: set[tuple[UUID, UUID, UUID]] = set()
        self._quarantined: set[tuple[UUID, UUID, UUID]] = set()
        self._ready = True

    @property
    def occupied(self) -> int:
        with self._lock:
            return len(self._owners)

    def operational_snapshot(self) -> dict[str, int | bool]:
        """Count safety states under the gate lock; never export claim identities."""
        with self._lock:
            return {
                "limit": self.limit,
                "occupied": len(self._owners),
                "quarantined": len(self._quarantined),
                "recovery_ready": self._ready,
                "saturated": len(self._owners) >= self.limit,
            }

    @property
    def ready(self) -> bool:
        with self._lock:
            return self._ready

    def set_recovery_ready(self, ready: bool) -> None:
        with self._lock:
            self._ready = ready and not self._quarantined

    def try_acquire(self, binding: KeyBinding, request_id: UUID) -> _Claim | None:
        identity = (binding.tenant_id, binding.key_id, request_id)
        with self._lock:
            if not self._ready:
                return None
            if identity in self._owners:
                raise CapacityOwnershipError()
            if len(self._owners) >= self.limit:
                return None
            nonce = object()
            self._owners[identity] = nonce
            return _Claim(identity, nonce)

    def release(self, claim: _Claim) -> bool:
        with self._lock:
            if self._owners.get(claim.identity) is not claim.nonce:
                return False
            if claim.identity in self._dispatched or claim.identity in self._quarantined:
                return False
            del self._owners[claim.identity]
            self._provider_started.discard(claim.identity)
            return True

    def transfer_after_dispatch(self, claim: _Claim) -> None:
        with self._lock:
            if self._owners.get(claim.identity) is not claim.nonce:
                raise CapacityOwnershipError()
            self._dispatched.add(claim.identity)

    def quarantine(self, claim: _Claim) -> None:
        with self._lock:
            if self._owners.get(claim.identity) is not claim.nonce:
                raise CapacityOwnershipError()
            self._dispatched.add(claim.identity)
            self._quarantined.add(claim.identity)
            self._ready = False

    def restore_unknown(self, identity: tuple[UUID, UUID, UUID]) -> None:
        """Rebuild an effective capacity claim from durable, uncleared unknown work."""
        with self._lock:
            if identity not in self._owners:
                self._owners[identity] = object()
            self._dispatched.add(identity)
            self._quarantined.add(identity)
            self._ready = False

    def release_reserved_identity(self, identity: tuple[UUID, UUID, UUID]) -> bool:
        with self._lock:
            if identity not in self._owners or identity in self._dispatched:
                return False
            del self._owners[identity]
            self._provider_started.discard(identity)
            return True

    def release_cleared_unknown(self, identity: tuple[UUID, UUID, UUID]) -> bool:
        with self._lock:
            if identity not in self._quarantined:
                return False
            self._quarantined.remove(identity)
            self._dispatched.discard(identity)
            self._provider_started.discard(identity)
            del self._owners[identity]
            return True

    def release_terminal(self, claim: _Claim) -> bool:
        with self._lock:
            if self._owners.get(claim.identity) is not claim.nonce:
                return False
            if claim.identity not in self._dispatched or claim.identity in self._quarantined:
                raise CapacityOwnershipError()
            self._dispatched.remove(claim.identity)
            self._provider_started.discard(claim.identity)
            del self._owners[claim.identity]
            return True

    def owns(self, claim: _Claim) -> bool:
        with self._lock:
            return self._owners.get(claim.identity) is claim.nonce

    def claim_provider_once(self, claim: _Claim) -> bool:
        """One local invocation claim; never reset it while this capacity owner lives."""
        with self._lock:
            if self._owners.get(claim.identity) is not claim.nonce:
                return False
            if claim.identity in self._provider_started:
                return False
            self._provider_started.add(claim.identity)
            return True


# One gate for the supported single-worker process. No route creates another.
process_capacity = CapacityGate()
process_capacity.set_recovery_ready(False)


class CapacityLease:
    """Internal in-flight owner; no automatic destructor or HTTP-facing handle."""

    def __init__(
        self,
        result: ReservationResult,
        binding: KeyBinding,
        claim: _Claim,
        gate: CapacityGate,
        releaser: ReleaseService,
    ) -> None:
        self.result = result
        self._binding = binding
        self._claim = claim
        self._gate = gate
        self._releaser = releaser

    def release_before_dispatch(self, reason: OwnedReleaseReason = "cancelled") -> ReleaseResult:
        # Only a committed database release proves that this slot is safe to free.
        released = self._releaser.release(self._binding, self.result.request_id, reason)
        if released.state not in {"released", "rejected_capacity"}:
            raise CapacityOwnershipError()
        self._gate.release(self._claim)
        return released

    def owns(self) -> bool:
        return self._gate.owns(self._claim)

    def _transfer_after_dispatch(self) -> None:
        self._gate.transfer_after_dispatch(self._claim)

    def _quarantine_unknown(self) -> None:
        self._gate.quarantine(self._claim)

    def _release_after_confirmed(self, released: ReleaseResult) -> None:
        """Free only this claim after an outer transaction commits a release."""
        if released.request_id != self.result.request_id or released.state not in {
            "released",
            "rejected_capacity",
        }:
            raise CapacityOwnershipError()
        self._gate.release(self._claim)

    def _claim_provider_once(self) -> bool:
        return self._gate.claim_provider_once(self._claim)

    def _release_after_terminal(self, request_id: UUID, state: str) -> bool:
        if request_id != self.result.request_id or state not in {"succeeded", "failed"}:
            raise CapacityOwnershipError()
        return self._gate.release_terminal(self._claim)

    def prepare(self, action: Callable[[], None]) -> None:
        """Guard a synchronous pre-dispatch step, including cancellation.

        A successful step keeps the slot. A failed step releases its durable
        reservation before freeing the slot. This is not dispatch authorization.
        """
        if not self._gate.owns(self._claim):
            raise CapacityOwnershipError()
        try:
            action()
        except BaseException:
            self.release_before_dispatch("cancelled")
            raise


class CapacityService:
    """Reserve in PostgreSQL first, then try the one process-local slot."""

    def __init__(
        self,
        reservation: ReservationService,
        release: ReleaseService,
        gate: CapacityGate = process_capacity,
    ) -> None:
        self._reservation = reservation
        self._release = release
        self._gate = gate

    def reserve_and_acquire(
        self,
        credential: SecretStr,
        idempotency: str,
        request: ReservationInput,
    ) -> CapacityLease:
        reserved = self._reservation.reserve_for_capacity(credential, idempotency, request)
        binding, result = reserved.binding, reserved.result
        try:
            claim = self._gate.try_acquire(binding, result.request_id)
        except BaseException:
            self._release.release(binding, result.request_id, "cancelled")
            raise
        if claim is None:
            self._release.release(binding, result.request_id, "rejected_capacity")
            raise CapacityUnavailable()
        return CapacityLease(result, binding, claim, self._gate, self._release)
