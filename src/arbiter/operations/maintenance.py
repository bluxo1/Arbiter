"""Supervised 10-second reconciliation; no provider call or automatic redispatch."""

from dataclasses import dataclass
from threading import Lock

from sqlalchemy.engine import Engine
from sqlalchemy.exc import DBAPIError, SQLAlchemyError

from arbiter.governance.capacity import CapacityGate, process_capacity
from arbiter.governance.release import (
    ReleaseConflict,
    ReleaseNotFound,
    ReleaseService,
    ReleaseUnavailable,
)
from arbiter.identity.context import TenantContext
from arbiter.observability import observed
from arbiter.persistence.maintenance import MaintenanceCandidate, candidates
from arbiter.persistence.tenant import tenant_transaction
from arbiter.persistence.terminal import TerminalRepository
from arbiter.persistence.workload import KeyBinding

CADENCE_SECONDS = 10


class MaintenanceUnavailable(Exception):
    code = "unavailable"
    status_code = 503


@dataclass(frozen=True, slots=True)
class MaintenanceResult:
    released: int
    marked_unknown: int
    unresolved_unknown: int
    recovered_capacity: int
    recovery_ready: bool


class MaintenanceService:
    """Single-worker recovery coordinator; database transitions remain authoritative."""

    def __init__(
        self, engine: Engine, discovery: Engine, gate: CapacityGate = process_capacity
    ) -> None:
        self._engine = engine
        self._discovery = discovery
        self._gate = gate
        self._lock = Lock()
        self._startup_complete = False
        self._gate.set_recovery_ready(False)

    @property
    def recovery_ready(self) -> bool:
        return self._startup_complete and self._gate.ready

    @staticmethod
    def _binding(item: MaintenanceCandidate) -> KeyBinding:
        return KeyBinding(item.key_id, item.tenant_id, ("inference:write",))

    def _mark_unknown(self, item: MaintenanceCandidate) -> bool:
        with tenant_transaction(self._engine, TenantContext(item.tenant_id)) as transaction:
            return TerminalRepository(transaction).finalize(
                self._binding(item), item.request_id, "unknown", "unknown", None, None
            )

    @observed("maintenance")
    def run_once(self) -> MaintenanceResult:
        """Repeat safely; a failed scan or mutation always closes recovery readiness."""
        with self._lock:
            self._gate.set_recovery_ready(False)
            released = marked = recovered = 0
            try:
                if not self._startup_complete:
                    # No new work can enter this gate until every prior dispatch is
                    # terminal or quarantined. A crash between individual rows is safe:
                    # the next pass finds the remaining dispatched rows.
                    for item in candidates(self._discovery, "restart"):
                        try:
                            marked += int(self._mark_unknown(item))
                        except DBAPIError as error:
                            if getattr(error.orig, "sqlstate", None) != "TL002":
                                raise
                    self._startup_complete = True

                for item in candidates(self._discovery, "stale"):
                    try:
                        result = ReleaseService(self._engine).release(
                            self._binding(item), item.request_id, "reservation_expired"
                        )
                    except ReleaseConflict:
                        # Dispatch or another release won the request row lock.
                        continue
                    if result.state in {"released", "rejected_capacity"}:
                        released += int(
                            result.changed
                            and result.state == "released"
                            and result.outcome == "reservation_expired"
                        )
                        self._gate.release_reserved_identity(item.identity)
                    else:
                        raise MaintenanceUnavailable()

                unknown = candidates(self._discovery, "unknown")
                uncleared = 0
                for item in unknown:
                    if item.cleared:
                        recovered += int(self._gate.release_cleared_unknown(item.identity))
                    else:
                        uncleared += 1
                        self._gate.restore_unknown(item.identity)
                self._gate.set_recovery_ready(uncleared == 0)
                return MaintenanceResult(
                    released, marked, uncleared, recovered, self.recovery_ready
                )
            except (
                DBAPIError,
                SQLAlchemyError,
                RuntimeError,
                ReleaseNotFound,
                ReleaseUnavailable,
                MaintenanceUnavailable,
            ):
                self._gate.set_recovery_ready(False)
                raise MaintenanceUnavailable() from None
