"""Internal dispatch-authorization transaction; deliberately no provider call."""

from dataclasses import dataclass
from uuid import UUID

from sqlalchemy.engine import Engine
from sqlalchemy.exc import DBAPIError, SQLAlchemyError

from arbiter.governance.capacity import CapacityLease, CapacityOwnershipError
from arbiter.identity.context import TenantContext
from arbiter.persistence.dispatch import DispatchRepository
from arbiter.persistence.release import ReleaseRepository, ReleaseResult
from arbiter.persistence.tenant import tenant_transaction


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
