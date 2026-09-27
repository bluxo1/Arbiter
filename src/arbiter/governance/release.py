"""Internal, off-event-loop cleanup; no authentication endpoint or dispatch seam.

The caller retains the verified KeyBinding from admission. Re-authentication is
deliberately not required for cleanup after revocation/expiry/suspension. A route
selector must never construct this binding. This capability can only release an
existing reserved request bound to that same tenant/key; it grants no new work.
"""

from uuid import UUID

from sqlalchemy.engine import Engine
from sqlalchemy.exc import DBAPIError, SQLAlchemyError

from arbiter.identity.context import TenantContext
from arbiter.persistence.release import ReleaseReason, ReleaseRepository, ReleaseResult
from arbiter.persistence.tenant import tenant_transaction
from arbiter.persistence.workload import KeyBinding


class ReleaseNotFound(Exception):
    status_code = 404
    code = "not_found"

    def __init__(self) -> None:
        super().__init__("request unavailable")


class ReleaseConflict(Exception):
    status_code = 409
    code = "request_not_releasable"

    def __init__(self) -> None:
        super().__init__("request not releasable")


class ReleaseUnavailable(Exception):
    status_code = 503
    code = "unavailable"

    def __init__(self) -> None:
        super().__init__("release unavailable")


class InvalidRelease(Exception):
    status_code = 422
    code = "invalid_fields"

    def __init__(self) -> None:
        super().__init__("invalid release")


class ReleaseService:
    def __init__(self, engine: Engine) -> None:
        self._engine = engine

    def release(
        self, binding: KeyBinding, request_id: UUID, reason: ReleaseReason
    ) -> ReleaseResult:
        if (
            not isinstance(binding, KeyBinding)
            or not isinstance(request_id, UUID)
            or reason
            not in {
                "cancelled",
                "provider_unavailable",
                "rejected_capacity",
                "authorization_changed",
                "admission_window_changed",
                "reservation_expired",
            }
        ):
            raise InvalidRelease()
        try:
            with tenant_transaction(self._engine, TenantContext(binding.tenant_id)) as transaction:
                result = ReleaseRepository(transaction).release(binding, request_id, reason)
            # Includes commit-time deferred audit and settlement checks.
            return result
        except DBAPIError as error:
            code = getattr(error.orig, "sqlstate", None)
            if code == "RL001":
                raise ReleaseNotFound() from None
            if code == "RL002":
                raise ReleaseConflict() from None
            if code == "22023":
                raise InvalidRelease() from None
            raise ReleaseUnavailable() from None
        except (SQLAlchemyError, RuntimeError):
            raise ReleaseUnavailable() from None
