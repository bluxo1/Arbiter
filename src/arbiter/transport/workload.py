"""Reusable workload authentication boundary; verification is not dispatch authority."""

from collections.abc import Callable

from fastapi import Request
from fastapi.responses import JSONResponse
from pydantic import SecretStr

from arbiter.identity.keys import InvalidKey
from arbiter.identity.oidc import InvalidIdentity
from arbiter.identity.workload import MissingScope, WorkloadAccess, WorkloadUnavailable
from arbiter.persistence.tenant import TenantTransaction
from arbiter.persistence.workload import KeyBinding, KeyScope
from arbiter.transport.errors import error_response
from arbiter.transport.identity import management_bearer


def workload_bearer(request: Request) -> SecretStr:
    # Shared duplicate/mixed/header syntax guard only; OIDC verification is not used.
    try:
        return SecretStr(management_bearer(request))
    except InvalidIdentity:
        raise InvalidKey() from None


async def run_workload[T](
    request: Request,
    operation: Callable[[KeyBinding, TenantTransaction], T],
    *,
    required_scope: KeyScope | None = None,
) -> T | JSONResponse:
    try:
        credential = workload_bearer(request)
        access: WorkloadAccess | None = getattr(request.app.state, "workload_access", None)
        if access is None:
            raise WorkloadUnavailable()
        return await access.run(credential, operation, required_scope=required_scope)
    except InvalidKey:
        return error_response(401, "invalid_credentials", "Invalid credentials")
    except MissingScope:
        return error_response(403, "permission_denied", "Permission denied")
    except WorkloadUnavailable:
        return error_response(503, "unavailable", "Service unavailable")
