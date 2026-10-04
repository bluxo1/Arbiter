"""Bounded usage/request metadata transports; no content, completion or existence leaks."""

from datetime import UTC, datetime
from typing import Literal
from uuid import UUID

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from pydantic import AwareDatetime, BaseModel, ConfigDict, Field

from arbiter.identity.access import MembershipUnavailable
from arbiter.identity.oidc import IdentityUnavailable, InvalidIdentity
from arbiter.operations.usage import (
    InvalidUsageQuery,
    ManagementUsage,
    UsageReader,
    current_window,
)
from arbiter.persistence.identity import InaccessibleTenant
from arbiter.persistence.tenant import TenantTransaction
from arbiter.persistence.usage import RequestStatus, RetiredRequest, UsageTotals
from arbiter.persistence.workload import KeyBinding
from arbiter.transport.errors import error_response
from arbiter.transport.identity import management_bearer
from arbiter.transport.workload import run_workload

router = APIRouter()

Outcome = Literal[
    "succeeded",
    "provider_failure",
    "provider_deadline",
    "provider_unavailable",
    "provider_malformed",
    "unknown",
    "cancelled",
    "rejected_capacity",
    "authorization_changed",
    "admission_window_changed",
    "reservation_expired",
]
State = Literal[
    "reserved",
    "dispatched",
    "succeeded",
    "failed",
    "unknown",
    "released",
    "rejected_capacity",
]


class PublicUsage(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)
    window: Literal["day", "month"]
    window_start: AwareDatetime
    committed: int = Field(ge=0, le=9223372036854775807)
    reserved: int = Field(ge=0, le=9223372036854775807)


class UsageResponse(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)
    data: tuple[PublicUsage, ...]


class PublicRequestStatus(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)
    id: UUID
    state: State
    outcome: Outcome | None
    credit_charge: int = Field(ge=1, le=9223372036854775807)
    input_tokens: int | None
    output_tokens: int | None
    model_alias: str
    policy_revision: int = Field(ge=1, le=9223372036854775807)
    created_at: AwareDatetime
    dispatched_at: AwareDatetime | None
    finished_at: AwareDatetime | None


class RequestStatusResponse(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)
    data: PublicRequestStatus


def _usage_response(totals: list[UsageTotals]) -> JSONResponse:
    result = UsageResponse(
        data=tuple(
            PublicUsage(
                window=item.unit,
                window_start=item.window_start,
                committed=item.committed,
                reserved=item.reserved,
            )
            for item in totals
        )
    )
    return JSONResponse(result.model_dump(mode="json"), headers={"Cache-Control": "no-store"})


def _status_response(status: RequestStatus | RetiredRequest) -> JSONResponse:
    if isinstance(status, RetiredRequest):
        return JSONResponse(
            status_code=410,
            content={
                "error": {"code": "request_retired", "message": "Request retired"},
                "request_id": str(status.id),
                "state": status.state,
            },
            headers={"Cache-Control": "no-store"},
        )
    result = RequestStatusResponse(
        data=PublicRequestStatus(
            id=status.id,
            state=status.state,  # type: ignore[arg-type]  # DB CHECK constrains values
            outcome=status.outcome,  # type: ignore[arg-type]  # DB CHECK constrains values
            credit_charge=status.credit_charge,
            input_tokens=status.input_tokens,
            output_tokens=status.output_tokens,
            model_alias=status.model_alias,
            policy_revision=status.policy_revision,
            created_at=status.created_at,
            dispatched_at=status.dispatched_at,
            finished_at=status.finished_at,
        )
    )
    return JSONResponse(result.model_dump(mode="json"), headers={"Cache-Control": "no-store"})


def _request_id(value: str) -> UUID:
    # Structural validation only; existence is never inferred from parse success.
    try:
        if len(value) != 36:
            raise ValueError("noncanonical identifier")
        return UUID(value)
    except ValueError:
        raise InvalidUsageQuery() from None


def _management_service(request: Request) -> ManagementUsage:
    service: ManagementUsage | None = getattr(request.app.state, "management_usage", None)
    if service is None:
        raise MembershipUnavailable()
    return service


def _reject_query_params(request: Request) -> None:
    if request.query_params:
        raise InvalidUsageQuery()


@router.get("/v1/usage", response_model=UsageResponse)
async def workload_usage(request: Request) -> JSONResponse:
    """API key with usage scope; current UTC daily/monthly allocation totals."""

    def read(binding: KeyBinding, scoped: TenantTransaction) -> list[UsageTotals]:
        del binding
        # Query validation deliberately follows authentication and scope checks.
        _reject_query_params(request)
        now = datetime.now(UTC)
        reader = UsageReader()
        return [reader.totals(scoped, unit, current_window(unit, now)) for unit in ("day", "month")]

    try:
        result = await run_workload(request, read, required_scope="usage:read")
        return result if isinstance(result, JSONResponse) else _usage_response(result)
    except InvalidUsageQuery:
        return error_response(422, "invalid_request", "Invalid request")
    except MembershipUnavailable:
        return error_response(503, "unavailable", "Service unavailable")


@router.get("/v1/requests/{request_id}", response_model=RequestStatusResponse)
async def workload_request(request: Request, request_id: str) -> JSONResponse:
    """API key with usage scope; stored request metadata only, no completion replay."""
    identifier = _request_id(request_id)

    def read(binding: KeyBinding, scoped: TenantTransaction) -> RequestStatus | RetiredRequest:
        del binding
        # Query validation deliberately follows authentication and scope checks.
        _reject_query_params(request)
        status = UsageReader().request_status(scoped, identifier)
        if status is None:
            # Foreign and nonexistent requests share this sanitized absence.
            raise InaccessibleTenant()
        return status

    try:
        result = await run_workload(request, read, required_scope="usage:read")
        return result if isinstance(result, JSONResponse) else _status_response(result)
    except InvalidUsageQuery:
        return error_response(422, "invalid_request", "Invalid request")
    except InaccessibleTenant:
        return error_response(404, "not_found", "Resource not found")
    except MembershipUnavailable:
        return error_response(503, "unavailable", "Service unavailable")


@router.get("/v1/tenants/{tenant_id}/usage", response_model=UsageResponse)
async def management_usage(tenant_id: str, request: Request) -> JSONResponse:
    """Member/admin JWT; current totals, or one bounded historical UTC window."""
    try:
        # Authentication first; selector/query validation strictly afterwards.
        token = management_bearer(request)
        try:
            selector = UUID(tenant_id)
        except ValueError:
            # Invalid selectors do not trigger an existence lookup.
            raise InvalidUsageQuery() from None
        service = _management_service(request)
        selected: dict[str, str] = {}
        for name, value in request.query_params.multi_items():
            if name not in {"window", "window_start"} or name in selected:
                raise InvalidUsageQuery()
            selected[name] = value
        if ("window" in selected) != ("window_start" in selected):
            raise InvalidUsageQuery()
        totals = await service.totals(
            token, selector, selected.get("window"), selected.get("window_start")
        )
        return _usage_response(totals)
    except InvalidIdentity:
        return error_response(401, "invalid_credentials", "Invalid credentials")
    except InvalidUsageQuery:
        return error_response(422, "invalid_request", "Invalid request")
    except InaccessibleTenant:
        return error_response(404, "not_found", "Resource not found")
    except (IdentityUnavailable, MembershipUnavailable):
        return error_response(503, "unavailable", "Service unavailable")


@router.get(
    "/v1/tenants/{tenant_id}/requests/{request_id}",
    response_model=RequestStatusResponse,
)
async def management_request(tenant_id: str, request_id: str, request: Request) -> JSONResponse:
    """Member/admin JWT; same metadata contract as the workload status route."""
    try:
        # Authentication first; selector/query validation strictly afterwards.
        token = management_bearer(request)
        try:
            selector = UUID(tenant_id)
        except ValueError:
            raise InvalidUsageQuery() from None
        identifier = _request_id(request_id)
        _reject_query_params(request)
        service = _management_service(request)
        status = await service.request_status(token, selector, identifier)
        if status is None:
            raise InaccessibleTenant()
        return _status_response(status)
    except InvalidIdentity:
        return error_response(401, "invalid_credentials", "Invalid credentials")
    except InvalidUsageQuery:
        return error_response(422, "invalid_request", "Invalid request")
    except InaccessibleTenant:
        return error_response(404, "not_found", "Resource not found")
    except (IdentityUnavailable, MembershipUnavailable):
        return error_response(503, "unavailable", "Service unavailable")
