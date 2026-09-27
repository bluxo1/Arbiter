"""Thin management transport: credentials, selector, sanitized responses."""

from typing import Literal
from uuid import UUID, uuid4

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from pydantic import AwareDatetime, BaseModel, ConfigDict, Field

from arbiter.identity.access import MembershipUnavailable
from arbiter.identity.audit_cursor import InvalidAuditQuery
from arbiter.identity.oidc import IdentityUnavailable, InvalidIdentity
from arbiter.operations.audit import AuditService
from arbiter.persistence.identity import InaccessibleTenant
from arbiter.transport.identity import management_bearer

router = APIRouter()


class AuditMetadata(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    id: UUID
    actor_type: Literal["member", "operator"]
    actor_membership_id: UUID | None
    action: str = Field(min_length=1, max_length=64)
    target_id: UUID
    policy_revision: int = Field(ge=1)
    request_id: UUID | None
    occurred_at: AwareDatetime
    outcome: Literal["succeeded", "denied"]


class AuditResponse(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    data: tuple[AuditMetadata, ...]
    next_cursor: str | None


def _error(status: int, code: str, message: str) -> JSONResponse:
    headers = {"Cache-Control": "no-store"}
    if status == 401:
        headers["WWW-Authenticate"] = "Bearer"
    return JSONResponse(
        status_code=status,
        content={"error": {"code": code, "message": message}, "request_id": str(uuid4())},
        headers=headers,
    )


@router.get("/v1/tenants/{tenant_id}/audit", response_model=AuditResponse)
async def audit_list(tenant_id: str, request: Request) -> JSONResponse:
    try:
        token = management_bearer(request)
        try:
            selector = UUID(tenant_id)
        except ValueError:
            raise InvalidAuditQuery() from None
        service: AuditService = request.app.state.audit_service
        page = await service.list(token, selector, list(request.query_params.multi_items()))
        response = AuditResponse(
            data=tuple(
                AuditMetadata(
                    id=item.id,
                    actor_type=item.actor_type,
                    actor_membership_id=item.actor_membership_id,
                    action=item.action,
                    target_id=item.target_id,
                    policy_revision=item.policy_revision,
                    request_id=item.request_id,
                    occurred_at=item.occurred_at,
                    outcome=item.outcome,
                )
                for item in page.data
            ),
            next_cursor=page.next_cursor,
        )
        return JSONResponse(
            content=response.model_dump(mode="json"), headers={"Cache-Control": "no-store"}
        )
    except InvalidIdentity:
        return _error(401, "invalid_credentials", "Invalid credentials")
    except InaccessibleTenant:
        return _error(404, "not_found", "Resource not found")
    except InvalidAuditQuery:
        return _error(422, "invalid_fields", "Invalid audit query")
    except (IdentityUnavailable, MembershipUnavailable):
        return _error(503, "unavailable", "Service unavailable")
