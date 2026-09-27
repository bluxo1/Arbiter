"""OIDC-member and workload-key catalogs; explicit public metadata serialization."""

from uuid import UUID

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field

from arbiter.identity.access import MembershipUnavailable
from arbiter.identity.model_cursor import InvalidModelQuery
from arbiter.identity.oidc import IdentityUnavailable, InvalidIdentity
from arbiter.operations.models import ManagementModels, ModelCatalog, ModelPage
from arbiter.persistence.identity import InaccessibleTenant
from arbiter.persistence.tenant import TenantTransaction
from arbiter.persistence.workload import KeyBinding
from arbiter.transport.errors import error_response
from arbiter.transport.identity import management_bearer
from arbiter.transport.workload import run_workload

router = APIRouter()


class PublicModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)
    alias: str = Field(pattern=r"^[a-z][a-z0-9_-]{0,63}$")
    output_cap: int = Field(ge=1, le=1024)
    credit_charge: int = Field(ge=1, le=9223372036854775807)
    policy_revision: int = Field(ge=1, le=9223372036854775807)


class ModelResponse(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)
    data: tuple[PublicModel, ...]
    next_cursor: str | None


def response(page: ModelPage) -> JSONResponse:
    result = ModelResponse(
        data=tuple(
            PublicModel(
                alias=item.alias,
                output_cap=item.output_cap,
                credit_charge=item.credit_charge,
                policy_revision=item.policy_revision,
            )
            for item in page.data
        ),
        next_cursor=page.next_cursor,
    )
    return JSONResponse(result.model_dump(mode="json"), headers={"Cache-Control": "no-store"})


@router.get("/v1/tenants/{tenant_id}/models", response_model=ModelResponse)
async def management_models(tenant_id: str, request: Request) -> JSONResponse:
    try:
        token = management_bearer(request)
        try:
            selector = UUID(tenant_id)
        except ValueError:
            # Invalid selectors do not trigger an existence lookup.
            raise InvalidModelQuery() from None
        service: ManagementModels | None = getattr(request.app.state, "management_models", None)
        if service is None:
            raise MembershipUnavailable()
        page = await service.list(token, selector, list(request.query_params.multi_items()))
        return response(page)
    except InvalidIdentity:
        return error_response(401, "invalid_credentials", "Invalid credentials")
    except InaccessibleTenant:
        return error_response(404, "not_found", "Resource not found")
    except InvalidModelQuery:
        return error_response(422, "invalid_request", "Invalid request")
    except (IdentityUnavailable, MembershipUnavailable):
        return error_response(503, "unavailable", "Service unavailable")


@router.get("/v1/models", response_model=ModelResponse)
async def workload_models(request: Request) -> JSONResponse:
    try:

        def read(binding: KeyBinding, scoped: TenantTransaction) -> ModelPage:
            catalog: ModelCatalog | None = getattr(request.app.state, "model_catalog", None)
            if catalog is None:
                raise MembershipUnavailable()
            return catalog.read(scoped, list(request.query_params.multi_items()))

        # Design.md grants catalog access to either valid API-key scope.
        result = await run_workload(request, read)
        return result if isinstance(result, JSONResponse) else response(result)
    except InvalidModelQuery:
        return error_response(422, "invalid_request", "Invalid request")
    except MembershipUnavailable:
        return error_response(503, "unavailable", "Service unavailable")
