"""OIDC-admin key administration; no workload verification or inference route."""

from typing import Literal
from uuid import UUID

from anyio import fail_after
from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, SecretStr, field_serializer
from starlette.requests import ClientDisconnect

from arbiter.identity.access import InsufficientRole, MembershipUnavailable
from arbiter.identity.key_cursor import InvalidKeyQuery
from arbiter.identity.oidc import IdentityUnavailable, InvalidIdentity
from arbiter.operations.key_listing import KeyListService
from arbiter.operations.key_revocation import KeyRevocationService
from arbiter.operations.keys import InvalidKeyRequest, KeyCreationConflict, KeyService
from arbiter.persistence.identity import InaccessibleTenant
from arbiter.transport.errors import error_response
from arbiter.transport.identity import management_bearer

router = APIRouter()


class KeyResponse(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    id: UUID
    public_id: str = Field(pattern="^[0-9a-f]{32}$")
    label: str = Field(min_length=1, max_length=64)
    scopes: tuple[str, ...]
    created_at: AwareDatetime
    expires_at: AwareDatetime
    api_key: SecretStr
    request_id: UUID

    @field_serializer("api_key")
    def one_time_credential(self, value: SecretStr) -> str:
        return value.get_secret_value()


class BodyTooLarge(Exception):
    pass


class KeyMetadata(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    id: UUID
    public_id: str = Field(pattern="^[0-9a-f]{32}$")
    label: str = Field(min_length=1, max_length=64)
    scopes: tuple[Literal["inference:write", "usage:read"], ...] = Field(min_length=1, max_length=2)
    created_at: AwareDatetime
    expires_at: AwareDatetime
    revoked_at: AwareDatetime | None


class KeyListResponse(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    data: tuple[KeyMetadata, ...]
    next_cursor: str | None


class KeyRevocationResponse(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    id: UUID
    revoked_at: AwareDatetime


@router.post("/v1/tenants/{tenant_id}/keys/{key_id}/revoke", response_model=KeyRevocationResponse)
async def revoke_key(tenant_id: str, key_id: str, request: Request) -> JSONResponse:
    try:
        token = management_bearer(request)
        try:
            selector = UUID(tenant_id)
        except ValueError:
            raise InvalidKeyRequest() from None
        service: KeyRevocationService | None = getattr(
            request.app.state, "key_revocation_service", None
        )
        if service is None:
            raise MembershipUnavailable()
        # This operation has no body or options. Read at most one nonempty chunk.
        invalid_input = bool(request.query_params) or any(
            name.lower() == b"content-encoding" for name, _ in request.scope["headers"]
        )
        with fail_after(5):
            async for chunk in request.stream():
                if chunk:
                    invalid_input = True
                    break
        identifier, revoked_at = await service.revoke(
            token, selector, key_id, invalid_input=invalid_input
        )
        response = KeyRevocationResponse(id=identifier, revoked_at=revoked_at)
        return JSONResponse(
            content=response.model_dump(mode="json"), headers={"Cache-Control": "no-store"}
        )
    except InvalidIdentity:
        return error_response(401, "invalid_credentials", "Invalid credentials")
    except InaccessibleTenant:
        return error_response(404, "not_found", "Resource not found")
    except InsufficientRole:
        return error_response(403, "permission_denied", "Permission denied")
    except InvalidKeyRequest:
        return error_response(422, "invalid_fields", "Invalid key request")
    except (IdentityUnavailable, MembershipUnavailable, TimeoutError):
        return error_response(503, "unavailable", "Service unavailable")
    except ClientDisconnect:
        return error_response(422, "invalid_fields", "Invalid key request")


@router.get("/v1/tenants/{tenant_id}/keys", response_model=KeyListResponse)
async def list_keys(tenant_id: str, request: Request) -> JSONResponse:
    try:
        token = management_bearer(request)
        try:
            selector = UUID(tenant_id)
        except ValueError:
            raise InvalidKeyQuery() from None
        service: KeyListService | None = getattr(request.app.state, "key_list_service", None)
        if service is None:
            raise MembershipUnavailable()
        page = await service.list(token, selector, list(request.query_params.multi_items()))
        response = KeyListResponse(
            data=tuple(
                KeyMetadata(
                    id=item.id,
                    public_id=item.public_id,
                    label=item.label,
                    scopes=item.scopes,
                    created_at=item.created_at,
                    expires_at=item.expires_at,
                    revoked_at=item.revoked_at,
                )
                for item in page.data
            ),
            next_cursor=page.next_cursor,
        )
        return JSONResponse(
            content=response.model_dump(mode="json"), headers={"Cache-Control": "no-store"}
        )
    except InvalidIdentity:
        return error_response(401, "invalid_credentials", "Invalid credentials")
    except InaccessibleTenant:
        return error_response(404, "not_found", "Resource not found")
    except InsufficientRole:
        return error_response(403, "permission_denied", "Permission denied")
    except InvalidKeyQuery:
        return error_response(422, "invalid_fields", "Invalid key query")
    except (IdentityUnavailable, MembershipUnavailable):
        return error_response(503, "unavailable", "Service unavailable")


async def _body(request: Request) -> bytes:
    headers = request.scope["headers"]
    types = [value for name, value in headers if name.lower() == b"content-type"]
    lengths = [value for name, value in headers if name.lower() == b"content-length"]
    encodings = [value for name, value in headers if name.lower() == b"content-encoding"]
    if len(types) != 1 or types[0].split(b";", 1)[0].strip().lower() != b"application/json":
        raise InvalidKeyRequest()
    if len(lengths) > 1 or encodings:
        raise InvalidKeyRequest()
    if lengths:
        try:
            length = int(lengths[0])
        except ValueError:
            raise InvalidKeyRequest() from None
        if length < 0:
            raise InvalidKeyRequest()
        if length > 65536:
            raise BodyTooLarge()
    body = bytearray()
    with fail_after(5):
        async for chunk in request.stream():
            if len(body) + len(chunk) > 65536:
                raise BodyTooLarge()
            body.extend(chunk)
    return bytes(body)


@router.post("/v1/tenants/{tenant_id}/keys", status_code=201, response_model=KeyResponse)
async def create_key(tenant_id: str, request: Request) -> JSONResponse:
    try:
        token = management_bearer(request)
        try:
            selector = UUID(tenant_id)
        except ValueError:
            raise InvalidKeyRequest() from None
        if request.query_params:
            raise InvalidKeyRequest()
        body = await _body(request)
        service: KeyService | None = getattr(request.app.state, "key_service", None)
        if service is None:
            raise MembershipUnavailable()
        created = await service.create(token, selector, body)
        response = KeyResponse(
            id=created.id,
            public_id=created.public_id,
            label=created.label,
            scopes=created.scopes,
            created_at=created.created_at,
            expires_at=created.expires_at,
            api_key=created.api_key,
            request_id=created.request_id,
        )
        return JSONResponse(
            status_code=201,
            headers={"Cache-Control": "no-store"},
            content=response.model_dump(mode="json"),
        )
    except InvalidIdentity:
        return error_response(401, "invalid_credentials", "Invalid credentials")
    except InaccessibleTenant:
        return error_response(404, "not_found", "Resource not found")
    except InsufficientRole:
        return error_response(403, "permission_denied", "Permission denied")
    except InvalidKeyRequest:
        return error_response(422, "invalid_fields", "Invalid key request")
    except KeyCreationConflict:
        return error_response(409, "creation_conflict", "Key creation conflict")
    except BodyTooLarge:
        return error_response(413, "body_too_large", "Request body too large")
    except (IdentityUnavailable, MembershipUnavailable, TimeoutError):
        return error_response(503, "unavailable", "Service unavailable")
    except ClientDisconnect:
        return error_response(422, "invalid_fields", "Invalid key request")
