"""Create only: admin authorization, strict input, verifier and atomic audit."""

import json
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Literal
from uuid import UUID, uuid4

from pydantic import (
    AwareDatetime,
    BaseModel,
    ConfigDict,
    Field,
    SecretStr,
    ValidationError,
    field_validator,
)
from sqlalchemy.exc import DBAPIError

from arbiter.identity.access import AuthorizedMember, InsufficientRole, ManagementAccess
from arbiter.identity.keys import KeyIssuer
from arbiter.persistence.identity import InaccessibleTenant
from arbiter.persistence.keys import KeyRepository
from arbiter.persistence.tenant import TenantTransaction


class InvalidKeyRequest(Exception):
    def __init__(self) -> None:
        super().__init__("invalid key request")


class KeyCreationConflict(Exception):
    def __init__(self) -> None:
        super().__init__("key creation conflict")


class KeyRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    label: str = Field(min_length=1, max_length=64)
    scopes: list[Literal["inference:write", "usage:read"]] = Field(min_length=1, max_length=2)
    expires_at: AwareDatetime | None = None

    @field_validator("label")
    @classmethod
    def safe_label(cls, value: str) -> str:
        if not value.strip() or any(not 32 <= ord(c) <= 126 for c in value):
            raise ValueError("invalid label")
        if "arb1." in value:
            raise ValueError("credential is not a label")
        return value

    @field_validator("scopes")
    @classmethod
    def unique_scopes(cls, values: list[str]) -> list[str]:
        if len(set(values)) != len(values):
            raise ValueError("duplicate scopes")
        return values


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for name, value in pairs:
        if name in result:
            raise ValueError("duplicate JSON field")
        result[name] = value
    return result


def parse_key_request(body: bytes) -> KeyRequest:
    try:
        if not 1 <= len(body) <= 65536:
            raise ValueError("invalid body size")
        # Validate UTF-8/root/duplicates before model parsing; both are off the event loop.
        payload = json.loads(body.decode("utf-8"), object_pairs_hook=_unique_object)
        if not isinstance(payload, dict):
            raise ValueError("object required")
        if "expires_at" in payload and not isinstance(payload["expires_at"], str):
            raise ValueError("explicit expiration must be an aware timestamp")
        return KeyRequest.model_validate_json(body)
    except (ValueError, UnicodeError, ValidationError, RecursionError):
        raise InvalidKeyRequest() from None


@dataclass(frozen=True, slots=True)
class KeyCreation:
    id: UUID
    public_id: str
    label: str
    scopes: tuple[str, ...]
    created_at: datetime
    expires_at: datetime
    api_key: SecretStr
    request_id: UUID


class KeyService:
    def __init__(self, access: ManagementAccess, issuer: KeyIssuer) -> None:
        self._access = access
        self._issuer = issuer

    async def create(self, token: str, selector: UUID, body: bytes) -> KeyCreation:
        def write(member: AuthorizedMember, scoped: TenantTransaction) -> KeyCreation:
            request = parse_key_request(body)
            issued = self._issuer.issue()
            audit_id, request_id = uuid4(), uuid4()
            try:
                created = KeyRepository(scoped).create(
                    member,
                    issued,
                    label=request.label,
                    scopes=sorted(request.scopes),
                    expires_at=request.expires_at,
                    audit_id=audit_id,
                    request_id=request_id,
                )
            except DBAPIError as error:
                code = getattr(error.orig, "sqlstate", None)
                if code == "P0002":
                    raise InaccessibleTenant() from None
                if code == "42501":
                    raise InsufficientRole() from None
                if code in {"22023", "23514"}:
                    raise InvalidKeyRequest() from None
                if code == "23505":
                    raise KeyCreationConflict() from None
                raise
            return KeyCreation(
                issued.id,
                issued.public_id,
                request.label,
                tuple(sorted(request.scopes)),
                created.created_at,
                created.expires_at,
                issued.credential,
                request_id,
            )

        # The return reaches transport only after the enclosing transaction commits.
        return await self._access.run(token, selector, write, require_admin=True)
