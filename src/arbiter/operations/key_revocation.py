"""Admin authorization and atomic, idempotent revocation; no workload auth path."""

from datetime import datetime
from uuid import UUID, uuid4

from sqlalchemy.exc import DBAPIError

from arbiter.identity.access import AuthorizedMember, InsufficientRole, ManagementAccess
from arbiter.operations.keys import InvalidKeyRequest
from arbiter.persistence.identity import InaccessibleTenant
from arbiter.persistence.keys import KeyRepository
from arbiter.persistence.tenant import TenantTransaction


class KeyRevocationService:
    def __init__(self, access: ManagementAccess) -> None:
        self._access = access

    async def revoke(
        self, token: str, selector: UUID, key_id: str, *, invalid_input: bool = False
    ) -> tuple[UUID, datetime]:
        def write(member: AuthorizedMember, scoped: TenantTransaction) -> tuple[UUID, datetime]:
            # Parse the object selector only after verified membership/admin authorization.
            try:
                identifier = UUID(key_id)
            except ValueError:
                raise InvalidKeyRequest() from None
            if invalid_input:
                raise InvalidKeyRequest()
            try:
                revoked = KeyRepository(scoped).revoke(
                    member, identifier, audit_id=uuid4(), request_id=uuid4()
                )
            except DBAPIError as error:
                code = getattr(error.orig, "sqlstate", None)
                if code == "P0002":
                    raise InaccessibleTenant() from None
                if code == "42501":
                    raise InsufficientRole() from None
                # Constraint/audit/connection failures reach the common sanitized 503 boundary.
                raise
            return identifier, revoked

        # No successful response can precede transaction commit.
        return await self._access.run(token, selector, write, require_admin=True)
