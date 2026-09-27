"""Verify first; resolve active membership; then execute one scoped service transaction.

This boundary does not add HTTP routes or cache successful authorization. Server
services supply the callback; client input cannot supply a callback or SQL.
"""

from collections.abc import Callable
from dataclasses import dataclass
from typing import TypeVar
from uuid import UUID

from anyio import CapacityLimiter, to_thread
from sqlalchemy import text
from sqlalchemy.engine import Engine
from sqlalchemy.exc import SQLAlchemyError

from arbiter.identity.context import TenantContext
from arbiter.identity.oidc import OidcVerifier, VerifiedPrincipal
from arbiter.persistence.identity import MembershipBinding, resolve_membership
from arbiter.persistence.tenant import TenantTransaction, bind_tenant_transaction

T = TypeVar("T")


class MembershipUnavailable(Exception):
    def __init__(self) -> None:
        super().__init__("membership verification unavailable")


class InsufficientRole(Exception):
    def __init__(self) -> None:
        super().__init__("permission denied")


@dataclass(frozen=True, slots=True)
class AuthorizedMember:
    principal: VerifiedPrincipal
    binding: MembershipBinding


class ManagementAccess:
    def __init__(self, verifier: OidcVerifier, engine: Engine) -> None:
        self._verifier = verifier
        self._engine = engine
        self._slots = CapacityLimiter(2)

    async def run(
        self,
        token: str,
        selector: UUID,
        operation: Callable[[AuthorizedMember, TenantTransaction], T],
        *,
        require_admin: bool = False,
    ) -> T:
        if not isinstance(selector, UUID):
            raise TypeError("tenant UUID selector required")
        principal = await self._verifier.verify(token)
        # The entire synchronous DB transaction runs outside the HTTP event loop.
        return await to_thread.run_sync(
            self._run_scoped, principal, selector, operation, require_admin, limiter=self._slots
        )

    def _run_scoped(
        self,
        principal: VerifiedPrincipal,
        selector: UUID,
        operation: Callable[[AuthorizedMember, TenantTransaction], T],
        require_admin: bool,
    ) -> T:
        try:
            with self._engine.connect() as connection, connection.begin() as transaction:
                context: str | None = connection.execute(
                    text("SELECT NULLIF(current_setting('arbiter.tenant_id', true), '')")
                ).scalar_one()
                if context is not None:
                    connection.invalidate()
                    raise MembershipUnavailable()
                binding = resolve_membership(connection, principal, selector)
                if require_admin and binding.role != "admin":
                    raise InsufficientRole()
                scoped = bind_tenant_transaction(
                    connection, transaction, TenantContext(binding.tenant_id)
                )
                return operation(AuthorizedMember(principal, binding), scoped)
        except SQLAlchemyError:
            raise MembershipUnavailable() from None
