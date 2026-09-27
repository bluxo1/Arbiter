"""Pre-context lookup is one restricted function, never a global repository."""

from dataclasses import dataclass
from typing import Literal
from uuid import UUID

from sqlalchemy import text
from sqlalchemy.engine import Connection

from arbiter.identity.oidc import VerifiedPrincipal


class InaccessibleTenant(Exception):
    def __init__(self) -> None:
        super().__init__("inaccessible tenant")


@dataclass(frozen=True, slots=True)
class MembershipBinding:
    tenant_id: UUID
    membership_id: UUID
    principal_id: UUID
    role: Literal["member", "admin"]


def resolve_membership(
    connection: Connection, principal: VerifiedPrincipal, selector: UUID
) -> MembershipBinding:
    row = connection.execute(
        text(
            "SELECT tenant_id,membership_id,principal_id,member_role "
            "FROM arbiter.resolve_membership(:tenant,:issuer,:subject)"
        ),
        {"tenant": selector, "issuer": principal.issuer, "subject": principal.subject},
    ).one_or_none()
    if row is None:
        raise InaccessibleTenant()
    if row.tenant_id != selector or row.member_role not in ("member", "admin"):
        raise RuntimeError("invalid membership binding")
    return MembershipBinding(row.tenant_id, row.membership_id, row.principal_id, row.member_role)
