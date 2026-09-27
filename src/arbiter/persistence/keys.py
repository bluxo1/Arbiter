"""One tenant-scoped, parameterized, audited creation function; no general key writes."""

from dataclasses import dataclass
from datetime import datetime
from uuid import UUID

from sqlalchemy import text

from arbiter.identity.access import AuthorizedMember
from arbiter.identity.keys import IssuedKey
from arbiter.persistence.tenant import TenantTransaction


@dataclass(frozen=True, slots=True)
class CreatedKey:
    created_at: datetime
    expires_at: datetime


class KeyRepository:
    def __init__(self, transaction: TenantTransaction) -> None:
        self._transaction = transaction

    def create(
        self,
        member: AuthorizedMember,
        issued: IssuedKey,
        *,
        label: str,
        scopes: list[str],
        expires_at: datetime | None,
        audit_id: UUID,
        request_id: UUID,
    ) -> CreatedKey:
        tenant = self._transaction.context.tenant_id
        if member.binding.tenant_id != tenant:
            raise ValueError("inaccessible key actor")
        row = (
            self._transaction.connection()
            .execute(
                text("""
                SELECT created_at, expires_at FROM arbiter.create_api_key(
                    :tenant, :actor, :principal, :id, :public_id, :label,
                    :verifier, :version, CAST(:scopes AS text[]), :expires, :audit, :request)
            """),
                {
                    "tenant": tenant,
                    "actor": member.binding.membership_id,
                    "principal": member.binding.principal_id,
                    "id": issued.id,
                    "public_id": issued.public_id,
                    "label": label,
                    "verifier": issued.verifier.get_secret_value(),
                    "version": issued.pepper_version,
                    "scopes": scopes,
                    "expires": expires_at,
                    "audit": audit_id,
                    "request": request_id,
                },
            )
            .one()
        )
        return CreatedKey(row.created_at, row.expires_at)
