"""Scoped metadata reads and audited key mutations; no general writes or secret reads."""

from dataclasses import dataclass
from datetime import datetime
from typing import Literal
from uuid import UUID

from sqlalchemy import text

from arbiter.identity.access import AuthorizedMember
from arbiter.identity.keys import IssuedKey
from arbiter.persistence.tenant import TenantTransaction


@dataclass(frozen=True, slots=True)
class CreatedKey:
    created_at: datetime
    expires_at: datetime


@dataclass(frozen=True, slots=True)
class KeyMetadataRecord:
    id: UUID
    public_id: str
    label: str
    scopes: tuple[Literal["inference:write", "usage:read"], ...]
    created_at: datetime
    expires_at: datetime
    revoked_at: datetime | None


class KeyRepository:
    def __init__(self, transaction: TenantTransaction) -> None:
        self._transaction = transaction

    def revoke(
        self, member: AuthorizedMember, key_id: UUID, *, audit_id: UUID, request_id: UUID
    ) -> datetime:
        tenant = self._transaction.context.tenant_id
        if member.binding.tenant_id != tenant:
            raise ValueError("inaccessible key actor")
        revoked: datetime = (
            self._transaction.connection()
            .execute(
                text("""
                SELECT revoked_at FROM arbiter.revoke_api_key(
                    :tenant,:actor,:principal,:key,:audit,:request)
            """),
                {
                    "tenant": tenant,
                    "actor": member.binding.membership_id,
                    "principal": member.binding.principal_id,
                    "key": key_id,
                    "audit": audit_id,
                    "request": request_id,
                },
            )
            .scalar_one()
        )
        return revoked

    def list_page(self, *, page_size: int, after: UUID | None) -> list[KeyMetadataRecord]:
        if not 1 <= page_size <= 100:
            raise ValueError("page size must be 1-100")
        statement = (
            text("""
            SELECT id, public_id, label, scopes, created_at, expires_at, revoked_at
            FROM arbiter.api_keys WHERE tenant_id=:tenant
            ORDER BY id LIMIT :limit
        """)
            if after is None
            else text("""
            SELECT id, public_id, label, scopes, created_at, expires_at, revoked_at
            FROM arbiter.api_keys WHERE tenant_id=:tenant AND id > CAST(:after AS uuid)
            ORDER BY id LIMIT :limit
        """)
        )
        rows = self._transaction.connection().execute(
            statement,
            {
                "tenant": self._transaction.context.tenant_id,
                "after": after,
                "limit": page_size + 1,
            },
        )
        return [
            KeyMetadataRecord(
                row.id,
                row.public_id,
                row.label,
                tuple(row.scopes),
                row.created_at,
                row.expires_at,
                row.revoked_at,
            )
            for row in rows
        ]

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
