"""Tenant repositories: explicit tenant predicates in addition to database RLS.

No administration/provisioning service or HTTP identity resolver is provided here.
Audit-producing administration will be added in its own bounded Phase 1 task.
"""

from dataclasses import dataclass
from datetime import datetime
from typing import Literal
from uuid import UUID, uuid4

from sqlalchemy import text

from arbiter.persistence.tenant import TenantTransaction


@dataclass(frozen=True, slots=True)
class TenantRecord:
    id: UUID
    status: str
    policy_revision: int


@dataclass(frozen=True, slots=True)
class MembershipRecord:
    id: UUID
    principal_id: UUID
    role: str
    active: bool


@dataclass(frozen=True, slots=True)
class AuditRecord:
    id: UUID
    action: str
    actor_membership_id: UUID | None
    actor_role: str | None
    occurred_at: datetime


class TenantRepository:
    def __init__(self, transaction: TenantTransaction) -> None:
        self._transaction = transaction

    def get(self) -> TenantRecord | None:
        row = (
            self._transaction.connection()
            .execute(
                text(
                    "SELECT id, status, policy_revision FROM arbiter.tenants "
                    "WHERE tenant_id=:tenant"
                ),
                {"tenant": self._transaction.context.tenant_id},
            )
            .one_or_none()
        )
        return None if row is None else TenantRecord(row.id, row.status, row.policy_revision)


class MembershipRepository:
    def __init__(self, transaction: TenantTransaction) -> None:
        self._transaction = transaction

    def get(self, object_id: UUID) -> MembershipRecord | None:
        row = (
            self._transaction.connection()
            .execute(
                text("""
                SELECT id, principal_id, role, active FROM arbiter.memberships
                WHERE tenant_id=:tenant AND id=:object_id
            """),
                {"tenant": self._transaction.context.tenant_id, "object_id": object_id},
            )
            .one_or_none()
        )
        return (
            None
            if row is None
            else MembershipRecord(row.id, row.principal_id, row.role, row.active)
        )


class AuditRepository:
    def __init__(self, transaction: TenantTransaction) -> None:
        self._transaction = transaction

    def append_member_event(
        self,
        *,
        actor_membership_id: UUID,
        action: str,
        target_id: UUID,
        policy_revision: int,
        outcome: Literal["succeeded", "denied"],
        request_id: UUID | None = None,
    ) -> UUID:
        """Persist service-generated metadata in the caller's existing transaction.

        No caller-selected tenant, arbitrary payload, or independent commit. This
        storage primitive performs no membership authorization or administration.
        """
        if not 1 <= len(action) <= 64 or policy_revision < 1:
            raise ValueError("invalid audit metadata")
        if MembershipRepository(self._transaction).get(actor_membership_id) is None:
            raise ValueError("inaccessible audit actor")
        object_id = uuid4()
        self._transaction.connection().execute(
            text("""
                INSERT INTO arbiter.audit_events
                (id, tenant_id, actor_type, actor_reference, actor_membership_id,
                 action, target_id, policy_revision, request_id, outcome)
                VALUES (:id, :tenant, 'member', :actor_reference, :actor,
                        :action, :target, :revision, :request, :outcome)
            """),
            {
                "id": object_id,
                "tenant": self._transaction.context.tenant_id,
                "actor_reference": str(actor_membership_id),
                "actor": actor_membership_id,
                "action": action,
                "target": target_id,
                "revision": policy_revision,
                "request": request_id,
                "outcome": outcome,
            },
        )
        return object_id

    def list_with_actor(self, *, limit: int = 50) -> list[AuditRecord]:
        if not 1 <= limit <= 100:
            raise ValueError("page size must be 1-100")
        rows = self._transaction.connection().execute(
            text("""
                SELECT a.id, a.action, a.actor_membership_id, m.role AS actor_role, a.occurred_at
                FROM arbiter.audit_events AS a
                LEFT JOIN arbiter.memberships AS m
                  ON m.tenant_id=a.tenant_id AND m.id=a.actor_membership_id
                  AND m.tenant_id=:tenant
                WHERE a.tenant_id=:tenant
                ORDER BY a.occurred_at, a.id LIMIT :limit
            """),
            {"tenant": self._transaction.context.tenant_id, "limit": limit},
        )
        return [
            AuditRecord(
                row.id, row.action, row.actor_membership_id, row.actor_role, row.occurred_at
            )
            for row in rows
        ]
