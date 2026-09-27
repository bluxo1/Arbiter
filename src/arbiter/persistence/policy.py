"""Explicitly scoped operator policy persistence; runtime has read-only RLS access."""

from uuid import UUID

from sqlalchemy import text
from sqlalchemy.engine import Connection

from arbiter.persistence.operator import ProvisioningNotFound, require_operator
from arbiter.persistence.tenant import TenantTransaction


class PolicyRepository:
    def __init__(self, transaction: TenantTransaction) -> None:
        self._transaction = transaction

    def _connection(self) -> Connection:
        connection = self._transaction.connection()
        require_operator(connection)
        return connection

    def validate_aliases(self, aliases: tuple[str, ...]) -> None:
        connection = self._connection()
        # Phase 3 must replace this fail-closed guard with consumption/occupancy checks.
        if connection.execute(
            text("""
                SELECT to_regclass('arbiter.quota_windows') IS NOT NULL
                    OR to_regclass('arbiter.budget_windows') IS NOT NULL
                    OR to_regclass('arbiter.requests') IS NOT NULL
            """)
        ).scalar_one():
            raise RuntimeError("accounting-aware policy updates required")
        valid = connection.execute(
            text("SELECT arbiter.lock_policy_aliases(CAST(:aliases AS text[]))"),
            {"aliases": list(aliases)},
        ).scalar_one()
        if valid is not True:
            raise ValueError("model alias unavailable")

    def advance_revision(self, previous: int, revision: int) -> None:
        tenant = self._transaction.context.tenant_id
        result = self._connection().execute(
            text("""
                UPDATE arbiter.tenants SET policy_revision=:revision
                WHERE tenant_id=:tenant AND id=:tenant AND policy_revision=:previous
            """),
            {"tenant": tenant, "revision": revision, "previous": previous},
        )
        if result.rowcount != 1:
            raise ProvisioningNotFound("tenant unavailable")

    def insert(
        self,
        *,
        policy_id: UUID,
        revision: int,
        audit_id: UUID,
        limits: tuple[int, int, int, int, int],
        aliases: tuple[str, ...],
    ) -> None:
        self._connection().execute(
            text("""
                INSERT INTO arbiter.tenant_policies
                    (id,tenant_id,revision,audit_id,tenant_rate,key_rate,daily_quota,
                     monthly_budget,concurrency,model_aliases)
                VALUES (:id,:tenant,:revision,:audit,:tenant_rate,:key_rate,:quota,
                        :budget,:concurrency,:aliases)
            """),
            {
                "id": policy_id,
                "tenant": self._transaction.context.tenant_id,
                "revision": revision,
                "audit": audit_id,
                "tenant_rate": limits[0],
                "key_rate": limits[1],
                "quota": limits[2],
                "budget": limits[3],
                "concurrency": limits[4],
                "aliases": sorted(aliases),
            },
        )
