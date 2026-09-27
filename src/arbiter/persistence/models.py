"""Scoped public metadata projection; no global registry/adapter/secret access."""

from dataclasses import dataclass

from sqlalchemy import text

from arbiter.persistence.tenant import TenantTransaction


@dataclass(frozen=True, slots=True)
class ModelMetadataRecord:
    alias: str
    output_cap: int
    credit_charge: int
    policy_revision: int


class ModelRepository:
    def __init__(self, transaction: TenantTransaction) -> None:
        self._transaction = transaction

    def list_page(self, *, page_size: int, after: str | None) -> list[ModelMetadataRecord]:
        if not 1 <= page_size <= 100:
            raise ValueError("page size must be 1-100")
        rows = (
            self._transaction.connection()
            .execute(
                text("""
                SELECT alias,output_cap,credit_charge,policy_revision
                FROM arbiter.list_tenant_models(:tenant,:after,:limit)
            """),
                {
                    "tenant": self._transaction.context.tenant_id,
                    "after": after,
                    "limit": page_size + 1,
                },
            )
            .all()
        )
        return [
            ModelMetadataRecord(row.alias, row.output_cap, row.credit_charge, row.policy_revision)
            for row in rows
        ]
