"""Global operator capability; tenant repositories and runtime cannot use this path."""

from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from uuid import UUID

from sqlalchemy import text
from sqlalchemy.engine import Connection, Engine

from arbiter.persistence.operator import OperatorAccessDenied, require_operator


@contextmanager
def registry_transaction(engine: Engine) -> Iterator[Connection]:
    with engine.connect() as connection, connection.begin():
        require_operator(connection)
        context: str | None = connection.execute(
            text("SELECT NULLIF(current_setting('arbiter.tenant_id',true),'')")
        ).scalar_one()
        if context is not None:
            connection.invalidate()
            raise OperatorAccessDenied("unexpected operator tenant context")
        yield connection


@dataclass(frozen=True, slots=True)
class RegistryRecord:
    model_id: UUID
    revision: int
    journal_id: UUID


class RegistryRepository:
    def __init__(self, connection: Connection) -> None:
        self._connection = connection

    def provision(
        self,
        *,
        alias: str,
        adapter: str,
        digest: str,
        context: int,
        output: int,
        charge: int,
        active: bool,
        approval: str,
        expected: int | None,
        object_id: UUID,
        journal_id: UUID,
        correlation: UUID,
    ) -> RegistryRecord:
        require_operator(self._connection)
        row = self._connection.execute(
            text("""
            SELECT model_id,revision,journal_id FROM arbiter.provision_model(
                :alias,:adapter,:digest,:context,:output,:charge,:active,:approval,
                :expected,:id,:journal,:correlation)
        """),
            {
                "alias": alias,
                "adapter": adapter,
                "digest": digest,
                "context": context,
                "output": output,
                "charge": charge,
                "active": active,
                "approval": approval,
                "expected": expected,
                "id": object_id,
                "journal": journal_id,
                "correlation": correlation,
            },
        ).one()
        return RegistryRecord(row.model_id, row.revision, row.journal_id)
