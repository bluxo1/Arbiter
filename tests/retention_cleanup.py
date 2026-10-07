"""Owner-only cleanup of unreferenced test audits; never used by production code."""

from uuid import UUID

from sqlalchemy import text
from sqlalchemy.engine import Connection


def delete_fixture_audits(connection: Connection, tenant_id: UUID) -> None:
    """Delete one fixture tenant's audits inside the caller's cleanup transaction.

    Referencing fixture rows (such as API keys) must already be removed. Foreign
    keys stay enabled: deferred AFTER DELETE events must be checked before ALTER
    TABLE can restore the retention guard. Constraint timing stays immediate for
    the rest of this cleanup transaction and resets at its end.

    The savepoint rolls back deletion and transactional trigger DDL together on
    any failure, even if the caller catches it and commits the outer transaction.
    """
    if not connection.in_transaction():
        raise ValueError("fixture cleanup requires an active transaction")
    with connection.begin_nested():
        if connection.execute(text("SELECT current_user, session_user")).one() != (
            "arbiter_migration",
            "arbiter_migration",
        ):
            raise PermissionError("fixture cleanup requires the migration owner")
        if (
            connection.execute(
                text("""
                SELECT tgenabled FROM pg_trigger
                WHERE tgrelid='arbiter.audit_events'::regclass
                    AND tgname='retention_delete_guard'
            """)
            ).scalar_one()
            != "O"
        ):
            raise RuntimeError("fixture cleanup requires an enabled retention guard")
        connection.execute(
            text("SELECT set_config('arbiter.tenant_id', :tenant, true)"),
            {"tenant": str(tenant_id)},
        )
        connection.execute(
            text("ALTER TABLE arbiter.audit_events DISABLE TRIGGER retention_delete_guard")
        )
        connection.execute(
            text("DELETE FROM arbiter.audit_events WHERE tenant_id=:tenant"),
            {"tenant": tenant_id},
        )
        connection.execute(text("SET CONSTRAINTS ALL IMMEDIATE"))
        connection.execute(
            text("ALTER TABLE arbiter.audit_events ENABLE TRIGGER retention_delete_guard")
        )
