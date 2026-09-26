"""Runtime cannot manufacture operator-labelled audit evidence."""

from alembic import op

revision: str = "0003_operator_audit"
down_revision: str | None = "0002_tenant_isolation"
branch_labels: str | None = None
depends_on: str | None = None


def upgrade() -> None:
    op.execute("""
        CREATE POLICY runtime_audit_actor ON arbiter.audit_events AS RESTRICTIVE
        FOR INSERT TO arbiter_runtime WITH CHECK (actor_type = 'member')
    """)


def downgrade() -> None:
    op.execute("DROP POLICY runtime_audit_actor ON arbiter.audit_events")
