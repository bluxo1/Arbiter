"""Establish the migration chain; tenant tables belong to the next bounded task."""

from alembic import op

revision: str = "0001_foundation"
down_revision: str | None = None
branch_labels: str | None = None
depends_on: str | None = None


def upgrade() -> None:
    op.execute("CREATE SCHEMA arbiter AUTHORIZATION arbiter_migration")
    op.execute("REVOKE ALL ON SCHEMA arbiter FROM PUBLIC")
    op.execute("GRANT USAGE ON SCHEMA arbiter TO arbiter_runtime, arbiter_operator")


def downgrade() -> None:
    # RESTRICT fails rather than deleting any unexpected objects.
    op.execute("DROP SCHEMA arbiter RESTRICT")
