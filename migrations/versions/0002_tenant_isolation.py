"""Initial tenant persistence, policies and deliberately narrow role grants."""

from alembic import op

revision: str = "0002_tenant_isolation"
down_revision: str | None = "0001_foundation"
branch_labels: str | None = None
depends_on: str | None = None


def upgrade() -> None:
    # Static migration SQL only. No caller-controlled identifiers or values.
    op.execute("""
        CREATE TABLE arbiter.tenants (
            id uuid PRIMARY KEY,
            tenant_id uuid GENERATED ALWAYS AS (id) STORED NOT NULL,
            status varchar(16) NOT NULL DEFAULT 'active'
                CHECK (status IN ('active', 'suspended')),
            policy_revision bigint NOT NULL DEFAULT 1 CHECK (policy_revision > 0),
            created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
            UNIQUE (tenant_id, id)
        )
    """)
    op.execute("""
        CREATE TABLE arbiter.principals (
            id uuid PRIMARY KEY,
            issuer varchar(2048) NOT NULL CHECK (length(issuer) > 0),
            subject varchar(255) NOT NULL CHECK (length(subject) > 0),
            created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
            UNIQUE (issuer, subject)
        )
    """)
    op.execute("""
        CREATE TABLE arbiter.memberships (
            id uuid PRIMARY KEY,
            tenant_id uuid NOT NULL REFERENCES arbiter.tenants (id),
            principal_id uuid NOT NULL REFERENCES arbiter.principals (id),
            role varchar(16) NOT NULL CHECK (role IN ('member', 'admin')),
            active boolean NOT NULL DEFAULT true,
            created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
            UNIQUE (tenant_id, id),
            UNIQUE (tenant_id, principal_id)
        )
    """)
    op.execute("""
        CREATE TABLE arbiter.audit_events (
            id uuid PRIMARY KEY,
            tenant_id uuid NOT NULL REFERENCES arbiter.tenants (id),
            actor_type varchar(16) NOT NULL CHECK (actor_type IN ('member', 'operator')),
            actor_reference varchar(255) NOT NULL CHECK (length(actor_reference) > 0),
            actor_membership_id uuid,
            action varchar(64) NOT NULL CHECK (length(action) > 0),
            target_id uuid NOT NULL,
            policy_revision bigint NOT NULL CHECK (policy_revision > 0),
            request_id uuid,
            occurred_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
            outcome varchar(16) NOT NULL CHECK (outcome IN ('succeeded', 'denied')),
            UNIQUE (tenant_id, id),
            CONSTRAINT audit_actor_membership_fk FOREIGN KEY (tenant_id, actor_membership_id)
                REFERENCES arbiter.memberships (tenant_id, id),
            CHECK ((actor_type = 'member' AND actor_membership_id IS NOT NULL)
                OR (actor_type = 'operator' AND actor_membership_id IS NULL))
        )
    """)
    op.execute("""
        CREATE INDEX audit_events_tenant_time_idx
        ON arbiter.audit_events (tenant_id, occurred_at, id)
    """)
    op.execute("""
        CREATE INDEX audit_events_actor_idx
        ON arbiter.audit_events (tenant_id, actor_membership_id)
    """)
    op.execute("""
        CREATE FUNCTION arbiter.reject_ownership_change() RETURNS trigger
        LANGUAGE plpgsql SECURITY INVOKER SET search_path = pg_catalog AS $$
        BEGIN
            IF NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
                OR NEW.id IS DISTINCT FROM OLD.id THEN
                RAISE EXCEPTION 'immutable record ownership' USING ERRCODE = '23514';
            END IF;
            RETURN NEW;
        END
        $$
    """)
    op.execute("REVOKE ALL ON FUNCTION arbiter.reject_ownership_change() FROM PUBLIC")
    for table in ("tenants", "memberships", "audit_events"):
        op.execute(f"ALTER TABLE arbiter.{table} ENABLE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE arbiter.{table} FORCE ROW LEVEL SECURITY")
        # Restrictive ownership also constrains any future permissive command policy.
        expression = "tenant_id = NULLIF(current_setting('arbiter.tenant_id', true), '')::uuid"
        op.execute(f"""
            CREATE POLICY tenant_ownership ON arbiter.{table} AS RESTRICTIVE
            TO arbiter_runtime, arbiter_operator, arbiter_migration
            USING ({expression}) WITH CHECK ({expression})
        """)
        op.execute(f"""
            CREATE POLICY scoped_access ON arbiter.{table}
            TO arbiter_runtime, arbiter_operator, arbiter_migration
            USING (true) WITH CHECK (true)
        """)
        op.execute(f"""
            CREATE TRIGGER immutable_ownership AFTER UPDATE ON arbiter.{table}
            FOR EACH ROW EXECUTE FUNCTION arbiter.reject_ownership_change()
        """)
        op.execute(f"REVOKE ALL ON arbiter.{table} FROM PUBLIC, arbiter_runtime, arbiter_operator")
        op.execute(f"GRANT SELECT ON arbiter.{table} TO arbiter_runtime, arbiter_operator")
        op.execute(f"GRANT INSERT ON arbiter.{table} TO arbiter_operator")

    op.execute("REVOKE ALL ON arbiter.principals FROM PUBLIC, arbiter_runtime, arbiter_operator")
    op.execute("GRANT SELECT, INSERT ON arbiter.principals TO arbiter_operator")
    op.execute("GRANT UPDATE (status, policy_revision) ON arbiter.tenants TO arbiter_operator")
    op.execute("GRANT UPDATE (role, active) ON arbiter.memberships TO arbiter_operator")
    op.execute("GRANT INSERT ON arbiter.audit_events TO arbiter_runtime")


def downgrade() -> None:
    # No CASCADE: unexpected dependents fail rather than being silently deleted.
    for table in ("audit_events", "memberships", "principals", "tenants"):
        op.execute(f"DROP TABLE arbiter.{table} RESTRICT")
    op.execute("DROP FUNCTION arbiter.reject_ownership_change() RESTRICT")
