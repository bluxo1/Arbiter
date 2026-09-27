"""Narrow pre-context active membership resolution; ordinary runtime RLS is unchanged."""

from alembic import op

revision: str = "0004_identity_lookup"
down_revision: str | None = "0003_operator_audit"
branch_labels: str | None = None
depends_on: str | None = None


def upgrade() -> None:
    # Owner is provisioned by explicit bootstrap, never created/elevated by runtime.
    op.execute("GRANT USAGE ON SCHEMA arbiter TO arbiter_identity_lookup")
    op.execute("GRANT SELECT (id, tenant_id, status) ON arbiter.tenants TO arbiter_identity_lookup")
    op.execute("""
        GRANT SELECT (id, tenant_id, principal_id, role, active)
        ON arbiter.memberships TO arbiter_identity_lookup
    """)
    op.execute(
        "GRANT SELECT (id, issuer, subject) ON arbiter.principals TO arbiter_identity_lookup"
    )
    # Dedicated owner alone has these SELECT policies. No BYPASSRLS or runtime
    # membership in this role, no writes, and no ordinary application directory reads.
    for table in ("tenants", "memberships"):
        op.execute(f"""
            CREATE POLICY identity_lookup_read ON arbiter.{table}
            FOR SELECT TO arbiter_identity_lookup USING (true)
        """)
    op.execute("""
        CREATE FUNCTION arbiter.resolve_membership(p_tenant uuid, p_issuer text, p_subject text)
        RETURNS TABLE (tenant_id uuid, membership_id uuid, principal_id uuid, member_role text)
        LANGUAGE sql STABLE STRICT SECURITY DEFINER SET search_path = pg_catalog AS $$
            SELECT t.id, m.id, p.id, m.role::text
            FROM arbiter.tenants AS t
            JOIN arbiter.memberships AS m ON m.tenant_id=t.tenant_id AND m.tenant_id=p_tenant
            JOIN arbiter.principals AS p ON p.id=m.principal_id
            WHERE session_user='arbiter_runtime'
              AND t.id=p_tenant AND t.tenant_id=p_tenant AND t.status='active'
              AND m.active AND p.issuer=p_issuer AND p.subject=p_subject
        $$
    """)
    op.execute("REVOKE ALL ON FUNCTION arbiter.resolve_membership(uuid,text,text) FROM PUBLIC")
    op.execute(
        "GRANT EXECUTE ON FUNCTION arbiter.resolve_membership(uuid,text,text) TO arbiter_runtime"
    )
    # PostgreSQL requires CREATE for ownership transfer; revoke it in this same
    # migration transaction. The final function owner has no schema-create privilege.
    op.execute("GRANT CREATE ON SCHEMA arbiter TO arbiter_identity_lookup")
    op.execute(
        "ALTER FUNCTION arbiter.resolve_membership(uuid,text,text) OWNER TO arbiter_identity_lookup"
    )
    op.execute("REVOKE CREATE ON SCHEMA arbiter FROM arbiter_identity_lookup")


def downgrade() -> None:
    op.execute("DROP FUNCTION arbiter.resolve_membership(uuid,text,text) RESTRICT")
    for table in ("tenants", "memberships"):
        op.execute(f"DROP POLICY identity_lookup_read ON arbiter.{table}")
    for table in ("tenants", "memberships", "principals"):
        op.execute(f"REVOKE ALL ON arbiter.{table} FROM arbiter_identity_lookup")
    op.execute(
        "REVOKE SELECT (id,tenant_id,status) ON arbiter.tenants FROM arbiter_identity_lookup"
    )
    op.execute("""
        REVOKE SELECT (id,tenant_id,principal_id,role,active)
        ON arbiter.memberships FROM arbiter_identity_lookup
    """)
    op.execute(
        "REVOKE SELECT (id,issuer,subject) ON arbiter.principals FROM arbiter_identity_lookup"
    )
    op.execute("REVOKE USAGE ON SCHEMA arbiter FROM arbiter_identity_lookup")
