"""Runtime projection of only current tenant-approved public model metadata."""

from alembic import op

revision: str = "0009_model_catalog"
down_revision: str | None = "0008_tenant_policies"
branch_labels: str | None = None
depends_on: str | None = None


def upgrade() -> None:
    op.execute("""
        CREATE FUNCTION arbiter.list_tenant_models(p_tenant uuid,p_after text,p_limit integer)
        RETURNS TABLE (alias text,output_cap bigint,credit_charge bigint,policy_revision bigint)
        LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog AS $$
        BEGIN
            IF session_user<>'arbiter_runtime' OR p_tenant IS NULL OR
                NULLIF(current_setting('arbiter.tenant_id',true),'') IS NULL OR
                NULLIF(current_setting('arbiter.tenant_id',true),'')::uuid<>p_tenant THEN
                RAISE EXCEPTION 'permission denied' USING ERRCODE='42501';
            END IF;
            IF p_limit IS NULL OR p_limit NOT BETWEEN 1 AND 101 OR
                (p_after IS NOT NULL AND p_after !~ '^[a-z][a-z0-9_-]{0,63}$') THEN
                RAISE EXCEPTION 'invalid model query' USING ERRCODE='22023';
            END IF;
            RETURN QUERY
                SELECT m.alias::text,m.output_cap,m.credit_charge,p.revision
                FROM arbiter.tenants t JOIN arbiter.tenant_policies p
                    ON p.tenant_id=t.tenant_id AND p.revision=t.policy_revision
                JOIN arbiter.provider_models m ON m.alias=ANY(p.model_aliases)
                WHERE t.id=p_tenant AND t.tenant_id=p_tenant AND p.tenant_id=p_tenant
                    AND t.status='active' AND m.active
                    AND (p_after IS NULL OR m.alias COLLATE "C">p_after COLLATE "C")
                ORDER BY m.alias COLLATE "C" LIMIT p_limit;
        END $$
    """)
    op.execute("REVOKE ALL ON FUNCTION arbiter.list_tenant_models(uuid,text,integer) FROM PUBLIC")
    op.execute(
        "GRANT EXECUTE ON FUNCTION arbiter.list_tenant_models(uuid,text,integer) TO arbiter_runtime"
    )


def downgrade() -> None:
    op.execute("DROP FUNCTION arbiter.list_tenant_models(uuid,text,integer) RESTRICT")
