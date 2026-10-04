"""Scoped pre-dispatch check for an immutable registered-model binding."""

from alembic import op

revision: str = "0019_reserved_provider_binding"
down_revision: str | None = "0018_provider_binding"
branch_labels: str | None = None
depends_on: str | None = None

_FUNCTION = "arbiter.reserved_provider_binding_available(uuid,uuid,uuid,bigint)"


def upgrade() -> None:
    op.execute("""
        CREATE FUNCTION arbiter.reserved_provider_binding_available(
            p_tenant uuid,p_key uuid,p_request uuid,p_revision bigint)
        RETURNS boolean LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog AS $$
        BEGIN
            IF session_user<>'arbiter_runtime' OR p_tenant IS NULL OR
                p_tenant IS DISTINCT FROM
                    NULLIF(current_setting('arbiter.tenant_id',true),'')::uuid OR
                p_key IS NULL OR p_request IS NULL OR p_revision IS NULL THEN
                RAISE EXCEPTION 'permission denied' USING ERRCODE='42501';
            END IF;
            RETURN EXISTS (
                SELECT 1 FROM arbiter.requests r
                JOIN arbiter.provider_model_bindings b
                    ON b.model_id=r.model_id AND b.revision=r.model_revision
                    AND b.provider_kind=r.model_adapter
                WHERE r.tenant_id=p_tenant AND r.key_id=p_key AND r.id=p_request
                    AND r.state='reserved' AND r.dispatch_audit_id IS NULL
                    AND r.model_revision=p_revision
            );
        END $$
    """)
    op.execute(f"REVOKE ALL ON FUNCTION {_FUNCTION} FROM PUBLIC")
    op.execute(f"GRANT EXECUTE ON FUNCTION {_FUNCTION} TO arbiter_runtime")
    op.execute("GRANT CREATE ON SCHEMA arbiter TO arbiter_dispatch_writer")
    op.execute(f"ALTER FUNCTION {_FUNCTION} OWNER TO arbiter_dispatch_writer")
    op.execute("REVOKE CREATE ON SCHEMA arbiter FROM arbiter_dispatch_writer")


def downgrade() -> None:
    op.execute(f"DROP FUNCTION {_FUNCTION} RESTRICT")
