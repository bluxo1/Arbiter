"""Read-only pre-tenant verification; only authenticated binding leaves the helper."""

from alembic import op

revision: str = "0007_workload_key_lookup"
down_revision: str | None = "0006_api_key_revocation"
branch_labels: str | None = None
depends_on: str | None = None

FUNCTION = "arbiter.resolve_api_key(text,bytea,integer)"


def upgrade() -> None:
    op.execute("GRANT USAGE ON SCHEMA arbiter TO arbiter_key_lookup")
    op.execute("GRANT SELECT (id,tenant_id,status) ON arbiter.tenants TO arbiter_key_lookup")
    op.execute("""
        GRANT SELECT (id,tenant_id,public_id,verifier,pepper_version,scopes,expires_at,revoked_at)
        ON arbiter.api_keys TO arbiter_key_lookup
    """)
    for table in ("tenants", "api_keys"):
        op.execute(f"""
            CREATE POLICY key_lookup_read ON arbiter.{table}
            FOR SELECT TO arbiter_key_lookup USING (true)
        """)
    op.execute("""
        CREATE FUNCTION arbiter.resolve_api_key(p_public text,p_candidate bytea,p_version integer)
        RETURNS TABLE (key_id uuid,tenant_id uuid,scopes text[])
        LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog AS $$
        DECLARE
            v_key uuid; v_tenant uuid; v_scopes text[]; v_status text;
            v_expiry timestamptz; v_revoked timestamptz; v_version integer;
            v_stored bytea; v_found boolean; v_difference integer := 0;
        BEGIN
            IF session_user <> 'arbiter_runtime' OR
                NULLIF(current_setting('arbiter.tenant_id',true),'') IS NOT NULL THEN
                RAISE EXCEPTION 'permission denied' USING ERRCODE='42501';
            END IF;
            IF p_public IS NULL OR p_public !~ '^[0-9a-f]{32}$' OR p_candidate IS NULL OR
                octet_length(p_candidate)<>32 OR p_version IS NULL OR p_version<1 THEN
                RETURN;
            END IF;
            SELECT k.id,k.tenant_id,k.scopes,k.verifier,k.pepper_version,k.expires_at,
                   k.revoked_at,t.status
                INTO v_key,v_tenant,v_scopes,v_stored,v_version,v_expiry,v_revoked,v_status
                FROM arbiter.api_keys k JOIN arbiter.tenants t
                    ON t.id=k.tenant_id AND t.tenant_id=k.tenant_id
                WHERE k.public_id=p_public;
            v_found := FOUND;
            -- Unknown identifiers still execute the complete fixed-width comparison.
            v_stored := COALESCE(v_stored,decode(repeat('00',32),'hex'));
            FOR i IN 0..31 LOOP
                v_difference := v_difference | (get_byte(v_stored,i) # get_byte(p_candidate,i));
            END LOOP;
            -- No byte equality shortcut or mismatch-dependent exit in the verifier comparison.
            IF v_found AND v_difference=0 AND v_version=p_version AND v_revoked IS NULL
                AND v_expiry>clock_timestamp() AND v_status='active' THEN
                RETURN QUERY SELECT v_key,v_tenant,v_scopes;
            END IF;
        END $$
    """)
    op.execute(f"REVOKE ALL ON FUNCTION {FUNCTION} FROM PUBLIC")
    op.execute(f"GRANT EXECUTE ON FUNCTION {FUNCTION} TO arbiter_runtime")
    op.execute("GRANT CREATE ON SCHEMA arbiter TO arbiter_key_lookup")
    op.execute(f"ALTER FUNCTION {FUNCTION} OWNER TO arbiter_key_lookup")
    op.execute("REVOKE CREATE ON SCHEMA arbiter FROM arbiter_key_lookup")


def downgrade() -> None:
    op.execute(f"DROP FUNCTION {FUNCTION} RESTRICT")
    for table in ("tenants", "api_keys"):
        op.execute(f"DROP POLICY key_lookup_read ON arbiter.{table}")
    op.execute("REVOKE SELECT (id,tenant_id,status) ON arbiter.tenants FROM arbiter_key_lookup")
    op.execute("""
        REVOKE SELECT (id,tenant_id,public_id,verifier,pepper_version,scopes,expires_at,revoked_at)
        ON arbiter.api_keys FROM arbiter_key_lookup
    """)
    op.execute("REVOKE USAGE ON SCHEMA arbiter FROM arbiter_key_lookup")
