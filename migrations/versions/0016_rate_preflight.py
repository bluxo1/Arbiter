"""Read-only rate preflight and revision-bound durable reservation capability."""

from alembic import op

revision: str = "0016_rate_preflight"
down_revision: str | None = "0015_terminal_lifecycle"
branch_labels: str | None = None
depends_on: str | None = None

FUNCTION = "arbiter.rate_preflight(uuid,uuid,text,bytea,integer,text,bytea,integer,text,integer)"
RESERVE_FUNCTION = (
    "arbiter.reserve_request_governed(uuid,uuid,text,bytea,integer,text,bytea,integer,"
    "text,integer,bigint)"
)


def upgrade() -> None:
    op.execute("""
        CREATE FUNCTION arbiter.rate_preflight(
            p_tenant uuid,p_key uuid,p_public text,p_candidate bytea,p_pepper integer,
            p_idempotency text,p_fingerprint bytea,p_fingerprint_version integer,
            p_alias text,p_output integer)
        RETURNS TABLE (tenant_rate bigint,key_rate bigint,policy_revision bigint,
            duplicate_id uuid,duplicate_state text)
        LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog AS $$
        DECLARE
            v_tenant arbiter.tenants%ROWTYPE; v_key arbiter.api_keys%ROWTYPE;
            v_policy arbiter.tenant_policies%ROWTYPE; v_existing arbiter.requests%ROWTYPE;
            v_found boolean; v_stored bytea; v_difference integer := 0;
        BEGIN
            IF session_user<>'arbiter_runtime' OR p_tenant IS NULL OR p_tenant IS DISTINCT FROM
                NULLIF(current_setting('arbiter.tenant_id',true),'')::uuid THEN
                RAISE EXCEPTION 'permission denied' USING ERRCODE='42501';
            END IF;
            IF p_key IS NULL OR p_public IS NULL OR p_public !~ '^[0-9a-f]{32}$'
                OR p_candidate IS NULL OR octet_length(p_candidate)<>32
                OR p_pepper IS NULL OR p_pepper<1 THEN
                RAISE EXCEPTION 'invalid credentials' USING ERRCODE='AR001';
            END IF;
            IF p_idempotency IS NULL OR p_idempotency !~ '^[ -~]{16,128}$'
                OR p_fingerprint IS NULL OR octet_length(p_fingerprint)<>32
                OR p_fingerprint_version IS NULL OR p_fingerprint_version<1
                OR p_alias IS NULL OR p_alias !~ '^[a-z][a-z0-9_-]{0,63}$'
                OR p_output IS NULL OR p_output NOT BETWEEN 1 AND 1024 THEN
                RAISE EXCEPTION 'invalid fields' USING ERRCODE='22023';
            END IF;
            SELECT t.* INTO v_tenant FROM arbiter.tenants t
                WHERE t.id=p_tenant AND t.tenant_id=p_tenant;
            IF NOT FOUND OR v_tenant.status<>'active' THEN
                RAISE EXCEPTION 'invalid credentials' USING ERRCODE='AR001';
            END IF;
            SELECT k.* INTO v_key FROM arbiter.api_keys k
                WHERE k.tenant_id=p_tenant AND k.id=p_key AND k.public_id=p_public;
            v_found:=FOUND;
            v_stored:=COALESCE(v_key.verifier,decode(repeat('00',32),'hex'));
            FOR i IN 0..31 LOOP
                v_difference:=v_difference | (get_byte(v_stored,i) # get_byte(p_candidate,i));
            END LOOP;
            IF NOT v_found OR v_difference<>0 OR v_key.pepper_version<>p_pepper
                OR v_key.revoked_at IS NOT NULL OR v_key.expires_at<=clock_timestamp() THEN
                RAISE EXCEPTION 'invalid credentials' USING ERRCODE='AR001';
            END IF;
            IF NOT ('inference:write'=ANY(v_key.scopes)) THEN
                RAISE EXCEPTION 'permission denied' USING ERRCODE='AR002';
            END IF;
            SELECT p.* INTO v_policy FROM arbiter.tenant_policies p
                WHERE p.tenant_id=p_tenant AND p.revision=v_tenant.policy_revision;
            IF NOT FOUND THEN RAISE EXCEPTION 'unavailable' USING ERRCODE='AR008'; END IF;
            IF NOT (p_alias=ANY(v_policy.model_aliases)) OR NOT EXISTS (
                SELECT 1 FROM arbiter.provider_models m
                WHERE m.alias=p_alias AND m.active) THEN
                RAISE EXCEPTION 'model denied' USING ERRCODE='AR004';
            END IF;
            IF NOT EXISTS (SELECT 1 FROM arbiter.provider_models m
                WHERE m.alias=p_alias AND m.active AND p_output<=m.output_cap) THEN
                RAISE EXCEPTION 'invalid fields' USING ERRCODE='22023';
            END IF;
            SELECT r.* INTO v_existing FROM arbiter.requests r
                WHERE r.tenant_id=p_tenant AND r.key_id=p_key
                    AND r.idempotency_key=p_idempotency;
            IF FOUND THEN
                v_difference:=0;
                FOR i IN 0..31 LOOP
                    v_difference:=v_difference |
                        (get_byte(v_existing.payload_hmac,i) # get_byte(p_fingerprint,i));
                END LOOP;
                IF v_difference<>0 OR v_existing.fingerprint_version<>p_fingerprint_version THEN
                    RAISE EXCEPTION 'idempotency conflict' USING ERRCODE='AR003';
                END IF;
                RETURN QUERY SELECT v_policy.tenant_rate,v_policy.key_rate,v_policy.revision,
                    v_existing.id,v_existing.state::text;
                RETURN;
            END IF;
            RETURN QUERY SELECT v_policy.tenant_rate,v_policy.key_rate,v_policy.revision,
                NULL::uuid,NULL::text;
        END $$
    """)
    op.execute(f"REVOKE ALL ON FUNCTION {FUNCTION} FROM PUBLIC")
    op.execute(f"GRANT EXECUTE ON FUNCTION {FUNCTION} TO arbiter_runtime")
    op.execute("GRANT CREATE ON SCHEMA arbiter TO arbiter_reservation_writer")
    op.execute(f"ALTER FUNCTION {FUNCTION} OWNER TO arbiter_reservation_writer")
    op.execute("""
        CREATE FUNCTION arbiter.reserve_request_governed(
            p_tenant uuid,p_key uuid,p_public text,p_candidate bytea,p_pepper integer,
            p_idempotency text,p_fingerprint bytea,p_fingerprint_version integer,
            p_alias text,p_output integer,p_policy_revision bigint)
        RETURNS TABLE (request_id uuid,state text,model_alias text,credit_charge bigint,
            policy_revision bigint,model_revision bigint,duplicate boolean)
        LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog AS $$
        DECLARE v_current bigint;
        BEGIN
            IF session_user<>'arbiter_runtime' OR p_tenant IS NULL OR p_tenant IS DISTINCT FROM
                NULLIF(current_setting('arbiter.tenant_id',true),'')::uuid
                OR p_policy_revision IS NULL OR p_policy_revision<1 THEN
                RAISE EXCEPTION 'permission denied' USING ERRCODE='42501';
            END IF;
            SELECT t.policy_revision INTO v_current FROM arbiter.tenants t
                WHERE t.id=p_tenant AND t.tenant_id=p_tenant FOR UPDATE;
            IF NOT FOUND THEN
                RAISE EXCEPTION 'invalid credentials' USING ERRCODE='AR001';
            END IF;
            IF v_current<>p_policy_revision THEN
                RAISE EXCEPTION 'unavailable' USING ERRCODE='AR008';
            END IF;
            RETURN QUERY SELECT r.request_id,r.state,r.model_alias,r.credit_charge,
                r.policy_revision,r.model_revision,r.duplicate
                FROM arbiter.reserve_request(p_tenant,p_key,p_public,p_candidate,p_pepper,
                    p_idempotency,p_fingerprint,p_fingerprint_version,p_alias,p_output) r;
        END $$
    """)
    op.execute(f"REVOKE ALL ON FUNCTION {RESERVE_FUNCTION} FROM PUBLIC")
    op.execute(f"GRANT EXECUTE ON FUNCTION {RESERVE_FUNCTION} TO arbiter_runtime")
    op.execute(f"ALTER FUNCTION {RESERVE_FUNCTION} OWNER TO arbiter_reservation_writer")
    op.execute("REVOKE CREATE ON SCHEMA arbiter FROM arbiter_reservation_writer")


def downgrade() -> None:
    op.execute(f"DROP FUNCTION {RESERVE_FUNCTION} RESTRICT")
    op.execute(f"DROP FUNCTION {FUNCTION} RESTRICT")
