"""Narrow, tenant-locked admin revocation with transactional security evidence."""

from alembic import op

revision: str = "0006_api_key_revocation"
down_revision: str | None = "0005_api_key_creation"
branch_labels: str | None = None
depends_on: str | None = None

FUNCTION = "arbiter.revoke_api_key(uuid,uuid,uuid,uuid,uuid,uuid)"


def upgrade() -> None:
    op.execute("""
        GRANT SELECT (id,tenant_id,revoked_at), UPDATE (revoked_at)
        ON arbiter.api_keys TO arbiter_key_writer
    """)
    op.execute("""
        ALTER POLICY key_writer_audit ON arbiter.audit_events WITH CHECK
            (actor_type='member' AND action IN ('api_key_created','api_key_revoked')
             AND outcome='succeeded' AND actor_reference=actor_membership_id::text)
    """)
    op.execute("""
        CREATE OR REPLACE FUNCTION arbiter.reject_key_change() RETURNS trigger
        LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog AS $$
        BEGIN
            IF (to_jsonb(NEW)-'revoked_at') IS DISTINCT FROM (to_jsonb(OLD)-'revoked_at') OR
                (OLD.revoked_at IS NOT NULL AND NEW.revoked_at IS DISTINCT FROM OLD.revoked_at)
            THEN
                RAISE EXCEPTION 'immutable key metadata' USING ERRCODE='23514';
            END IF;
            RETURN NEW;
        END $$
    """)
    op.execute("""
        CREATE FUNCTION arbiter.revoke_api_key(
            p_tenant uuid,p_actor uuid,p_principal uuid,p_key uuid,p_audit uuid,p_request uuid)
        RETURNS TABLE (revoked_at timestamptz)
        LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
        DECLARE
            v_status text; v_revision bigint; v_role text; v_active boolean;
            v_revoked timestamptz;
        BEGIN
            IF session_user <> 'arbiter_runtime' OR p_tenant IS NULL OR
                NULLIF(current_setting('arbiter.tenant_id',true),'')::uuid IS DISTINCT FROM p_tenant
            THEN
                RAISE EXCEPTION 'permission denied' USING ERRCODE='42501';
            END IF;
            -- Same tenant-first/key-second ordering required of future dispatch authorization.
            SELECT t.status,t.policy_revision INTO v_status,v_revision FROM arbiter.tenants t
                WHERE t.tenant_id=p_tenant AND t.id=p_tenant FOR UPDATE;
            IF NOT FOUND OR v_status <> 'active' THEN
                RAISE EXCEPTION 'inaccessible resource' USING ERRCODE='P0002';
            END IF;
            SELECT m.role,m.active INTO v_role,v_active FROM arbiter.memberships m
                WHERE m.tenant_id=p_tenant AND m.id=p_actor AND m.principal_id=p_principal;
            IF NOT FOUND OR NOT v_active THEN
                RAISE EXCEPTION 'inaccessible resource' USING ERRCODE='P0002';
            END IF;
            IF v_role <> 'admin' THEN
                RAISE EXCEPTION 'permission denied' USING ERRCODE='42501';
            END IF;
            SELECT k.revoked_at INTO v_revoked FROM arbiter.api_keys k
                WHERE k.tenant_id=p_tenant AND k.id=p_key FOR UPDATE;
            IF NOT FOUND THEN
                RAISE EXCEPTION 'inaccessible resource' USING ERRCODE='P0002';
            END IF;
            IF v_revoked IS NOT NULL THEN
                RETURN QUERY SELECT v_revoked;
                RETURN;
            END IF;
            IF p_audit IS NULL OR p_request IS NULL THEN
                RAISE EXCEPTION 'invalid key request' USING ERRCODE='22023';
            END IF;
            v_revoked := clock_timestamp();
            UPDATE arbiter.api_keys k SET revoked_at=v_revoked
                WHERE k.tenant_id=p_tenant AND k.id=p_key;
            INSERT INTO arbiter.audit_events (id,tenant_id,actor_type,actor_reference,
                actor_membership_id,action,target_id,policy_revision,request_id,occurred_at,outcome)
                VALUES (p_audit,p_tenant,'member',p_actor::text,p_actor,'api_key_revoked',p_key,
                        v_revision,p_request,v_revoked,'succeeded');
            RETURN QUERY SELECT v_revoked;
        END $$
    """)
    op.execute(f"REVOKE ALL ON FUNCTION {FUNCTION} FROM PUBLIC")
    op.execute(f"GRANT EXECUTE ON FUNCTION {FUNCTION} TO arbiter_runtime")
    op.execute("GRANT CREATE ON SCHEMA arbiter TO arbiter_key_writer")
    op.execute(f"ALTER FUNCTION {FUNCTION} OWNER TO arbiter_key_writer")
    op.execute("REVOKE CREATE ON SCHEMA arbiter FROM arbiter_key_writer")


def downgrade() -> None:
    op.execute(f"DROP FUNCTION {FUNCTION} RESTRICT")
    op.execute("""
        REVOKE SELECT (id,tenant_id,revoked_at), UPDATE (revoked_at)
        ON arbiter.api_keys FROM arbiter_key_writer
    """)
    op.execute("""
        ALTER POLICY key_writer_audit ON arbiter.audit_events WITH CHECK
            (actor_type='member' AND action='api_key_created'
             AND outcome='succeeded' AND actor_reference=actor_membership_id::text)
    """)
    op.execute("""
        CREATE OR REPLACE FUNCTION arbiter.reject_key_change() RETURNS trigger
        LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog AS $$
        BEGIN
            IF (to_jsonb(NEW)-'revoked_at') IS DISTINCT FROM (to_jsonb(OLD)-'revoked_at') THEN
                RAISE EXCEPTION 'immutable key metadata' USING ERRCODE='23514';
            END IF;
            RETURN NEW;
        END $$
    """)
