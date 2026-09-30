"""Restricted content-free recovery discovery and audited operator clearance."""

from alembic import op

revision: str = "0017_maintenance_recovery"
down_revision: str | None = "0016_rate_preflight"
branch_labels: str | None = None
depends_on: str | None = None

ROLE = "arbiter_maintenance_worker"
SCAN = "arbiter.maintenance_candidates(text)"
CLEAR = "arbiter.clear_unknown_capacity(uuid,uuid)"


def upgrade() -> None:
    op.execute("GRANT USAGE ON SCHEMA arbiter TO arbiter_maintenance_worker")
    op.execute("GRANT USAGE ON SCHEMA arbiter TO arbiter_maintenance")
    op.execute("""
        CREATE TABLE arbiter.capacity_clearances (
            tenant_id uuid NOT NULL,
            request_id uuid NOT NULL,
            audit_id uuid NOT NULL,
            cleared_at timestamptz NOT NULL DEFAULT clock_timestamp(),
            PRIMARY KEY (tenant_id,request_id),
            UNIQUE (audit_id),
            FOREIGN KEY (tenant_id,request_id) REFERENCES arbiter.requests(tenant_id,id),
            FOREIGN KEY (tenant_id,audit_id) REFERENCES arbiter.audit_events(tenant_id,id)
        )
    """)
    op.execute("ALTER TABLE arbiter.capacity_clearances ENABLE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE arbiter.capacity_clearances FORCE ROW LEVEL SECURITY")
    op.execute("""
        CREATE POLICY maintenance_clearance_access ON arbiter.capacity_clearances
        TO arbiter_maintenance_worker USING (true) WITH CHECK (true)
    """)
    op.execute("""
        CREATE POLICY maintenance_request_read ON arbiter.requests
        TO arbiter_maintenance_worker USING (true)
    """)
    op.execute("""
        CREATE POLICY maintenance_audit_insert ON arbiter.audit_events
        TO arbiter_maintenance_worker WITH CHECK (true)
    """)
    op.execute("""
        GRANT SELECT (id,tenant_id,key_id,state,created_at,dispatched_at,
            finished_at,policy_revision)
            ON arbiter.requests TO arbiter_maintenance_worker
    """)
    op.execute("GRANT SELECT,INSERT ON arbiter.capacity_clearances TO arbiter_maintenance_worker")
    op.execute("GRANT INSERT ON arbiter.audit_events TO arbiter_maintenance_worker")
    op.execute("GRANT UPDATE (finished_at) ON arbiter.requests TO arbiter_maintenance_worker")
    op.execute("""
        CREATE OR REPLACE FUNCTION arbiter.guard_terminal_state() RETURNS trigger
        LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog AS $$
        DECLARE v_original arbiter.requests%ROWTYPE;
        BEGIN
            IF OLD.state='unknown' THEN
                v_original:=NEW;
                v_original.finished_at:=OLD.finished_at;
                -- Stored generated columns are unset in BEFORE UPDATE trigger rows.
                v_original.reserve_kind:=OLD.reserve_kind;
                IF NOT (
                    NEW.state='unknown' AND OLD.finished_at IS NULL
                    AND NEW.finished_at IS NOT NULL
                    AND v_original IS NOT DISTINCT FROM OLD
                    AND EXISTS (SELECT 1 FROM arbiter.capacity_clearances c
                        WHERE c.tenant_id=OLD.tenant_id AND c.request_id=OLD.id)) THEN
                    RAISE EXCEPTION 'invalid terminal transition' USING ERRCODE='23514';
                END IF;
            ELSIF OLD.state IN ('succeeded','failed') OR
                (OLD.state='reserved' AND
                    NEW.state NOT IN ('reserved','dispatched','released','rejected_capacity')) OR
                (OLD.state='dispatched' AND NEW.state<>'dispatched' AND
                    (NEW.state NOT IN ('succeeded','failed','unknown') OR
                        NEW.terminal_audit_id IS NULL OR OLD.terminal_audit_id IS NOT NULL)) THEN
                RAISE EXCEPTION 'invalid terminal transition' USING ERRCODE='23514';
            END IF;
            RETURN NEW;
        END $$
    """)
    op.execute("""
        CREATE FUNCTION arbiter.maintenance_candidates(p_kind text)
        RETURNS TABLE(tenant_id uuid,key_id uuid,request_id uuid,cleared boolean)
        LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog AS $$
        BEGIN
            IF session_user<>'arbiter_maintenance' OR
                NULLIF(current_setting('arbiter.tenant_id',true),'') IS NOT NULL OR
                (p_kind IS NULL OR p_kind NOT IN ('stale','restart','unknown')) THEN
                RAISE EXCEPTION 'permission denied' USING ERRCODE='42501';
            END IF;
            RETURN QUERY
            SELECT r.tenant_id,r.key_id,r.id,(c.request_id IS NOT NULL)
            FROM arbiter.requests r LEFT JOIN arbiter.capacity_clearances c
                ON c.tenant_id=r.tenant_id AND c.request_id=r.id
            WHERE (p_kind='stale' AND r.state='reserved' AND
                    r.created_at<=clock_timestamp()-interval '30 seconds')
                OR (p_kind='restart' AND r.state='dispatched')
                OR (p_kind='unknown' AND r.state='unknown')
            ORDER BY r.tenant_id,r.id;
        END $$
    """)
    op.execute("""
        CREATE FUNCTION arbiter.clear_unknown_capacity(p_tenant uuid,p_request uuid)
        RETURNS boolean
        LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog AS $$
        DECLARE v_revision bigint; v_audit uuid;
        BEGIN
            IF session_user<>'arbiter_operator' OR p_tenant IS NULL OR
                p_tenant IS DISTINCT FROM
                    NULLIF(current_setting('arbiter.tenant_id',true),'')::uuid OR
                p_request IS NULL THEN
                RAISE EXCEPTION 'permission denied' USING ERRCODE='42501';
            END IF;
            SELECT r.policy_revision INTO v_revision FROM arbiter.requests r
                WHERE r.tenant_id=p_tenant AND r.id=p_request AND r.state='unknown';
            IF NOT FOUND THEN
                RAISE EXCEPTION 'unknown request unavailable' USING ERRCODE='RC001';
            END IF;
            IF EXISTS (SELECT 1 FROM arbiter.capacity_clearances c
                WHERE c.tenant_id=p_tenant AND c.request_id=p_request) THEN
                RETURN false;
            END IF;
            v_audit:=gen_random_uuid();
            INSERT INTO arbiter.audit_events
                (id,tenant_id,actor_type,actor_reference,action,target_id,
                    policy_revision,request_id,outcome)
            VALUES (v_audit,p_tenant,'operator','arbiter_operator',
                'unknown_capacity_cleared',p_request,v_revision,
                p_request,'succeeded');
            INSERT INTO arbiter.capacity_clearances(tenant_id,request_id,audit_id)
                VALUES (p_tenant,p_request,v_audit)
                ON CONFLICT (tenant_id,request_id) DO NOTHING;
            IF NOT FOUND THEN
                -- A competing operator committed first. Roll back this unused audit.
                RAISE EXCEPTION 'concurrent clearance' USING ERRCODE='40001';
            END IF;
            UPDATE arbiter.requests SET finished_at=clock_timestamp()
                WHERE tenant_id=p_tenant AND id=p_request AND state='unknown'
                    AND finished_at IS NULL;
            IF NOT FOUND THEN
                RAISE EXCEPTION 'unknown capacity unavailable' USING ERRCODE='RC002';
            END IF;
            RETURN true;
        END $$
    """)
    for function, caller in ((SCAN, "arbiter_maintenance"), (CLEAR, "arbiter_operator")):
        op.execute(f"REVOKE ALL ON FUNCTION {function} FROM PUBLIC")
        op.execute(f"GRANT EXECUTE ON FUNCTION {function} TO {caller}")
        op.execute(f"GRANT CREATE ON SCHEMA arbiter TO {ROLE}")
        op.execute(f"ALTER FUNCTION {function} OWNER TO {ROLE}")
        op.execute(f"REVOKE CREATE ON SCHEMA arbiter FROM {ROLE}")


def downgrade() -> None:
    op.execute("""
        ALTER TABLE arbiter.capacity_clearances ADD CONSTRAINT clearance_downgrade_guard
        CHECK (false)
    """)
    op.execute("ALTER TABLE arbiter.capacity_clearances DROP CONSTRAINT clearance_downgrade_guard")
    op.execute("""
        CREATE OR REPLACE FUNCTION arbiter.guard_terminal_state() RETURNS trigger
        LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog AS $$
        BEGIN
            IF OLD.state IN ('succeeded','failed','unknown') OR
                (OLD.state='reserved' AND
                    NEW.state NOT IN ('reserved','dispatched','released','rejected_capacity')) OR
                (OLD.state='dispatched' AND NEW.state<>'dispatched' AND
                    (NEW.state NOT IN ('succeeded','failed','unknown') OR
                        NEW.terminal_audit_id IS NULL OR OLD.terminal_audit_id IS NOT NULL)) THEN
                RAISE EXCEPTION 'invalid terminal transition' USING ERRCODE='23514';
            END IF;
            RETURN NEW;
        END $$
    """)
    op.execute(f"DROP FUNCTION {CLEAR} RESTRICT")
    op.execute(f"DROP FUNCTION {SCAN} RESTRICT")
    op.execute("DROP POLICY maintenance_audit_insert ON arbiter.audit_events")
    op.execute("DROP POLICY maintenance_request_read ON arbiter.requests")
    op.execute("DROP TABLE arbiter.capacity_clearances RESTRICT")
    op.execute("REVOKE ALL ON arbiter.audit_events FROM arbiter_maintenance_worker")
    op.execute("REVOKE ALL ON arbiter.requests FROM arbiter_maintenance_worker")
    op.execute("REVOKE USAGE ON SCHEMA arbiter FROM arbiter_maintenance_worker")
    op.execute("REVOKE USAGE ON SCHEMA arbiter FROM arbiter_maintenance")
