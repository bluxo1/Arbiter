"""Bounded operator cleanup of unreferenced UTC windows and standalone audits."""

from alembic import op

revision: str = "0021_history_retention"
down_revision: str | None = "0020_request_retention"
branch_labels: str | None = None
depends_on: str | None = None

ROLE = "arbiter_retention_writer"
SCOPE = "tenant_id=NULLIF(current_setting('arbiter.tenant_id',true),'')::uuid"
FUNCTION = "arbiter.retire_history(uuid,timestamptz,uuid,integer)"


def _request_guard(standalone: bool) -> None:
    # The original 0020 request/tombstone predicate remains unchanged below the new branch.
    branch = (
        """
        IF TG_TABLE_NAME='audit_events' THEN
            IF arbiter.standalone_audit_eligible(OLD.tenant_id,OLD.id,clock_timestamp()) THEN
                RETURN OLD;
            END IF;
        END IF;
    """
        if standalone
        else ""
    )
    op.execute(
        """
        CREATE OR REPLACE FUNCTION arbiter.guard_retention_delete() RETURNS trigger
        LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog AS $$
        DECLARE v_request arbiter.requests%ROWTYPE; v_id uuid;
        BEGIN
            IF TG_OP<>'DELETE' OR current_user<>'arbiter_retention_writer' OR
                session_user<>'arbiter_operator' OR OLD.tenant_id IS DISTINCT FROM
                    NULLIF(current_setting('arbiter.tenant_id',true),'')::uuid THEN
                RAISE EXCEPTION 'retention deletion only' USING ERRCODE='42501';
            END IF;
            __STANDALONE__
            IF TG_TABLE_NAME='requests' THEN
                v_request:=OLD;
            ELSE
                v_id:=OLD.request_id;
                SELECT r.* INTO v_request FROM arbiter.requests r
                    WHERE r.tenant_id=OLD.tenant_id AND r.id=v_id;
            END IF;
            IF v_request.id IS NULL OR v_request.state NOT IN
                ('succeeded','failed','released','rejected_capacity') OR
                v_request.finished_at IS NULL OR
                v_request.finished_at>clock_timestamp()-interval '90 days' THEN
                RAISE EXCEPTION 'request not eligible for retention' USING ERRCODE='23514';
            END IF;
            IF TG_TABLE_NAME='audit_events' THEN
                IF OLD.id IS DISTINCT FROM v_request.reservation_audit_id AND
                    OLD.id IS DISTINCT FROM v_request.release_audit_id AND
                    OLD.id IS DISTINCT FROM v_request.dispatch_audit_id AND
                    OLD.id IS DISTINCT FROM v_request.terminal_audit_id THEN
                    RAISE EXCEPTION 'unrelated audit evidence' USING ERRCODE='23514';
                END IF;
            END IF;
            IF NOT EXISTS (SELECT 1 FROM arbiter.idempotency_tombstones t
                WHERE t.tenant_id=v_request.tenant_id AND t.key_id=v_request.key_id
                    AND t.request_id=v_request.id AND t.idempotency_key=v_request.idempotency_key
                    AND t.payload_hmac=v_request.payload_hmac
                    AND t.fingerprint_version=v_request.fingerprint_version
                    AND t.state=v_request.state) THEN
                RAISE EXCEPTION 'tombstone required' USING ERRCODE='23514';
            END IF;
            RETURN OLD;
        END $$
    """.replace("__STANDALONE__", branch)
    )


def upgrade() -> None:
    for table in ("quota_windows", "budget_windows", "tenant_policies"):
        op.execute(f"""
            CREATE POLICY retention_scope ON arbiter.{table} AS RESTRICTIVE TO {ROLE}
                USING ({SCOPE}) WITH CHECK ({SCOPE});
            CREATE POLICY retention_access ON arbiter.{table} TO {ROLE}
                USING (true) WITH CHECK ({SCOPE});
            GRANT SELECT ON arbiter.{table} TO {ROLE}
        """)
    for table in ("quota_windows", "budget_windows"):
        op.execute(f"GRANT DELETE ON arbiter.{table} TO {ROLE}")
    op.execute("""
        CREATE FUNCTION arbiter.retention_has_reference(p_table regclass,p_tenant uuid,p_id uuid)
        RETURNS boolean LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog AS $$
        DECLARE v_fk record; v_join text; v_exists boolean;
        BEGIN
            IF current_user<>'arbiter_retention_writer' OR session_user<>'arbiter_operator'
                OR p_tenant IS NULL OR p_tenant IS DISTINCT FROM
                    NULLIF(current_setting('arbiter.tenant_id',true),'')::uuid
                OR p_table IS NULL OR p_id IS NULL OR p_table NOT IN
                    ('arbiter.quota_windows'::regclass,'arbiter.budget_windows'::regclass,
                        'arbiter.audit_events'::regclass) THEN
                RAISE EXCEPTION 'permission denied' USING ERRCODE='42501';
            END IF;
            FOR v_fk IN SELECT k.conkey,k.confkey,n.nspname,c.relname
                FROM pg_catalog.pg_constraint k
                JOIN pg_catalog.pg_class c ON c.oid=k.conrelid
                JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
                WHERE k.contype='f' AND k.confrelid=p_table ORDER BY k.oid
            LOOP
                SELECT string_agg(format('c.%I=p.%I',ca.attname,pa.attname),' AND ' ORDER BY x.ord)
                    INTO v_join FROM unnest(v_fk.conkey,v_fk.confkey) WITH ORDINALITY
                        AS x(child,parent,ord)
                    JOIN pg_catalog.pg_attribute ca ON ca.attrelid=format('%I.%I',v_fk.nspname,
                        v_fk.relname)::regclass AND ca.attnum=x.child
                    JOIN pg_catalog.pg_attribute pa ON pa.attrelid=p_table AND pa.attnum=x.parent;
                -- Identifiers come solely from PostgreSQL's catalog, values stay bound.
                -- A new reference without a readable scoped policy fails closed.
                EXECUTE format('SELECT EXISTS (SELECT 1 FROM %I.%I c JOIN %s p ON %s
                    WHERE p.tenant_id=$1 AND p.id=$2)',v_fk.nspname,v_fk.relname,p_table,v_join)
                    INTO v_exists USING p_tenant,p_id;
                IF v_exists THEN RETURN true; END IF;
            END LOOP;
            RETURN false;
        END $$
    """)
    op.execute("""
        CREATE FUNCTION arbiter.retention_window_eligible(p_kind text,p_tenant uuid,p_id uuid,
            p_at timestamptz) RETURNS boolean
        LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog AS $$
        DECLARE v_start timestamptz; v_close interval; v_table regclass;
        BEGIN
            IF p_kind='quota_windows' THEN
                SELECT window_start INTO v_start FROM arbiter.quota_windows
                    WHERE tenant_id=p_tenant AND id=p_id;
                v_close:=interval '1 day'; v_table:='arbiter.quota_windows'::regclass;
                IF EXISTS (SELECT 1 FROM arbiter.requests WHERE tenant_id=p_tenant
                    AND quota_window_id=p_id UNION ALL SELECT 1 FROM arbiter.reservations
                    WHERE tenant_id=p_tenant AND quota_window_id=p_id UNION ALL SELECT 1
                    FROM arbiter.accounting_events WHERE tenant_id=p_tenant
                    AND quota_window_id=p_id) THEN RETURN false; END IF;
            ELSIF p_kind='budget_windows' THEN
                SELECT window_start INTO v_start FROM arbiter.budget_windows
                    WHERE tenant_id=p_tenant AND id=p_id;
                v_close:=interval '1 month'; v_table:='arbiter.budget_windows'::regclass;
                IF EXISTS (SELECT 1 FROM arbiter.requests WHERE tenant_id=p_tenant
                    AND budget_window_id=p_id UNION ALL SELECT 1 FROM arbiter.reservations
                    WHERE tenant_id=p_tenant AND budget_window_id=p_id UNION ALL SELECT 1
                    FROM arbiter.accounting_events WHERE tenant_id=p_tenant
                    AND budget_window_id=p_id) THEN RETURN false; END IF;
            ELSE RETURN false;
            END IF;
            IF v_start IS NULL OR p_at IS NULL OR NOT isfinite(p_at) OR
                ((v_start AT TIME ZONE 'UTC')+v_close+interval '13 months')
                    AT TIME ZONE 'UTC'>p_at THEN RETURN false; END IF;
            RETURN NOT arbiter.retention_has_reference(v_table,p_tenant,p_id);
        END $$
    """)
    op.execute("""
        CREATE FUNCTION arbiter.standalone_audit_eligible(p_tenant uuid,p_id uuid,p_at timestamptz)
        RETURNS boolean LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog AS $$
        DECLARE v_audit arbiter.audit_events%ROWTYPE;
        BEGIN
            SELECT a.* INTO v_audit FROM arbiter.audit_events a
                WHERE a.tenant_id=p_tenant AND a.id=p_id;
            IF NOT FOUND OR p_at IS NULL OR NOT isfinite(p_at) OR
                ((v_audit.occurred_at AT TIME ZONE 'UTC')+interval '90 days')
                    AT TIME ZONE 'UTC'>p_at OR v_audit.action IN
                    ('request_reserved','request_released','request_dispatched','request_finalized')
                OR EXISTS (SELECT 1 FROM arbiter.requests r WHERE r.tenant_id=p_tenant
                    AND (r.id=v_audit.request_id OR p_id IN (r.reservation_audit_id,
                        r.release_audit_id,r.dispatch_audit_id,r.terminal_audit_id)))
                THEN RETURN false; END IF;
            RETURN NOT arbiter.retention_has_reference('arbiter.audit_events',p_tenant,p_id);
        END $$
    """)
    op.execute("""
        CREATE FUNCTION arbiter.guard_window_retention() RETURNS trigger
        LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog AS $$
        BEGIN
            IF TG_OP<>'DELETE' OR current_user<>'arbiter_retention_writer' OR
                session_user<>'arbiter_operator' OR OLD.tenant_id IS DISTINCT FROM
                    NULLIF(current_setting('arbiter.tenant_id',true),'')::uuid THEN
                RAISE EXCEPTION 'retention deletion only' USING ERRCODE='42501';
            END IF;
            IF NOT arbiter.retention_window_eligible(TG_TABLE_NAME,OLD.tenant_id,OLD.id,
                clock_timestamp()) THEN
                RAISE EXCEPTION 'window not eligible for retention' USING ERRCODE='23514';
            END IF;
            RETURN OLD;
        END $$
    """)
    for table in ("quota_windows", "budget_windows"):
        op.execute(f"""
            CREATE TRIGGER retention_delete_guard BEFORE DELETE ON arbiter.{table}
                FOR EACH ROW EXECUTE FUNCTION arbiter.guard_window_retention()
        """)
    _request_guard(True)
    op.execute("""
        CREATE FUNCTION arbiter.retire_history(p_tenant uuid,p_at timestamptz,p_operation uuid,
            p_limit integer)
        RETURNS TABLE (quota_windows_removed bigint,budget_windows_removed bigint,
            standalone_audits_removed bigint,audit_id uuid)
        LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
        DECLARE v_at timestamptz; v_revision bigint; v_ids uuid[]; v_audit uuid;
        BEGIN
            IF session_user<>'arbiter_operator' OR p_tenant IS NULL OR
                p_tenant IS DISTINCT FROM NULLIF(current_setting('arbiter.tenant_id',true),'')::uuid
                THEN RAISE EXCEPTION 'permission denied' USING ERRCODE='42501'; END IF;
            v_at:=COALESCE(p_at,statement_timestamp());
            IF NOT isfinite(v_at) OR v_at>statement_timestamp() OR p_operation IS NULL
                OR p_limit IS NULL OR p_limit NOT BETWEEN 1 AND 100 THEN
                RAISE EXCEPTION 'invalid history batch' USING ERRCODE='22023';
            END IF;
            SELECT policy_revision INTO v_revision FROM arbiter.tenants
                WHERE tenant_id=p_tenant AND id=p_tenant FOR UPDATE;
            IF NOT FOUND THEN RAISE EXCEPTION 'tenant unavailable' USING ERRCODE='RT001'; END IF;
            -- Tenant lock serializes admission, revocation, retirement and other cleanup.
            -- DELETE acquires each row lock; quota precedes budget, no later key lock.
            SELECT array_agg(id) INTO v_ids FROM (SELECT id FROM arbiter.quota_windows
                WHERE tenant_id=p_tenant
                    AND arbiter.retention_window_eligible('quota_windows',p_tenant,id,v_at)
                ORDER BY window_start,id LIMIT p_limit) q;
            DELETE FROM arbiter.quota_windows WHERE tenant_id=p_tenant AND id=ANY(v_ids);
            GET DIAGNOSTICS quota_windows_removed=ROW_COUNT;
            SELECT array_agg(id) INTO v_ids FROM (SELECT id FROM arbiter.budget_windows
                WHERE tenant_id=p_tenant
                    AND arbiter.retention_window_eligible('budget_windows',p_tenant,id,v_at)
                ORDER BY window_start,id LIMIT p_limit) b;
            DELETE FROM arbiter.budget_windows WHERE tenant_id=p_tenant AND id=ANY(v_ids);
            GET DIAGNOSTICS budget_windows_removed=ROW_COUNT;
            SELECT array_agg(id) INTO v_ids FROM (SELECT id FROM arbiter.audit_events
                WHERE tenant_id=p_tenant AND arbiter.standalone_audit_eligible(p_tenant,id,v_at)
                ORDER BY occurred_at,id LIMIT p_limit) a;
            DELETE FROM arbiter.audit_events WHERE tenant_id=p_tenant AND id=ANY(v_ids);
            GET DIAGNOSTICS standalone_audits_removed=ROW_COUNT;
            v_audit:=gen_random_uuid();
            INSERT INTO arbiter.audit_events (id,tenant_id,actor_type,actor_reference,action,
                target_id,policy_revision,request_id,outcome,retention_summary)
            VALUES (v_audit,p_tenant,'operator','arbiter_operator','retention_cleaned',p_operation,
                v_revision,p_operation,'succeeded',jsonb_build_object('as_of',v_at,
                    'quota_windows',quota_windows_removed,'budget_windows',budget_windows_removed,
                    'standalone_audits',standalone_audits_removed));
            audit_id:=v_audit;
            RETURN NEXT;
        END $$
    """)
    for function in (
        "retention_has_reference(regclass,uuid,uuid)",
        "retention_window_eligible(text,uuid,uuid,timestamptz)",
        "standalone_audit_eligible(uuid,uuid,timestamptz)",
        "guard_window_retention()",
    ):
        op.execute(f"REVOKE ALL ON FUNCTION arbiter.{function} FROM PUBLIC")
        op.execute(f"GRANT EXECUTE ON FUNCTION arbiter.{function} TO {ROLE}")
    op.execute(f"REVOKE ALL ON FUNCTION {FUNCTION} FROM PUBLIC")
    op.execute(f"GRANT EXECUTE ON FUNCTION {FUNCTION} TO arbiter_operator")
    op.execute(f"GRANT CREATE ON SCHEMA arbiter TO {ROLE}")
    op.execute(f"ALTER FUNCTION {FUNCTION} OWNER TO {ROLE}")
    op.execute(f"REVOKE CREATE ON SCHEMA arbiter FROM {ROLE}")


def downgrade() -> None:
    # No evidence/table is discarded; 0020's more restrictive deletion rules return.
    op.execute(f"SET LOCAL ROLE {ROLE}")
    op.execute(f"DROP FUNCTION {FUNCTION} RESTRICT")
    op.execute("SET LOCAL ROLE arbiter_migration")
    _request_guard(False)
    for table in ("quota_windows", "budget_windows"):
        op.execute(f"DROP TRIGGER retention_delete_guard ON arbiter.{table}")
    for function in (
        "guard_window_retention()",
        "standalone_audit_eligible(uuid,uuid,timestamptz)",
        "retention_window_eligible(text,uuid,uuid,timestamptz)",
        "retention_has_reference(regclass,uuid,uuid)",
    ):
        op.execute(f"DROP FUNCTION arbiter.{function} RESTRICT")
    for table in ("quota_windows", "budget_windows", "tenant_policies"):
        op.execute(f"DROP POLICY retention_access ON arbiter.{table}")
        op.execute(f"DROP POLICY retention_scope ON arbiter.{table}")
        op.execute(f"REVOKE ALL ON arbiter.{table} FROM {ROLE}")
