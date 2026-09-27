"""One scoped reservation capability; no direct runtime writes or dispatch grants."""

from alembic import op

revision: str = "0012_reservation_transactions"
down_revision: str | None = "0011_accounting_foundation"
branch_labels: str | None = None
depends_on: str | None = None

FUNCTION = "arbiter.reserve_request(uuid,uuid,text,bytea,integer,text,bytea,integer,text,integer)"
TABLES = (
    "tenants",
    "api_keys",
    "tenant_policies",
    "quota_windows",
    "budget_windows",
    "requests",
    "reservations",
    "accounting_events",
    "audit_events",
)
SCOPE = "tenant_id=NULLIF(current_setting('arbiter.tenant_id',true),'')::uuid"


def upgrade() -> None:
    op.execute("""
        ALTER TABLE arbiter.audit_events
            DROP CONSTRAINT audit_events_actor_type_check,
            DROP CONSTRAINT audit_events_check,
            ADD COLUMN actor_api_key_id uuid,
            ADD CONSTRAINT audit_events_actor_type_check
                CHECK (actor_type IN ('member','operator','api_key')),
            ADD CONSTRAINT audit_events_check CHECK (
                (actor_type='member' AND actor_membership_id IS NOT NULL
                    AND actor_api_key_id IS NULL)
                OR (actor_type='operator' AND actor_membership_id IS NULL
                    AND actor_api_key_id IS NULL)
                OR (actor_type='api_key' AND actor_membership_id IS NULL
                    AND actor_api_key_id IS NOT NULL AND actor_reference=actor_api_key_id::text
                    AND action='request_reserved' AND outcome='succeeded'
                    AND request_id IS NOT NULL AND request_id=target_id)),
            ADD CONSTRAINT audit_actor_key_fk FOREIGN KEY (tenant_id,actor_api_key_id)
                REFERENCES arbiter.api_keys(tenant_id,id),
            ADD CONSTRAINT audit_reservation_binding UNIQUE
                (tenant_id,id,target_id,actor_api_key_id,policy_revision,action,outcome)
    """)
    # Legacy foundation records are retained without fabricating audit evidence.
    # New writer INSERT policy below requires the exact deferred audit binding.
    op.execute("""
        ALTER TABLE arbiter.requests
            ADD COLUMN reservation_audit_id uuid,
            ADD COLUMN audit_action varchar(64) NOT NULL DEFAULT 'request_reserved'
                CHECK (audit_action='request_reserved'),
            ADD COLUMN audit_outcome varchar(16) NOT NULL DEFAULT 'succeeded'
                CHECK (audit_outcome='succeeded'),
            ADD CONSTRAINT request_audit_fk FOREIGN KEY
                (tenant_id,reservation_audit_id,id,key_id,policy_revision,audit_action,audit_outcome)
                REFERENCES arbiter.audit_events
                (tenant_id,id,target_id,actor_api_key_id,policy_revision,action,outcome)
                DEFERRABLE INITIALLY DEFERRED
    """)
    op.execute("GRANT USAGE ON SCHEMA arbiter TO arbiter_reservation_writer")
    for table in TABLES:
        check = SCOPE
        if table == "requests":
            check += " AND reservation_audit_id IS NOT NULL AND state='reserved'"
        elif table == "accounting_events":
            check += " AND kind='reserve'"
        elif table == "audit_events":
            check += " AND actor_type='api_key' AND action='request_reserved'"
        op.execute(f"""
            CREATE POLICY reservation_writer_scope ON arbiter.{table} AS RESTRICTIVE
            TO arbiter_reservation_writer USING ({SCOPE}) WITH CHECK ({check})
        """)
        op.execute(f"""
            CREATE POLICY reservation_writer_access ON arbiter.{table}
            TO arbiter_reservation_writer USING (true) WITH CHECK (true)
        """)
        op.execute(f"GRANT SELECT ON arbiter.{table} TO arbiter_reservation_writer")
    op.execute("""
        GRANT INSERT ON arbiter.quota_windows,arbiter.budget_windows,arbiter.requests,
            arbiter.reservations,arbiter.accounting_events,arbiter.audit_events
        TO arbiter_reservation_writer
    """)
    op.execute("""
        GRANT UPDATE (reserved) ON arbiter.quota_windows,arbiter.budget_windows
        TO arbiter_reservation_writer
    """)
    # PostgreSQL row locking requires UPDATE privilege; no status/state write is granted.
    for table in ("tenants", "api_keys", "tenant_policies", "provider_models"):
        op.execute(f"GRANT UPDATE (id) ON arbiter.{table} TO arbiter_reservation_writer")
    op.execute("GRANT SELECT ON arbiter.provider_models TO arbiter_reservation_writer")
    op.execute("""
        CREATE FUNCTION arbiter.reserve_request(
            p_tenant uuid,p_key uuid,p_public text,p_candidate bytea,p_pepper integer,
            p_idempotency text,p_fingerprint bytea,p_fingerprint_version integer,
            p_alias text,p_output integer)
        RETURNS TABLE (request_id uuid,state text,model_alias text,credit_charge bigint,
            policy_revision bigint,model_revision bigint,duplicate boolean)
        LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog AS $$
        DECLARE
            v_tenant arbiter.tenants%ROWTYPE; v_key arbiter.api_keys%ROWTYPE;
            v_policy arbiter.tenant_policies%ROWTYPE; v_model arbiter.provider_models%ROWTYPE;
            v_existing arbiter.requests%ROWTYPE; v_quota arbiter.quota_windows%ROWTYPE;
            v_budget arbiter.budget_windows%ROWTYPE;
            v_now timestamptz; v_day timestamptz; v_month timestamptz;
            v_key_found boolean; v_difference integer := 0; v_stored bytea;
            v_occupancy bigint; v_request uuid; v_reservation uuid; v_event uuid; v_audit uuid;
        BEGIN
            IF session_user<>'arbiter_runtime' OR p_tenant IS NULL OR
                p_tenant IS DISTINCT FROM
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
            -- Every mutation path holds this admission lock first, including policy/key changes.
            SELECT t.* INTO v_tenant FROM arbiter.tenants t
                WHERE t.id=p_tenant AND t.tenant_id=p_tenant FOR UPDATE;
            IF NOT FOUND OR v_tenant.status<>'active' THEN
                RAISE EXCEPTION 'invalid credentials' USING ERRCODE='AR001';
            END IF;
            SELECT k.* INTO v_key FROM arbiter.api_keys k
                WHERE k.tenant_id=p_tenant AND k.id=p_key AND k.public_id=p_public FOR UPDATE;
            v_key_found:=FOUND;
            v_stored:=COALESCE(v_key.verifier,decode(repeat('00',32),'hex'));
            FOR i IN 0..31 LOOP
                v_difference:=v_difference | (get_byte(v_stored,i) # get_byte(p_candidate,i));
            END LOOP;
            IF NOT v_key_found OR v_difference<>0 OR v_key.pepper_version<>p_pepper
                OR v_key.revoked_at IS NOT NULL OR v_key.expires_at<=clock_timestamp() THEN
                RAISE EXCEPTION 'invalid credentials' USING ERRCODE='AR001';
            END IF;
            IF NOT ('inference:write'=ANY(v_key.scopes)) THEN
                RAISE EXCEPTION 'permission denied' USING ERRCODE='AR002';
            END IF;
            SELECT p.* INTO v_policy FROM arbiter.tenant_policies p
                WHERE p.tenant_id=p_tenant AND p.revision=v_tenant.policy_revision FOR SHARE;
            IF NOT FOUND THEN
                RAISE EXCEPTION 'unavailable' USING ERRCODE='AR008';
            END IF;
            SELECT r.* INTO v_existing FROM arbiter.requests r
                WHERE r.tenant_id=p_tenant AND r.key_id=p_key AND r.idempotency_key=p_idempotency;
            IF FOUND THEN
                v_difference:=0;
                FOR i IN 0..31 LOOP
                    v_difference:=v_difference |
                        (get_byte(v_existing.payload_hmac,i) # get_byte(p_fingerprint,i));
                END LOOP;
                IF v_difference<>0 OR v_existing.fingerprint_version<>p_fingerprint_version THEN
                    RAISE EXCEPTION 'idempotency conflict' USING ERRCODE='AR003';
                END IF;
                RETURN QUERY SELECT v_existing.id,v_existing.state::text,
                    v_existing.model_alias::text,v_existing.credit_charge,
                    v_existing.policy_revision,v_existing.model_revision,true;
                RETURN;
            END IF;
            IF NOT (p_alias=ANY(v_policy.model_aliases)) THEN
                RAISE EXCEPTION 'model denied' USING ERRCODE='AR004';
            END IF;
            v_now:=clock_timestamp();
            v_day:=date_trunc('day',v_now AT TIME ZONE 'UTC') AT TIME ZONE 'UTC';
            v_month:=date_trunc('month',v_now AT TIME ZONE 'UTC') AT TIME ZONE 'UTC';
            -- Missing-window creation also takes row locks in quota -> budget order.
            INSERT INTO arbiter.quota_windows(id,tenant_id,window_start)
                VALUES (gen_random_uuid(),p_tenant,v_day)
                ON CONFLICT (tenant_id,window_start) DO NOTHING;
            SELECT q.* INTO STRICT v_quota FROM arbiter.quota_windows q
                WHERE q.tenant_id=p_tenant AND q.window_start=v_day FOR UPDATE;
            INSERT INTO arbiter.budget_windows(id,tenant_id,window_start)
                VALUES (gen_random_uuid(),p_tenant,v_month)
                ON CONFLICT (tenant_id,window_start) DO NOTHING;
            SELECT b.* INTO STRICT v_budget FROM arbiter.budget_windows b
                WHERE b.tenant_id=p_tenant AND b.window_start=v_month FOR UPDATE;
            -- Global registry locks are last; registry-only writers never acquire tenant locks.
            SELECT m.* INTO v_model FROM arbiter.provider_models m
                WHERE m.alias=p_alias AND m.active FOR SHARE;
            IF NOT FOUND THEN
                RAISE EXCEPTION 'model denied' USING ERRCODE='AR004';
            END IF;
            IF p_output>v_model.output_cap THEN
                RAISE EXCEPTION 'invalid fields' USING ERRCODE='22023';
            END IF;
            -- Numeric comparisons avoid overflow before the checked BIGINT updates.
            IF v_quota.committed::numeric+v_quota.reserved::numeric+1>v_policy.daily_quota THEN
                RAISE EXCEPTION 'quota exhausted' USING ERRCODE='AR005';
            END IF;
            IF v_budget.committed::numeric+v_budget.reserved::numeric+
                v_model.credit_charge::numeric>v_policy.monthly_budget THEN
                RAISE EXCEPTION 'budget exhausted' USING ERRCODE='AR006';
            END IF;
            SELECT count(*) INTO v_occupancy FROM arbiter.requests r
                WHERE r.tenant_id=p_tenant AND r.state IN ('reserved','dispatched','unknown')
                    AND r.finished_at IS NULL;
            IF v_occupancy>=v_policy.concurrency THEN
                RAISE EXCEPTION 'tenant capacity exhausted' USING ERRCODE='AR007';
            END IF;
            v_now:=clock_timestamp();
            IF v_key.expires_at<=v_now THEN
                RAISE EXCEPTION 'invalid credentials' USING ERRCODE='AR001';
            END IF;
            IF v_day<>date_trunc('day',v_now AT TIME ZONE 'UTC') AT TIME ZONE 'UTC'
                OR v_month<>date_trunc('month',v_now AT TIME ZONE 'UTC') AT TIME ZONE 'UTC' THEN
                RAISE EXCEPTION 'unavailable' USING ERRCODE='AR008';
            END IF;
            v_request:=gen_random_uuid(); v_reservation:=gen_random_uuid();
            v_event:=gen_random_uuid(); v_audit:=gen_random_uuid();
            UPDATE arbiter.quota_windows SET reserved=reserved+1
                WHERE tenant_id=p_tenant AND id=v_quota.id;
            UPDATE arbiter.budget_windows SET reserved=reserved+v_model.credit_charge
                WHERE tenant_id=p_tenant AND id=v_budget.id;
            INSERT INTO arbiter.requests
                (id,tenant_id,key_id,idempotency_key,payload_hmac,fingerprint_version,
                 policy_revision,model_id,model_revision,model_alias,model_adapter,model_digest,
                 context_cap,output_cap,credit_charge,quota_window_id,budget_window_id,
                 quota_start,budget_start,reservation_id,reserve_event_id,reservation_audit_id,
                 state,created_at)
                VALUES (v_request,p_tenant,p_key,p_idempotency,p_fingerprint,p_fingerprint_version,
                    v_policy.revision,v_model.id,v_model.revision,v_model.alias,v_model.adapter,
                    v_model.model_digest,v_model.context_cap,p_output,v_model.credit_charge,
                    v_quota.id,v_budget.id,v_day,v_month,v_reservation,v_event,v_audit,'reserved',v_now);
            INSERT INTO arbiter.reservations
                (id,tenant_id,request_id,quota_window_id,budget_window_id,request_count,credits)
                VALUES (v_reservation,p_tenant,v_request,v_quota.id,v_budget.id,1,
                    v_model.credit_charge);
            INSERT INTO arbiter.accounting_events
                (id,tenant_id,request_id,reservation_id,quota_window_id,budget_window_id,
                 request_count,credits,kind,occurred_at)
                VALUES (v_event,p_tenant,v_request,v_reservation,v_quota.id,v_budget.id,1,
                    v_model.credit_charge,'reserve',v_now);
            INSERT INTO arbiter.audit_events
                (id,tenant_id,actor_type,actor_reference,actor_api_key_id,action,target_id,
                 policy_revision,request_id,occurred_at,outcome)
                VALUES (v_audit,p_tenant,'api_key',p_key::text,p_key,'request_reserved',v_request,
                    v_policy.revision,v_request,v_now,'succeeded');
            RETURN QUERY SELECT v_request,'reserved'::text,p_alias,v_model.credit_charge,
                v_policy.revision,v_model.revision,false;
        END $$
    """)
    op.execute(f"REVOKE ALL ON FUNCTION {FUNCTION} FROM PUBLIC")
    op.execute(f"GRANT EXECUTE ON FUNCTION {FUNCTION} TO arbiter_runtime")
    op.execute("GRANT CREATE ON SCHEMA arbiter TO arbiter_reservation_writer")
    op.execute(f"ALTER FUNCTION {FUNCTION} OWNER TO arbiter_reservation_writer")
    op.execute("REVOKE CREATE ON SCHEMA arbiter FROM arbiter_reservation_writer")


def downgrade() -> None:
    # Foundation cannot represent accepted key-audit records; fail before deleting evidence.
    # Constraint validation examines every row even under context-free FORCE RLS.
    op.execute("""
        ALTER TABLE arbiter.audit_events ADD CONSTRAINT reservation_downgrade_guard
        CHECK (actor_type<>'api_key')
    """)
    op.execute("ALTER TABLE arbiter.audit_events DROP CONSTRAINT reservation_downgrade_guard")
    op.execute(f"DROP FUNCTION {FUNCTION} RESTRICT")
    # Remove only this capability's policies before dropping their referenced columns.
    for table in TABLES:
        op.execute(f"DROP POLICY reservation_writer_access ON arbiter.{table}")
        op.execute(f"DROP POLICY reservation_writer_scope ON arbiter.{table}")
    op.execute("ALTER TABLE arbiter.requests DROP CONSTRAINT request_audit_fk")
    op.execute("""
        ALTER TABLE arbiter.requests DROP COLUMN reservation_audit_id,
            DROP COLUMN audit_action,DROP COLUMN audit_outcome
    """)
    op.execute("""
        ALTER TABLE arbiter.audit_events DROP CONSTRAINT audit_reservation_binding,
            DROP CONSTRAINT audit_actor_key_fk,DROP CONSTRAINT audit_events_actor_type_check,
            DROP CONSTRAINT audit_events_check,DROP COLUMN actor_api_key_id,
            ADD CONSTRAINT audit_events_actor_type_check
                CHECK (actor_type IN ('member','operator')),
            ADD CONSTRAINT audit_events_check CHECK (
                (actor_type='member' AND actor_membership_id IS NOT NULL)
                OR (actor_type='operator' AND actor_membership_id IS NULL))
    """)
    for table in TABLES:
        op.execute(f"REVOKE ALL ON arbiter.{table} FROM arbiter_reservation_writer")
    for table in ("tenants", "api_keys", "tenant_policies", "provider_models"):
        op.execute(f"REVOKE UPDATE (id) ON arbiter.{table} FROM arbiter_reservation_writer")
    for table in ("quota_windows", "budget_windows"):
        op.execute(f"REVOKE UPDATE (reserved) ON arbiter.{table} FROM arbiter_reservation_writer")
    op.execute("REVOKE SELECT ON arbiter.provider_models FROM arbiter_reservation_writer")
    op.execute("REVOKE USAGE ON SCHEMA arbiter FROM arbiter_reservation_writer")
