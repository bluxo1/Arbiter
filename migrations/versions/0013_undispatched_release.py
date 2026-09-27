"""Reserved-only settlement, isolated from admission and future dispatch privileges."""

from alembic import op

revision: str = "0013_undispatched_release"
down_revision: str | None = "0012_reservation_transactions"
branch_labels: str | None = None
depends_on: str | None = None

FUNCTION = "arbiter.release_request(uuid,uuid,uuid,text)"
ROLE = "arbiter_release_writer"
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


def _audit_check(release: bool) -> None:
    actions = "'request_reserved','request_released'" if release else "'request_reserved'"
    op.execute(f"""
        ALTER TABLE arbiter.audit_events DROP CONSTRAINT audit_events_check,
        ADD CONSTRAINT audit_events_check CHECK (
            (actor_type='member' AND actor_membership_id IS NOT NULL AND actor_api_key_id IS NULL)
            OR (actor_type='operator' AND actor_membership_id IS NULL AND actor_api_key_id IS NULL)
            OR (actor_type='api_key' AND actor_membership_id IS NULL
                AND actor_api_key_id IS NOT NULL AND actor_reference=actor_api_key_id::text
                AND action IN ({actions}) AND outcome='succeeded'
                AND request_id IS NOT NULL AND request_id=target_id))
    """)


def _snapshot(release: bool) -> None:
    columns = (
        "'reserve_kind','state','dispatched_at','finished_at','outcome',"
        "'input_tokens','output_tokens'"
    )
    guard = ""
    if release:
        columns += ",'release_audit_id'"
        guard = """
            IF NEW.release_audit_id IS DISTINCT FROM OLD.release_audit_id AND
                NOT (OLD.release_audit_id IS NULL AND OLD.state='reserved'
                    AND OLD.dispatched_at IS NULL AND NEW.release_audit_id IS NOT NULL
                    AND NEW.state IN ('released','rejected_capacity')) THEN
                RAISE EXCEPTION 'immutable release evidence' USING ERRCODE='23514';
            END IF;
        """
    op.execute(f"""
        CREATE OR REPLACE FUNCTION arbiter.immutable_request_snapshot() RETURNS trigger
        LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog AS $$
        BEGIN
            IF (to_jsonb(NEW)-ARRAY[{columns}]) IS DISTINCT FROM
                (to_jsonb(OLD)-ARRAY[{columns}]) THEN
                RAISE EXCEPTION 'immutable request snapshot' USING ERRCODE='23514';
            END IF;
            {guard}
            RETURN NEW;
        END $$
    """)


def upgrade() -> None:
    _audit_check(True)
    op.execute("""
        ALTER TABLE arbiter.requests
            ADD COLUMN release_audit_id uuid,
            ADD COLUMN release_action varchar(64) NOT NULL DEFAULT 'request_released'
                CHECK (release_action='request_released'),
            ADD CONSTRAINT request_release_audit_fk FOREIGN KEY
                (tenant_id,release_audit_id,id,key_id,policy_revision,release_action,audit_outcome)
                REFERENCES arbiter.audit_events
                (tenant_id,id,target_id,actor_api_key_id,policy_revision,action,outcome)
                DEFERRABLE INITIALLY DEFERRED,
            ADD CONSTRAINT request_release_link_state CHECK (release_audit_id IS NULL OR
                (state IN ('released','rejected_capacity') AND dispatched_at IS NULL
                    AND outcome IN ('cancelled','provider_unavailable',
                        'rejected_capacity','authorization_changed',
                        'admission_window_changed','reservation_expired')))
    """)
    _snapshot(True)
    # This guard applies to every DML role, including ordinary migration-owner DML.
    # It makes a released request irrevocably undispatchable without adding dispatch.
    op.execute("""
        CREATE FUNCTION arbiter.guard_release_terminal() RETURNS trigger
        LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog AS $$
        BEGIN
            IF TG_TABLE_NAME='requests' THEN
                IF OLD.state IN ('released','rejected_capacity') OR
                    (OLD.dispatched_at IS NOT NULL AND
                        NEW.dispatched_at IS DISTINCT FROM OLD.dispatched_at) OR
                    (OLD.state<>'reserved' AND NEW.state='reserved') THEN
                    RAISE EXCEPTION 'invalid request transition' USING ERRCODE='23514';
                END IF;
            ELSE
                IF OLD.disposition<>'reserved' AND
                    (NEW.disposition IS DISTINCT FROM OLD.disposition OR
                        NEW.settlement_event_id IS DISTINCT FROM OLD.settlement_event_id) THEN
                    RAISE EXCEPTION 'immutable settlement' USING ERRCODE='23514';
                END IF;
            END IF;
            RETURN NEW;
        END $$
    """)
    op.execute("REVOKE ALL ON FUNCTION arbiter.guard_release_terminal() FROM PUBLIC")
    for table in ("requests", "reservations"):
        op.execute(f"""
            CREATE TRIGGER guard_release_terminal BEFORE UPDATE ON arbiter.{table}
            FOR EACH ROW EXECUTE FUNCTION arbiter.guard_release_terminal()
        """)
    op.execute(f"GRANT USAGE ON SCHEMA arbiter TO {ROLE}")
    for table in TABLES:
        check = SCOPE
        if table == "requests":
            check += (
                " AND state IN ('released','rejected_capacity') AND release_audit_id IS NOT NULL"
            )
        elif table == "reservations":
            check += " AND disposition='released' AND settlement_event_id IS NOT NULL"
        elif table == "accounting_events":
            check += " AND kind='release'"
        elif table == "audit_events":
            check += " AND actor_type='api_key' AND action='request_released'"
        op.execute(f"""
            CREATE POLICY release_writer_scope ON arbiter.{table} AS RESTRICTIVE TO {ROLE}
            USING ({SCOPE}) WITH CHECK ({check})
        """)
        op.execute(f"""
            CREATE POLICY release_writer_access ON arbiter.{table} TO {ROLE}
            USING (true) WITH CHECK (true)
        """)
        op.execute(f"GRANT SELECT ON arbiter.{table} TO {ROLE}")
    for table in ("tenants", "api_keys", "tenant_policies", "provider_models"):
        op.execute(f"GRANT UPDATE (id) ON arbiter.{table} TO {ROLE}")
    op.execute(f"GRANT SELECT ON arbiter.provider_models TO {ROLE}")
    op.execute(f"GRANT UPDATE (reserved) ON arbiter.quota_windows,arbiter.budget_windows TO {ROLE}")
    op.execute(f"""
        GRANT UPDATE (state,finished_at,outcome,release_audit_id) ON arbiter.requests TO {ROLE};
        GRANT UPDATE (disposition,settlement_event_id) ON arbiter.reservations TO {ROLE};
        GRANT INSERT ON arbiter.accounting_events,arbiter.audit_events TO {ROLE}
    """)
    op.execute("""
        CREATE FUNCTION arbiter.release_request(
            p_tenant uuid,p_key uuid,p_request uuid,p_reason text)
        RETURNS TABLE (request_id uuid,state text,outcome text,changed boolean)
        LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog AS $$
        DECLARE
            v_tenant arbiter.tenants%ROWTYPE; v_key arbiter.api_keys%ROWTYPE;
            v_policy arbiter.tenant_policies%ROWTYPE; v_request arbiter.requests%ROWTYPE;
            v_quota arbiter.quota_windows%ROWTYPE; v_budget arbiter.budget_windows%ROWTYPE;
            v_reservation arbiter.reservations%ROWTYPE; v_model arbiter.provider_models%ROWTYPE;
            v_now timestamptz; v_event uuid; v_audit uuid; v_state text;
        BEGIN
            IF session_user<>'arbiter_runtime' OR p_tenant IS NULL OR p_tenant IS DISTINCT FROM
                NULLIF(current_setting('arbiter.tenant_id',true),'')::uuid THEN
                RAISE EXCEPTION 'permission denied' USING ERRCODE='42501';
            END IF;
            IF p_key IS NULL OR p_request IS NULL THEN
                RAISE EXCEPTION 'request unavailable' USING ERRCODE='RL001';
            END IF;
            IF p_reason IS NULL OR p_reason NOT IN ('cancelled','provider_unavailable',
                'rejected_capacity',
                'authorization_changed','admission_window_changed','reservation_expired') THEN
                RAISE EXCEPTION 'invalid release reason' USING ERRCODE='22023';
            END IF;
            -- Authority is the trusted in-flight binding, not fresh admission permission.
            -- Revocation, expiry and suspension must not strand an undispatched allocation.
            SELECT t.* INTO v_tenant FROM arbiter.tenants t
                WHERE t.tenant_id=p_tenant AND t.id=p_tenant FOR UPDATE;
            IF NOT FOUND THEN RAISE EXCEPTION 'request unavailable' USING ERRCODE='RL001'; END IF;
            SELECT k.* INTO v_key FROM arbiter.api_keys k
                WHERE k.tenant_id=p_tenant AND k.id=p_key FOR UPDATE;
            IF NOT FOUND THEN RAISE EXCEPTION 'request unavailable' USING ERRCODE='RL001'; END IF;
            SELECT p.* INTO STRICT v_policy FROM arbiter.tenant_policies p
                WHERE p.tenant_id=p_tenant AND p.revision=v_tenant.policy_revision FOR SHARE;
            -- Read immutable window references before acquiring their locks. All supported
            -- tenant mutation paths already hold the admission row; recheck the request below.
            SELECT r.* INTO v_request FROM arbiter.requests r
                WHERE r.tenant_id=p_tenant AND r.id=p_request AND r.key_id=p_key;
            IF NOT FOUND THEN RAISE EXCEPTION 'request unavailable' USING ERRCODE='RL001'; END IF;
            SELECT q.* INTO STRICT v_quota FROM arbiter.quota_windows q
                WHERE q.tenant_id=p_tenant AND q.id=v_request.quota_window_id FOR UPDATE;
            SELECT b.* INTO STRICT v_budget FROM arbiter.budget_windows b
                WHERE b.tenant_id=p_tenant AND b.id=v_request.budget_window_id FOR UPDATE;
            SELECT r.* INTO STRICT v_request FROM arbiter.requests r
                WHERE r.tenant_id=p_tenant AND r.id=p_request AND r.key_id=p_key FOR UPDATE;
            SELECT s.* INTO STRICT v_reservation FROM arbiter.reservations s
                WHERE s.tenant_id=p_tenant AND s.id=v_request.reservation_id
                    AND s.request_id=p_request FOR UPDATE;
            -- Registry is always last; registry-only updates never take tenant locks.
            SELECT m.* INTO STRICT v_model FROM arbiter.provider_models m
                WHERE m.id=v_request.model_id FOR SHARE;
            IF v_request.state IN ('released','rejected_capacity') AND
                v_request.dispatched_at IS NULL AND v_reservation.disposition='released' THEN
                RETURN QUERY SELECT p_request,v_request.state::text,v_request.outcome::text,false;
                RETURN;
            END IF;
            IF v_request.state<>'reserved' OR v_request.dispatched_at IS NOT NULL OR
                v_reservation.disposition<>'reserved' OR
                v_reservation.settlement_event_id IS NOT NULL THEN
                RAISE EXCEPTION 'request not releasable' USING ERRCODE='RL002';
            END IF;
            v_now:=clock_timestamp();
            IF p_reason='authorization_changed' AND NOT (
                v_tenant.status<>'active' OR v_key.revoked_at IS NOT NULL OR v_key.expires_at<=v_now
                OR NOT ('inference:write'=ANY(v_key.scopes))
                OR v_request.policy_revision<>v_policy.revision
                OR NOT (v_request.model_alias=ANY(v_policy.model_aliases))
                OR NOT v_model.active OR v_model.revision<>v_request.model_revision) THEN
                RAISE EXCEPTION 'release condition absent' USING ERRCODE='RL002';
            END IF;
            IF p_reason='admission_window_changed' AND
                v_request.quota_start=date_trunc('day',v_now AT TIME ZONE 'UTC') AT TIME ZONE 'UTC'
                AND v_request.budget_start=date_trunc('month',v_now AT TIME ZONE 'UTC')
                    AT TIME ZONE 'UTC' THEN
                RAISE EXCEPTION 'release condition absent' USING ERRCODE='RL002';
            END IF;
            IF p_reason='reservation_expired' AND v_request.created_at>v_now-interval '30 seconds'
                THEN RAISE EXCEPTION 'release condition absent' USING ERRCODE='RL002'; END IF;
            IF v_reservation.request_count<>v_request.request_count OR
                v_reservation.credits<>v_request.credit_charge OR
                v_reservation.quota_window_id<>v_quota.id OR
                v_reservation.budget_window_id<>v_budget.id OR
                v_quota.reserved<v_reservation.request_count OR
                v_budget.reserved<v_reservation.credits THEN
                RAISE EXCEPTION 'accounting unavailable' USING ERRCODE='RL003';
            END IF;
            v_event:=gen_random_uuid(); v_audit:=gen_random_uuid();
            v_state:=CASE WHEN p_reason='rejected_capacity'
                THEN 'rejected_capacity' ELSE 'released' END;
            UPDATE arbiter.quota_windows SET reserved=reserved-v_reservation.request_count
                WHERE tenant_id=p_tenant AND id=v_quota.id;
            UPDATE arbiter.budget_windows SET reserved=reserved-v_reservation.credits
                WHERE tenant_id=p_tenant AND id=v_budget.id;
            UPDATE arbiter.requests AS r SET state=v_state,finished_at=v_now,outcome=p_reason,
                release_audit_id=v_audit WHERE r.tenant_id=p_tenant AND r.id=p_request
                    AND r.state='reserved' AND r.dispatched_at IS NULL;
            IF NOT FOUND THEN
                RAISE EXCEPTION 'request not releasable' USING ERRCODE='RL002'; END IF;
            UPDATE arbiter.reservations SET disposition='released',settlement_event_id=v_event
                WHERE tenant_id=p_tenant AND id=v_reservation.id AND disposition='reserved';
            IF NOT FOUND THEN
                RAISE EXCEPTION 'request not releasable' USING ERRCODE='RL002'; END IF;
            INSERT INTO arbiter.accounting_events
                (id,tenant_id,request_id,reservation_id,quota_window_id,budget_window_id,
                    request_count,credits,kind,occurred_at)
                VALUES (v_event,p_tenant,p_request,v_reservation.id,v_quota.id,v_budget.id,
                    v_reservation.request_count,v_reservation.credits,'release',v_now);
            INSERT INTO arbiter.audit_events
                (id,tenant_id,actor_type,actor_reference,actor_api_key_id,action,target_id,
                    policy_revision,request_id,occurred_at,outcome)
                VALUES (v_audit,p_tenant,'api_key',p_key::text,p_key,'request_released',p_request,
                    v_request.policy_revision,p_request,v_now,'succeeded');
            RETURN QUERY SELECT p_request,v_state,p_reason,true;
        END $$
    """)
    op.execute(f"REVOKE ALL ON FUNCTION {FUNCTION} FROM PUBLIC")
    op.execute(f"GRANT EXECUTE ON FUNCTION {FUNCTION} TO arbiter_runtime")
    op.execute(f"GRANT CREATE ON SCHEMA arbiter TO {ROLE}")
    op.execute(f"ALTER FUNCTION {FUNCTION} OWNER TO {ROLE}")
    op.execute(f"REVOKE CREATE ON SCHEMA arbiter FROM {ROLE}")


def downgrade() -> None:
    # Constraint validation sees even context-hidden rows. Do not discard accepted evidence.
    op.execute("""
        ALTER TABLE arbiter.requests ADD CONSTRAINT release_downgrade_guard
        CHECK (release_audit_id IS NULL)
    """)
    op.execute("ALTER TABLE arbiter.requests DROP CONSTRAINT release_downgrade_guard")
    op.execute(f"DROP FUNCTION {FUNCTION} RESTRICT")
    for table in TABLES:
        op.execute(f"DROP POLICY release_writer_access ON arbiter.{table}")
        op.execute(f"DROP POLICY release_writer_scope ON arbiter.{table}")
        op.execute(f"REVOKE ALL ON arbiter.{table} FROM {ROLE}")
    for table in ("tenants", "api_keys", "tenant_policies", "provider_models"):
        op.execute(f"REVOKE UPDATE (id) ON arbiter.{table} FROM {ROLE}")
    for table in ("quota_windows", "budget_windows"):
        op.execute(f"REVOKE UPDATE (reserved) ON arbiter.{table} FROM {ROLE}")
    op.execute(
        "REVOKE UPDATE (state,finished_at,outcome,release_audit_id) "
        "ON arbiter.requests FROM arbiter_release_writer"
    )
    op.execute(
        "REVOKE UPDATE (disposition,settlement_event_id) "
        "ON arbiter.reservations FROM arbiter_release_writer"
    )
    op.execute("REVOKE SELECT ON arbiter.provider_models FROM arbiter_release_writer")
    op.execute(f"REVOKE USAGE ON SCHEMA arbiter FROM {ROLE}")
    for table in ("requests", "reservations"):
        op.execute(f"DROP TRIGGER guard_release_terminal ON arbiter.{table}")
    op.execute("DROP FUNCTION arbiter.guard_release_terminal() RESTRICT")
    _snapshot(False)
    op.execute("""
        ALTER TABLE arbiter.requests DROP CONSTRAINT request_release_audit_fk,
            DROP CONSTRAINT request_release_link_state,
            DROP COLUMN release_audit_id,DROP COLUMN release_action
    """)
    _audit_check(False)
