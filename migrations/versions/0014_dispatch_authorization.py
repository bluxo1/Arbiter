"""Restricted, auditable dispatch marker; no provider or terminal writer."""

from alembic import op

revision: str = "0014_dispatch_authorization"
down_revision: str | None = "0013_undispatched_release"
branch_labels: str | None = None
depends_on: str | None = None

ROLE = "arbiter_dispatch_writer"
FUNCTION = "arbiter.authorize_dispatch(uuid,uuid,uuid)"
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


def _audit_check(dispatch: bool) -> None:
    actions = "'request_reserved','request_released'"
    if dispatch:
        actions += ",'request_dispatched'"
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


def _snapshot(dispatch: bool) -> None:
    columns = (
        "'reserve_kind','state','dispatched_at','finished_at','outcome',"
        "'input_tokens','output_tokens','release_audit_id'"
    )
    dispatch_guard = ""
    if dispatch:
        columns += ",'dispatch_audit_id'"
        dispatch_guard = """
            IF NEW.dispatch_audit_id IS DISTINCT FROM OLD.dispatch_audit_id AND
                NOT (OLD.dispatch_audit_id IS NULL AND OLD.state='reserved'
                    AND OLD.dispatched_at IS NULL AND NEW.dispatch_audit_id IS NOT NULL
                    AND NEW.state='dispatched' AND NEW.dispatched_at IS NOT NULL) THEN
                RAISE EXCEPTION 'immutable dispatch evidence' USING ERRCODE='23514';
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
            IF NEW.release_audit_id IS DISTINCT FROM OLD.release_audit_id AND
                NOT (OLD.release_audit_id IS NULL AND OLD.state='reserved'
                    AND OLD.dispatched_at IS NULL AND NEW.release_audit_id IS NOT NULL
                    AND NEW.state IN ('released','rejected_capacity')) THEN
                RAISE EXCEPTION 'immutable release evidence' USING ERRCODE='23514';
            END IF;
            {dispatch_guard}
            RETURN NEW;
        END $$
    """)


def upgrade() -> None:
    _audit_check(True)
    op.execute("""
        ALTER TABLE arbiter.requests
            ADD COLUMN dispatch_audit_id uuid,
            ADD COLUMN dispatch_action varchar(64) NOT NULL DEFAULT 'request_dispatched'
                CHECK (dispatch_action='request_dispatched'),
            ADD CONSTRAINT request_dispatch_audit_fk FOREIGN KEY
                (tenant_id,dispatch_audit_id,id,key_id,policy_revision,dispatch_action,
                    audit_outcome)
                REFERENCES arbiter.audit_events
                (tenant_id,id,target_id,actor_api_key_id,policy_revision,action,outcome)
                DEFERRABLE INITIALLY DEFERRED,
            ADD CONSTRAINT request_dispatch_link_state CHECK (dispatch_audit_id IS NULL OR
                (state IN ('dispatched','succeeded','failed','unknown')
                    AND dispatched_at IS NOT NULL AND release_audit_id IS NULL))
    """)
    _snapshot(True)
    op.execute(f"GRANT USAGE ON SCHEMA arbiter TO {ROLE}")
    for table in TABLES:
        check = SCOPE
        if table == "requests":
            check += " AND state='dispatched' AND dispatch_audit_id IS NOT NULL"
        elif table == "reservations":
            check += " AND disposition='committed' AND settlement_event_id IS NOT NULL"
        elif table == "accounting_events":
            check += " AND kind='commit'"
        elif table == "audit_events":
            check += " AND actor_type='api_key' AND action='request_dispatched'"
        op.execute(f"""
            CREATE POLICY dispatch_writer_scope ON arbiter.{table} AS RESTRICTIVE TO {ROLE}
            USING ({SCOPE}) WITH CHECK ({check})
        """)
        op.execute(f"""
            CREATE POLICY dispatch_writer_access ON arbiter.{table} TO {ROLE}
            USING (true) WITH CHECK (true)
        """)
        op.execute(f"GRANT SELECT ON arbiter.{table} TO {ROLE}")
    for table in ("tenants", "api_keys", "tenant_policies", "provider_models"):
        op.execute(f"GRANT UPDATE (id) ON arbiter.{table} TO {ROLE}")
    op.execute(f"GRANT SELECT ON arbiter.provider_models TO {ROLE}")
    op.execute("""
        GRANT UPDATE (committed,reserved) ON arbiter.quota_windows,arbiter.budget_windows
        TO arbiter_dispatch_writer
    """)
    op.execute(f"""
        GRANT UPDATE (state,dispatched_at,dispatch_audit_id) ON arbiter.requests TO {ROLE};
        GRANT UPDATE (disposition,settlement_event_id) ON arbiter.reservations TO {ROLE};
        GRANT INSERT ON arbiter.accounting_events,arbiter.audit_events TO {ROLE}
    """)
    op.execute("""
        CREATE FUNCTION arbiter.authorize_dispatch(p_tenant uuid,p_key uuid,p_request uuid)
        RETURNS TABLE (request_id uuid,decision text)
        LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog AS $$
        DECLARE
            v_tenant arbiter.tenants%ROWTYPE; v_key arbiter.api_keys%ROWTYPE;
            v_policy arbiter.tenant_policies%ROWTYPE; v_request arbiter.requests%ROWTYPE;
            v_quota arbiter.quota_windows%ROWTYPE; v_budget arbiter.budget_windows%ROWTYPE;
            v_reservation arbiter.reservations%ROWTYPE; v_model arbiter.provider_models%ROWTYPE;
            v_now timestamptz; v_event uuid; v_audit uuid;
        BEGIN
            IF session_user<>'arbiter_runtime' OR p_tenant IS NULL OR p_tenant IS DISTINCT FROM
                NULLIF(current_setting('arbiter.tenant_id',true),'')::uuid THEN
                RAISE EXCEPTION 'permission denied' USING ERRCODE='42501';
            END IF;
            IF p_key IS NULL OR p_request IS NULL THEN
                RAISE EXCEPTION 'request unavailable' USING ERRCODE='DA001';
            END IF;
            SELECT t.* INTO v_tenant FROM arbiter.tenants t
                WHERE t.tenant_id=p_tenant AND t.id=p_tenant FOR UPDATE;
            IF NOT FOUND THEN RAISE EXCEPTION 'request unavailable' USING ERRCODE='DA001'; END IF;
            SELECT k.* INTO v_key FROM arbiter.api_keys k
                WHERE k.tenant_id=p_tenant AND k.id=p_key FOR UPDATE;
            IF NOT FOUND THEN RAISE EXCEPTION 'request unavailable' USING ERRCODE='DA001'; END IF;
            SELECT p.* INTO v_policy FROM arbiter.tenant_policies p
                WHERE p.tenant_id=p_tenant AND p.revision=v_tenant.policy_revision FOR SHARE;
            IF NOT FOUND THEN RAISE EXCEPTION 'policy unavailable' USING ERRCODE='DA003'; END IF;
            -- Read immutable window IDs under the tenant admission lock, then lock in order.
            SELECT r.* INTO v_request FROM arbiter.requests r
                WHERE r.tenant_id=p_tenant AND r.id=p_request AND r.key_id=p_key;
            IF NOT FOUND THEN RAISE EXCEPTION 'request unavailable' USING ERRCODE='DA001'; END IF;
            SELECT q.* INTO v_quota FROM arbiter.quota_windows q
                WHERE q.tenant_id=p_tenant AND q.id=v_request.quota_window_id FOR UPDATE;
            IF NOT FOUND THEN RAISE EXCEPTION 'quota unavailable' USING ERRCODE='DA003'; END IF;
            SELECT b.* INTO v_budget FROM arbiter.budget_windows b
                WHERE b.tenant_id=p_tenant AND b.id=v_request.budget_window_id FOR UPDATE;
            IF NOT FOUND THEN RAISE EXCEPTION 'budget unavailable' USING ERRCODE='DA003'; END IF;
            SELECT r.* INTO v_request FROM arbiter.requests r
                WHERE r.tenant_id=p_tenant AND r.id=p_request AND r.key_id=p_key FOR UPDATE;
            IF NOT FOUND THEN RAISE EXCEPTION 'request unavailable' USING ERRCODE='DA001'; END IF;
            SELECT s.* INTO v_reservation FROM arbiter.reservations s
                WHERE s.tenant_id=p_tenant AND s.id=v_request.reservation_id
                    AND s.request_id=p_request FOR UPDATE;
            IF NOT FOUND THEN
                RAISE EXCEPTION 'reservation unavailable' USING ERRCODE='DA003';
            END IF;
            -- Registry-only writers never later acquire a tenant lock.
            SELECT m.* INTO v_model FROM arbiter.provider_models m
                WHERE m.id=v_request.model_id FOR SHARE;
            IF NOT FOUND THEN RAISE EXCEPTION 'model unavailable' USING ERRCODE='DA003'; END IF;
            IF v_request.state<>'reserved' OR v_request.dispatched_at IS NOT NULL OR
                v_reservation.disposition<>'reserved' OR
                v_reservation.settlement_event_id IS NOT NULL THEN
                RAISE EXCEPTION 'request not reserved' USING ERRCODE='DA002';
            END IF;
            v_now:=clock_timestamp();
            IF v_tenant.status<>'active' OR v_key.revoked_at IS NOT NULL OR
                v_key.expires_at<=v_now OR NOT ('inference:write'=ANY(v_key.scopes)) OR
                v_request.policy_revision<>v_policy.revision OR
                NOT (v_request.model_alias=ANY(v_policy.model_aliases)) OR
                NOT v_model.active OR v_model.revision<>v_request.model_revision OR
                v_model.alias<>v_request.model_alias THEN
                RETURN QUERY SELECT p_request,'authorization_changed'::text; RETURN;
            END IF;
            IF v_request.quota_start<>
                date_trunc('day',v_now AT TIME ZONE 'UTC') AT TIME ZONE 'UTC' OR
                v_request.budget_start<>
                date_trunc('month',v_now AT TIME ZONE 'UTC') AT TIME ZONE 'UTC' THEN
                RETURN QUERY SELECT p_request,'admission_window_changed'::text; RETURN;
            END IF;
            IF v_quota.reserved<v_reservation.request_count OR
                v_budget.reserved<v_reservation.credits OR
                v_reservation.request_count<>v_request.request_count OR
                v_reservation.credits<>v_request.credit_charge OR
                v_quota.window_start<>v_request.quota_start OR
                v_budget.window_start<>v_request.budget_start THEN
                RAISE EXCEPTION 'accounting unavailable' USING ERRCODE='DA003';
            END IF;
            v_now:=clock_timestamp();
            IF v_key.expires_at<=v_now THEN
                RETURN QUERY SELECT p_request,'authorization_changed'::text; RETURN;
            END IF;
            IF v_request.quota_start<>
                date_trunc('day',v_now AT TIME ZONE 'UTC') AT TIME ZONE 'UTC' OR
                v_request.budget_start<>
                date_trunc('month',v_now AT TIME ZONE 'UTC') AT TIME ZONE 'UTC' THEN
                RETURN QUERY SELECT p_request,'admission_window_changed'::text; RETURN;
            END IF;
            v_event:=gen_random_uuid(); v_audit:=gen_random_uuid();
            UPDATE arbiter.quota_windows SET reserved=reserved-v_reservation.request_count,
                committed=committed+v_reservation.request_count
                WHERE tenant_id=p_tenant AND id=v_quota.id;
            UPDATE arbiter.budget_windows SET reserved=reserved-v_reservation.credits,
                committed=committed+v_reservation.credits
                WHERE tenant_id=p_tenant AND id=v_budget.id;
            UPDATE arbiter.requests SET state='dispatched',dispatched_at=v_now,
                dispatch_audit_id=v_audit WHERE tenant_id=p_tenant AND id=p_request
                    AND state='reserved' AND dispatched_at IS NULL;
            IF NOT FOUND THEN RAISE EXCEPTION 'request not reserved' USING ERRCODE='DA002'; END IF;
            UPDATE arbiter.reservations SET disposition='committed',settlement_event_id=v_event
                WHERE tenant_id=p_tenant AND id=v_reservation.id AND disposition='reserved';
            IF NOT FOUND THEN RAISE EXCEPTION 'request not reserved' USING ERRCODE='DA002'; END IF;
            INSERT INTO arbiter.accounting_events
                (id,tenant_id,request_id,reservation_id,quota_window_id,budget_window_id,
                    request_count,credits,kind,occurred_at)
                VALUES (v_event,p_tenant,p_request,v_reservation.id,v_quota.id,v_budget.id,
                    v_reservation.request_count,v_reservation.credits,'commit',v_now);
            INSERT INTO arbiter.audit_events
                (id,tenant_id,actor_type,actor_reference,actor_api_key_id,action,target_id,
                    policy_revision,request_id,occurred_at,outcome)
                VALUES (v_audit,p_tenant,'api_key',p_key::text,p_key,'request_dispatched',p_request,
                    v_request.policy_revision,p_request,v_now,'succeeded');
            RETURN QUERY SELECT p_request,'authorized'::text;
        END $$
    """)
    op.execute(f"REVOKE ALL ON FUNCTION {FUNCTION} FROM PUBLIC")
    op.execute(f"GRANT EXECUTE ON FUNCTION {FUNCTION} TO arbiter_runtime")
    op.execute(f"GRANT CREATE ON SCHEMA arbiter TO {ROLE}")
    op.execute(f"ALTER FUNCTION {FUNCTION} OWNER TO {ROLE}")
    op.execute(f"REVOKE CREATE ON SCHEMA arbiter FROM {ROLE}")


def downgrade() -> None:
    # Reject any accepted dispatch evidence, including context-hidden rows.
    op.execute("""
        ALTER TABLE arbiter.audit_events ADD CONSTRAINT dispatch_downgrade_guard
        CHECK (action<>'request_dispatched')
    """)
    op.execute("ALTER TABLE arbiter.audit_events DROP CONSTRAINT dispatch_downgrade_guard")
    op.execute(f"DROP FUNCTION {FUNCTION} RESTRICT")
    for table in TABLES:
        op.execute(f"DROP POLICY dispatch_writer_access ON arbiter.{table}")
        op.execute(f"DROP POLICY dispatch_writer_scope ON arbiter.{table}")
        op.execute(f"REVOKE ALL ON arbiter.{table} FROM {ROLE}")
    for table in ("tenants", "api_keys", "tenant_policies", "provider_models"):
        op.execute(f"REVOKE UPDATE (id) ON arbiter.{table} FROM {ROLE}")
    op.execute("""
        REVOKE UPDATE (committed,reserved) ON arbiter.quota_windows,arbiter.budget_windows
        FROM arbiter_dispatch_writer
    """)
    op.execute(
        f"REVOKE UPDATE (state,dispatched_at,dispatch_audit_id) ON arbiter.requests FROM {ROLE}"
    )
    op.execute(
        f"REVOKE UPDATE (disposition,settlement_event_id) ON arbiter.reservations FROM {ROLE}"
    )
    op.execute("REVOKE SELECT ON arbiter.provider_models FROM arbiter_dispatch_writer")
    op.execute(f"REVOKE USAGE ON SCHEMA arbiter FROM {ROLE}")
    _snapshot(False)
    op.execute("""
        ALTER TABLE arbiter.requests DROP CONSTRAINT request_dispatch_audit_fk,
            DROP CONSTRAINT request_dispatch_link_state,
            DROP COLUMN dispatch_audit_id,DROP COLUMN dispatch_action
    """)
    _audit_check(False)
