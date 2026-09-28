"""Restricted, content-free post-dispatch finalization; committed charges stay fixed."""

from alembic import op

revision: str = "0015_terminal_lifecycle"
down_revision: str | None = "0014_dispatch_authorization"
branch_labels: str | None = None
depends_on: str | None = None

ROLE = "arbiter_terminal_writer"
FUNCTION = "arbiter.finalize_dispatched(uuid,uuid,uuid,text,text,bigint,bigint)"
SCOPE = "tenant_id=NULLIF(current_setting('arbiter.tenant_id',true),'')::uuid"


def _audit_check(terminal: bool) -> None:
    actions = "'request_reserved','request_released','request_dispatched'"
    if terminal:
        actions += ",'request_finalized'"
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


def upgrade() -> None:
    _audit_check(True)
    op.execute("""
        ALTER TABLE arbiter.requests
            ADD COLUMN terminal_audit_id uuid,
            ADD COLUMN terminal_action varchar(64) NOT NULL DEFAULT 'request_finalized'
                CHECK (terminal_action='request_finalized'),
            ADD CONSTRAINT request_terminal_audit_fk FOREIGN KEY
                (tenant_id,terminal_audit_id,id,key_id,policy_revision,terminal_action,
                    audit_outcome)
                REFERENCES arbiter.audit_events
                (tenant_id,id,target_id,actor_api_key_id,policy_revision,action,outcome)
                DEFERRABLE INITIALLY DEFERRED,
            ADD CONSTRAINT request_terminal_link_state CHECK (terminal_audit_id IS NULL OR
                (state IN ('succeeded','failed','unknown') AND dispatched_at IS NOT NULL
                    AND dispatch_audit_id IS NOT NULL AND release_audit_id IS NULL))
    """)
    # The existing immutable-snapshot trigger compares every other column, including
    # the new audit ID, so explicitly permit only the first dispatched transition.
    op.execute("""
        CREATE OR REPLACE FUNCTION arbiter.immutable_request_snapshot() RETURNS trigger
        LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog AS $$
        BEGIN
            IF (to_jsonb(NEW)-ARRAY['reserve_kind','state','dispatched_at','finished_at',
                'outcome','input_tokens','output_tokens','release_audit_id',
                'dispatch_audit_id','terminal_audit_id']) IS DISTINCT FROM
                (to_jsonb(OLD)-ARRAY['reserve_kind','state','dispatched_at','finished_at',
                'outcome','input_tokens','output_tokens','release_audit_id',
                'dispatch_audit_id','terminal_audit_id']) THEN
                RAISE EXCEPTION 'immutable request snapshot' USING ERRCODE='23514';
            END IF;
            IF NEW.release_audit_id IS DISTINCT FROM OLD.release_audit_id AND
                NOT (OLD.release_audit_id IS NULL AND OLD.state='reserved'
                    AND OLD.dispatched_at IS NULL AND NEW.release_audit_id IS NOT NULL
                    AND NEW.state IN ('released','rejected_capacity')) THEN
                RAISE EXCEPTION 'immutable release evidence' USING ERRCODE='23514';
            END IF;
            IF NEW.dispatch_audit_id IS DISTINCT FROM OLD.dispatch_audit_id AND
                NOT (OLD.dispatch_audit_id IS NULL AND OLD.state='reserved'
                    AND OLD.dispatched_at IS NULL AND NEW.dispatch_audit_id IS NOT NULL
                    AND NEW.state='dispatched' AND NEW.dispatched_at IS NOT NULL) THEN
                RAISE EXCEPTION 'immutable dispatch evidence' USING ERRCODE='23514';
            END IF;
            IF NEW.terminal_audit_id IS DISTINCT FROM OLD.terminal_audit_id AND
                NOT (OLD.terminal_audit_id IS NULL AND OLD.state='dispatched'
                    AND OLD.dispatch_audit_id IS NOT NULL AND NEW.terminal_audit_id IS NOT NULL
                    AND NEW.state IN ('succeeded','failed','unknown')) THEN
                RAISE EXCEPTION 'immutable terminal evidence' USING ERRCODE='23514';
            END IF;
            RETURN NEW;
        END $$
    """)
    op.execute("""
        CREATE FUNCTION arbiter.guard_terminal_state() RETURNS trigger
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
    op.execute("REVOKE ALL ON FUNCTION arbiter.guard_terminal_state() FROM PUBLIC")
    op.execute("""
        CREATE TRIGGER guard_terminal_state BEFORE UPDATE ON arbiter.requests
        FOR EACH ROW EXECUTE FUNCTION arbiter.guard_terminal_state()
    """)
    op.execute(f"GRANT USAGE ON SCHEMA arbiter TO {ROLE}")
    for table in ("requests", "reservations", "audit_events"):
        check = SCOPE
        if table == "requests":
            check += (
                " AND state IN ('succeeded','failed','unknown') AND terminal_audit_id IS NOT NULL"
            )
        elif table == "audit_events":
            check += " AND actor_type='api_key' AND action='request_finalized'"
        op.execute(f"""
            CREATE POLICY terminal_writer_scope ON arbiter.{table} AS RESTRICTIVE TO {ROLE}
            USING ({SCOPE}) WITH CHECK ({check})
        """)
        op.execute(f"""
            CREATE POLICY terminal_writer_access ON arbiter.{table} TO {ROLE}
            USING (true) WITH CHECK (true)
        """)
        op.execute(f"GRANT SELECT ON arbiter.{table} TO {ROLE}")
    op.execute(f"""
        GRANT UPDATE (state,finished_at,outcome,input_tokens,output_tokens,terminal_audit_id)
            ON arbiter.requests TO {ROLE};
        GRANT INSERT ON arbiter.audit_events TO {ROLE}
    """)
    op.execute("""
        CREATE FUNCTION arbiter.finalize_dispatched(p_tenant uuid,p_key uuid,p_request uuid,
            p_state text,p_outcome text,p_input bigint,p_output bigint)
        RETURNS TABLE (request_id uuid,changed boolean)
        LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog AS $$
        DECLARE v_request arbiter.requests%ROWTYPE; v_now timestamptz; v_audit uuid;
        BEGIN
            IF session_user<>'arbiter_runtime' OR p_tenant IS NULL OR p_tenant IS DISTINCT FROM
                NULLIF(current_setting('arbiter.tenant_id',true),'')::uuid THEN
                RAISE EXCEPTION 'permission denied' USING ERRCODE='42501';
            END IF;
            IF p_key IS NULL OR p_request IS NULL THEN
                RAISE EXCEPTION 'request unavailable' USING ERRCODE='TL001';
            END IF;
            IF NOT ((p_state='succeeded' AND p_outcome='succeeded') OR
                (p_state='failed' AND p_outcome='provider_failure') OR
                (p_state='unknown' AND p_outcome='unknown')) OR
                p_input<0 OR p_output<0 THEN
                RAISE EXCEPTION 'invalid terminal outcome' USING ERRCODE='22023';
            END IF;
            SELECT r.* INTO v_request FROM arbiter.requests r
                WHERE r.tenant_id=p_tenant AND r.id=p_request AND r.key_id=p_key FOR UPDATE;
            IF NOT FOUND THEN
                RAISE EXCEPTION 'request unavailable' USING ERRCODE='TL001';
            END IF;
            IF v_request.state IN ('succeeded','failed','unknown') AND
                v_request.terminal_audit_id IS NOT NULL AND v_request.state=p_state AND
                v_request.outcome=p_outcome AND
                v_request.input_tokens IS NOT DISTINCT FROM p_input AND
                v_request.output_tokens IS NOT DISTINCT FROM p_output THEN
                RETURN QUERY SELECT p_request,false; RETURN;
            END IF;
            IF v_request.state<>'dispatched' OR v_request.dispatch_audit_id IS NULL OR
                v_request.dispatched_at IS NULL OR v_request.terminal_audit_id IS NOT NULL OR
                p_output>v_request.output_cap OR NOT EXISTS (
                    SELECT 1 FROM arbiter.reservations s WHERE s.tenant_id=p_tenant
                        AND s.id=v_request.reservation_id AND s.request_id=p_request
                        AND s.disposition='committed' AND s.settlement_event_id IS NOT NULL) THEN
                RAISE EXCEPTION 'request not dispatchable' USING ERRCODE='TL002';
            END IF;
            v_now:=clock_timestamp(); v_audit:=gen_random_uuid();
            UPDATE arbiter.requests SET state=p_state,outcome=p_outcome,
                finished_at=CASE WHEN p_state='unknown' THEN NULL ELSE v_now END,
                input_tokens=p_input,output_tokens=p_output,terminal_audit_id=v_audit
                WHERE tenant_id=p_tenant AND id=p_request AND state='dispatched';
            IF NOT FOUND THEN
                RAISE EXCEPTION 'request not dispatchable' USING ERRCODE='TL002';
            END IF;
            INSERT INTO arbiter.audit_events
                (id,tenant_id,actor_type,actor_reference,actor_api_key_id,action,target_id,
                    policy_revision,request_id,occurred_at,outcome)
                VALUES (v_audit,p_tenant,'api_key',p_key::text,p_key,'request_finalized',p_request,
                    v_request.policy_revision,p_request,v_now,'succeeded');
            RETURN QUERY SELECT p_request,true;
        END $$
    """)
    op.execute(f"REVOKE ALL ON FUNCTION {FUNCTION} FROM PUBLIC")
    op.execute(f"GRANT EXECUTE ON FUNCTION {FUNCTION} TO arbiter_runtime")
    op.execute(f"GRANT CREATE ON SCHEMA arbiter TO {ROLE}")
    op.execute(f"ALTER FUNCTION {FUNCTION} OWNER TO {ROLE}")
    op.execute(f"REVOKE CREATE ON SCHEMA arbiter FROM {ROLE}")


def downgrade() -> None:
    # A table CHECK scans all rows even when migration RLS has no tenant context.
    op.execute("""
        ALTER TABLE arbiter.audit_events ADD CONSTRAINT terminal_downgrade_guard
        CHECK (action<>'request_finalized')
    """)
    op.execute("ALTER TABLE arbiter.audit_events DROP CONSTRAINT terminal_downgrade_guard")
    op.execute(f"DROP FUNCTION {FUNCTION} RESTRICT")
    for table in ("requests", "reservations", "audit_events"):
        op.execute(f"DROP POLICY terminal_writer_access ON arbiter.{table}")
        op.execute(f"DROP POLICY terminal_writer_scope ON arbiter.{table}")
        op.execute(f"REVOKE ALL ON arbiter.{table} FROM {ROLE}")
    op.execute("""
        REVOKE UPDATE (state,finished_at,outcome,input_tokens,output_tokens,terminal_audit_id)
            ON arbiter.requests FROM arbiter_terminal_writer
    """)
    op.execute(f"REVOKE USAGE ON SCHEMA arbiter FROM {ROLE}")
    op.execute("DROP TRIGGER guard_terminal_state ON arbiter.requests")
    op.execute("DROP FUNCTION arbiter.guard_terminal_state() RESTRICT")
    op.execute("""
        ALTER TABLE arbiter.requests DROP CONSTRAINT request_terminal_audit_fk,
            DROP CONSTRAINT request_terminal_link_state,
            DROP COLUMN terminal_audit_id,DROP COLUMN terminal_action
    """)
    # Restore the exact prior trigger while its terminal-only column is absent.
    op.execute("""
        CREATE OR REPLACE FUNCTION arbiter.immutable_request_snapshot() RETURNS trigger
        LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog AS $$
        BEGIN
            IF (to_jsonb(NEW)-ARRAY['reserve_kind','state','dispatched_at','finished_at',
                'outcome','input_tokens','output_tokens','release_audit_id',
                'dispatch_audit_id']) IS DISTINCT FROM
                (to_jsonb(OLD)-ARRAY['reserve_kind','state','dispatched_at','finished_at',
                'outcome','input_tokens','output_tokens','release_audit_id',
                'dispatch_audit_id']) THEN
                RAISE EXCEPTION 'immutable request snapshot' USING ERRCODE='23514';
            END IF;
            IF NEW.release_audit_id IS DISTINCT FROM OLD.release_audit_id AND
                NOT (OLD.release_audit_id IS NULL AND OLD.state='reserved'
                    AND OLD.dispatched_at IS NULL AND NEW.release_audit_id IS NOT NULL
                    AND NEW.state IN ('released','rejected_capacity')) THEN
                RAISE EXCEPTION 'immutable release evidence' USING ERRCODE='23514';
            END IF;
            IF NEW.dispatch_audit_id IS DISTINCT FROM OLD.dispatch_audit_id AND
                NOT (OLD.dispatch_audit_id IS NULL AND OLD.state='reserved'
                    AND OLD.dispatched_at IS NULL AND NEW.dispatch_audit_id IS NOT NULL
                    AND NEW.state='dispatched' AND NEW.dispatched_at IS NOT NULL) THEN
                RAISE EXCEPTION 'immutable dispatch evidence' USING ERRCODE='23514';
            END IF;
            RETURN NEW;
        END $$
    """)
    _audit_check(False)
