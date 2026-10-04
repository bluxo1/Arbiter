"""Privileged terminal graph retirement with atomic scoped idempotency tombstones."""

from alembic import op

revision: str = "0020_request_retention"
down_revision: str | None = "0019_reserved_provider_binding"
branch_labels: str | None = None
depends_on: str | None = None

ROLE = "arbiter_retention_writer"
SCOPE = "tenant_id=NULLIF(current_setting('arbiter.tenant_id',true),'')::uuid"
SIGNATURE = "uuid,uuid,text,bytea,integer,text,bytea,integer,text,integer"
GRAPH = (
    "capacity_clearances",
    "dispatched_provider_bindings",
    "audit_events",
    "accounting_events",
    "reservations",
    "requests",
)


def upgrade() -> None:
    op.execute("""
        CREATE TABLE arbiter.idempotency_tombstones (
            tenant_id uuid NOT NULL REFERENCES arbiter.tenants(id),
            key_id uuid NOT NULL,
            idempotency_key varchar(128) NOT NULL CHECK (idempotency_key ~ '^[ -~]{16,128}$'),
            request_id uuid PRIMARY KEY,
            payload_hmac bytea NOT NULL CHECK (octet_length(payload_hmac)=32),
            fingerprint_version integer NOT NULL CHECK (fingerprint_version>0),
            state varchar(24) NOT NULL CHECK (
                state IN ('succeeded','failed','released','rejected_capacity')),
            tombstoned_at timestamptz NOT NULL DEFAULT clock_timestamp()
                CHECK (isfinite(tombstoned_at)),
            UNIQUE (tenant_id,request_id), UNIQUE (tenant_id,key_id,idempotency_key),
            FOREIGN KEY (tenant_id,key_id) REFERENCES arbiter.api_keys(tenant_id,id)
        )
    """)
    op.execute("ALTER TABLE arbiter.idempotency_tombstones ENABLE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE arbiter.idempotency_tombstones FORCE ROW LEVEL SECURITY")
    op.execute("""
        CREATE INDEX request_retention_idx ON arbiter.requests(tenant_id,key_id,finished_at,id)
            WHERE state IN ('succeeded','failed','released','rejected_capacity')
    """)
    for role in (
        "arbiter_runtime",
        "arbiter_operator",
        "arbiter_migration",
        "arbiter_reservation_writer",
        ROLE,
    ):
        op.execute(f"""
            CREATE POLICY tombstone_{role}_scope ON arbiter.idempotency_tombstones
                AS RESTRICTIVE TO {role} USING ({SCOPE}) WITH CHECK ({SCOPE})
        """)
        op.execute(f"""
            CREATE POLICY tombstone_{role}_access ON arbiter.idempotency_tombstones
                TO {role} USING (true) WITH CHECK (true)
        """)
    op.execute("REVOKE ALL ON arbiter.idempotency_tombstones FROM PUBLIC")
    op.execute(f"GRANT USAGE ON SCHEMA arbiter TO {ROLE}")
    op.execute("""
        GRANT SELECT ON arbiter.idempotency_tombstones
            TO arbiter_runtime,arbiter_operator,arbiter_reservation_writer
    """)
    op.execute(f"GRANT SELECT,INSERT,DELETE ON arbiter.idempotency_tombstones TO {ROLE}")
    for table in (*GRAPH, "tenants", "api_keys"):
        op.execute(f"""
            CREATE POLICY retention_scope ON arbiter.{table} AS RESTRICTIVE TO {ROLE}
                USING ({SCOPE}) WITH CHECK ({SCOPE})
        """)
        op.execute(f"""
            CREATE POLICY retention_access ON arbiter.{table} TO {ROLE}
                USING (true) WITH CHECK ({SCOPE})
        """)
        op.execute(f"GRANT SELECT ON arbiter.{table} TO {ROLE}")
    for table in GRAPH:
        op.execute(f"GRANT DELETE ON arbiter.{table} TO {ROLE}")
    for table in ("tenants", "api_keys", "requests"):
        # PostgreSQL requires an UPDATE grant for SELECT FOR UPDATE; no values are updated.
        op.execute(f"GRANT UPDATE (id) ON arbiter.{table} TO {ROLE}")
    op.execute(f"GRANT INSERT ON arbiter.audit_events TO {ROLE}")
    op.execute("ALTER TABLE arbiter.audit_events ADD COLUMN retention_summary jsonb")
    op.execute("""
        CREATE FUNCTION arbiter.guard_retention_audit() RETURNS trigger
        LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog AS $$
        BEGIN
            IF NEW.action='retention_cleaned' OR NEW.retention_summary IS NOT NULL THEN
                IF TG_OP<>'INSERT' OR current_user<>'arbiter_retention_writer' OR
                    session_user<>'arbiter_operator' OR NEW.actor_type<>'operator' OR
                    NEW.actor_reference<>'arbiter_operator' OR NEW.action<>'retention_cleaned'
                    OR NEW.outcome<>'succeeded' OR NEW.retention_summary IS NULL OR
                    NEW.request_id IS DISTINCT FROM NEW.target_id THEN
                    RAISE EXCEPTION 'invalid retention audit' USING ERRCODE='42501';
                END IF;
            END IF;
            RETURN NEW;
        END $$
    """)
    op.execute("REVOKE ALL ON FUNCTION arbiter.guard_retention_audit() FROM PUBLIC")
    op.execute("""
        CREATE TRIGGER retention_audit_guard BEFORE INSERT OR UPDATE ON arbiter.audit_events
            FOR EACH ROW EXECUTE FUNCTION arbiter.guard_retention_audit()
    """)
    op.execute("""
        CREATE FUNCTION arbiter.guard_retention_delete() RETURNS trigger
        LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog AS $$
        DECLARE v_request arbiter.requests%ROWTYPE; v_id uuid;
        BEGIN
            IF TG_OP<>'DELETE' OR current_user<>'arbiter_retention_writer' OR
                session_user<>'arbiter_operator' OR OLD.tenant_id IS DISTINCT FROM
                    NULLIF(current_setting('arbiter.tenant_id',true),'')::uuid THEN
                RAISE EXCEPTION 'retention deletion only' USING ERRCODE='42501';
            END IF;
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
    """)
    op.execute("REVOKE ALL ON FUNCTION arbiter.guard_retention_delete() FROM PUBLIC")
    for table in GRAPH:
        if table != "accounting_events":
            op.execute(f"""
                CREATE TRIGGER retention_delete_guard BEFORE DELETE ON arbiter.{table}
                    FOR EACH ROW EXECUTE FUNCTION arbiter.guard_retention_delete()
            """)
    # The existing accounting trigger retains its unconditional UPDATE/TRUNCATE denial.
    op.execute("""
        CREATE OR REPLACE FUNCTION arbiter.immutable_accounting() RETURNS trigger
        LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog AS $$
        BEGIN
            IF TG_OP='DELETE' AND current_user='arbiter_retention_writer' AND
                session_user='arbiter_operator' THEN RETURN OLD; END IF;
            RAISE EXCEPTION 'immutable accounting evidence' USING ERRCODE='42501';
        END $$
    """)
    op.execute("""
        CREATE TRIGGER retention_delete_guard BEFORE DELETE ON arbiter.accounting_events
            FOR EACH ROW EXECUTE FUNCTION arbiter.guard_retention_delete()
    """)
    op.execute("""
        CREATE FUNCTION arbiter.guard_tombstone() RETURNS trigger
        LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog AS $$
        BEGIN
            IF TG_OP NOT IN ('INSERT','DELETE') OR current_user<>'arbiter_retention_writer'
                OR session_user<>'arbiter_operator' THEN
                RAISE EXCEPTION 'immutable retention tombstone' USING ERRCODE='42501';
            END IF;
            IF TG_OP='INSERT' THEN
                IF NOT EXISTS (SELECT 1 FROM arbiter.requests r WHERE r.tenant_id=NEW.tenant_id
                    AND r.id=NEW.request_id AND r.key_id=NEW.key_id
                    AND r.idempotency_key=NEW.idempotency_key AND r.payload_hmac=NEW.payload_hmac
                    AND r.fingerprint_version=NEW.fingerprint_version AND r.state=NEW.state
                    AND r.state IN ('succeeded','failed','released','rejected_capacity')
                    AND r.finished_at<=clock_timestamp()-interval '90 days') THEN
                    RAISE EXCEPTION 'invalid retirement snapshot' USING ERRCODE='23514';
                END IF;
                RETURN NEW;
            END IF;
            IF NOT EXISTS (SELECT 1 FROM arbiter.api_keys k WHERE k.tenant_id=OLD.tenant_id
                AND k.id=OLD.key_id AND k.revoked_at<=clock_timestamp()-interval '90 days') THEN
                RAISE EXCEPTION 'tombstone still required' USING ERRCODE='23514';
            END IF;
            RETURN OLD;
        END $$
    """)
    op.execute("REVOKE ALL ON FUNCTION arbiter.guard_tombstone() FROM PUBLIC")
    op.execute("""
        CREATE TRIGGER tombstone_guard BEFORE INSERT OR UPDATE OR DELETE
            ON arbiter.idempotency_tombstones FOR EACH ROW
            EXECUTE FUNCTION arbiter.guard_tombstone();
        CREATE TRIGGER tombstone_truncate_guard BEFORE TRUNCATE
            ON arbiter.idempotency_tombstones FOR EACH STATEMENT
            EXECUTE FUNCTION arbiter.guard_tombstone()
    """)
    op.execute("""
        CREATE FUNCTION arbiter.reject_retired_request() RETURNS trigger
        LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog AS $$
        BEGIN
            IF EXISTS (SELECT 1 FROM arbiter.idempotency_tombstones t
                WHERE t.tenant_id=NEW.tenant_id AND (t.request_id=NEW.id OR
                    (t.key_id=NEW.key_id AND t.idempotency_key=NEW.idempotency_key))) THEN
                RAISE EXCEPTION 'request already retired' USING ERRCODE='23505';
            END IF;
            RETURN NEW;
        END $$
    """)
    op.execute("REVOKE ALL ON FUNCTION arbiter.reject_retired_request() FROM PUBLIC")
    op.execute("""
        CREATE TRIGGER retired_request_guard BEFORE INSERT ON arbiter.requests
            FOR EACH ROW EXECUTE FUNCTION arbiter.reject_retired_request()
    """)
    _admission()
    op.execute("""
        CREATE FUNCTION arbiter.retire_requests(p_tenant uuid,p_key uuid,p_cutoff timestamptz,
            p_operation uuid,p_limit integer)
        RETURNS TABLE (requests_removed bigint,reservations_removed bigint,
            accounting_removed bigint,audits_removed bigint,bindings_removed bigint,
            clearances_removed bigint,tombstones_removed bigint,audit_id uuid)
        LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
        DECLARE v_request arbiter.requests%ROWTYPE; v_revision bigint; v_revoked timestamptz;
            v_count bigint; v_audit uuid; v_ids uuid[];
        BEGIN
            IF session_user<>'arbiter_operator' OR p_tenant IS NULL OR p_key IS NULL OR
                p_tenant IS DISTINCT FROM NULLIF(current_setting('arbiter.tenant_id',true),'')::uuid
                THEN RAISE EXCEPTION 'permission denied' USING ERRCODE='42501'; END IF;
            IF p_cutoff IS NULL OR NOT isfinite(p_cutoff) OR
                p_cutoff>statement_timestamp()-interval '90 days' OR
                p_operation IS NULL OR p_limit IS NULL OR p_limit NOT BETWEEN 1 AND 100 THEN
                RAISE EXCEPTION 'invalid retention batch' USING ERRCODE='22023';
            END IF;
            SELECT policy_revision INTO v_revision FROM arbiter.tenants
                WHERE tenant_id=p_tenant AND id=p_tenant FOR UPDATE;
            IF NOT FOUND THEN RAISE EXCEPTION 'tenant unavailable' USING ERRCODE='RT001'; END IF;
            SELECT revoked_at INTO v_revoked FROM arbiter.api_keys
                WHERE tenant_id=p_tenant AND id=p_key FOR UPDATE;
            IF NOT FOUND THEN RAISE EXCEPTION 'key unavailable' USING ERRCODE='RT001'; END IF;
            requests_removed:=0; reservations_removed:=0; accounting_removed:=0;
            audits_removed:=0; bindings_removed:=0; clearances_removed:=0; tombstones_removed:=0;
            FOR v_request IN SELECT r.* FROM arbiter.requests r
                WHERE r.tenant_id=p_tenant AND r.key_id=p_key AND r.finished_at<=p_cutoff
                    AND r.state IN ('succeeded','failed','released','rejected_capacity')
                ORDER BY r.finished_at,r.id LIMIT p_limit FOR UPDATE
            LOOP
                INSERT INTO arbiter.idempotency_tombstones
                    (tenant_id,key_id,idempotency_key,request_id,payload_hmac,fingerprint_version,state)
                VALUES (p_tenant,p_key,v_request.idempotency_key,v_request.id,
                    v_request.payload_hmac,v_request.fingerprint_version,v_request.state);
                DELETE FROM arbiter.capacity_clearances
                    WHERE tenant_id=p_tenant AND request_id=v_request.id;
                GET DIAGNOSTICS v_count=ROW_COUNT; clearances_removed:=clearances_removed+v_count;
                DELETE FROM arbiter.dispatched_provider_bindings
                    WHERE tenant_id=p_tenant AND request_id=v_request.id;
                GET DIAGNOSTICS v_count=ROW_COUNT; bindings_removed:=bindings_removed+v_count;
                DELETE FROM arbiter.audit_events WHERE tenant_id=p_tenant AND id=ANY(ARRAY[
                    v_request.reservation_audit_id,v_request.release_audit_id,
                    v_request.dispatch_audit_id,v_request.terminal_audit_id]);
                GET DIAGNOSTICS v_count=ROW_COUNT; audits_removed:=audits_removed+v_count;
                DELETE FROM arbiter.accounting_events
                    WHERE tenant_id=p_tenant AND request_id=v_request.id;
                GET DIAGNOSTICS v_count=ROW_COUNT; accounting_removed:=accounting_removed+v_count;
                DELETE FROM arbiter.reservations
                    WHERE tenant_id=p_tenant AND id=v_request.reservation_id;
                GET DIAGNOSTICS v_count=ROW_COUNT;
                reservations_removed:=reservations_removed+v_count;
                DELETE FROM arbiter.requests WHERE tenant_id=p_tenant AND id=v_request.id;
                requests_removed:=requests_removed+1;
            END LOOP;
            IF v_revoked IS NOT NULL AND v_revoked<=p_cutoff THEN
                SELECT array_agg(t.request_id) INTO v_ids FROM (
                    SELECT request_id FROM arbiter.idempotency_tombstones
                    WHERE tenant_id=p_tenant AND key_id=p_key
                    ORDER BY request_id LIMIT p_limit) t;
                DELETE FROM arbiter.idempotency_tombstones
                    WHERE tenant_id=p_tenant AND key_id=p_key AND request_id=ANY(v_ids);
                GET DIAGNOSTICS tombstones_removed=ROW_COUNT;
            END IF;
            v_audit:=gen_random_uuid();
            INSERT INTO arbiter.audit_events (id,tenant_id,actor_type,actor_reference,action,
                target_id,policy_revision,request_id,outcome,retention_summary)
            VALUES (v_audit,p_tenant,'operator','arbiter_operator','retention_cleaned',
                p_operation,v_revision,p_operation,'succeeded',jsonb_build_object(
                    'cutoff',p_cutoff,'requests',requests_removed,'reservations',reservations_removed,
                    'accounting',accounting_removed,'audits',audits_removed,'bindings',bindings_removed,
                    'clearances',clearances_removed,'tombstones',tombstones_removed));
            audit_id:=v_audit;
            RETURN NEXT;
        END $$
    """)
    signature = "arbiter.retire_requests(uuid,uuid,timestamptz,uuid,integer)"
    op.execute(f"REVOKE ALL ON FUNCTION {signature} FROM PUBLIC")
    op.execute(f"GRANT EXECUTE ON FUNCTION {signature} TO arbiter_operator")
    op.execute(f"GRANT CREATE ON SCHEMA arbiter TO {ROLE}")
    op.execute(f"ALTER FUNCTION {signature} OWNER TO {ROLE}")
    op.execute(f"REVOKE CREATE ON SCHEMA arbiter FROM {ROLE}")


def _admission() -> None:
    op.execute("""
        CREATE FUNCTION arbiter.check_retired_idempotency(p_tenant uuid,p_key uuid,
            p_idempotency text,p_fingerprint bytea,p_version integer) RETURNS void
        LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog AS $$
        DECLARE v_old arbiter.idempotency_tombstones%ROWTYPE; v_difference integer:=0;
        BEGIN
            SELECT t.* INTO v_old FROM arbiter.idempotency_tombstones t
                WHERE t.tenant_id=p_tenant AND t.key_id=p_key AND t.idempotency_key=p_idempotency;
            IF NOT FOUND THEN RETURN; END IF;
            FOR i IN 0..31 LOOP
                v_difference:=v_difference |
                    (get_byte(v_old.payload_hmac,i) # get_byte(p_fingerprint,i));
            END LOOP;
            IF v_difference<>0 OR v_old.fingerprint_version<>p_version THEN
                RAISE EXCEPTION 'idempotency conflict' USING ERRCODE='AR003';
            END IF;
            RAISE EXCEPTION 'request already admitted' USING ERRCODE='AR009',
                DETAIL=jsonb_build_object('request_id',v_old.request_id,'state',v_old.state)::text;
        END $$
    """)
    op.execute(
        "REVOKE ALL ON FUNCTION arbiter.check_retired_idempotency"
        "(uuid,uuid,text,bytea,integer) FROM PUBLIC"
    )
    op.execute(
        "GRANT EXECUTE ON FUNCTION arbiter.check_retired_idempotency"
        "(uuid,uuid,text,bytea,integer) TO arbiter_reservation_writer"
    )
    op.execute("GRANT CREATE ON SCHEMA arbiter TO arbiter_reservation_writer")
    op.execute("SET LOCAL ROLE arbiter_reservation_writer")
    for name in ("rate_preflight", "reserve_request"):
        op.execute(f"ALTER FUNCTION arbiter.{name}({SIGNATURE}) RENAME TO {name}_live")
        op.execute(
            f"REVOKE EXECUTE ON FUNCTION arbiter.{name}_live({SIGNATURE}) FROM arbiter_runtime"
        )
    op.execute("SET LOCAL ROLE arbiter_migration")
    op.execute("""
        CREATE FUNCTION arbiter.rate_preflight(p_tenant uuid,p_key uuid,p_public text,
            p_candidate bytea,p_pepper integer,p_idempotency text,p_fingerprint bytea,
            p_fingerprint_version integer,p_alias text,p_output integer)
        RETURNS TABLE (tenant_rate bigint,key_rate bigint,policy_revision bigint,
            duplicate_id uuid,duplicate_state text)
        LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
        DECLARE v_result record;
        BEGIN
            SELECT * INTO STRICT v_result FROM arbiter.rate_preflight_live(
                p_tenant,p_key,p_public,p_candidate,p_pepper,p_idempotency,
                p_fingerprint,p_fingerprint_version,p_alias,p_output);
            IF v_result.duplicate_id IS NULL THEN
                PERFORM arbiter.check_retired_idempotency(p_tenant,p_key,p_idempotency,
                    p_fingerprint,p_fingerprint_version);
            END IF;
            RETURN QUERY SELECT v_result.tenant_rate,v_result.key_rate,v_result.policy_revision,
                v_result.duplicate_id,v_result.duplicate_state;
        END $$
    """)
    op.execute("""
        CREATE FUNCTION arbiter.reserve_request(p_tenant uuid,p_key uuid,p_public text,
            p_candidate bytea,p_pepper integer,p_idempotency text,p_fingerprint bytea,
            p_fingerprint_version integer,p_alias text,p_output integer)
        RETURNS TABLE (request_id uuid,state text,model_alias text,credit_charge bigint,
            policy_revision bigint,model_revision bigint,duplicate boolean)
        LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
        BEGIN
            IF session_user<>'arbiter_runtime' OR p_tenant IS NULL OR p_tenant IS DISTINCT FROM
                NULLIF(current_setting('arbiter.tenant_id',true),'')::uuid THEN
                RAISE EXCEPTION 'permission denied' USING ERRCODE='42501';
            END IF;
            PERFORM id FROM arbiter.tenants WHERE tenant_id=p_tenant AND id=p_tenant FOR UPDATE;
            PERFORM id FROM arbiter.api_keys WHERE tenant_id=p_tenant AND id=p_key FOR UPDATE;
            -- Existing authority/model validation still precedes all duplicate decisions.
            PERFORM * FROM arbiter.rate_preflight(p_tenant,p_key,p_public,p_candidate,p_pepper,
                p_idempotency,p_fingerprint,p_fingerprint_version,p_alias,p_output);
            RETURN QUERY SELECT * FROM arbiter.reserve_request_live(p_tenant,p_key,p_public,
                p_candidate,p_pepper,p_idempotency,p_fingerprint,p_fingerprint_version,p_alias,p_output);
        END $$
    """)
    op.execute("GRANT CREATE ON SCHEMA arbiter TO arbiter_reservation_writer")
    for name in ("rate_preflight", "reserve_request"):
        signature = f"arbiter.{name}({SIGNATURE})"
        op.execute(f"REVOKE ALL ON FUNCTION {signature} FROM PUBLIC")
        op.execute(f"GRANT EXECUTE ON FUNCTION {signature} TO arbiter_runtime")
        op.execute(f"ALTER FUNCTION {signature} OWNER TO arbiter_reservation_writer")
    op.execute("REVOKE CREATE ON SCHEMA arbiter FROM arbiter_reservation_writer")


def downgrade() -> None:
    # A downgrade must never discard the only remaining at-most-once evidence or its audit.
    op.execute(
        "ALTER TABLE arbiter.idempotency_tombstones "
        "ADD CONSTRAINT retention_downgrade_guard CHECK (false)"
    )
    op.execute(
        "ALTER TABLE arbiter.audit_events ADD CONSTRAINT retention_audit_downgrade_guard "
        "CHECK (retention_summary IS NULL)"
    )
    op.execute("ALTER TABLE arbiter.audit_events DROP CONSTRAINT retention_audit_downgrade_guard")
    op.execute(
        "ALTER TABLE arbiter.idempotency_tombstones DROP CONSTRAINT retention_downgrade_guard"
    )
    op.execute(f"SET LOCAL ROLE {ROLE}")
    op.execute("DROP FUNCTION arbiter.retire_requests(uuid,uuid,timestamptz,uuid,integer) RESTRICT")
    op.execute("SET LOCAL ROLE arbiter_migration")
    op.execute("GRANT CREATE ON SCHEMA arbiter TO arbiter_reservation_writer")
    op.execute("SET LOCAL ROLE arbiter_reservation_writer")
    for name in ("rate_preflight", "reserve_request"):
        op.execute(f"DROP FUNCTION arbiter.{name}({SIGNATURE}) RESTRICT")
        op.execute(f"ALTER FUNCTION arbiter.{name}_live({SIGNATURE}) RENAME TO {name}")
        op.execute(f"GRANT EXECUTE ON FUNCTION arbiter.{name}({SIGNATURE}) TO arbiter_runtime")
    op.execute("SET LOCAL ROLE arbiter_migration")
    op.execute("REVOKE CREATE ON SCHEMA arbiter FROM arbiter_reservation_writer")
    op.execute(
        "DROP FUNCTION arbiter.check_retired_idempotency(uuid,uuid,text,bytea,integer) RESTRICT"
    )
    op.execute("DROP TRIGGER retired_request_guard ON arbiter.requests")
    op.execute("DROP FUNCTION arbiter.reject_retired_request() RESTRICT")
    op.execute("DROP TRIGGER retention_audit_guard ON arbiter.audit_events")
    op.execute("DROP FUNCTION arbiter.guard_retention_audit() RESTRICT")
    op.execute("ALTER TABLE arbiter.audit_events DROP COLUMN retention_summary")
    for table in GRAPH:
        op.execute(f"DROP TRIGGER retention_delete_guard ON arbiter.{table}")
    op.execute("DROP FUNCTION arbiter.guard_retention_delete() RESTRICT")
    op.execute("DROP TABLE arbiter.idempotency_tombstones RESTRICT")
    op.execute("DROP INDEX arbiter.request_retention_idx")
    op.execute("DROP FUNCTION arbiter.guard_tombstone() RESTRICT")
    op.execute("""
        CREATE OR REPLACE FUNCTION arbiter.immutable_accounting() RETURNS trigger
        LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog AS $$
        BEGIN RAISE EXCEPTION 'immutable accounting evidence' USING ERRCODE='42501'; END $$
    """)
    for table in (*GRAPH, "tenants", "api_keys"):
        op.execute(f"DROP POLICY retention_access ON arbiter.{table}")
        op.execute(f"DROP POLICY retention_scope ON arbiter.{table}")
        op.execute(f"REVOKE ALL ON arbiter.{table} FROM {ROLE}")
    op.execute(f"REVOKE USAGE ON SCHEMA arbiter FROM {ROLE}")
