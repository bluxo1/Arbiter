"""Durable tenant accounting records; no runtime write or dispatch capability."""

from alembic import op

revision: str = "0011_accounting_foundation"
down_revision: str | None = "0010_model_registry"
branch_labels: str | None = None
depends_on: str | None = None

TABLES = ("quota_windows", "budget_windows", "requests", "reservations", "accounting_events")
SCOPE = "tenant_id = NULLIF(current_setting('arbiter.tenant_id',true),'')::uuid"


def _policy_guard(accounting: bool) -> None:
    # Static migration-owned SQL only. Restore the exact pre-foundation guard on downgrade.
    guard = (
        "PERFORM arbiter.assert_policy_limits(NEW.tenant_id,NEW.daily_quota,"
        "NEW.monthly_budget,NEW.concurrency);"
        if accounting
        else """IF to_regclass('arbiter.quota_windows') IS NOT NULL
            OR to_regclass('arbiter.budget_windows') IS NOT NULL
            OR to_regclass('arbiter.requests') IS NOT NULL THEN
            RAISE EXCEPTION 'accounting-aware policy updates required' USING ERRCODE='23514';
        END IF;"""
    )
    op.execute(
        """
        CREATE OR REPLACE FUNCTION arbiter.validate_policy_insert() RETURNS trigger
        LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog AS $$
        DECLARE v_revision bigint; v_alias text; v_aliases text[] := ARRAY[]::text[];
        BEGIN
            __POLICY_GUARD__
            SELECT policy_revision INTO v_revision FROM arbiter.tenants
                WHERE id=NEW.tenant_id AND tenant_id=NEW.tenant_id FOR UPDATE;
            IF NOT FOUND OR v_revision<>NEW.revision THEN
                RAISE EXCEPTION 'invalid policy revision' USING ERRCODE='23514';
            END IF;
            IF EXISTS (SELECT 1 FROM arbiter.tenant_policies
                WHERE tenant_id=NEW.tenant_id AND revision>=NEW.revision) THEN
                RAISE EXCEPTION 'invalid policy revision' USING ERRCODE='23514';
            END IF;
            FOREACH v_alias IN ARRAY NEW.model_aliases LOOP
                IF v_alias IS NULL OR v_alias !~ '^[a-z][a-z0-9_-]{0,63}$'
                    OR v_alias=ANY(v_aliases) THEN
                    RAISE EXCEPTION 'invalid model aliases' USING ERRCODE='23514';
                END IF;
                v_aliases := array_append(v_aliases,v_alias);
            END LOOP;
            IF NOT arbiter.lock_policy_aliases(NEW.model_aliases) THEN
                RAISE EXCEPTION 'model alias unavailable' USING ERRCODE='23514';
            END IF;
            RETURN NEW;
        END $$
    """.replace("__POLICY_GUARD__", guard)
    )


def upgrade() -> None:
    for table, unit in (("quota_windows", "day"), ("budget_windows", "month")):
        op.execute(f"""
            CREATE TABLE arbiter.{table} (
                id uuid PRIMARY KEY,
                tenant_id uuid NOT NULL REFERENCES arbiter.tenants(id),
                window_start timestamptz NOT NULL CHECK (isfinite(window_start)
                    AND window_start = date_trunc('{unit}',window_start AT TIME ZONE 'UTC')
                        AT TIME ZONE 'UTC'),
                committed bigint NOT NULL DEFAULT 0 CHECK (committed>=0),
                reserved bigint NOT NULL DEFAULT 0 CHECK (reserved>=0),
                CHECK (committed::numeric+reserved::numeric<=9223372036854775807),
                UNIQUE (tenant_id,id), UNIQUE (tenant_id,window_start),
                UNIQUE (tenant_id,id,window_start)
            )
        """)
    op.execute("""
        CREATE TABLE arbiter.requests (
            id uuid PRIMARY KEY,
            tenant_id uuid NOT NULL REFERENCES arbiter.tenants(id),
            key_id uuid NOT NULL,
            idempotency_key varchar(128) NOT NULL CHECK (idempotency_key ~ '^[ -~]{16,128}$'),
            payload_hmac bytea NOT NULL CHECK (octet_length(payload_hmac)=32),
            fingerprint_version integer NOT NULL CHECK (fingerprint_version>0),
            policy_revision bigint NOT NULL CHECK (policy_revision>1),
            model_id uuid NOT NULL REFERENCES arbiter.provider_models(id),
            model_revision bigint NOT NULL CHECK (model_revision>0),
            model_alias varchar(64) NOT NULL CHECK (model_alias ~ '^[a-z][a-z0-9_-]{0,63}$'),
            model_adapter varchar(16) NOT NULL CHECK (model_adapter='ollama'),
            model_digest varchar(71) NOT NULL CHECK (model_digest ~ '^sha256:[0-9a-f]{64}$'),
            context_cap bigint NOT NULL CHECK (context_cap>0),
            output_cap bigint NOT NULL CHECK (output_cap BETWEEN 1 AND 1024
                AND output_cap<=context_cap),
            credit_charge bigint NOT NULL CHECK (credit_charge>0),
            request_count bigint NOT NULL DEFAULT 1 CHECK (request_count=1),
            quota_window_id uuid NOT NULL, budget_window_id uuid NOT NULL,
            quota_start timestamptz NOT NULL, budget_start timestamptz NOT NULL,
            reservation_id uuid NOT NULL, reserve_event_id uuid NOT NULL,
            reserve_kind varchar(8) GENERATED ALWAYS AS ('reserve') STORED,
            state varchar(24) NOT NULL DEFAULT 'reserved' CHECK (state IN
                ('reserved','dispatched','succeeded','failed','unknown',
                 'released','rejected_capacity')),
            created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP CHECK (isfinite(created_at)),
            dispatched_at timestamptz CHECK (isfinite(dispatched_at) AND dispatched_at>=created_at),
            finished_at timestamptz CHECK (isfinite(finished_at) AND finished_at>=created_at
                AND (dispatched_at IS NULL OR finished_at>=dispatched_at)),
            outcome varchar(32) CHECK (outcome IN
                ('succeeded','provider_failure','provider_deadline',
                'provider_unavailable','provider_malformed','unknown','cancelled','rejected_capacity',
                'authorization_changed','admission_window_changed','reservation_expired')),
            input_tokens bigint CHECK (input_tokens>=0),
            output_tokens bigint CHECK (output_tokens>=0 AND output_tokens<=output_cap),
            CHECK ((state IN ('reserved','released','rejected_capacity') AND dispatched_at IS NULL)
                OR (state IN ('dispatched','succeeded','failed','unknown')
                    AND dispatched_at IS NOT NULL)),
            CHECK ((state IN ('reserved','dispatched') AND finished_at IS NULL AND outcome IS NULL)
                OR (state='unknown' AND outcome IS NOT NULL AND outcome='unknown')
                OR (state IN ('succeeded','failed','released','rejected_capacity')
                    AND finished_at IS NOT NULL AND outcome IS NOT NULL)),
            CHECK (state NOT IN ('reserved','released','rejected_capacity')
                OR (input_tokens IS NULL AND output_tokens IS NULL)),
            CHECK (budget_start=date_trunc('month',quota_start AT TIME ZONE 'UTC')
                AT TIME ZONE 'UTC'),
            CHECK (created_at>=quota_start AND created_at<
                ((quota_start AT TIME ZONE 'UTC')+interval '1 day') AT TIME ZONE 'UTC'),
            UNIQUE (tenant_id,id), UNIQUE (tenant_id,key_id,idempotency_key),
            UNIQUE (tenant_id,id,quota_window_id,budget_window_id,request_count,credit_charge),
            FOREIGN KEY (tenant_id,key_id) REFERENCES arbiter.api_keys(tenant_id,id),
            FOREIGN KEY (tenant_id,policy_revision)
                REFERENCES arbiter.tenant_policies(tenant_id,revision),
            FOREIGN KEY (tenant_id,quota_window_id,quota_start)
                REFERENCES arbiter.quota_windows(tenant_id,id,window_start),
            FOREIGN KEY (tenant_id,budget_window_id,budget_start)
                REFERENCES arbiter.budget_windows(tenant_id,id,window_start)
        )
    """)
    # Historical model snapshots do not reference a mutable registry revision.
    op.execute("""
        CREATE TABLE arbiter.reservations (
            id uuid PRIMARY KEY,
            tenant_id uuid NOT NULL REFERENCES arbiter.tenants(id),
            request_id uuid NOT NULL,
            quota_window_id uuid NOT NULL, budget_window_id uuid NOT NULL,
            request_count bigint NOT NULL CHECK (request_count=1),
            credits bigint NOT NULL CHECK (credits>0),
            disposition varchar(16) NOT NULL DEFAULT 'reserved'
                CHECK (disposition IN ('reserved','committed','released')),
            settlement_event_id uuid,
            settlement_kind varchar(8) GENERATED ALWAYS AS
                (CASE disposition WHEN 'committed' THEN 'commit'
                    WHEN 'released' THEN 'release' END) STORED,
            CHECK ((disposition='reserved' AND settlement_event_id IS NULL)
                OR (disposition<>'reserved' AND settlement_event_id IS NOT NULL)),
            UNIQUE (tenant_id,id), UNIQUE (tenant_id,request_id),
            UNIQUE (tenant_id,id,request_id,quota_window_id,budget_window_id,request_count,credits),
            FOREIGN KEY (tenant_id,request_id,quota_window_id,budget_window_id,
                request_count,credits)
                REFERENCES arbiter.requests
                (tenant_id,id,quota_window_id,budget_window_id,request_count,credit_charge)
                DEFERRABLE INITIALLY DEFERRED
        )
    """)
    op.execute("""
        CREATE TABLE arbiter.accounting_events (
            id uuid PRIMARY KEY,
            tenant_id uuid NOT NULL REFERENCES arbiter.tenants(id),
            request_id uuid NOT NULL, reservation_id uuid NOT NULL,
            quota_window_id uuid NOT NULL, budget_window_id uuid NOT NULL,
            request_count bigint NOT NULL CHECK (request_count=1),
            credits bigint NOT NULL CHECK (credits>0),
            kind varchar(8) NOT NULL CHECK (kind IN ('reserve','commit','release')),
            occurred_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP
                CHECK (isfinite(occurred_at)),
            UNIQUE (tenant_id,id), UNIQUE (tenant_id,request_id,kind),
            UNIQUE (tenant_id,id,reservation_id,request_id,quota_window_id,budget_window_id,
                request_count,credits,kind),
            FOREIGN KEY (tenant_id,reservation_id,request_id,quota_window_id,budget_window_id,
                request_count,credits) REFERENCES arbiter.reservations
                (tenant_id,id,request_id,quota_window_id,budget_window_id,request_count,credits)
                DEFERRABLE INITIALLY DEFERRED
        )
    """)
    op.execute("""
        CREATE UNIQUE INDEX accounting_single_settlement ON arbiter.accounting_events
        (tenant_id,request_id) WHERE kind IN ('commit','release')
    """)
    op.execute("""
        ALTER TABLE arbiter.requests ADD CONSTRAINT request_reservation_fk FOREIGN KEY
        (tenant_id,reservation_id,id,quota_window_id,budget_window_id,request_count,credit_charge)
        REFERENCES arbiter.reservations
        (tenant_id,id,request_id,quota_window_id,budget_window_id,request_count,credits)
        DEFERRABLE INITIALLY DEFERRED
    """)
    op.execute("""
        ALTER TABLE arbiter.requests ADD CONSTRAINT request_reserve_evidence_fk FOREIGN KEY
        (tenant_id,reserve_event_id,reservation_id,id,quota_window_id,budget_window_id,
            request_count,credit_charge,reserve_kind)
        REFERENCES arbiter.accounting_events
        (tenant_id,id,reservation_id,request_id,quota_window_id,budget_window_id,
            request_count,credits,kind) DEFERRABLE INITIALLY DEFERRED
    """)
    op.execute("""
        ALTER TABLE arbiter.reservations ADD CONSTRAINT reservation_settlement_fk FOREIGN KEY
        (tenant_id,settlement_event_id,id,request_id,quota_window_id,budget_window_id,
            request_count,credits,settlement_kind)
        REFERENCES arbiter.accounting_events
        (tenant_id,id,reservation_id,request_id,quota_window_id,budget_window_id,
            request_count,credits,kind) DEFERRABLE INITIALLY DEFERRED
    """)
    op.execute("""
        CREATE INDEX requests_tenant_state_idx ON arbiter.requests(tenant_id,state,id)
    """)
    op.execute("""
        CREATE INDEX accounting_tenant_time_idx
        ON arbiter.accounting_events(tenant_id,occurred_at,id)
    """)
    op.execute("""
        CREATE FUNCTION arbiter.immutable_window_identity() RETURNS trigger
        LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog AS $$
        BEGIN
            IF NEW.window_start IS DISTINCT FROM OLD.window_start THEN
                RAISE EXCEPTION 'immutable allocation window' USING ERRCODE='23514';
            END IF;
            RETURN NEW;
        END $$
    """)
    op.execute("REVOKE ALL ON FUNCTION arbiter.immutable_window_identity() FROM PUBLIC")
    for table in ("quota_windows", "budget_windows"):
        op.execute(f"""
            CREATE TRIGGER immutable_window_identity BEFORE UPDATE ON arbiter.{table}
            FOR EACH ROW EXECUTE FUNCTION arbiter.immutable_window_identity()
        """)
    for table in TABLES:
        op.execute(f"ALTER TABLE arbiter.{table} ENABLE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE arbiter.{table} FORCE ROW LEVEL SECURITY")
        op.execute(f"""
            CREATE POLICY tenant_ownership ON arbiter.{table} AS RESTRICTIVE
            TO arbiter_runtime,arbiter_operator,arbiter_migration
            USING ({SCOPE}) WITH CHECK ({SCOPE})
        """)
        op.execute(f"""
            CREATE POLICY scoped_access ON arbiter.{table}
            TO arbiter_runtime,arbiter_operator,arbiter_migration USING (true) WITH CHECK (true)
        """)
        op.execute(f"""
            CREATE TRIGGER immutable_ownership BEFORE UPDATE ON arbiter.{table}
            FOR EACH ROW EXECUTE FUNCTION arbiter.reject_ownership_change()
        """)
        op.execute(f"REVOKE ALL ON arbiter.{table} FROM PUBLIC,arbiter_runtime,arbiter_operator")
        # Admission write capabilities are deliberately absent until an atomic writer is reviewed.
        op.execute(f"GRANT SELECT ON arbiter.{table} TO arbiter_runtime,arbiter_operator")
    op.execute("""
        CREATE FUNCTION arbiter.immutable_accounting() RETURNS trigger
        LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog AS $$
        BEGIN RAISE EXCEPTION 'immutable accounting evidence' USING ERRCODE='42501'; END $$
    """)
    op.execute("REVOKE ALL ON FUNCTION arbiter.immutable_accounting() FROM PUBLIC")
    op.execute("""
        CREATE TRIGGER immutable_accounting BEFORE UPDATE OR DELETE ON arbiter.accounting_events
        FOR EACH ROW EXECUTE FUNCTION arbiter.immutable_accounting()
    """)
    op.execute("""
        CREATE TRIGGER immutable_accounting_truncate BEFORE TRUNCATE ON arbiter.accounting_events
        FOR EACH STATEMENT EXECUTE FUNCTION arbiter.immutable_accounting()
    """)
    op.execute("""
        CREATE FUNCTION arbiter.immutable_request_snapshot() RETURNS trigger
        LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog AS $$
        BEGIN
            -- Stored generated columns are recomputed after BEFORE triggers.
            -- reserve_kind is fixed by its generation expression, not mutable caller input.
            IF (to_jsonb(NEW)-ARRAY['reserve_kind','state','dispatched_at','finished_at','outcome',
                'input_tokens','output_tokens']) IS DISTINCT FROM
                (to_jsonb(OLD)-ARRAY['reserve_kind','state','dispatched_at','finished_at','outcome',
                'input_tokens','output_tokens']) THEN
                RAISE EXCEPTION 'immutable request snapshot' USING ERRCODE='23514';
            END IF;
            RETURN NEW;
        END $$
    """)
    op.execute("REVOKE ALL ON FUNCTION arbiter.immutable_request_snapshot() FROM PUBLIC")
    op.execute("""
        CREATE TRIGGER immutable_request_snapshot BEFORE UPDATE ON arbiter.requests
        FOR EACH ROW EXECUTE FUNCTION arbiter.immutable_request_snapshot()
    """)
    op.execute("""
        CREATE FUNCTION arbiter.check_reservation_state() RETURNS trigger
        LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog AS $$
        DECLARE v_id uuid; v_state text; v_disposition text;
        BEGIN
            IF TG_TABLE_NAME='requests' THEN v_id:=NEW.id; ELSE v_id:=NEW.request_id; END IF;
            SELECT r.state,s.disposition INTO v_state,v_disposition FROM arbiter.requests r
            JOIN arbiter.reservations s ON s.tenant_id=r.tenant_id AND s.id=r.reservation_id
            WHERE r.tenant_id=NEW.tenant_id AND r.id=v_id;
            IF NOT FOUND OR v_disposition<>(CASE
                WHEN v_state='reserved' THEN 'reserved'
                WHEN v_state IN ('released','rejected_capacity') THEN 'released'
                ELSE 'committed' END) THEN
                RAISE EXCEPTION 'inconsistent reservation state' USING ERRCODE='23514';
            END IF;
            IF TG_TABLE_NAME='accounting_events' THEN
                IF NEW.kind IN ('commit','release') AND v_disposition<>
                    (CASE WHEN NEW.kind='commit' THEN 'committed' ELSE 'released' END) THEN
                    RAISE EXCEPTION 'inconsistent settlement evidence' USING ERRCODE='23514';
                END IF;
            END IF;
            RETURN NULL;
        END $$
    """)
    op.execute("REVOKE ALL ON FUNCTION arbiter.check_reservation_state() FROM PUBLIC")
    for table in ("requests", "reservations", "accounting_events"):
        op.execute(f"""
            CREATE CONSTRAINT TRIGGER consistent_reservation
            AFTER INSERT OR UPDATE ON arbiter.{table}
            DEFERRABLE INITIALLY DEFERRED FOR EACH ROW
            EXECUTE FUNCTION arbiter.check_reservation_state()
        """)
    op.execute("""
        CREATE FUNCTION arbiter.assert_policy_limits(p_tenant uuid,p_quota bigint,
            p_budget bigint,p_concurrency bigint) RETURNS void
        LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
        DECLARE v_quota bigint; v_budget bigint; v_occupancy bigint;
        BEGIN
            IF session_user<>'arbiter_operator' OR p_tenant IS NULL OR
                p_tenant IS DISTINCT FROM
                    NULLIF(current_setting('arbiter.tenant_id',true),'')::uuid THEN
                RAISE EXCEPTION 'permission denied' USING ERRCODE='42501';
            END IF;
            IF p_quota IS NULL OR p_budget IS NULL OR p_concurrency IS NULL
                OR p_quota<0 OR p_budget<0 OR p_concurrency NOT BETWEEN 0 AND 2 THEN
                RAISE EXCEPTION 'invalid policy limit' USING ERRCODE='23514';
            END IF;
            -- Existing operator path holds tenant first. Reentrant locks preserve tenant,
            -- current policy, quota, budget order, before any registry alias locks.
            PERFORM id FROM arbiter.tenants WHERE tenant_id=p_tenant AND id=p_tenant FOR UPDATE;
            IF NOT FOUND THEN RAISE EXCEPTION 'tenant unavailable' USING ERRCODE='23514'; END IF;
            PERFORM id FROM arbiter.tenant_policies WHERE tenant_id=p_tenant
                ORDER BY revision DESC LIMIT 1 FOR SHARE;
            SELECT committed+reserved INTO v_quota FROM arbiter.quota_windows
                WHERE tenant_id=p_tenant AND window_start=
                    date_trunc('day',CURRENT_TIMESTAMP AT TIME ZONE 'UTC') AT TIME ZONE 'UTC'
                FOR UPDATE;
            SELECT committed+reserved INTO v_budget FROM arbiter.budget_windows
                WHERE tenant_id=p_tenant AND window_start=
                    date_trunc('month',CURRENT_TIMESTAMP AT TIME ZONE 'UTC') AT TIME ZONE 'UTC'
                FOR UPDATE;
            SELECT count(*) INTO v_occupancy FROM arbiter.requests
                WHERE tenant_id=p_tenant AND state IN ('reserved','dispatched','unknown')
                    AND finished_at IS NULL;
            IF p_quota<COALESCE(v_quota,0) OR p_budget<COALESCE(v_budget,0)
                OR p_concurrency<v_occupancy THEN
                RAISE EXCEPTION 'policy below durable consumption' USING ERRCODE='23514';
            END IF;
        END $$
    """)
    op.execute("""
        REVOKE ALL ON FUNCTION arbiter.assert_policy_limits(uuid,bigint,bigint,bigint) FROM PUBLIC
    """)
    op.execute("""
        GRANT EXECUTE ON FUNCTION arbiter.assert_policy_limits(uuid,bigint,bigint,bigint)
        TO arbiter_operator
    """)
    _policy_guard(True)


def downgrade() -> None:
    _policy_guard(False)
    op.execute("DROP FUNCTION arbiter.assert_policy_limits(uuid,bigint,bigint,bigint) RESTRICT")
    for constraint in ("request_reservation_fk", "request_reserve_evidence_fk"):
        op.execute(f"ALTER TABLE arbiter.requests DROP CONSTRAINT {constraint}")
    op.execute("ALTER TABLE arbiter.reservations DROP CONSTRAINT reservation_settlement_fk")
    for table in reversed(TABLES):
        op.execute(f"DROP TABLE arbiter.{table} RESTRICT")
    for function in (
        "check_reservation_state",
        "immutable_request_snapshot",
        "immutable_accounting",
        "immutable_window_identity",
    ):
        op.execute(f"DROP FUNCTION arbiter.{function}() RESTRICT")
