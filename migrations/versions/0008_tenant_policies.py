"""Operator-only versioned tenant policies and minimal model-registry prerequisite."""

from alembic import op

revision: str = "0008_tenant_policies"
down_revision: str | None = "0007_workload_key_lookup"
branch_labels: str | None = None
depends_on: str | None = None


def upgrade() -> None:
    # No models are registered by migration; activation requires a later operator task.
    op.execute("""
        CREATE TABLE arbiter.provider_models (
            id uuid PRIMARY KEY,
            alias varchar(64) NOT NULL UNIQUE CHECK (alias ~ '^[a-z][a-z0-9_-]{0,63}$'),
            adapter varchar(16) NOT NULL CHECK (adapter='ollama'),
            model_digest varchar(71) NOT NULL CHECK (model_digest ~ '^sha256:[0-9a-f]{64}$'),
            context_cap bigint NOT NULL CHECK (context_cap>0),
            output_cap bigint NOT NULL CHECK (output_cap BETWEEN 1 AND 1024),
            credit_charge bigint NOT NULL CHECK (credit_charge>0),
            revision bigint NOT NULL CHECK (revision>0),
            active boolean NOT NULL DEFAULT false
        )
    """)
    op.execute(
        "REVOKE ALL ON arbiter.provider_models FROM PUBLIC, arbiter_runtime, arbiter_operator"
    )
    op.execute("GRANT SELECT ON arbiter.provider_models TO arbiter_operator")
    # Row locks require UPDATE privilege; expose only this validation/lock operation.
    op.execute("""
        CREATE FUNCTION arbiter.lock_policy_aliases(p_aliases text[]) RETURNS boolean
        LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog AS $$
        DECLARE v_valid boolean;
        BEGIN
            IF session_user<>'arbiter_operator' OR
                NULLIF(current_setting('arbiter.tenant_id',true),'') IS NULL THEN
                RAISE EXCEPTION 'permission denied' USING ERRCODE='42501';
            END IF;
            IF p_aliases IS NULL OR cardinality(p_aliases)>32 THEN RETURN false; END IF;
            SELECT count(*)=cardinality(p_aliases) INTO v_valid FROM (
                SELECT alias FROM arbiter.provider_models
                WHERE alias=ANY(p_aliases) AND active ORDER BY alias FOR SHARE
            ) locked;
            RETURN v_valid;
        END $$
    """)
    op.execute("REVOKE ALL ON FUNCTION arbiter.lock_policy_aliases(text[]) FROM PUBLIC")
    op.execute("GRANT EXECUTE ON FUNCTION arbiter.lock_policy_aliases(text[]) TO arbiter_operator")
    op.execute("""
        ALTER TABLE arbiter.audit_events ADD CONSTRAINT policy_audit_binding_unique
        UNIQUE (tenant_id,id,target_id,policy_revision,action,actor_type,outcome,actor_reference)
    """)
    op.execute("""
        CREATE TABLE arbiter.tenant_policies (
            id uuid PRIMARY KEY,
            tenant_id uuid NOT NULL REFERENCES arbiter.tenants(id),
            revision bigint NOT NULL CHECK (revision>1),
            audit_id uuid NOT NULL,
            tenant_rate bigint NOT NULL CHECK (tenant_rate>=0),
            key_rate bigint NOT NULL CHECK (key_rate>=0),
            daily_quota bigint NOT NULL CHECK (daily_quota>=0),
            monthly_budget bigint NOT NULL CHECK (monthly_budget>=0),
            concurrency bigint NOT NULL CHECK (concurrency BETWEEN 0 AND 2),
            model_aliases text[] NOT NULL CHECK (
                cardinality(model_aliases)<=32 AND array_position(model_aliases,NULL) IS NULL
                AND (cardinality(model_aliases)=0 OR array_ndims(model_aliases)=1)),
            created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
            audit_action varchar(64) GENERATED ALWAYS AS ('tenant_policy_set') STORED,
            audit_actor varchar(16) GENERATED ALWAYS AS ('operator') STORED,
            audit_outcome varchar(16) GENERATED ALWAYS AS ('succeeded') STORED,
            audit_reference varchar(255) GENERATED ALWAYS AS ('arbiter_operator') STORED,
            UNIQUE (tenant_id,id), UNIQUE (tenant_id,revision),
            CONSTRAINT policy_audit_fk FOREIGN KEY
                (tenant_id,audit_id,id,revision,audit_action,audit_actor,audit_outcome,audit_reference)
                REFERENCES arbiter.audit_events
                (tenant_id,id,target_id,policy_revision,action,actor_type,outcome,actor_reference)
                DEFERRABLE INITIALLY DEFERRED
        )
    """)
    op.execute("ALTER TABLE arbiter.tenant_policies ENABLE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE arbiter.tenant_policies FORCE ROW LEVEL SECURITY")
    expression = "tenant_id = NULLIF(current_setting('arbiter.tenant_id',true),'')::uuid"
    op.execute(f"""
        CREATE POLICY tenant_ownership ON arbiter.tenant_policies AS RESTRICTIVE
        TO arbiter_runtime, arbiter_operator, arbiter_migration
        USING ({expression}) WITH CHECK ({expression})
    """)
    op.execute("""
        CREATE POLICY scoped_access ON arbiter.tenant_policies
        TO arbiter_runtime, arbiter_operator, arbiter_migration USING (true) WITH CHECK (true)
    """)
    op.execute(
        "REVOKE ALL ON arbiter.tenant_policies FROM PUBLIC, arbiter_runtime, arbiter_operator"
    )
    op.execute("GRANT SELECT ON arbiter.tenant_policies TO arbiter_runtime, arbiter_operator")
    op.execute("GRANT INSERT ON arbiter.tenant_policies TO arbiter_operator")
    op.execute("""
        CREATE FUNCTION arbiter.validate_policy_insert() RETURNS trigger
        LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog AS $$
        DECLARE v_revision bigint; v_alias text; v_aliases text[] := ARRAY[]::text[];
        BEGIN
            IF to_regclass('arbiter.quota_windows') IS NOT NULL
                OR to_regclass('arbiter.budget_windows') IS NOT NULL
                OR to_regclass('arbiter.requests') IS NOT NULL THEN
                RAISE EXCEPTION 'accounting-aware policy updates required' USING ERRCODE='23514';
            END IF;
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
    """)
    op.execute("REVOKE ALL ON FUNCTION arbiter.validate_policy_insert() FROM PUBLIC")
    op.execute("""
        CREATE TRIGGER validate_policy_insert BEFORE INSERT ON arbiter.tenant_policies
        FOR EACH ROW EXECUTE FUNCTION arbiter.validate_policy_insert()
    """)
    op.execute("""
        CREATE FUNCTION arbiter.reject_policy_update() RETURNS trigger
        LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog AS $$
        BEGIN
            RAISE EXCEPTION 'immutable policy history' USING ERRCODE='23514';
        END $$
    """)
    op.execute("REVOKE ALL ON FUNCTION arbiter.reject_policy_update() FROM PUBLIC")
    op.execute("""
        CREATE TRIGGER immutable_policy BEFORE UPDATE ON arbiter.tenant_policies
        FOR EACH ROW EXECUTE FUNCTION arbiter.reject_policy_update()
    """)


def downgrade() -> None:
    op.execute("DROP TABLE arbiter.tenant_policies RESTRICT")
    op.execute("DROP FUNCTION arbiter.validate_policy_insert() RESTRICT")
    op.execute("DROP FUNCTION arbiter.reject_policy_update() RESTRICT")
    op.execute("ALTER TABLE arbiter.audit_events DROP CONSTRAINT policy_audit_binding_unique")
    op.execute("DROP FUNCTION arbiter.lock_policy_aliases(text[]) RESTRICT")
    op.execute("DROP TABLE arbiter.provider_models RESTRICT")
