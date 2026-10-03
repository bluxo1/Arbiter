"""Operator-owned native Ollama bindings and revision-pinned dispatch selection."""

from alembic import op

revision: str = "0018_provider_binding"
down_revision: str | None = "0017_maintenance_recovery"
branch_labels: str | None = None
depends_on: str | None = None

_BIND = "arbiter.bind_provider_model(uuid,bigint,text,text,text,bigint,bigint,text,uuid,uuid)"
_READ = "arbiter.dispatched_provider_binding(uuid,uuid,uuid)"


def upgrade() -> None:
    op.execute("""
        ALTER TABLE arbiter.model_registry_journal
            DROP CONSTRAINT model_registry_journal_action_check,
            ADD CONSTRAINT model_registry_journal_action_check
                CHECK (action IN ('model_registered','model_updated','model_bound')),
            ADD COLUMN native_name varchar(145) CHECK (
                native_name IS NULL OR
                (native_name ~ '^[A-Za-z0-9_-][A-Za-z0-9_.-]{0,63}:[A-Za-z0-9_.-]{1,80}$'
                    AND right(lower(native_name),6) NOT IN (chr(58)||'cloud','-cloud'))),
            ADD COLUMN provider_kind varchar(16)
                CHECK (provider_kind IS NULL OR provider_kind='ollama'),
            ADD CONSTRAINT registry_binding_action_check CHECK (
                (action='model_bound')=(native_name IS NOT NULL)
                AND (action='model_bound')=(provider_kind IS NOT NULL)
                AND (provider_kind IS NULL OR provider_kind=adapter)),
            ADD CONSTRAINT registry_binding_exact UNIQUE
                (model_id,revision,provider_kind,native_name)
    """)
    op.execute("""
        CREATE TABLE arbiter.provider_model_bindings (
            model_id uuid NOT NULL REFERENCES arbiter.provider_models(id),
            revision bigint NOT NULL CHECK (revision>1),
            provider_kind varchar(16) NOT NULL CHECK (provider_kind='ollama'),
            native_name varchar(145) NOT NULL CHECK (
                native_name ~ '^[A-Za-z0-9_-][A-Za-z0-9_.-]{0,63}:[A-Za-z0-9_.-]{1,80}$'
                AND right(lower(native_name),6) NOT IN (chr(58)||'cloud','-cloud')),
            PRIMARY KEY (model_id,revision),
            FOREIGN KEY (model_id,revision,provider_kind,native_name)
                REFERENCES arbiter.model_registry_journal
                    (model_id,revision,provider_kind,native_name)
        )
    """)
    op.execute("""
        REVOKE ALL ON arbiter.provider_model_bindings
            FROM PUBLIC,arbiter_runtime,arbiter_operator;
        GRANT SELECT ON arbiter.provider_model_bindings
            TO arbiter_operator,arbiter_dispatch_writer
    """)
    op.execute("""
        CREATE FUNCTION arbiter.guard_provider_model_binding() RETURNS trigger
        LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog AS $$
        BEGIN
            IF TG_OP<>'INSERT' THEN
                RAISE EXCEPTION 'immutable provider binding' USING ERRCODE='42501';
            END IF;
            IF session_user<>'arbiter_operator' THEN
                RAISE EXCEPTION 'operator binding only' USING ERRCODE='42501';
            END IF;
            RETURN NEW;
        END $$
    """)
    op.execute("REVOKE ALL ON FUNCTION arbiter.guard_provider_model_binding() FROM PUBLIC")
    op.execute("""
        CREATE TRIGGER provider_model_binding_guard BEFORE INSERT OR UPDATE OR DELETE
        ON arbiter.provider_model_bindings FOR EACH ROW
        EXECUTE FUNCTION arbiter.guard_provider_model_binding()
    """)
    op.execute("""
        CREATE TRIGGER provider_model_binding_truncate_guard BEFORE TRUNCATE
        ON arbiter.provider_model_bindings FOR EACH STATEMENT
        EXECUTE FUNCTION arbiter.guard_provider_model_binding()
    """)
    op.execute("""
        CREATE FUNCTION arbiter.bind_provider_model(
            p_model uuid,p_expected bigint,p_kind text,p_native text,p_digest text,
            p_context bigint,p_output bigint,p_approval text,p_journal uuid,p_correlation uuid)
        RETURNS TABLE (model_id uuid,revision bigint,journal_id uuid)
        LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
        DECLARE v_model arbiter.provider_models%ROWTYPE; v_revision bigint;
        BEGIN
            IF session_user<>'arbiter_operator' OR
                NULLIF(current_setting('arbiter.tenant_id',true),'') IS NOT NULL THEN
                RAISE EXCEPTION 'permission denied' USING ERRCODE='42501';
            END IF;
            IF p_model IS NULL OR p_expected IS NULL OR p_expected<1 OR
                p_expected=9223372036854775807 OR p_journal IS NULL OR
                p_correlation IS NULL OR p_native IS NULL OR
                p_kind IS DISTINCT FROM 'ollama' OR
                p_native !~ '^[A-Za-z0-9_-][A-Za-z0-9_.-]{0,63}:[A-Za-z0-9_.-]{1,80}$' OR
                right(lower(p_native),6) IN (chr(58)||'cloud','-cloud') OR p_digest IS NULL OR
                p_digest !~ '^sha256:[0-9a-f]{64}$' OR
                p_context IS NULL OR p_context<1 OR p_output IS NULL OR
                p_output NOT BETWEEN 1 AND 1024 OR p_output>p_context OR
                p_approval IS NULL OR p_approval !~ '^sha256:[0-9a-f]{64}$' THEN
                RAISE EXCEPTION 'invalid provider binding' USING ERRCODE='22023';
            END IF;
            SELECT m.* INTO v_model FROM arbiter.provider_models m
                WHERE m.id=p_model FOR UPDATE;
            IF NOT FOUND OR v_model.revision<>p_expected OR
                v_model.adapter<>'ollama' OR v_model.model_digest<>p_digest OR
                v_model.context_cap>p_context OR v_model.output_cap>p_output THEN
                RAISE EXCEPTION 'registry conflict' USING ERRCODE='23505';
            END IF;
            v_revision:=v_model.revision+1;
            INSERT INTO arbiter.model_registry_journal
                (id,model_id,revision,alias,adapter,model_digest,context_cap,output_cap,
                 credit_charge,active,approval_digest,actor_reference,action,outcome,
                 correlation_id,provider_kind,native_name)
            VALUES (p_journal,v_model.id,v_revision,v_model.alias,v_model.adapter,
                v_model.model_digest,v_model.context_cap,v_model.output_cap,
                v_model.credit_charge,v_model.active,p_approval,'arbiter_operator',
                'model_bound','succeeded',p_correlation,p_kind,p_native);
            UPDATE arbiter.provider_models SET revision=v_revision,journal_id=p_journal
                WHERE id=v_model.id;
            INSERT INTO arbiter.provider_model_bindings
                (model_id,revision,provider_kind,native_name)
                VALUES (v_model.id,v_revision,p_kind,p_native);
            RETURN QUERY SELECT v_model.id,v_revision,p_journal;
        END $$
    """)
    op.execute(f"REVOKE ALL ON FUNCTION {_BIND} FROM PUBLIC")
    op.execute(f"GRANT EXECUTE ON FUNCTION {_BIND} TO arbiter_operator")

    op.execute("""
        CREATE TABLE arbiter.dispatched_provider_bindings (
            tenant_id uuid NOT NULL,
            request_id uuid NOT NULL,
            model_id uuid NOT NULL,
            model_revision bigint NOT NULL,
            PRIMARY KEY (tenant_id,request_id),
            FOREIGN KEY (tenant_id,request_id)
                REFERENCES arbiter.requests(tenant_id,id),
            FOREIGN KEY (model_id,model_revision)
                REFERENCES arbiter.provider_model_bindings(model_id,revision)
        )
    """)
    op.execute("ALTER TABLE arbiter.dispatched_provider_bindings ENABLE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE arbiter.dispatched_provider_bindings FORCE ROW LEVEL SECURITY")
    op.execute("""
        CREATE POLICY dispatch_binding_scope ON arbiter.dispatched_provider_bindings
            AS RESTRICTIVE TO arbiter_dispatch_writer
            USING (tenant_id=NULLIF(current_setting('arbiter.tenant_id',true),'')::uuid)
            WITH CHECK (tenant_id=NULLIF(current_setting('arbiter.tenant_id',true),'')::uuid)
    """)
    op.execute("""
        CREATE POLICY dispatch_binding_access ON arbiter.dispatched_provider_bindings
            TO arbiter_dispatch_writer USING (true) WITH CHECK (true)
    """)
    op.execute("""
        REVOKE ALL ON arbiter.dispatched_provider_bindings
            FROM PUBLIC,arbiter_runtime,arbiter_operator;
        GRANT SELECT,INSERT ON arbiter.dispatched_provider_bindings
            TO arbiter_dispatch_writer
    """)
    op.execute("""
        CREATE FUNCTION arbiter.capture_dispatched_provider_binding() RETURNS trigger
        LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog AS $$
        BEGIN
            IF OLD.state='reserved' AND NEW.state='dispatched' AND
                NEW.dispatch_audit_id IS NOT NULL AND session_user='arbiter_runtime' THEN
                INSERT INTO arbiter.dispatched_provider_bindings
                    (tenant_id,request_id,model_id,model_revision)
                SELECT NEW.tenant_id,NEW.id,b.model_id,b.revision
                FROM arbiter.provider_model_bindings b
                WHERE b.model_id=NEW.model_id AND b.revision=NEW.model_revision;
            END IF;
            RETURN NEW;
        END $$
    """)
    op.execute("REVOKE ALL ON FUNCTION arbiter.capture_dispatched_provider_binding() FROM PUBLIC")
    op.execute("""
        CREATE TRIGGER capture_dispatched_provider_binding
        AFTER UPDATE OF state ON arbiter.requests FOR EACH ROW
        EXECUTE FUNCTION arbiter.capture_dispatched_provider_binding()
    """)
    op.execute("""
        CREATE FUNCTION arbiter.dispatched_provider_binding(
            p_tenant uuid,p_key uuid,p_request uuid)
        RETURNS TABLE (model_id uuid,model_digest text,model_revision bigint,
            provider_kind text,native_name text,context_cap bigint,output_cap bigint)
        LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog AS $$
        BEGIN
            IF session_user<>'arbiter_runtime' OR p_tenant IS NULL OR
                p_tenant IS DISTINCT FROM
                    NULLIF(current_setting('arbiter.tenant_id',true),'')::uuid OR
                p_key IS NULL OR p_request IS NULL THEN
                RAISE EXCEPTION 'permission denied' USING ERRCODE='42501';
            END IF;
            RETURN QUERY
            SELECT r.model_id,r.model_digest::text,r.model_revision,
                b.provider_kind::text,b.native_name::text,r.context_cap,r.output_cap
            FROM arbiter.requests r
            JOIN arbiter.dispatched_provider_bindings d
                ON d.tenant_id=r.tenant_id AND d.request_id=r.id
                AND d.model_id=r.model_id AND d.model_revision=r.model_revision
            JOIN arbiter.provider_model_bindings b
                ON b.model_id=d.model_id AND b.revision=d.model_revision
            WHERE r.tenant_id=p_tenant AND r.key_id=p_key AND r.id=p_request
                AND r.state='dispatched' AND r.dispatch_audit_id IS NOT NULL;
        END $$
    """)
    op.execute(f"REVOKE ALL ON FUNCTION {_READ} FROM PUBLIC")
    op.execute(f"GRANT EXECUTE ON FUNCTION {_READ} TO arbiter_runtime")
    op.execute("GRANT CREATE ON SCHEMA arbiter TO arbiter_dispatch_writer")
    op.execute(f"ALTER FUNCTION {_READ} OWNER TO arbiter_dispatch_writer")
    op.execute("REVOKE CREATE ON SCHEMA arbiter FROM arbiter_dispatch_writer")


def downgrade() -> None:
    op.execute("""
        DO $$ BEGIN
            IF EXISTS (SELECT 1 FROM arbiter.provider_model_bindings) OR
                EXISTS (SELECT 1 FROM arbiter.dispatched_provider_bindings) OR
                EXISTS (SELECT 1 FROM arbiter.model_registry_journal
                    WHERE action='model_bound') THEN
                RAISE EXCEPTION 'provider binding downgrade would lose evidence'
                    USING ERRCODE='23514';
            END IF;
        END $$
    """)
    op.execute(f"DROP FUNCTION {_READ} RESTRICT")
    op.execute("DROP TRIGGER capture_dispatched_provider_binding ON arbiter.requests")
    op.execute("DROP FUNCTION arbiter.capture_dispatched_provider_binding() RESTRICT")
    op.execute("DROP TABLE arbiter.dispatched_provider_bindings RESTRICT")
    op.execute(f"DROP FUNCTION {_BIND} RESTRICT")
    op.execute("DROP TABLE arbiter.provider_model_bindings RESTRICT")
    op.execute("DROP FUNCTION arbiter.guard_provider_model_binding() RESTRICT")
    op.execute("""
        ALTER TABLE arbiter.model_registry_journal
            DROP CONSTRAINT model_registry_journal_action_check,
            DROP CONSTRAINT registry_binding_action_check,
            DROP CONSTRAINT registry_binding_exact,
            DROP COLUMN native_name,
            DROP COLUMN provider_kind,
            ADD CONSTRAINT model_registry_journal_action_check
                CHECK (action IN ('model_registered','model_updated'))
    """)
