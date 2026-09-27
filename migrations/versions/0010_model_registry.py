"""Operator-only registry mutations linked atomically to immutable global evidence."""

from alembic import op

revision: str = "0010_model_registry"
down_revision: str | None = "0009_model_catalog"
branch_labels: str | None = None
depends_on: str | None = None


def upgrade() -> None:
    op.execute("""
        CREATE TABLE arbiter.model_registry_journal (
            id uuid PRIMARY KEY,
            model_id uuid NOT NULL,
            revision bigint NOT NULL CHECK (revision>0),
            alias varchar(64) NOT NULL CHECK (alias ~ '^[a-z][a-z0-9_-]{0,63}$'),
            adapter varchar(16) NOT NULL CHECK (adapter='ollama'),
            model_digest varchar(71) NOT NULL CHECK (model_digest ~ '^sha256:[0-9a-f]{64}$'),
            context_cap bigint NOT NULL CHECK (context_cap>0),
            output_cap bigint NOT NULL CHECK (output_cap BETWEEN 1 AND 1024
                AND output_cap<=context_cap),
            credit_charge bigint NOT NULL CHECK (credit_charge>0),
            active boolean NOT NULL,
            approval_digest varchar(71) NOT NULL CHECK (approval_digest ~ '^sha256:[0-9a-f]{64}$'),
            actor_reference varchar(32) NOT NULL CHECK (actor_reference='arbiter_operator'),
            action varchar(32) NOT NULL CHECK (action IN ('model_registered','model_updated')),
            outcome varchar(16) NOT NULL CHECK (outcome='succeeded'),
            correlation_id uuid NOT NULL UNIQUE,
            occurred_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
            UNIQUE (model_id,revision),
            UNIQUE (id,model_id,revision,alias,adapter,model_digest,context_cap,
                output_cap,credit_charge,active)
        )
    """)
    op.execute(
        "REVOKE ALL ON arbiter.model_registry_journal FROM PUBLIC,arbiter_runtime,arbiter_operator"
    )
    op.execute("GRANT SELECT ON arbiter.model_registry_journal TO arbiter_operator")
    # Legacy/migration-owned fixtures keep NULL; never manufacture historical operator evidence.
    op.execute("ALTER TABLE arbiter.provider_models ADD COLUMN journal_id uuid")
    op.execute("""
        ALTER TABLE arbiter.provider_models ADD CONSTRAINT registry_revision_journal_fk
        FOREIGN KEY (journal_id,id,revision,alias,adapter,model_digest,context_cap,
            output_cap,credit_charge,active)
        REFERENCES arbiter.model_registry_journal
            (id,model_id,revision,alias,adapter,model_digest,context_cap,
             output_cap,credit_charge,active) DEFERRABLE INITIALLY DEFERRED
    """)
    op.execute("""
        CREATE FUNCTION arbiter.guard_registry_journal() RETURNS trigger
        LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog AS $$
        BEGIN
            IF TG_OP<>'INSERT' THEN
                RAISE EXCEPTION 'immutable registry journal' USING ERRCODE='42501';
            END IF;
            IF session_user<>'arbiter_operator' THEN
                RAISE EXCEPTION 'operator journal only' USING ERRCODE='42501';
            END IF;
            RETURN NEW;
        END $$
    """)
    op.execute("REVOKE ALL ON FUNCTION arbiter.guard_registry_journal() FROM PUBLIC")
    op.execute("""
        CREATE TRIGGER registry_journal_guard BEFORE INSERT OR UPDATE OR DELETE
        ON arbiter.model_registry_journal FOR EACH ROW
        EXECUTE FUNCTION arbiter.guard_registry_journal()
    """)
    op.execute("""
        CREATE TRIGGER registry_journal_truncate_guard BEFORE TRUNCATE
        ON arbiter.model_registry_journal FOR EACH STATEMENT
        EXECUTE FUNCTION arbiter.guard_registry_journal()
    """)
    op.execute("""
        CREATE FUNCTION arbiter.guard_registry_revision() RETURNS trigger
        LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog AS $$
        BEGIN
            IF session_user='arbiter_operator' THEN
                IF NEW.journal_id IS NULL THEN
                    RAISE EXCEPTION 'registry journal required' USING ERRCODE='23514';
                END IF;
                IF TG_OP='INSERT' AND NEW.revision<>1 THEN
                    RAISE EXCEPTION 'invalid registry revision' USING ERRCODE='23514';
                END IF;
            END IF;
            IF TG_OP='UPDATE' AND (session_user='arbiter_operator' OR OLD.journal_id IS NOT NULL)
                AND (NEW.id<>OLD.id OR NEW.alias<>OLD.alias OR NEW.journal_id IS NULL
                    OR NEW.journal_id=OLD.journal_id OR NEW.revision<>OLD.revision+1) THEN
                RAISE EXCEPTION 'invalid registry revision' USING ERRCODE='23514';
            END IF;
            RETURN NEW;
        END $$
    """)
    op.execute("REVOKE ALL ON FUNCTION arbiter.guard_registry_revision() FROM PUBLIC")
    op.execute("""
        CREATE TRIGGER registry_revision_guard BEFORE INSERT OR UPDATE ON arbiter.provider_models
        FOR EACH ROW EXECUTE FUNCTION arbiter.guard_registry_revision()
    """)
    op.execute("""
        CREATE FUNCTION arbiter.provision_model(p_alias text,p_adapter text,p_digest text,
            p_context bigint,p_output bigint,p_charge bigint,p_active boolean,
            p_approval text,p_expected bigint,p_id uuid,p_journal uuid,p_correlation uuid)
        RETURNS TABLE (model_id uuid,revision bigint,journal_id uuid)
        LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
        DECLARE v_id uuid; v_revision bigint;
        BEGIN
            IF session_user<>'arbiter_operator' OR
                NULLIF(current_setting('arbiter.tenant_id',true),'') IS NOT NULL THEN
                RAISE EXCEPTION 'permission denied' USING ERRCODE='42501';
            END IF;
            IF p_alias IS NULL OR p_alias !~ '^[a-z][a-z0-9_-]{0,63}$'
                OR p_adapter IS DISTINCT FROM 'ollama'
                OR p_digest IS NULL OR p_digest !~ '^sha256:[0-9a-f]{64}$'
                OR p_approval IS NULL OR p_approval !~ '^sha256:[0-9a-f]{64}$'
                OR p_context IS NULL OR p_context<1 OR p_output IS NULL
                OR p_output NOT BETWEEN 1 AND 1024 OR p_output>p_context
                OR p_charge IS NULL OR p_charge<1 OR p_active IS NULL
                OR p_id IS NULL OR p_journal IS NULL OR p_correlation IS NULL THEN
                RAISE EXCEPTION 'invalid model configuration' USING ERRCODE='22023';
            END IF;
            IF p_expected IS NULL THEN
                v_id:=p_id; v_revision:=1;
            ELSE
                SELECT m.id,m.revision INTO v_id,v_revision FROM arbiter.provider_models m
                    WHERE m.alias=p_alias FOR UPDATE;
                IF NOT FOUND OR p_expected<1 OR v_revision<>p_expected
                    OR v_revision=9223372036854775807 THEN
                    RAISE EXCEPTION 'registry conflict' USING ERRCODE='23505';
                END IF;
                v_revision:=v_revision+1;
            END IF;
            INSERT INTO arbiter.model_registry_journal
                (id,model_id,revision,alias,adapter,model_digest,context_cap,output_cap,
                 credit_charge,active,approval_digest,actor_reference,action,outcome,correlation_id)
            VALUES (p_journal,v_id,v_revision,p_alias,p_adapter,p_digest,p_context,p_output,
                p_charge,p_active,p_approval,'arbiter_operator',
                CASE WHEN p_expected IS NULL THEN 'model_registered' ELSE 'model_updated' END,
                'succeeded',p_correlation);
            IF p_expected IS NULL THEN
                INSERT INTO arbiter.provider_models
                    (id,alias,adapter,model_digest,context_cap,output_cap,credit_charge,
                     revision,active,journal_id)
                VALUES (v_id,p_alias,p_adapter,p_digest,p_context,p_output,p_charge,1,
                    p_active,p_journal);
            ELSE
                UPDATE arbiter.provider_models SET adapter=p_adapter,model_digest=p_digest,
                    context_cap=p_context,output_cap=p_output,credit_charge=p_charge,
                    active=p_active,revision=v_revision,journal_id=p_journal WHERE id=v_id;
            END IF;
            RETURN QUERY SELECT v_id,v_revision,p_journal;
        END $$
    """)
    op.execute("""
        REVOKE ALL ON FUNCTION arbiter.provision_model(text,text,text,bigint,bigint,bigint,
            boolean,text,bigint,uuid,uuid,uuid) FROM PUBLIC
    """)
    op.execute("""
        GRANT EXECUTE ON FUNCTION arbiter.provision_model(text,text,text,bigint,bigint,bigint,
            boolean,text,bigint,uuid,uuid,uuid) TO arbiter_operator
    """)


def downgrade() -> None:
    op.execute("""DROP FUNCTION arbiter.provision_model(text,text,text,bigint,bigint,bigint,
        boolean,text,bigint,uuid,uuid,uuid) RESTRICT""")
    op.execute("ALTER TABLE arbiter.provider_models DROP CONSTRAINT registry_revision_journal_fk")
    op.execute("DROP TRIGGER registry_revision_guard ON arbiter.provider_models")
    op.execute("DROP FUNCTION arbiter.guard_registry_revision() RESTRICT")
    op.execute("ALTER TABLE arbiter.provider_models DROP COLUMN journal_id")
    op.execute("DROP TABLE arbiter.model_registry_journal RESTRICT")
    op.execute("DROP FUNCTION arbiter.guard_registry_journal() RESTRICT")
