"""Tenant-owned verifier storage and one audited admin-only runtime mutation path."""

from alembic import op

revision: str = "0005_api_key_creation"
down_revision: str | None = "0004_identity_lookup"
branch_labels: str | None = None
depends_on: str | None = None

FUNCTION = (
    "arbiter.create_api_key(uuid,uuid,uuid,uuid,text,text,bytea,integer,"
    "text[],timestamptz,uuid,uuid)"
)
SCOPE = "tenant_id = NULLIF(current_setting('arbiter.tenant_id', true), '')::uuid"


def upgrade() -> None:
    op.execute("""
        ALTER TABLE arbiter.audit_events ADD CONSTRAINT audit_key_creation_target
        UNIQUE (tenant_id,id,target_id,actor_membership_id)
    """)
    op.execute("""
        CREATE TABLE arbiter.api_keys (
            id uuid PRIMARY KEY,
            tenant_id uuid NOT NULL REFERENCES arbiter.tenants(id),
            public_id varchar(32) NOT NULL UNIQUE CHECK (public_id ~ '^[0-9a-f]{32}$'),
            label varchar(64) NOT NULL CHECK (label ~ '^[ -~]{1,64}$' AND length(btrim(label)) > 0),
            verifier bytea NOT NULL CHECK (octet_length(verifier)=32),
            pepper_version integer NOT NULL CHECK (pepper_version > 0),
            scopes text[] NOT NULL CHECK (scopes IN (
                ARRAY['inference:write'], ARRAY['usage:read'],
                ARRAY['inference:write','usage:read'])),
            created_at timestamptz NOT NULL,
            expires_at timestamptz NOT NULL CHECK (expires_at > created_at
                AND expires_at <= created_at + interval '90 days'),
            revoked_at timestamptz CHECK (revoked_at IS NULL OR revoked_at >= created_at),
            created_by_membership_id uuid NOT NULL,
            creation_audit_id uuid NOT NULL,
            UNIQUE (tenant_id,id),
            CONSTRAINT key_creator_membership_fk FOREIGN KEY (tenant_id,created_by_membership_id)
                REFERENCES arbiter.memberships(tenant_id,id),
            CONSTRAINT key_creation_audit_fk FOREIGN KEY
                (tenant_id,creation_audit_id,id,created_by_membership_id)
                REFERENCES arbiter.audit_events(tenant_id,id,target_id,actor_membership_id)
                DEFERRABLE INITIALLY DEFERRED
        )
    """)
    op.execute("ALTER TABLE arbiter.api_keys ENABLE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE arbiter.api_keys FORCE ROW LEVEL SECURITY")
    op.execute(f"""
        CREATE POLICY tenant_ownership ON arbiter.api_keys AS RESTRICTIVE
        TO arbiter_runtime,arbiter_operator,arbiter_migration,arbiter_key_writer
        USING ({SCOPE}) WITH CHECK ({SCOPE})
    """)
    op.execute("""
        CREATE POLICY scoped_access ON arbiter.api_keys
        TO arbiter_runtime,arbiter_operator,arbiter_migration,arbiter_key_writer
        USING (true) WITH CHECK (true)
    """)
    op.execute("""
        CREATE FUNCTION arbiter.reject_key_change() RETURNS trigger
        LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog AS $$
        BEGIN
            IF (to_jsonb(NEW)-'revoked_at') IS DISTINCT FROM (to_jsonb(OLD)-'revoked_at') THEN
                RAISE EXCEPTION 'immutable key metadata' USING ERRCODE='23514';
            END IF;
            RETURN NEW;
        END $$
    """)
    op.execute("REVOKE ALL ON FUNCTION arbiter.reject_key_change() FROM PUBLIC")
    op.execute("""
        CREATE TRIGGER immutable_key BEFORE UPDATE ON arbiter.api_keys
        FOR EACH ROW EXECUTE FUNCTION arbiter.reject_key_change()
    """)
    op.execute("REVOKE ALL ON arbiter.api_keys FROM PUBLIC,arbiter_runtime,arbiter_operator")
    op.execute("""
        GRANT SELECT (id,tenant_id,public_id,label,scopes,created_at,expires_at,revoked_at,
                      created_by_membership_id,creation_audit_id)
        ON arbiter.api_keys TO arbiter_runtime,arbiter_operator
    """)
    op.execute("GRANT USAGE ON SCHEMA arbiter TO arbiter_key_writer")
    op.execute(
        "GRANT SELECT (id,tenant_id,status,policy_revision), UPDATE (status) "
        "ON arbiter.tenants TO arbiter_key_writer"
    )
    op.execute("""
        GRANT SELECT (id,tenant_id,principal_id,role,active)
        ON arbiter.memberships TO arbiter_key_writer
    """)
    op.execute("GRANT INSERT ON arbiter.api_keys,arbiter.audit_events TO arbiter_key_writer")
    for table in ("tenants", "memberships", "audit_events"):
        op.execute(f"""
            CREATE POLICY key_writer_scope ON arbiter.{table} AS RESTRICTIVE
            TO arbiter_key_writer USING ({SCOPE}) WITH CHECK ({SCOPE})
        """)
        op.execute(f"""
            CREATE POLICY key_writer_access ON arbiter.{table}
            TO arbiter_key_writer USING (true) WITH CHECK (true)
        """)
    op.execute("""
        CREATE POLICY key_writer_audit ON arbiter.audit_events AS RESTRICTIVE FOR INSERT
        TO arbiter_key_writer WITH CHECK (actor_type='member' AND action='api_key_created'
            AND outcome='succeeded' AND actor_reference=actor_membership_id::text)
    """)
    op.execute("""
        CREATE FUNCTION arbiter.create_api_key(
            p_tenant uuid,p_actor uuid,p_principal uuid,p_id uuid,p_public_id text,p_label text,
            p_verifier bytea,p_version integer,p_scopes text[],p_expires timestamptz,
            p_audit uuid,p_request uuid)
        RETURNS TABLE (created_at timestamptz,expires_at timestamptz)
        LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
        DECLARE
            v_status text; v_revision bigint; v_role text; v_active boolean;
            v_now timestamptz; v_expires timestamptz;
        BEGIN
            IF session_user <> 'arbiter_runtime' OR p_tenant IS NULL OR
                NULLIF(current_setting('arbiter.tenant_id',true),'')::uuid IS DISTINCT FROM p_tenant
            THEN
                RAISE EXCEPTION 'permission denied' USING ERRCODE='42501';
            END IF;
            SELECT t.status,t.policy_revision INTO v_status,v_revision FROM arbiter.tenants t
                WHERE t.tenant_id=p_tenant AND t.id=p_tenant FOR UPDATE;
            IF NOT FOUND OR v_status <> 'active' THEN
                RAISE EXCEPTION 'inaccessible tenant' USING ERRCODE='P0002';
            END IF;
            SELECT m.role,m.active INTO v_role,v_active FROM arbiter.memberships m
                WHERE m.tenant_id=p_tenant AND m.id=p_actor AND m.principal_id=p_principal;
            IF NOT FOUND OR NOT v_active THEN
                RAISE EXCEPTION 'inaccessible tenant' USING ERRCODE='P0002';
            END IF;
            IF v_role <> 'admin' THEN
                RAISE EXCEPTION 'permission denied' USING ERRCODE='42501';
            END IF;
            IF p_id IS NULL OR p_public_id IS NULL OR p_label IS NULL OR p_verifier IS NULL OR
                p_version IS NULL OR p_scopes IS NULL OR p_audit IS NULL OR p_request IS NULL OR
                p_public_id !~ '^[0-9a-f]{32}$' OR p_label !~ '^[ -~]{1,64}$' OR
                length(btrim(p_label))=0 OR position('arb1.' in p_label)>0 OR
                octet_length(p_verifier)<>32 OR p_version<1 OR NOT (p_scopes IN (
                    ARRAY['inference:write'],ARRAY['usage:read'],ARRAY['inference:write','usage:read']))
            THEN
                RAISE EXCEPTION 'invalid key request' USING ERRCODE='22023';
            END IF;
            v_now := clock_timestamp();
            v_expires := COALESCE(p_expires,v_now+interval '30 days');
            IF v_expires <= v_now OR v_expires > v_now+interval '90 days' THEN
                RAISE EXCEPTION 'invalid key request' USING ERRCODE='22023';
            END IF;
            INSERT INTO arbiter.api_keys (id,tenant_id,public_id,label,verifier,pepper_version,
                scopes,created_at,expires_at,created_by_membership_id,creation_audit_id)
                VALUES (p_id,p_tenant,p_public_id,p_label,p_verifier,p_version,p_scopes,
                        v_now,v_expires,p_actor,p_audit);
            INSERT INTO arbiter.audit_events (id,tenant_id,actor_type,actor_reference,
                actor_membership_id,action,target_id,policy_revision,request_id,occurred_at,outcome)
                VALUES (p_audit,p_tenant,'member',p_actor::text,p_actor,'api_key_created',p_id,
                        v_revision,p_request,v_now,'succeeded');
            RETURN QUERY SELECT v_now,v_expires;
        END $$
    """)
    op.execute(f"REVOKE ALL ON FUNCTION {FUNCTION} FROM PUBLIC")
    op.execute(f"GRANT EXECUTE ON FUNCTION {FUNCTION} TO arbiter_runtime")
    op.execute("GRANT CREATE ON SCHEMA arbiter TO arbiter_key_writer")
    op.execute(f"ALTER FUNCTION {FUNCTION} OWNER TO arbiter_key_writer")
    op.execute("REVOKE CREATE ON SCHEMA arbiter FROM arbiter_key_writer")


def downgrade() -> None:
    op.execute(f"DROP FUNCTION {FUNCTION} RESTRICT")
    op.execute("DROP TABLE arbiter.api_keys RESTRICT")
    op.execute("DROP FUNCTION arbiter.reject_key_change() RESTRICT")
    op.execute("ALTER TABLE arbiter.audit_events DROP CONSTRAINT audit_key_creation_target")
    op.execute("DROP POLICY key_writer_audit ON arbiter.audit_events")
    for table in ("tenants", "memberships", "audit_events"):
        op.execute(f"DROP POLICY key_writer_scope ON arbiter.{table}")
        op.execute(f"DROP POLICY key_writer_access ON arbiter.{table}")
        op.execute(f"REVOKE ALL ON arbiter.{table} FROM arbiter_key_writer")
    op.execute(
        "REVOKE SELECT (id,tenant_id,status,policy_revision), UPDATE (status) "
        "ON arbiter.tenants FROM arbiter_key_writer"
    )
    op.execute(
        "REVOKE SELECT (id,tenant_id,principal_id,role,active) "
        "ON arbiter.memberships FROM arbiter_key_writer"
    )
    op.execute("REVOKE USAGE ON SCHEMA arbiter FROM arbiter_key_writer")
