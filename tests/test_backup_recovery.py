"""Native logical restore preserves security, governance and recovery authority."""

import hashlib
import json
import os
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from multiprocessing import get_context
from multiprocessing.connection import Connection
from pathlib import Path
from time import monotonic, sleep
from uuid import uuid4

import psycopg
import pytest
from fastapi.testclient import TestClient
from psycopg import sql
from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine
from sqlalchemy.exc import DBAPIError
from sqlalchemy.pool import NullPool
from test_chat_transport import _headers, _request, _service
from test_history_retention import audit, window
from test_provider_binding import DIGEST, bind
from test_provider_binding import binding_store as binding_store
from test_rate_admission import redis_ready as redis_ready
from test_request_retention import age, completed
from test_reservation_transactions import ReservationStore

from arbiter.config import DatabaseSettings
from arbiter.governance.capacity import CapacityGate
from arbiter.governance.dispatch import DispatchService
from arbiter.identity.context import TenantContext
from arbiter.identity.keys import InvalidKey
from arbiter.identity.workload import WorkloadAccess
from arbiter.main import create_app
from arbiter.operations.maintenance import MaintenanceService
from arbiter.operations.registry import ModelApproval
from arbiter.operations.retention import RetentionService
from arbiter.persistence.maintenance import clear_unknown
from arbiter.persistence.provider_binding import PinnedModelIdentity, dispatched_ollama_binding
from arbiter.persistence.tenant import tenant_transaction
from arbiter.persistence.workload import KeyBinding, resolve_key

pytest_plugins = ("test_migrations",)
pytestmark = pytest.mark.skipif(
    any(
        os.environ.get(name) != "1"
        for name in (
            "ARBITER_TEST_DATABASE",
            "ARBITER_TEST_MIGRATIONS",
            "ARBITER_TEST_REDIS",
            "ARBITER_TEST_EXIT_HOST",
        )
    ),
    reason="requires disposable PostgreSQL/Redis and verify-phase3.ps1 -Phase recovery",
)
BACKUP_REPLY_SECONDS = 300


@contextmanager
def admin_database(database: str) -> Iterator[psycopg.Connection[tuple[object, ...]]]:
    settings = DatabaseSettings()
    with psycopg.connect(
        host=settings.host,
        port=settings.port,
        dbname=database,
        user="arbiter_bootstrap",
        password=settings.password("bootstrap").get_secret_value(),
        connect_timeout=5,
        autocommit=True,
    ) as connection:
        yield connection


def snapshot(database: str) -> dict[str, tuple[int, str]]:
    """Compare all durable rows, without placing verifiers or tenant data in evidence."""
    result: dict[str, tuple[int, str]] = {}
    with admin_database(database) as connection:
        tables = connection.execute(
            "SELECT schemaname,tablename FROM pg_tables WHERE schemaname='arbiter' "
            "OR (schemaname='public' AND tablename='alembic_version') ORDER BY 1,2"
        ).fetchall()
        for schema, table in tables:
            rows = connection.execute(
                sql.SQL(
                    "SELECT row_to_json(t)::text FROM {} t ORDER BY row_to_json(t)::text"
                ).format(sql.Identifier(str(schema), str(table)))
            ).fetchall()
            digest = hashlib.sha256()
            for row in rows:
                digest.update(str(row[0]).encode())
                digest.update(b"\n")
            result[f"{schema}.{table}"] = len(rows), digest.hexdigest()
    return result


def schema_security(database: str) -> list[tuple[object, ...]]:
    with admin_database(database) as connection:
        return connection.execute("""
            SELECT 'table',c.relname,pg_get_userbyid(c.relowner),
                c.relrowsecurity::text,c.relforcerowsecurity::text
            FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
            WHERE n.nspname='arbiter' AND c.relkind='r'
            UNION ALL
            SELECT 'function',p.oid::regprocedure::text,pg_get_userbyid(p.proowner),
                p.prosecdef::text,pg_get_functiondef(p.oid)
            FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
            WHERE n.nspname='arbiter'
            UNION ALL
            -- pg_dump/reparse can distribute equivalent array casts differently.
            -- Compare policy authority here; exercise predicates through real roles below.
            SELECT 'policy',tablename,policyname,roles::text,
                concat_ws('|',cmd,permissive,(qual IS NOT NULL)::text,
                    (with_check IS NOT NULL)::text)
            FROM pg_policies WHERE schemaname='arbiter'
            UNION ALL
            SELECT 'grant',table_name,grantee,privilege_type,is_grantable
            FROM information_schema.role_table_grants WHERE table_schema='arbiter'
            UNION ALL
            SELECT 'column_grant',c.relname||'.'||a.attname,
                CASE WHEN g.grantee=0 THEN 'PUBLIC' ELSE pg_get_userbyid(g.grantee) END,
                g.privilege_type,concat_ws('|',pg_get_userbyid(g.grantor),g.is_grantable::text)
            FROM pg_attribute a JOIN pg_class c ON c.oid=a.attrelid
            JOIN pg_namespace n ON n.oid=c.relnamespace,
                LATERAL aclexplode(a.attacl) g
            WHERE n.nspname='arbiter' AND c.relkind='r' AND a.attnum>0 AND NOT a.attisdropped
            UNION ALL
            SELECT 'function_grant',p.oid::regprocedure::text,
                CASE WHEN a.grantee=0 THEN 'PUBLIC' ELSE pg_get_userbyid(a.grantee) END,
                a.privilege_type,a.is_grantable::text
            FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace,
                LATERAL aclexplode(COALESCE(p.proacl,acldefault('f',p.proowner))) a
            WHERE n.nspname='arbiter'
            ORDER BY 1,2,3,4,5
        """).fetchall()


def column_privileges(database: str) -> dict[tuple[str, str, str, str], tuple[bool, bool]]:
    """Effective permissions include table-level/inherited grants and grant options."""
    with admin_database(database) as connection:
        rows = connection.execute("""
            WITH columns AS MATERIALIZED (
                SELECT c.oid,c.relname,a.attnum,a.attname FROM pg_attribute a
                JOIN pg_class c ON c.oid=a.attrelid
                JOIN pg_namespace n ON n.oid=c.relnamespace
                WHERE n.nspname='arbiter' AND c.relkind='r'
                    AND a.attnum>0 AND NOT a.attisdropped
            )
            SELECT r.rolname,c.relname,c.attname,p.privilege,
                has_column_privilege(r.oid,c.oid,c.attnum,p.privilege),
                has_column_privilege(r.oid,c.oid,c.attnum,p.privilege||' WITH GRANT OPTION')
            FROM columns c CROSS JOIN pg_roles r CROSS JOIN
                (VALUES ('SELECT'),('INSERT'),('UPDATE'),('REFERENCES')) p(privilege)
            WHERE r.rolname LIKE 'arbiter\\_%' ESCAPE '\\'
            ORDER BY 1,2,3,4
        """).fetchall()
    return {
        (str(role), str(table), str(column), str(privilege)): (bool(allowed), bool(grantable))
        for role, table, column, privilege, allowed, grantable in rows
    }


def assert_column_boundaries(
    privileges: dict[tuple[str, str, str, str], tuple[bool, bool]],
) -> None:
    protected = {
        "quota_windows": ("committed", "reserved"),
        "budget_windows": ("committed", "reserved"),
        "api_keys": ("verifier", "pepper_version", "scopes", "expires_at", "revoked_at"),
        "accounting_events": ("credits", "request_count", "kind"),
        "audit_events": ("action", "occurred_at", "actor_reference", "outcome"),
    }
    for table, columns in protected.items():
        for column in columns:
            assert privileges["arbiter_runtime", table, column, "UPDATE"] == (False, False)
    assert privileges["arbiter_runtime", "api_keys", "verifier", "SELECT"] == (False, False)
    for table in ("quota_windows", "budget_windows"):
        for role in ("arbiter_reservation_writer", "arbiter_release_writer"):
            assert privileges[role, table, "reserved", "UPDATE"] == (True, False)
            assert privileges[role, table, "committed", "UPDATE"] == (False, False)
        for column in ("reserved", "committed"):
            assert privileges["arbiter_dispatch_writer", table, column, "UPDATE"] == (True, False)
        assert privileges["arbiter_reservation_writer", table, "reserved", "INSERT"] == (
            True,
            False,
        )
    for column in ("state", "finished_at", "outcome", "input_tokens", "output_tokens"):
        assert privileges["arbiter_terminal_writer", "requests", column, "UPDATE"] == (True, False)
    assert privileges["arbiter_key_writer", "api_keys", "revoked_at", "UPDATE"] == (True, False)
    assert privileges["arbiter_key_lookup", "api_keys", "verifier", "SELECT"] == (True, False)
    assert privileges["arbiter_maintenance_worker", "requests", "finished_at", "UPDATE"] == (
        True,
        False,
    )


@contextmanager
def template1_contamination() -> Iterator[str]:
    """Exclusive, reversible sentinel in the dedicated host-gated disposable cluster."""
    root = Path(os.environ["ARBITER_TEST_EXIT_CONTROL"])
    assert root == Path("/evidence/control"), "requires the dedicated disposable driver mount"
    schema, control = "template_probe_" + uuid4().hex, "arbiter_template_probe_" + uuid4().hex
    object_name = schema + ".marker"
    with admin_database(DatabaseSettings().name) as admin:
        assert admin.execute("SELECT pg_try_advisory_lock(58435,2)").fetchone() == (True,)
        try:
            with admin_database("template1") as template:
                template.execute(sql.SQL("CREATE SCHEMA {}").format(sql.Identifier(schema)))
                template.execute(
                    sql.SQL("CREATE TABLE {} (marker integer)").format(
                        sql.Identifier(schema, "marker")
                    )
                )
            # Close template1 connections before cloning; prove the sentinel really
            # contaminates template1 clones, not only a catalog string comparison.
            admin.execute(
                sql.SQL("CREATE DATABASE {} TEMPLATE template1").format(sql.Identifier(control))
            )
            admin.execute(
                sql.SQL("REVOKE ALL ON DATABASE {} FROM PUBLIC").format(sql.Identifier(control))
            )
            with admin_database(control) as probe:
                assert probe.execute(
                    "SELECT to_regclass(%s) IS NOT NULL", (object_name,)
                ).fetchone() == (True,)
            yield object_name
        finally:
            with admin_database("template1") as template:
                template.execute(
                    sql.SQL("DROP TABLE IF EXISTS {}").format(sql.Identifier(schema, "marker"))
                )
                template.execute(sql.SQL("DROP SCHEMA IF EXISTS {}").format(sql.Identifier(schema)))
            if admin.execute("SELECT 1 FROM pg_database WHERE datname=%s", (control,)).fetchone():
                admin.execute(sql.SQL("DROP DATABASE {}").format(sql.Identifier(control)))
            admin.execute("SELECT pg_advisory_unlock(58435,2)")
    with admin_database("template1") as template:
        assert template.execute("SELECT to_regnamespace(%s)", (schema,)).fetchone() == (None,)


def restore_through_host(source: str, target: str) -> None:
    root = Path(os.environ["ARBITER_TEST_EXIT_CONTROL"])
    ticket = uuid4().hex
    pending = root / f"{ticket}.tmp"
    request, reply = root / f"{ticket}.request.json", root / f"{ticket}.reply.json"
    pending.write_text(
        json.dumps({"operation": "backup_restore", "source": source, "restore": target}),
        encoding="utf-8",
    )
    pending.rename(request)
    deadline = monotonic() + BACKUP_REPLY_SECONDS
    while monotonic() < deadline:
        if reply.is_file():
            assert json.loads(reply.read_text(encoding="utf-8")) == {"complete": True}
            return
        sleep(0.1)
    pytest.fail("native backup/restore controller did not complete")


def recovery_worker(control: Connection, database: str) -> None:
    """A genuinely fresh application process reconstructs only durable authority."""
    settings = DatabaseSettings()
    engines = [
        create_engine(
            settings.url(role).set(database=database), poolclass=NullPool, hide_parameters=True
        )
        for role in ("runtime", "maintenance")
    ]
    calls = 0

    def unexpected_dispatch(*args: object, **kwargs: object) -> None:
        nonlocal calls
        calls += 1
        raise AssertionError("startup recovery must never redispatch provider work")

    try:
        with pytest.MonkeyPatch.context() as patch:
            patch.setattr(DispatchService, "run_double_once", unexpected_dispatch)
            gate = CapacityGate(2)
            maintenance = MaintenanceService(engines[0], engines[1], gate)
            result = maintenance.run_once()
            control.send(
                (
                    result.marked_unknown,
                    result.unresolved_unknown,
                    gate.occupied,
                    maintenance.recovery_ready,
                    calls,
                )
            )
    finally:
        for engine in engines:
            engine.dispose()
        control.close()


def recover_in_fresh_process(database: str) -> None:
    context = get_context("spawn")
    parent, child = context.Pipe()
    worker = context.Process(target=recovery_worker, args=(child, database))
    worker.start()
    child.close()
    try:
        assert parent.poll(45), "fresh recovery process did not report its durable reconstruction"
        assert parent.recv() == (1, 2, 2, False, 0)
        worker.join(timeout=15)
        assert worker.exitcode == 0
    finally:
        if worker.is_alive():
            worker.terminate()
            worker.join(timeout=15)
        parent.close()
        worker.close()


def test_native_restore_preserves_security_accounting_and_recovery(
    binding_store: tuple[ReservationStore, ModelApproval],
    redis_ready: None,
) -> None:
    store, proof = binding_store
    bind(store, proof, 1, "fixture:one")
    retired, unknown, dispatched, reserved, cleared, revoked = (store.actor() for _ in range(6))
    retired_id = completed(store, retired)
    with tenant_transaction(store.runtime, TenantContext(retired.tenant)) as tx:
        idem: str = (
            tx.connection()
            .execute(
                text(
                    "SELECT idempotency_key FROM arbiter.requests "
                    "WHERE tenant_id=:tenant AND id=:id"
                ),
                {"tenant": retired.tenant, "id": retired_id},
            )
            .scalar_one()
        )
    age(store, retired, retired_id, datetime(2020, 1, 1, tzinfo=UTC))
    assert (
        RetentionService(store.operator).run_once(retired.tenant, retired.key).requests_removed == 1
    )
    unknown_id = completed(store, unknown, state="unknown", mode="deadline")
    dispatched_id = completed(store, dispatched, state="dispatched")
    reserved_id = completed(store, reserved, state="reserved")
    cleared_id = completed(store, cleared, state="unknown", mode="deadline")
    assert clear_unknown(store.operator, cleared.tenant, cleared_id)
    with store.migration.begin() as connection:
        connection.execute(
            text("SELECT set_config('arbiter.tenant_id',:tenant,true)"),
            {"tenant": str(revoked.tenant)},
        )
        connection.execute(
            text(
                "UPDATE arbiter.api_keys SET revoked_at=clock_timestamp() "
                "WHERE tenant_id=:tenant AND id=:key"
            ),
            {"tenant": revoked.tenant, "key": revoked.key},
        )
    # Exercise and preserve actual Slice 2 deletion plus its fresh cleanup evidence.
    window(store, revoked, "quota_windows", datetime(2018, 1, 1, tzinfo=UTC))
    audit(store, revoked, datetime(2018, 1, 1, tzinfo=UTC))
    cleanup = RetentionService(store.operator).retire_history(revoked.tenant)
    assert cleanup.quota_windows_removed == cleanup.standalone_audits_removed == 1
    # Later binding revision must not replace the old dispatched target in the archive.
    bind(store, proof, 2, "fixture:two")
    source = store.migration.url.database
    assert source is not None
    before, security = snapshot(source), schema_security(source)
    source_columns = column_privileges(source)
    assert_column_boundaries(source_columns)
    target = "arbiter_restore_" + uuid4().hex
    engines: list[Engine] = []
    try:
        with template1_contamination() as sentinel:
            restore_through_host(source, target)
            with admin_database(target) as connection:
                assert connection.execute("SELECT to_regclass(%s)", (sentinel,)).fetchone() == (
                    None,
                )
        assert snapshot(source) == before, "backup/restore must not mutate its source"
        assert snapshot(target) == before
        assert schema_security(target) == security
        restored_columns = column_privileges(target)
        assert restored_columns == source_columns
        assert_column_boundaries(restored_columns)
        settings = DatabaseSettings()
        engines = [
            create_engine(
                settings.url(role).set(database=target), poolclass=NullPool, hide_parameters=True
            )
            for role in ("runtime", "operator", "migration", "maintenance")
        ]
        restored = ReservationStore(engines[0], engines[1], engines[2], store.model, store.alias)
        # Real runtime connections must reject writes, independently of catalog checks.
        for database_store in (store, restored):
            for table, columns in {
                "quota_windows": ("committed", "reserved"),
                "budget_windows": ("committed", "reserved"),
                "api_keys": ("verifier", "pepper_version", "scopes", "expires_at", "revoked_at"),
                "accounting_events": ("credits", "request_count", "kind"),
                "audit_events": ("action", "occurred_at", "actor_reference", "outcome"),
            }.items():
                for column in columns:
                    with pytest.raises(DBAPIError) as denied:
                        with tenant_transaction(
                            database_store.runtime, TenantContext(unknown.tenant)
                        ) as tx:
                            tx.connection().execute(
                                text(
                                    sql.SQL("UPDATE {} SET {}={} WHERE tenant_id=:tenant")
                                    .format(
                                        sql.Identifier("arbiter", table),
                                        sql.Identifier(column),
                                        sql.Identifier(column),
                                    )
                                    .as_string()
                                ),
                                {"tenant": unknown.tenant},
                            )
                    assert getattr(denied.value.orig, "sqlstate", None) == "42501"
        # Exercise every tenant-owned relation the runtime can read, including
        # fail-closed access without a tenant GUC, rather than trusting policy text.
        with admin_database(target) as connection:
            scoped_tables = connection.execute(
                "WITH scoped AS MATERIALIZED (SELECT c.oid,c.relname,a.attnum "
                "FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace "
                "JOIN pg_attribute a ON a.attrelid=c.oid AND a.attname='tenant_id' "
                "WHERE n.nspname='arbiter' AND c.relkind='r') SELECT relname FROM scoped "
                "WHERE has_column_privilege('arbiter_runtime',oid,attnum,'SELECT') "
                "ORDER BY relname"
            ).fetchall()
        assert scoped_tables
        for (scoped_table,) in scoped_tables:
            scoped_statement = text(
                sql.SQL("SELECT count(tenant_id) FROM {} WHERE tenant_id<>:tenant")
                .format(sql.Identifier("arbiter", str(scoped_table)))
                .as_string()
            )
            with tenant_transaction(restored.runtime, TenantContext(unknown.tenant)) as tx:
                assert (
                    tx.connection()
                    .execute(scoped_statement, {"tenant": unknown.tenant})
                    .scalar_one()
                    == 0
                )
            with restored.runtime.begin() as connection:
                assert connection.execute(scoped_statement, {"tenant": uuid4()}).scalar_one() == 0
        for actor in (unknown, dispatched, reserved, cleared):
            assert restored.totals(actor) == store.totals(actor)
        assert restored.totals(unknown) == (1, 0, 10, 0)
        assert restored.totals(reserved) == (0, 1, 0, 10)
        for actor, identifier, state in (
            (unknown, unknown_id, "unknown"),
            (dispatched, dispatched_id, "dispatched"),
            (reserved, reserved_id, "reserved"),
            (cleared, cleared_id, "unknown"),
        ):
            with tenant_transaction(restored.runtime, TenantContext(actor.tenant)) as tx:
                assert (
                    tx.connection()
                    .execute(
                        text(
                            "SELECT state FROM arbiter.requests WHERE tenant_id=:tenant AND id=:id"
                        ),
                        {"tenant": actor.tenant, "id": identifier},
                    )
                    .scalar_one()
                    == state
                )
                assert (
                    tx.connection()
                    .execute(
                        text("SELECT count(*) FROM arbiter.tenants WHERE tenant_id=:foreign"),
                        {"foreign": retired.tenant},
                    )
                    .scalar_one()
                    == 0
                )
        with restored.runtime.begin() as connection:
            with pytest.raises(InvalidKey):
                resolve_key(connection, revoked.candidate)
        with tenant_transaction(restored.runtime, TenantContext(dispatched.tenant)) as tx:
            selection = dispatched_ollama_binding(
                tx,
                KeyBinding(dispatched.key, dispatched.tenant, ("inference:write",)),
                dispatched_id,
                PinnedModelIdentity(store.model, DIGEST, 2),
            )
            assert selection.ollama_binding.native_name == "fixture:one"
        for statement in (
            "SELECT arbiter.retire_history(:tenant,NULL,:op,100)",
            "DELETE FROM arbiter.audit_events WHERE tenant_id=:tenant",
            "UPDATE arbiter.accounting_events SET credits=0 WHERE tenant_id=:tenant",
            "TRUNCATE arbiter.audit_events",
        ):
            with pytest.raises(DBAPIError) as denied:
                with tenant_transaction(restored.runtime, TenantContext(retired.tenant)) as tx:
                    tx.connection().execute(
                        text(statement), {"tenant": retired.tenant, "op": uuid4()}
                    )
            assert getattr(denied.value.orig, "sqlstate", None) == "42501"
        service, provider, names, gate = _service(restored)
        app = create_app(
            chat_service=service,
            workload_access=WorkloadAccess(restored.verifier, restored.runtime),
        )
        with TestClient(app) as client:
            duplicate = client.post(
                "/v1/chat/completions",
                json=_request(store.alias, "synthetic reservation input"),
                headers=_headers(retired.credential.get_secret_value(), idem),
            )
            assert duplicate.status_code == 409
            assert duplicate.json()["error"]["code"] == "request_already_admitted"
            assert duplicate.json()["request_id"] == str(retired_id)
            conflict = client.post(
                "/v1/chat/completions",
                json=_request(store.alias, "different"),
                headers=_headers(retired.credential.get_secret_value(), idem),
            )
            assert conflict.status_code == 409
            assert conflict.json()["error"]["code"] == "idempotency_conflict"
            status = client.get(
                f"/v1/requests/{retired_id}",
                headers={"Authorization": "Bearer " + retired.credential.get_secret_value()},
            )
            assert status.status_code == 410 and status.json()["error"]["code"] == "request_retired"
            foreign = client.get(
                f"/v1/requests/{retired_id}",
                headers={"Authorization": "Bearer " + unknown.credential.get_secret_value()},
            )
            assert foreign.status_code == 404
        assert provider.calls == () and names == [] and gate.occupied == 0
        assert snapshot(target) == before, "tombstone retries must not reserve or charge"
        # No inherited engine/capacity state: actual spawn reconstructs already-unknown
        # work, marks the prior dispatch unknown, and fails if dispatch is attempted.
        recover_in_fresh_process(target)
        # Repeat startup reconstruction to prove another restart cannot clear quarantine.
        restarted = CapacityGate(2)
        maintenance = MaintenanceService(restored.runtime, engines[3], restarted)
        first = maintenance.run_once()
        assert first.marked_unknown == 0 and first.unresolved_unknown == 2
        assert restarted.occupied == 2 and not maintenance.recovery_ready
        assert maintenance.run_once().marked_unknown == 0
        for actor, identifier in ((unknown, unknown_id), (dispatched, dispatched_id)):
            assert clear_unknown(restored.operator, actor.tenant, identifier)
            assert not clear_unknown(restored.operator, actor.tenant, identifier)
            with tenant_transaction(restored.runtime, TenantContext(actor.tenant)) as tx:
                assert (
                    tx.connection()
                    .execute(
                        text(
                            "SELECT state FROM arbiter.requests WHERE tenant_id=:tenant AND id=:id"
                        ),
                        {"tenant": actor.tenant, "id": identifier},
                    )
                    .scalar_one()
                    == "unknown"
                )
            # Clearance evidence has intentionally no generic runtime SELECT grant.
            # Inspect its audit FK only with the verification bootstrap connection.
            with admin_database(target) as connection:
                assert connection.execute(
                    "SELECT count(*) FROM arbiter.capacity_clearances c "
                    "JOIN arbiter.audit_events a ON a.tenant_id=c.tenant_id AND a.id=c.audit_id "
                    "WHERE c.tenant_id=%s AND c.request_id=%s "
                    "AND a.action='unknown_capacity_cleared' AND a.outcome='succeeded' "
                    "AND a.actor_reference='arbiter_operator'",
                    (actor.tenant, identifier),
                ).fetchone() == (1,)
            assert restored.totals(actor) == (1, 0, 10, 0)
        assert maintenance.run_once().recovered_capacity == 2
        assert maintenance.run_once().recovered_capacity == 0
        assert restarted.occupied == 0 and maintenance.recovery_ready
        assert provider.calls == ()
        evidence = {
            "template1_control_inherited_sentinel": True,
            "template0_restore_excluded_sentinel": True,
            "column_privilege_checks": len(source_columns),
            "column_privileges_match": True,
            "runtime_protected_writes_denied": True,
            "writer_column_grants_preserved": True,
            "table_counts": {table: count for table, (count, _) in before.items()},
            "source_unchanged": True,
            "restored_rows_match": True,
            "restored_security_matches": True,
            "tombstone_duplicate_status": 409,
            "tombstone_conflict_status": 409,
            "retired_status": 410,
            "revoked_key_rejected": True,
            "captured_binding_preserved": True,
            "provider_calls": 0,
            "reconstructed_unknown_slots": 2,
            "audited_capacity_releases": 2,
            "committed_charge_preserved": True,
        }
        (Path(os.environ["ARBITER_TEST_EXIT_CONTROL"]).parent / "restored-state.json").write_text(
            json.dumps(evidence, sort_keys=True), encoding="utf-8"
        )
    finally:
        for engine in engines:
            engine.dispose()
        # Only this generated restore target is removed, without FORCE or CASCADE.
        with admin_database(source) as connection:
            if connection.execute(
                "SELECT 1 FROM pg_database WHERE datname=%s", (target,)
            ).fetchone():
                connection.execute(sql.SQL("DROP DATABASE {}").format(sql.Identifier(target)))
