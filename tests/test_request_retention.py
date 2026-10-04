"""Real PostgreSQL retirement, retry and privilege proofs on disposable databases."""

import os
from collections.abc import Sequence
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from threading import Barrier
from uuid import UUID, uuid4

import pytest
from fastapi.testclient import TestClient
from psycopg import sql
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError
from test_chat_transport import _headers, _request, _service
from test_provider_binding import bind
from test_provider_binding import binding_store as binding_store
from test_rate_admission import redis_ready as redis_ready
from test_reservation_transactions import Actor, ReservationStore
from test_tenant_isolation import postgres_error, set_context

from arbiter.governance.capacity import CapacityGate, CapacityService
from arbiter.governance.dispatch import DispatchService
from arbiter.governance.release import ReleaseService
from arbiter.governance.reservation import IdempotencyConflict, RequestAlreadyAdmitted
from arbiter.identity.context import TenantContext
from arbiter.identity.workload import WorkloadAccess
from arbiter.main import create_app
from arbiter.operations.registry import ModelApproval
from arbiter.operations.retention import RetentionService
from arbiter.persistence.maintenance import clear_unknown
from arbiter.persistence.operator import OperatorAccessDenied, operator_transaction
from arbiter.persistence.tenant import tenant_transaction
from arbiter.persistence.usage import RetiredRequest, UsageRepository
from arbiter.providers.double import DeterministicProvider, DoubleMode

pytestmark = pytest.mark.skipif(
    os.environ.get("ARBITER_TEST_DATABASE") != "1"
    or os.environ.get("ARBITER_TEST_MIGRATIONS") != "1"
    or os.environ.get("ARBITER_TEST_REDIS") != "1",
    reason="requires real PostgreSQL, disposable migrated database and Redis",
)
pytest_plugins = ("test_migrations",)
# Far in the past: exact cutoff tests have no wall-clock scheduling margin.
CUTOFF = datetime(2020, 1, 1, tzinfo=UTC)


def completed(
    store: ReservationStore, actor: Actor, *, mode: DoubleMode = "success", state: str = "succeeded"
) -> UUID:
    gate = CapacityGate(1)
    lease = CapacityService(
        store.service(), ReleaseService(store.runtime), gate
    ).reserve_and_acquire(actor.credential, uuid4().hex, store.request())
    if state == "released":
        lease.release_before_dispatch("cancelled")
    elif state == "rejected_capacity":
        released = ReleaseService(store.runtime).release(
            lease._binding, lease.result.request_id, "rejected_capacity"
        )
        lease._release_after_confirmed(released)
    elif state != "reserved":
        DispatchService(store.runtime).authorize(lease)
        if state != "dispatched":
            provider = DeterministicProvider(store.model, "sha256:" + "d" * 64, 256, mode=mode)
            DispatchService(store.runtime).run_double_once(
                lease, store.request(), provider, store.fingerprint
            )
    return lease.result.request_id


def age(store: ReservationStore, actor: Actor, request: UUID, finished: datetime) -> None:
    """Owner-only fixture aging; production constraints/guards are restored in the transaction.

    Move original UTC windows with their unchanged totals and identities. No test
    cleanup privilege or predicate is used to create these historical fixtures.
    """
    created = finished - timedelta(hours=1)
    day = created.replace(hour=0, minute=0, second=0, microsecond=0)
    month = day.replace(day=1)
    with store.migration.begin() as connection:
        set_context(connection, actor.tenant)
        constraints: Sequence[str] = (
            connection.execute(
                text("""
            SELECT conname FROM pg_constraint WHERE conrelid='arbiter.requests'::regclass
                AND confrelid IN ('arbiter.quota_windows'::regclass,
                    'arbiter.budget_windows'::regclass)
        """)
            )
            .scalars()
            .all()
        )
        for name in constraints:
            connection.execute(
                text(
                    sql.SQL(
                        "ALTER TABLE arbiter.requests ALTER CONSTRAINT {} "
                        "DEFERRABLE INITIALLY DEFERRED"
                    )
                    .format(sql.Identifier(name))
                    .as_string()
                )
            )
        triggers = {
            "requests": (
                "immutable_request_snapshot",
                "guard_release_terminal",
                "guard_terminal_state",
            ),
            "quota_windows": ("immutable_window_identity",),
            "budget_windows": ("immutable_window_identity",),
        }
        for table, names in triggers.items():
            for name in names:
                connection.execute(
                    text(
                        sql.SQL("ALTER TABLE {} DISABLE TRIGGER {}")
                        .format(sql.Identifier("arbiter", table), sql.Identifier(name))
                        .as_string()
                    )
                )
        for table, start in (("quota_windows", day), ("budget_windows", month)):
            connection.execute(
                text(
                    sql.SQL("UPDATE {} SET window_start=:start WHERE tenant_id=:tenant")
                    .format(sql.Identifier("arbiter", table))
                    .as_string()
                ),
                {"tenant": actor.tenant, "start": start},
            )
        connection.execute(
            text("""
            UPDATE arbiter.requests SET created_at=:created,quota_start=:day,budget_start=:month,
                dispatched_at=CASE WHEN dispatched_at IS NULL THEN NULL ELSE :created END,
                finished_at=CASE WHEN finished_at IS NULL THEN NULL ELSE :finished END
            WHERE tenant_id=:tenant AND id=:request
        """),
            {
                "tenant": actor.tenant,
                "request": request,
                "created": created,
                "finished": finished,
                "day": day,
                "month": month,
            },
        )
        connection.execute(text("SET CONSTRAINTS ALL IMMEDIATE"))
        for table, names in triggers.items():
            for name in names:
                connection.execute(
                    text(
                        sql.SQL("ALTER TABLE {} ENABLE TRIGGER {}")
                        .format(sql.Identifier("arbiter", table), sql.Identifier(name))
                        .as_string()
                    )
                )
        for name in constraints:
            connection.execute(
                text(
                    sql.SQL("ALTER TABLE arbiter.requests ALTER CONSTRAINT {} NOT DEFERRABLE")
                    .format(sql.Identifier(name))
                    .as_string()
                )
            )


def tombstones(store: ReservationStore, actor: Actor) -> list[dict[str, object]]:
    with tenant_transaction(store.runtime, TenantContext(actor.tenant)) as tx:
        return [
            dict(row)
            for row in tx.connection()
            .execute(
                text("SELECT * FROM arbiter.idempotency_tombstones WHERE tenant_id=:tenant"),
                {"tenant": actor.tenant},
            )
            .mappings()
        ]


@pytest.mark.parametrize("offset,removed", [(1, 0), (0, 1), (-1, 1)])
def test_exact_finished_cutoff_is_inclusive_and_deterministic(
    binding_store: tuple[ReservationStore, ModelApproval], offset: int, removed: int
) -> None:
    store, _proof = binding_store
    actor = store.actor()
    identifier = completed(store, actor)
    age(store, actor, identifier, CUTOFF + timedelta(microseconds=offset))
    totals = store.totals(actor)
    result = RetentionService(store.operator).run_once(actor.tenant, actor.key, cutoff=CUTOFF)
    assert result.requests_removed == removed
    assert len(tombstones(store, actor)) == removed
    assert store.totals(actor) == totals


def test_recent_terminal_cannot_be_retired_and_future_cutoff_rejected(
    binding_store: tuple[ReservationStore, ModelApproval],
) -> None:
    store, _proof = binding_store
    actor = store.actor()
    identifier = completed(store, actor)
    age(store, actor, identifier, datetime.now(UTC) - timedelta(days=89))
    assert RetentionService(store.operator).run_once(actor.tenant, actor.key).requests_removed == 0
    with pytest.raises(DBAPIError):
        RetentionService(store.operator).run_once(actor.tenant, actor.key, cutoff=datetime.now(UTC))
    assert tombstones(store, actor) == []


@pytest.mark.parametrize(
    "state,mode",
    [
        ("reserved", "success"),
        ("dispatched", "success"),
        ("unknown", "deadline"),
        ("cleared_unknown", "deadline"),
    ],
)
def test_unresolved_work_never_retires(
    binding_store: tuple[ReservationStore, ModelApproval], state: str, mode: DoubleMode
) -> None:
    store, _proof = binding_store
    actor = store.actor()
    identifier = completed(
        store, actor, state="unknown" if state == "cleared_unknown" else state, mode=mode
    )
    if state == "cleared_unknown":
        assert clear_unknown(store.operator, actor.tenant, identifier)
    age(store, actor, identifier, CUTOFF)
    totals = store.totals(actor)
    assert (
        RetentionService(store.operator)
        .run_once(actor.tenant, actor.key, cutoff=CUTOFF)
        .requests_removed
        == 0
    )
    assert tombstones(store, actor) == [] and store.totals(actor) == totals


@pytest.mark.parametrize(
    "state,mode",
    [
        ("succeeded", "success"),
        ("failed", "definite_failure"),
        ("released", "success"),
        ("rejected_capacity", "success"),
    ],
)
def test_definite_terminal_graph_removed_with_minimal_tombstone_and_audit(
    binding_store: tuple[ReservationStore, ModelApproval], state: str, mode: DoubleMode
) -> None:
    store, proof = binding_store
    bind(store, proof, 1, "fixture:one")
    actor = store.actor()
    identifier = completed(store, actor, state=state, mode=mode)
    age(store, actor, identifier, CUTOFF)
    totals = store.totals(actor)
    result = RetentionService(store.operator).run_once(actor.tenant, actor.key, cutoff=CUTOFF)
    assert result.requests_removed == result.reservations_removed == 1
    assert result.accounting_removed == 2 and result.audits_removed in (2, 3)
    assert result.bindings_removed == int(state in {"succeeded", "failed"})
    (tombstone,) = tombstones(store, actor)
    assert set(tombstone) == {
        "tenant_id",
        "key_id",
        "idempotency_key",
        "request_id",
        "payload_hmac",
        "fingerprint_version",
        "state",
        "tombstoned_at",
    }
    assert tombstone["request_id"] == identifier and tombstone["state"] == state
    assert store.totals(actor) == totals
    with tenant_transaction(store.runtime, TenantContext(actor.tenant)) as tx:
        connection = tx.connection()
        for table in ("requests", "reservations", "accounting_events"):
            assert (
                connection.execute(
                    text(
                        sql.SQL("SELECT count(*) FROM {} WHERE tenant_id=:tenant")
                        .format(sql.Identifier("arbiter", table))
                        .as_string()
                    ),
                    {"tenant": actor.tenant},
                ).scalar_one()
                == 0
            )
        audit = connection.execute(
            text("SELECT * FROM arbiter.audit_events WHERE tenant_id=:tenant AND id=:id"),
            {"tenant": actor.tenant, "id": result.audit_id},
        ).one()
        assert audit.actor_type == "operator" and audit.actor_reference == "arbiter_operator"
        assert audit.outcome == "succeeded" and audit.action == "retention_cleaned"
        assert audit.request_id == audit.target_id and audit.occurred_at > CUTOFF
        assert audit.retention_summary["requests"] == 1
        assert set(audit.retention_summary) == {
            "cutoff",
            "requests",
            "reservations",
            "accounting",
            "audits",
            "bindings",
            "clearances",
            "tombstones",
        }
    with store.migration.begin() as connection:
        assert (
            connection.execute(
                text("SELECT count(*) FROM arbiter.provider_model_bindings WHERE model_id=:model"),
                {"model": store.model},
            ).scalar_one()
            == 1
        )
    repeated = RetentionService(store.operator).run_once(actor.tenant, actor.key, cutoff=CUTOFF)
    assert repeated.requests_removed == 0 and repeated.tombstones_removed == 0


def test_retired_retry_and_status_traverse_public_governance_without_provider_replay(
    binding_store: tuple[ReservationStore, ModelApproval],
    redis_ready: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store, proof = binding_store
    bind(store, proof, 1, "fixture:one")
    actor, foreign = store.actor(), store.actor()
    service, provider, names, gate = _service(store)
    headers = _headers(actor.credential.get_secret_value())
    with TestClient(
        create_app(
            chat_service=service, workload_access=WorkloadAccess(store.verifier, store.runtime)
        )
    ) as client:
        first = client.post("/v1/chat/completions", headers=headers, json=_request(store.alias))
        assert first.status_code == 200, first.text
        identifier = UUID(first.json()["request_id"])
        age(store, actor, identifier, CUTOFF)
        totals = store.totals(actor)
        RetentionService(store.operator).run_once(actor.tenant, actor.key, cutoff=CUTOFF)
        redis_calls = 0

        def unexpected_rate_admission(*_args: object, **_kwargs: object) -> None:
            nonlocal redis_calls
            redis_calls += 1
            raise AssertionError("retired retries must not enter Redis admission")

        monkeypatch.setattr("arbiter.governance.rate.RateGate.admit", unexpected_rate_admission)
        same = client.post("/v1/chat/completions", headers=headers, json=_request(store.alias))
        assert (
            same.status_code == 409 and same.json()["error"]["code"] == "request_already_admitted"
        )
        assert same.json()["request_id"] == str(identifier) and same.json()["state"] == "succeeded"
        assert same.json()["status_url"] == f"/v1/requests/{identifier}"
        conflict = client.post(
            "/v1/chat/completions", headers=headers, json=_request(store.alias, "different")
        )
        assert (
            conflict.status_code == 409
            and conflict.json()["error"]["code"] == "idempotency_conflict"
        )
        retired = client.get(f"/v1/requests/{identifier}", headers=headers)
        assert retired.status_code == 410, retired.text
        assert retired.json() == {
            "error": {"code": "request_retired", "message": "Request retired"},
            "request_id": str(identifier),
            "state": "succeeded",
        }
        hidden = client.get(
            f"/v1/requests/{identifier}", headers=_headers(foreign.credential.get_secret_value())
        )
        assert hidden.status_code == 404
    assert provider.calls == (identifier,) and names == ["fixture:one"]
    assert gate.occupied == 0 and store.totals(actor) == totals
    assert redis_calls == 0
    with tenant_transaction(store.runtime, TenantContext(actor.tenant)) as tx:
        assert (
            tx.connection()
            .execute(
                text("SELECT count(*) FROM arbiter.requests WHERE tenant_id=:tenant"),
                {"tenant": actor.tenant},
            )
            .scalar_one()
            == 0
        )


def test_raw_reservation_capability_honors_retired_identity(
    binding_store: tuple[ReservationStore, ModelApproval],
) -> None:
    store, _proof = binding_store
    actor = store.actor()
    identifier = completed(store, actor)
    age(store, actor, identifier, CUTOFF)
    RetentionService(store.operator).run_once(actor.tenant, actor.key, cutoff=CUTOFF)
    (tombstone,) = tombstones(store, actor)
    with pytest.raises(RequestAlreadyAdmitted) as same:
        store.service().reserve(
            actor.credential, str(tombstone["idempotency_key"]), store.request()
        )
    assert same.value.request_id == identifier and same.value.state == "succeeded"
    with pytest.raises(IdempotencyConflict):
        store.service().reserve(
            actor.credential, str(tombstone["idempotency_key"]), store.request("different")
        )


@pytest.mark.parametrize("revoked", [None, 1, 0, -1])
def test_tombstone_lifetime_uses_revocation_and_inclusive_cutoff(
    binding_store: tuple[ReservationStore, ModelApproval], revoked: int | None
) -> None:
    store, _proof = binding_store
    actor = store.actor()
    identifier = completed(store, actor)
    age(store, actor, identifier, CUTOFF)
    RetentionService(store.operator).run_once(actor.tenant, actor.key, cutoff=CUTOFF)
    with store.migration.begin() as connection:
        set_context(connection, actor.tenant)
        connection.execute(text("ALTER TABLE arbiter.api_keys DISABLE TRIGGER immutable_key"))
        connection.execute(
            text("""
            UPDATE arbiter.api_keys SET created_at=:created,expires_at=:expires
            WHERE tenant_id=:tenant AND id=:key
        """),
            {
                "tenant": actor.tenant,
                "key": actor.key,
                "created": CUTOFF - timedelta(days=1),
                "expires": CUTOFF + timedelta(days=1),
            },
        )
        if revoked is not None:
            connection.execute(
                text(
                    "UPDATE arbiter.api_keys SET revoked_at=:revoked WHERE "
                    "tenant_id=:tenant AND id=:key"
                ),
                {
                    "tenant": actor.tenant,
                    "key": actor.key,
                    "revoked": CUTOFF + timedelta(microseconds=revoked),
                },
            )
        connection.execute(text("SET CONSTRAINTS ALL IMMEDIATE"))
        connection.execute(text("ALTER TABLE arbiter.api_keys ENABLE TRIGGER immutable_key"))
    result = RetentionService(store.operator).run_once(actor.tenant, actor.key, cutoff=CUTOFF)
    removed = int(revoked is not None and revoked <= 0)
    assert result.tombstones_removed == removed and len(tombstones(store, actor)) == 1 - removed


def test_cleanup_is_atomic_rolls_back_and_serializes_concurrent_retry(
    binding_store: tuple[ReservationStore, ModelApproval],
) -> None:
    store, _proof = binding_store
    actor = store.actor()
    identifier = completed(store, actor)
    age(store, actor, identifier, CUTOFF)
    with pytest.raises(RuntimeError):
        with operator_transaction(store.operator, actor.tenant) as tx:
            tx.connection().execute(
                text("SELECT * FROM arbiter.retire_requests(:tenant,:key,:cutoff,:op,1)"),
                {"tenant": actor.tenant, "key": actor.key, "cutoff": CUTOFF, "op": uuid4()},
            ).one()
            # Another transaction sees the intact live graph until cleanup commits.
            with tenant_transaction(store.runtime, TenantContext(actor.tenant)) as reader:
                status = UsageRepository(reader).request_status(identifier)
                assert status is not None and not isinstance(status, RetiredRequest)
                assert tombstones(store, actor) == []
            raise RuntimeError("rollback before commit")
    assert tombstones(store, actor) == []
    start = Barrier(3)

    def cleanup() -> int:
        start.wait(timeout=10)
        return (
            RetentionService(store.operator)
            .run_once(actor.tenant, actor.key, cutoff=CUTOFF)
            .requests_removed
        )

    with tenant_transaction(store.runtime, TenantContext(actor.tenant)) as tx:
        idem: str = (
            tx.connection()
            .execute(
                text(
                    "SELECT idempotency_key FROM arbiter.requests WHERE "
                    "tenant_id=:tenant AND id=:id"
                ),
                {"tenant": actor.tenant, "id": identifier},
            )
            .scalar_one()
        )

    def retry() -> UUID:
        start.wait(timeout=10)
        with pytest.raises(RequestAlreadyAdmitted) as duplicate:
            store.service().reserve(actor.credential, idem, store.request())
        return duplicate.value.request_id

    with ThreadPoolExecutor(max_workers=3) as pool:
        cleanups = [pool.submit(cleanup), pool.submit(cleanup)]
        retried = pool.submit(retry)
        assert sorted(job.result(timeout=15) for job in cleanups) == [0, 1]
        assert retried.result(timeout=15) == identifier
    assert len(tombstones(store, actor)) == 1


def test_recent_revocation_cannot_expire_a_tombstone(
    binding_store: tuple[ReservationStore, ModelApproval],
) -> None:
    store, _proof = binding_store
    actor = store.actor()
    identifier = completed(store, actor)
    age(store, actor, identifier, CUTOFF)
    RetentionService(store.operator).run_once(actor.tenant, actor.key, cutoff=CUTOFF)
    with store.migration.begin() as connection:
        set_context(connection, actor.tenant)
        connection.execute(
            text(
                "UPDATE arbiter.api_keys SET revoked_at=clock_timestamp() "
                "WHERE tenant_id=:tenant AND id=:key"
            ),
            {"tenant": actor.tenant, "key": actor.key},
        )
    assert (
        RetentionService(store.operator).run_once(actor.tenant, actor.key).tombstones_removed == 0
    )
    assert tombstones(store, actor)[0]["request_id"] == identifier


def test_privileges_rls_direct_dml_and_unrelated_evidence_are_preserved(
    binding_store: tuple[ReservationStore, ModelApproval],
) -> None:
    store, _proof = binding_store
    actor, foreign = store.actor(), store.actor()
    identifier = completed(store, actor)
    age(store, actor, identifier, CUTOFF)
    with pytest.raises(OperatorAccessDenied):
        RetentionService(store.runtime).run_once(actor.tenant, actor.key, cutoff=CUTOFF)
    with pytest.raises(DBAPIError):
        with tenant_transaction(store.runtime, TenantContext(actor.tenant)) as tx:
            tx.connection().execute(
                text("SELECT * FROM arbiter.retire_requests(:tenant,:key,:cutoff,:op,1)"),
                {"tenant": actor.tenant, "key": actor.key, "cutoff": CUTOFF, "op": uuid4()},
            )
    with pytest.raises(DBAPIError):
        RetentionService(store.operator).run_once(foreign.tenant, actor.key, cutoff=CUTOFF)
    for statement in (
        "DELETE FROM arbiter.requests",
        "DELETE FROM arbiter.accounting_events",
        "UPDATE arbiter.accounting_events SET credits=credits",
        "TRUNCATE arbiter.accounting_events",
    ):
        with pytest.raises(DBAPIError) as denied:
            with tenant_transaction(store.runtime, TenantContext(actor.tenant)) as tx:
                tx.connection().execute(text(statement))
        assert postgres_error(denied.value).sqlstate == "42501"
    for statement in (
        "UPDATE arbiter.accounting_events SET credits=credits",
        "TRUNCATE arbiter.accounting_events CASCADE",
    ):
        with pytest.raises(DBAPIError) as immutable:
            with store.migration.begin() as connection:
                set_context(connection, actor.tenant)
                connection.execute(text(statement))
        assert postgres_error(immutable.value).sqlstate == "42501"
    for engine in (store.runtime, store.operator):
        with pytest.raises(DBAPIError) as denied_role:
            with engine.begin() as connection:
                connection.execute(text("SET LOCAL ROLE arbiter_retention_writer"))
        assert postgres_error(denied_role.value).sqlstate == "42501"
    with pytest.raises(DBAPIError) as missing_context:
        with store.operator.begin() as connection:
            connection.execute(
                text("SELECT * FROM arbiter.retire_requests(:tenant,:key,:cutoff,:op,1)"),
                {"tenant": actor.tenant, "key": actor.key, "cutoff": CUTOFF, "op": uuid4()},
            )
    assert postgres_error(missing_context.value).sqlstate == "42501"
    with tenant_transaction(store.runtime, TenantContext(actor.tenant)) as tx:
        count: int = (
            tx.connection()
            .execute(
                text(
                    "SELECT count(*) FROM arbiter.audit_events WHERE "
                    "tenant_id=:tenant AND actor_type<>'api_key'"
                ),
                {"tenant": actor.tenant},
            )
            .scalar_one()
        )
    RetentionService(store.operator).run_once(actor.tenant, actor.key, cutoff=CUTOFF)
    for statement in (
        "UPDATE arbiter.idempotency_tombstones SET state='failed'",
        "DELETE FROM arbiter.idempotency_tombstones",
        "TRUNCATE arbiter.idempotency_tombstones",
    ):
        with pytest.raises(DBAPIError) as immutable_tombstone:
            with store.migration.begin() as connection:
                set_context(connection, actor.tenant)
                connection.execute(text(statement))
        assert postgres_error(immutable_tombstone.value).sqlstate == "42501"
    with store.runtime.begin() as connection:
        assert (
            connection.execute(
                text("SELECT count(*) FROM arbiter.idempotency_tombstones")
            ).scalar_one()
            == 0
        )
    with tenant_transaction(store.runtime, TenantContext(foreign.tenant)) as tx:
        assert (
            tx.connection()
            .execute(
                text("SELECT count(*) FROM arbiter.idempotency_tombstones WHERE request_id=:id"),
                {"id": identifier},
            )
            .scalar_one()
            == 0
        )
    with tenant_transaction(store.runtime, TenantContext(actor.tenant)) as tx:
        assert (
            tx.connection()
            .execute(
                text(
                    "SELECT count(*) FROM arbiter.audit_events WHERE "
                    "tenant_id=:tenant AND actor_type<>'api_key'"
                ),
                {"tenant": actor.tenant},
            )
            .scalar_one()
            == count + 1
        )


def test_downgrade_refuses_to_discard_retired_identity(
    binding_store: tuple[ReservationStore, ModelApproval],
) -> None:
    from test_migrations import migrate_to

    store, _proof = binding_store
    actor = store.actor()
    identifier = completed(store, actor)
    age(store, actor, identifier, CUTOFF)
    RetentionService(store.operator).run_once(actor.tenant, actor.key, cutoff=CUTOFF)
    with pytest.raises(DBAPIError):
        migrate_to(store.migration, "0019_reserved_provider_binding", downgrade=True)
    assert tombstones(store, actor)[0]["request_id"] == identifier
