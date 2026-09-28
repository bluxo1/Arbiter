"""Real PostgreSQL authenticated reservations, contention and fault injection.

Accepted immutable fixtures remain in the isolated database; no evidence is deleted.
"""

import os
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from dataclasses import dataclass, field
from threading import Event
from time import monotonic, sleep
from typing import Any
from uuid import UUID, uuid4

import pytest
from psycopg import sql
from pydantic import SecretStr
from sqlalchemy import create_engine, event, text
from sqlalchemy.engine import Engine
from sqlalchemy.exc import DBAPIError
from test_tenant_isolation import credential_engine, postgres_error, set_context

from arbiter.config import DatabaseSettings
from arbiter.governance.capacity import CapacityGate, CapacityService
from arbiter.governance.dispatch import DispatchService
from arbiter.governance.fingerprint import (
    Fingerprinter,
    InvalidReservation,
    Message,
    ReservationInput,
)
from arbiter.governance.release import ReleaseService
from arbiter.governance.reservation import (
    IdempotencyConflict,
    ModelDenied,
    RequestAlreadyAdmitted,
    ReservationDenied,
    ReservationService,
    ReservationUnavailable,
)
from arbiter.identity.context import TenantContext
from arbiter.identity.keys import InvalidKey, KeyCandidate, KeyIssuer, KeyVerifier
from arbiter.identity.workload import MissingScope
from arbiter.operations.policy import PolicyInput, PolicyService
from arbiter.operations.provision import MemberInput, ProvisioningService
from arbiter.persistence.operator import OperatorRepository, operator_transaction
from arbiter.persistence.policy import PolicyRepository
from arbiter.persistence.reservation import ReservationRepository, ReservationResult
from arbiter.persistence.tenant import bind_tenant_transaction, tenant_transaction
from arbiter.persistence.workload import resolve_key
from arbiter.providers.double import DeterministicProvider

pytestmark = pytest.mark.skipif(
    os.environ.get("ARBITER_TEST_DATABASE") != "1", reason="requires real PostgreSQL"
)
MAXIMUM = 9223372036854775807
TABLES = ("quota_windows", "budget_windows", "requests", "reservations", "accounting_events")
FUNCTION = "arbiter.reserve_request(uuid,uuid,text,bytea,integer,text,bytea,integer,text,integer)"


@dataclass(frozen=True, slots=True)
class Actor:
    tenant: UUID
    key: UUID
    member: UUID
    credential: SecretStr
    candidate: KeyCandidate


@dataclass
class ReservationStore:
    runtime: Engine
    operator: Engine
    migration: Engine
    model: UUID
    alias: str
    verifier: KeyVerifier = field(default_factory=lambda: KeyVerifier(bytes(range(32)), 1))
    fingerprint: Fingerprinter = field(
        default_factory=lambda: Fingerprinter(bytes(reversed(range(32))))
    )

    def service(self, engine: Engine | None = None) -> ReservationService:
        return ReservationService(
            self.runtime if engine is None else engine, self.verifier, self.fingerprint
        )

    def request(
        self, message: str = "synthetic reservation input", output: int = 256
    ) -> ReservationInput:
        return ReservationInput(self.alias, (Message("user", message),), output)

    def actor(
        self,
        *,
        quota: int = 1000,
        budget: int = 10000,
        concurrency: int = 2,
        scopes: tuple[str, ...] = ("inference:write", "usage:read"),
        expired: bool = False,
        lifetime: int = 86400,
        existing: Actor | None = None,
    ) -> Actor:
        if existing is None:
            provision = ProvisioningService(self.operator)
            tenant = provision.create_tenant().tenant_id
            member = provision.create_member(
                tenant, MemberInput("https://fixture.invalid", uuid4().hex, "admin")
            ).object_id
            PolicyService(self.operator).set_policy(
                tenant,
                PolicyInput(
                    daily_quota=quota,
                    monthly_budget=budget,
                    concurrency=concurrency,
                    aliases=(self.alias,),
                ),
            )
        else:
            tenant, member = existing.tenant, existing.member
        issued = KeyIssuer(bytes(range(32)), 1).issue()
        audit = uuid4()
        with self.migration.begin() as connection:
            set_context(connection, tenant)
            connection.execute(
                text("""
                INSERT INTO arbiter.audit_events
                (id,tenant_id,actor_type,actor_reference,actor_membership_id,action,
                 target_id,policy_revision,outcome)
                VALUES (:audit,:tenant,'member',:reference,:member,
                    'api_key_created',:key,2,'succeeded')
            """),
                {
                    "audit": audit,
                    "tenant": tenant,
                    "reference": str(member),
                    "member": member,
                    "key": issued.id,
                },
            )
            connection.execute(
                text("""
                INSERT INTO arbiter.api_keys
                (id,tenant_id,public_id,label,verifier,pepper_version,scopes,created_at,
                 expires_at,created_by_membership_id,creation_audit_id)
                VALUES (:id,:tenant,:public,'reservation fixture',:verifier,1,:scopes,
                    CASE WHEN :expired THEN CURRENT_TIMESTAMP-interval '2 days'
                        ELSE CURRENT_TIMESTAMP END,
                    CASE WHEN :expired THEN CURRENT_TIMESTAMP-interval '1 day'
                        ELSE CURRENT_TIMESTAMP+(:lifetime * interval '1 second')
                        END,:member,:audit)
            """),
                {
                    "id": issued.id,
                    "tenant": tenant,
                    "public": issued.public_id,
                    "verifier": issued.verifier.get_secret_value(),
                    "scopes": list(scopes),
                    "member": member,
                    "audit": audit,
                    "expired": expired,
                    "lifetime": lifetime,
                },
            )
        return Actor(
            tenant, issued.id, member, issued.credential, self.verifier.candidate(issued.credential)
        )

    def counts(self, actor: Actor) -> tuple[int, ...]:
        with tenant_transaction(self.runtime, TenantContext(actor.tenant)) as tx:
            counts: list[int] = [
                tx.connection()
                .execute(
                    text(
                        sql.SQL("SELECT count(*) FROM {} WHERE tenant_id=:tenant")
                        .format(sql.Identifier("arbiter", table))
                        .as_string()
                    ),
                    {"tenant": actor.tenant},
                )
                .scalar_one()
                for table in TABLES
            ]
            audits: int = (
                tx.connection()
                .execute(
                    text("""
                SELECT count(*) FROM arbiter.audit_events
                WHERE tenant_id=:tenant AND action='request_reserved'
            """),
                    {"tenant": actor.tenant},
                )
                .scalar_one()
            )
            return (*counts, audits)

    def totals(self, actor: Actor) -> tuple[int, int, int, int]:
        with tenant_transaction(self.runtime, TenantContext(actor.tenant)) as tx:
            row = (
                tx.connection()
                .execute(
                    text("""
                SELECT q.committed,q.reserved,b.committed,b.reserved
                FROM arbiter.quota_windows q JOIN arbiter.budget_windows b
                    ON b.tenant_id=q.tenant_id AND b.tenant_id=:tenant
                WHERE q.tenant_id=:tenant
            """),
                    {"tenant": actor.tenant},
                )
                .one()
            )
            return row[0], row[1], row[2], row[3]


@pytest.fixture(scope="module")
def store() -> Iterator[ReservationStore]:
    runtime, operator, migration = (
        credential_engine(role) for role in ("runtime", "operator", "migration")
    )
    model, alias = uuid4(), "reserve-fixture-" + uuid4().hex
    with migration.begin() as connection:
        connection.execute(
            text("""
            INSERT INTO arbiter.provider_models
            (id,alias,adapter,model_digest,context_cap,output_cap,credit_charge,revision,active)
            VALUES (:id,:alias,'ollama',:digest,4096,256,10,1,true)
        """),
            {"id": model, "alias": alias, "digest": "sha256:" + "d" * 64},
        )
    try:
        yield ReservationStore(runtime, operator, migration, model, alias)
    finally:
        for engine in (runtime, operator, migration):
            engine.dispose()


def reserve(store: ReservationStore, actor: Actor, *, idem: str | None = None) -> ReservationResult:
    return store.service().reserve(
        actor.credential, uuid4().hex if idem is None else idem, store.request()
    )


def test_success_committed_bundle_and_content_free_snapshots(store: ReservationStore) -> None:
    actor = store.actor()
    result = reserve(store, actor)
    assert result.state == "reserved" and result.credit_charge == 10 and not result.duplicate
    assert result.policy_revision == 2 and result.model_revision == 1
    assert store.counts(actor) == (1, 1, 1, 1, 1, 1)
    assert store.totals(actor) == (0, 1, 0, 10)
    with tenant_transaction(store.runtime, TenantContext(actor.tenant)) as tx:
        row = (
            tx.connection()
            .execute(
                text("""
            SELECT r.*,s.disposition,a.actor_type,a.actor_api_key_id,a.actor_membership_id,
                a.target_id,a.request_id AS audit_request
            FROM arbiter.requests r JOIN arbiter.reservations s
                ON s.tenant_id=r.tenant_id AND s.id=r.reservation_id AND s.tenant_id=:tenant
            JOIN arbiter.audit_events a ON a.tenant_id=r.tenant_id
                AND a.id=r.reservation_audit_id AND a.tenant_id=:tenant
            WHERE r.tenant_id=:tenant AND r.id=:id
        """),
                {"tenant": actor.tenant, "id": result.request_id},
            )
            .one()
        )
        assert row.actor_type == "api_key" and row.actor_api_key_id == actor.key
        assert row.actor_membership_id is None
        assert row.target_id == row.audit_request == result.request_id
        assert row.dispatched_at is None and row.finished_at is None
        assert row.input_tokens is None and row.output_tokens is None
        assert row.disposition == "reserved" and row.model_digest == "sha256:" + "d" * 64
        stored: str = (
            tx.connection()
            .execute(
                text("""
            SELECT to_jsonb(r)::text FROM arbiter.requests r WHERE tenant_id=:tenant AND id=:id
        """),
                {"tenant": actor.tenant, "id": result.request_id},
            )
            .scalar_one()
        )
        forbidden = [actor.credential.get_secret_value(), "synthetic reservation input"]
        assert all(value not in stored for value in forbidden), "plaintext persisted"


@pytest.mark.parametrize(
    "quota,budget,code",
    [
        (1, 1000, "quota_exhausted"),
        (1000, 10, "budget_exhausted"),
        (0, 1000, "quota_exhausted"),
        (1000, 0, "budget_exhausted"),
        (1000, 9, "budget_exhausted"),
    ],
)
def test_quota_budget_boundaries_and_zero(
    store: ReservationStore,
    quota: int,
    budget: int,
    code: str,
) -> None:
    actor = store.actor(quota=quota, budget=budget)
    accepted = quota > 0 and budget >= 10
    if accepted:
        reserve(store, actor)
    before = store.counts(actor)
    with pytest.raises(ReservationDenied) as failure:
        reserve(store, actor)
    assert failure.value.code == code and failure.value.status_code == 429
    assert store.counts(actor) == before
    if accepted:
        assert store.totals(actor) == (0, 1, 0, 10)
    else:
        assert before == (0, 0, 0, 0, 0, 0)


@pytest.mark.parametrize("concurrency", [0, 1, 2])
def test_tenant_concurrency_boundary(store: ReservationStore, concurrency: int) -> None:
    actor = store.actor(concurrency=concurrency)
    for _ in range(concurrency):
        reserve(store, actor)
    with pytest.raises(ReservationDenied) as failure:
        reserve(store, actor)
    assert failure.value.code == "tenant_capacity"
    assert store.counts(actor)[2:] == (concurrency,) * 4


def test_matching_conflicting_and_versioned_idempotency(store: ReservationStore) -> None:
    actor = store.actor(quota=1)
    idem = uuid4().hex
    first = reserve(store, actor, idem=idem)
    before = store.counts(actor)
    with pytest.raises(RequestAlreadyAdmitted) as duplicate:
        reserve(store, actor, idem=idem)
    assert duplicate.value.request_id == first.request_id and duplicate.value.status_code == 409
    assert duplicate.value.state == "reserved"
    assert duplicate.value.status_url == f"/v1/requests/{first.request_id}"
    with pytest.raises(IdempotencyConflict) as conflict:
        store.service().reserve(actor.credential, idem, store.request("other synthetic payload"))
    assert conflict.value.code == "idempotency_conflict" and conflict.value.status_code == 409
    changed = ReservationService(store.runtime, store.verifier, Fingerprinter(bytes(range(32)), 2))
    with pytest.raises(IdempotencyConflict):
        changed.reserve(actor.credential, idem, store.request())
    assert store.counts(actor) == before and store.totals(actor) == (0, 1, 0, 10)


def test_denied_retry_may_reserve_after_policy_changes(store: ReservationStore) -> None:
    actor = store.actor(quota=0)
    idem = uuid4().hex
    with pytest.raises(ReservationDenied):
        reserve(store, actor, idem=idem)
    assert store.counts(actor) == (0,) * 6
    PolicyService(store.operator).set_policy(
        actor.tenant, PolicyInput(concurrency=2, aliases=(store.alias,))
    )
    result = reserve(store, actor, idem=idem)
    assert result.policy_revision == 3 and store.counts(actor) == (1,) * 6


@contextmanager
def parallel_engine() -> Iterator[Engine]:
    engine = create_engine(
        DatabaseSettings().url("runtime"),
        hide_parameters=True,
        pool_size=16,
        max_overflow=0,
        pool_timeout=15,
        connect_args={
            "connect_timeout": 5,
            "options": "-c lock_timeout=10000 -c statement_timeout=15000",
        },
    )
    try:
        yield engine
    finally:
        engine.dispose()


@pytest.mark.parametrize("scenario", ["duplicate", "conflict", "quota", "budget"])
def test_concurrent_duplicates_and_allocation_races(store: ReservationStore, scenario: str) -> None:
    actor = store.actor(
        quota=1 if scenario == "quota" else 1000, budget=10 if scenario == "budget" else 10000
    )
    idem, start = uuid4().hex, Event()
    with parallel_engine() as engine, ThreadPoolExecutor(max_workers=16) as executor:
        service = store.service(engine)

        def attempt(index: int) -> tuple[str, UUID | None]:
            assert start.wait(10)
            try:
                result = service.reserve(
                    actor.credential,
                    idem if scenario in {"duplicate", "conflict"} else uuid4().hex,
                    store.request(str(index) if scenario == "conflict" else "same synthetic input"),
                )
                return "reserved", result.request_id
            except RequestAlreadyAdmitted as error:
                return error.code, error.request_id
            except (IdempotencyConflict, ReservationDenied) as error:
                return error.code, None

        futures = [executor.submit(attempt, index) for index in range(100)]
        start.set()
        results = [future.result(timeout=30) for future in futures]
    assert sum(code == "reserved" for code, _ in results) == 1
    denial = {
        "duplicate": "request_already_admitted",
        "conflict": "idempotency_conflict",
        "quota": "quota_exhausted",
        "budget": "budget_exhausted",
    }[scenario]
    assert sum(code == denial for code, _ in results) == 99
    if scenario == "duplicate":
        assert len({identifier for _, identifier in results}) == 1
    assert store.counts(actor) == (1,) * 6 and store.totals(actor) == (0, 1, 0, 10)
    # 100 submitted attempts, <=16 simultaneous DB callers; capacity2 is nonbinding at allocation1.
    # This is not the later 100-simultaneous/10-admissions full Phase3 pipeline exit gate.


@pytest.mark.parametrize(
    "table,operation",
    [
        ("quota_windows", "INSERT"),
        ("budget_windows", "INSERT"),
        ("quota_windows", "UPDATE"),
        ("budget_windows", "UPDATE"),
        ("requests", "INSERT"),
        ("reservations", "INSERT"),
        ("accounting_events", "INSERT"),
        ("audit_events", "INSERT"),
    ],
)
def test_atomic_rollback_at_each_mutation(
    store: ReservationStore,
    table: str,
    operation: str,
) -> None:
    actor = store.actor()
    function, trigger = "fixture_" + uuid4().hex, "fixture_" + uuid4().hex
    with store.migration.begin() as connection:
        connection.execute(
            text(
                sql.SQL("""
            CREATE FUNCTION {}() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $$
            BEGIN IF NEW.tenant_id={}::uuid THEN
                RAISE EXCEPTION 'synthetic rejected mutation' USING ERRCODE='23514';
            END IF; RETURN NEW; END $$
        """)
                .format(sql.Identifier("arbiter", function), sql.Literal(str(actor.tenant)))
                .as_string()
            )
        )
        connection.execute(
            text(
                sql.SQL("REVOKE ALL ON FUNCTION {}() FROM PUBLIC")
                .format(sql.Identifier("arbiter", function))
                .as_string()
            )
        )
        connection.execute(
            text(
                sql.SQL("CREATE TRIGGER {} BEFORE {} ON {} FOR EACH ROW EXECUTE FUNCTION {}()")
                .format(
                    sql.Identifier(trigger),
                    sql.SQL(operation),
                    sql.Identifier("arbiter", table),
                    sql.Identifier("arbiter", function),
                )
                .as_string()
            )
        )
    try:
        idem = uuid4().hex
        with pytest.raises(ReservationUnavailable) as failure:
            reserve(store, actor, idem=idem)
        assert str(failure.value) == "reservation unavailable"
        assert store.counts(actor) == (0,) * 6
    finally:
        with store.migration.begin() as connection:
            connection.execute(
                text(
                    sql.SQL("DROP TRIGGER {} ON {}")
                    .format(sql.Identifier(trigger), sql.Identifier("arbiter", table))
                    .as_string()
                )
            )
            connection.execute(
                text(
                    sql.SQL("DROP FUNCTION {}() RESTRICT")
                    .format(sql.Identifier("arbiter", function))
                    .as_string()
                )
            )
    reserve(store, actor, idem=idem)
    assert store.counts(actor) == (1,) * 6


def test_runtime_cannot_write_or_become_the_reservation_owner(store: ReservationStore) -> None:
    actor = store.actor()
    for statement in (
        "SET ROLE arbiter_reservation_writer",
        "SET ROLE arbiter_migration",
        "UPDATE arbiter.quota_windows SET reserved=0",
        "INSERT INTO arbiter.requests (id,tenant_id) VALUES (gen_random_uuid(),:tenant)",
        "UPDATE arbiter.requests SET state='dispatched'",
        "UPDATE arbiter.accounting_events SET kind='commit'",
        "DELETE FROM arbiter.accounting_events",
        "DELETE FROM arbiter.requests",
    ):
        with pytest.raises(DBAPIError) as failure, store.runtime.begin() as connection:
            set_context(connection, actor.tenant)
            connection.execute(text(statement), {"tenant": actor.tenant})
        assert postgres_error(failure.value).sqlstate == "42501"
    with store.runtime.begin() as connection:
        assert (
            connection.execute(
                text("""
            SELECT has_function_privilege(current_user,:function,'EXECUTE')
        """),
                {"function": FUNCTION},
            ).scalar_one()
            is True
        )
    with store.operator.begin() as connection:
        assert (
            connection.execute(
                text("""
            SELECT has_function_privilege(current_user,:function,'EXECUTE')
        """),
                {"function": FUNCTION},
            ).scalar_one()
            is False
        )


def test_key_scope_and_model_denials_do_not_mutate(store: ReservationStore) -> None:
    no_scope = store.actor(scopes=("usage:read",))
    with pytest.raises(MissingScope):
        reserve(store, no_scope)
    actor = store.actor()
    for request, expected in (
        (ReservationInput("unregistered", (Message("user", "fixture"),)), ModelDenied),
        (store.request(output=257), InvalidReservation),
    ):
        with pytest.raises(expected):
            store.service().reserve(actor.credential, uuid4().hex, request)
    assert store.counts(no_scope) == store.counts(actor) == (0,) * 6


def test_pool_context_reset_and_no_cross_tenant_records(store: ReservationStore) -> None:
    actors = [store.actor(), store.actor()]
    for index in (0, 1, 0):
        actor, other = actors[index], actors[1 - index]
        result = reserve(store, actor)
        with store.runtime.begin() as connection:
            assert (
                connection.execute(
                    text("SELECT NULLIF(current_setting('arbiter.tenant_id',true),'')")
                ).scalar_one()
                is None
            )
            assert connection.execute(text("SELECT id FROM arbiter.requests")).all() == []
        with tenant_transaction(store.runtime, TenantContext(other.tenant)) as tx:
            assert (
                tx.connection()
                .execute(
                    text("""
                SELECT id FROM arbiter.requests WHERE tenant_id=:tenant AND id=:id
            """),
                    {"tenant": other.tenant, "id": result.request_id},
                )
                .all()
                == []
            )


def revoke_in_transaction(connection: Any, actor: Actor) -> None:
    principal = connection.execute(
        text("""
        SELECT principal_id FROM arbiter.memberships WHERE tenant_id=:tenant AND id=:member
    """),
        {"tenant": actor.tenant, "member": actor.member},
    ).scalar_one()
    connection.execute(
        text("""
        SELECT * FROM arbiter.revoke_api_key(:tenant,:member,:principal,:key,:audit,:request)
    """),
        {
            "tenant": actor.tenant,
            "member": actor.member,
            "principal": principal,
            "key": actor.key,
            "audit": uuid4(),
            "request": uuid4(),
        },
    )


@pytest.mark.parametrize("status", ["revoked", "expired", "suspended"])
def test_invalid_authority_leaves_no_allocation(store: ReservationStore, status: str) -> None:
    actor = store.actor(expired=status == "expired")
    if status == "revoked":
        with tenant_transaction(store.runtime, TenantContext(actor.tenant)) as tx:
            revoke_in_transaction(tx.connection(), actor)
    elif status == "suspended":
        ProvisioningService(store.operator).set_tenant_status(actor.tenant, "suspended")
    with pytest.raises(InvalidKey) as failure:
        reserve(store, actor)
    assert str(failure.value) == "invalid credentials"
    assert store.counts(actor) == (0,) * 6


def raw_parameters(store: ReservationStore, actor: Actor) -> dict[str, object]:
    fingerprint = store.fingerprint.compute(store.request())
    return {
        "tenant": actor.tenant,
        "key": actor.key,
        "public": actor.candidate.public_id,
        "candidate": actor.candidate.verifier.get_secret_value(),
        "pepper": 1,
        "idempotency": uuid4().hex,
        "fingerprint": fingerprint.digest.get_secret_value(),
        "version": 1,
        "alias": store.alias,
        "output": 256,
    }


RAW_CALL = text("""
    SELECT * FROM arbiter.reserve_request(:tenant,:key,:public,:candidate,:pepper,
        :idempotency,:fingerprint,:version,:alias,:output)
""")


@pytest.mark.parametrize(
    "misuse",
    [
        "missing",
        "foreign_context",
        "foreign_key",
        "unknown_key",
        "unknown_public",
        "wrong_secret",
        "wrong_pepper",
    ],
)
def test_raw_capability_rejects_forged_bindings(store: ReservationStore, misuse: str) -> None:
    actor, other = store.actor(), store.actor()
    values = raw_parameters(store, actor)
    if misuse == "foreign_key":
        values["key"] = other.key
    elif misuse == "unknown_key":
        values["key"] = uuid4()
    elif misuse == "unknown_public":
        values["public"] = uuid4().hex
    elif misuse == "wrong_secret":
        values["candidate"] = b"\x00" * 32
    elif misuse == "wrong_pepper":
        values["pepper"] = 2
    with pytest.raises(DBAPIError) as failure, store.runtime.begin() as connection:
        if misuse != "missing":
            set_context(connection, other.tenant if misuse == "foreign_context" else actor.tenant)
        connection.execute(RAW_CALL, values)
    assert postgres_error(failure.value).sqlstate == (
        "42501" if misuse in {"missing", "foreign_context"} else "AR001"
    )
    assert store.counts(actor) == store.counts(other) == (0,) * 6


def test_repository_rejects_foreign_and_changed_transaction_context(
    store: ReservationStore,
) -> None:
    actor, other = store.actor(), store.actor()
    with store.runtime.connect() as connection, connection.begin() as transaction:
        binding = resolve_key(connection, actor.candidate)
        scoped = bind_tenant_transaction(connection, transaction, TenantContext(other.tenant))
        with pytest.raises(InvalidKey):
            ReservationRepository(scoped).reserve(
                binding,
                actor.candidate,
                uuid4().hex,
                store.fingerprint.compute(store.request()),
                store.alias,
                256,
            )
        set_context(connection, actor.tenant)
        with pytest.raises(RuntimeError, match="context changed"):
            scoped.connection()
    assert store.counts(actor) == store.counts(other) == (0,) * 6


@pytest.mark.parametrize(
    "change", ["policy_deny", "policy_snapshot", "suspended", "revoked", "expiry"]
)
def test_locked_authority_and_policy_are_revalidated_after_contention(
    store: ReservationStore,
    change: str,
) -> None:
    actor = store.actor(lifetime=3 if change == "expiry" else 86400)
    sibling = store.actor(existing=actor) if change == "revoked" else None
    started = Event()
    backend: list[int] = []
    with parallel_engine() as engine, ThreadPoolExecutor(max_workers=1) as executor:

        def entering(
            connection: Any,
            cursor: Any,
            statement: str,
            parameters: Any,
            context: Any,
            executemany: bool,
        ) -> None:
            if "FROM arbiter.reserve_request" in statement:
                backend.append(connection.connection.driver_connection.info.backend_pid)
                started.set()

        event.listen(engine, "before_cursor_execute", entering)
        # Real holder uses the approved tenant-first lock. No auth mocking or arbitrary sleeps.
        holder_context = (
            tenant_transaction(store.runtime, TenantContext(actor.tenant))
            if change == "revoked"
            else operator_transaction(store.operator, actor.tenant)
        )
        with holder_context as holder:
            connection = holder.connection()
            if sibling is not None:
                # The approved revocation capability acquires the tenant lock without
                # granting direct tenant UPDATE privileges to the runtime test caller.
                revoke_in_transaction(connection, sibling)
            else:
                OperatorRepository(holder).lock_tenant()
            future = executor.submit(reserve_using_engine, store, actor, engine)
            assert started.wait(5), "reservation did not reach the database capability"
            deadline = monotonic() + 3
            while True:
                waiting: bool = connection.execute(
                    text("SELECT cardinality(pg_blocking_pids(:pid))>0"), {"pid": backend[0]}
                ).scalar_one()
                if waiting:
                    break
                assert monotonic() < deadline, "database lock contention was not observed"
                sleep(0.01)
            if change == "revoked":
                revoke_in_transaction(connection, actor)
            elif change == "expiry":
                deadline = monotonic() + 4
                while not connection.execute(
                    text(
                        "SELECT expires_at<=clock_timestamp() "
                        "FROM arbiter.api_keys WHERE tenant_id=:tenant AND id=:key"
                    ),
                    {"tenant": actor.tenant, "key": actor.key},
                ).scalar_one():
                    assert monotonic() < deadline, "fixture expiry was not observed"
                    sleep(0.02)
            elif change == "suspended":
                operator = OperatorRepository(holder)
                operator.set_status("suspended")
                operator.append_audit(
                    action="tenant_suspended",
                    target_id=actor.tenant,
                    revision=2,
                    correlation=uuid4(),
                )
            else:
                repository = PolicyRepository(holder)
                quota = 0 if change == "policy_deny" else 17
                repository.validate_limits(quota, 10000, 2)
                repository.validate_aliases((store.alias,))
                repository.advance_revision(2, 3)
                policy_id = uuid4()
                audit = OperatorRepository(holder).append_audit(
                    action="tenant_policy_set", target_id=policy_id, revision=3, correlation=uuid4()
                )
                repository.insert(
                    policy_id=policy_id,
                    revision=3,
                    audit_id=audit,
                    limits=(60, 30, quota, 10000, 2),
                    aliases=(store.alias,),
                )
        if change in {"revoked", "expiry", "suspended"}:
            with pytest.raises(InvalidKey):
                future.result(timeout=10)
            assert store.counts(actor) == (0,) * 6
        elif change == "policy_deny":
            with pytest.raises(ReservationDenied) as failure:
                future.result(timeout=10)
            assert failure.value.code == "quota_exhausted" and store.counts(actor) == (0,) * 6
        else:
            assert future.result(timeout=10).policy_revision == 3
            assert store.counts(actor) == (1,) * 6


def reserve_using_engine(
    store: ReservationStore, actor: Actor, engine: Engine
) -> ReservationResult:
    return store.service(engine).reserve(actor.credential, uuid4().hex, store.request())


@pytest.mark.parametrize("limit", [10, MAXIMUM])
def test_committed_plus_reserved_and_int64_boundary(store: ReservationStore, limit: int) -> None:
    actor = store.actor(quota=limit, budget=limit)
    # Synthetic historical totals in the test database only; no usage endpoint or production data.
    with store.migration.begin() as connection:
        set_context(connection, actor.tenant)
        connection.execute(
            text("""
            INSERT INTO arbiter.quota_windows(id,tenant_id,window_start,committed)
            VALUES (gen_random_uuid(),:tenant,
                date_trunc('day',clock_timestamp() AT TIME ZONE 'UTC')
                    AT TIME ZONE 'UTC',:committed)
        """),
            {"tenant": actor.tenant, "committed": limit - 1},
        )
        connection.execute(
            text("""
            INSERT INTO arbiter.budget_windows(id,tenant_id,window_start,committed)
            VALUES (gen_random_uuid(),:tenant,
                date_trunc('month',clock_timestamp() AT TIME ZONE 'UTC')
                    AT TIME ZONE 'UTC',:committed)
        """),
            {"tenant": actor.tenant, "committed": limit - 10},
        )
    reserve(store, actor)
    assert store.totals(actor) == (limit - 1, 1, limit - 10, 10)
    with pytest.raises(ReservationDenied) as failure:
        reserve(store, actor)
    assert failure.value.code == "quota_exhausted"
    assert store.totals(actor) == (limit - 1, 1, limit - 10, 10)


@pytest.mark.parametrize("limit", ["quota", "budget", "concurrency"])
def test_operator_cannot_lower_below_live_reservations(store: ReservationStore, limit: str) -> None:
    actor = store.actor()
    reserve(store, actor)
    policy = PolicyInput(
        daily_quota=0 if limit == "quota" else 1000,
        monthly_budget=9 if limit == "budget" else 10000,
        concurrency=0 if limit == "concurrency" else 2,
        aliases=(store.alias,),
    )
    with pytest.raises(DBAPIError) as failure:
        PolicyService(store.operator).set_policy(actor.tenant, policy)
    assert postgres_error(failure.value).sqlstate == "23514"
    assert store.counts(actor) == (1,) * 6 and store.totals(actor) == (0, 1, 0, 10)


def test_deferred_commit_failure_cannot_return_success(store: ReservationStore) -> None:
    actor = store.actor()
    name = "fixture_" + uuid4().hex
    with store.migration.begin() as connection:
        connection.execute(
            text(
                sql.SQL("""
            CREATE FUNCTION {}() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $$
            BEGIN IF NEW.tenant_id={}::uuid THEN
                RAISE EXCEPTION 'synthetic commit failure' USING ERRCODE='23514';
            END IF; RETURN NULL; END $$
        """)
                .format(sql.Identifier("arbiter", name), sql.Literal(str(actor.tenant)))
                .as_string()
            )
        )
        connection.execute(
            text(
                sql.SQL("REVOKE ALL ON FUNCTION {}() FROM PUBLIC")
                .format(sql.Identifier("arbiter", name))
                .as_string()
            )
        )
        connection.execute(
            text(
                sql.SQL(
                    "CREATE CONSTRAINT TRIGGER {} AFTER INSERT ON "
                    "arbiter.audit_events DEFERRABLE INITIALLY DEFERRED "
                    "FOR EACH ROW EXECUTE FUNCTION {}()"
                )
                .format(sql.Identifier(name), sql.Identifier("arbiter", name))
                .as_string()
            )
        )
    try:
        with pytest.raises(ReservationUnavailable):
            reserve(store, actor)
        assert store.counts(actor) == (0,) * 6
    finally:
        with store.migration.begin() as connection:
            connection.execute(
                text(
                    sql.SQL("DROP TRIGGER {} ON arbiter.audit_events")
                    .format(sql.Identifier(name))
                    .as_string()
                )
            )
            connection.execute(
                text(
                    sql.SQL("DROP FUNCTION {}() RESTRICT")
                    .format(sql.Identifier("arbiter", name))
                    .as_string()
                )
            )


@pytest.mark.parametrize("state", ["dispatched", "unknown"])
def test_durable_occupancy_states(store: ReservationStore, state: str) -> None:
    actor = store.actor(concurrency=1)
    gate = CapacityGate(limit=2)
    original = store.request()
    lease = CapacityService(
        store.service(), ReleaseService(store.runtime), gate
    ).reserve_and_acquire(actor.credential, uuid4().hex, original)
    service = DispatchService(store.runtime)
    service.authorize(lease)
    if state == "unknown":
        provider = DeterministicProvider(store.model, "sha256:" + "d" * 64, 256, mode="deadline")
        completion = service.run_double_once(lease, original, provider, store.fingerprint)
        assert completion.state == "unknown"
        assert provider.calls == (lease.result.request_id,)
    assert gate.occupied == 1
    with pytest.raises(ReservationDenied) as failure:
        reserve(store, actor)
    assert failure.value.code == "tenant_capacity"
    assert store.totals(actor) == (1, 0, 10, 0)


def test_function_owner_is_nonlogin_scoped_and_narrow(store: ReservationStore) -> None:
    with store.migration.begin() as connection:
        assert (
            connection.execute(
                text("""
            SELECT rolcanlogin,rolsuper,rolbypassrls,rolcreaterole,
                rolcreatedb,rolinherit,rolreplication
            FROM pg_roles WHERE rolname='arbiter_reservation_writer'
        """)
            ).one()
            == (False,) * 7
        )
        assert connection.execute(
            text("""
            SELECT prosecdef,proconfig,pg_get_userbyid(proowner)
            FROM pg_proc WHERE oid=CAST(:fn AS regprocedure)
        """),
            {"fn": FUNCTION},
        ).one() == (True, ["search_path=pg_catalog"], "arbiter_reservation_writer")
        for role in ("arbiter_runtime", "arbiter_operator"):
            assert (
                connection.execute(
                    text("""
                SELECT count(*) FROM pg_auth_members
                WHERE member=(SELECT oid FROM pg_roles WHERE rolname=:role)
            """),
                    {"role": role},
                ).scalar_one()
                == 0
            )
        assert (
            connection.execute(
                text("""
            SELECT has_schema_privilege('arbiter_reservation_writer','arbiter','CREATE')
        """)
            ).scalar_one()
            is False
        )
        for table in TABLES:
            assert (
                connection.execute(
                    text("""
                SELECT has_table_privilege('arbiter_reservation_writer',:table,'DELETE,TRUNCATE')
            """),
                    {"table": "arbiter." + table},
                ).scalar_one()
                is False
            )
        for table in ("quota_windows", "budget_windows"):
            assert connection.execute(
                text("""
                SELECT has_column_privilege(
                    'arbiter_reservation_writer',:table,'reserved','UPDATE'),
                    has_column_privilege('arbiter_reservation_writer',:table,'committed','UPDATE')
            """),
                {"table": "arbiter." + table},
            ).one() == (True, False)


def test_poisoned_pool_context_is_discarded(store: ReservationStore) -> None:
    actor, other = store.actor(), store.actor()
    engine = create_engine(
        DatabaseSettings().url("runtime"), hide_parameters=True, pool_size=1, max_overflow=0
    )
    try:
        with engine.begin() as connection:
            poisoned: int = connection.execute(text("SELECT pg_backend_pid()")).scalar_one()
            connection.execute(
                text("SELECT set_config('arbiter.tenant_id',:tenant,false)"),
                {"tenant": str(other.tenant)},
            )
        with pytest.raises(ReservationUnavailable):
            reserve_using_engine(store, actor, engine)
        assert store.counts(actor) == store.counts(other) == (0,) * 6
        reserve_using_engine(store, actor, engine)
        with engine.begin() as connection:
            assert connection.execute(text("SELECT pg_backend_pid()")).scalar_one() != poisoned
            assert (
                connection.execute(
                    text("SELECT NULLIF(current_setting('arbiter.tenant_id',true),'')")
                ).scalar_one()
                is None
            )
    finally:
        engine.dispose()


def test_idempotency_is_bound_to_both_verified_key_and_tenant(store: ReservationStore) -> None:
    actor = store.actor()
    sibling, foreign = store.actor(existing=actor), store.actor()
    idem = uuid4().hex
    results = [reserve(store, each, idem=idem) for each in (actor, sibling, foreign)]
    assert len({result.request_id for result in results}) == 3
    assert store.counts(actor) == (1, 1, 2, 2, 2, 2)
    assert store.counts(foreign) == (1,) * 6


def test_revoked_key_cannot_obtain_an_existing_idempotency_record(store: ReservationStore) -> None:
    actor = store.actor()
    idem = uuid4().hex
    reserve(store, actor, idem=idem)
    with tenant_transaction(store.runtime, TenantContext(actor.tenant)) as tx:
        revoke_in_transaction(tx.connection(), actor)
    with pytest.raises(InvalidKey):
        reserve(store, actor, idem=idem)
    assert store.counts(actor) == (1,) * 6


def test_initial_model_authorization_precedes_idempotency(store: ReservationStore) -> None:
    actor = store.actor()
    idem = uuid4().hex
    reserve(store, actor, idem=idem)
    PolicyService(store.operator).set_policy(actor.tenant, PolicyInput(concurrency=2, aliases=()))
    with pytest.raises(ModelDenied):
        reserve(store, actor, idem=idem)
    assert store.counts(actor) == (1,) * 6


@pytest.mark.parametrize(
    "field,value",
    [
        ("idempotency", "x" * 15),
        ("idempotency", "x" * 129),
        ("fingerprint", b"x" * 31),
        ("fingerprint", None),
        ("version", 0),
        ("alias", "https://fixture.invalid"),
        ("output", 0),
        ("output", 1025),
    ],
)
def test_raw_input_cannot_bypass_validated_contract(
    store: ReservationStore,
    field: str,
    value: object,
) -> None:
    actor = store.actor()
    values = raw_parameters(store, actor)
    values[field] = value
    with pytest.raises(DBAPIError) as failure, store.runtime.begin() as connection:
        set_context(connection, actor.tenant)
        connection.execute(RAW_CALL, values)
    assert postgres_error(failure.value).sqlstate == "22023"
    assert store.counts(actor) == (0,) * 6


def test_new_workload_audit_projection_remains_content_free(
    store: ReservationStore,
    caplog: pytest.LogCaptureFixture,
    capsys: pytest.CaptureFixture[str],
) -> None:
    from dataclasses import asdict

    from arbiter.persistence.repositories import AuditRepository
    from arbiter.transport.audit import AuditMetadata

    actor = store.actor()
    result = reserve(store, actor)
    with tenant_transaction(store.runtime, TenantContext(actor.tenant)) as tx:
        events = AuditRepository(tx).list_page(page_size=100, after=None)
        projected = [AuditMetadata.model_validate(asdict(row)).model_dump_json() for row in events]
        stored: str = (
            tx.connection()
            .execute(
                text("""
            SELECT string_agg(to_jsonb(a)::text,'')
            FROM arbiter.audit_events a WHERE tenant_id=:tenant
        """),
                {"tenant": actor.tenant},
            )
            .scalar_one()
        )
    assert any('"actor_type":"api_key"' in row for row in projected)
    captured = capsys.readouterr()
    outputs = [stored, *projected, repr(result), caplog.text, captured.out, captured.err]
    sensitive = [
        actor.credential.get_secret_value(),
        actor.credential.get_secret_value().split(".")[-1],
        actor.candidate.verifier.get_secret_value().hex(),
        "synthetic reservation input",
    ]
    assert all(value not in output for value in sensitive for output in outputs), (
        "sensitive leakage"
    )
    assert all(
        "actor_api_key_id" not in row and "reservation_audit_id" not in row for row in projected
    )
