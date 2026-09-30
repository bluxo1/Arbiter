"""100 simultaneous allocations with user-approved, disposable capacity configuration.

Only this fresh test database raises the two capacity ceiling checks to 256.
Quota, budget, idempotency, identity, RLS, writer privileges, locking, accounting,
dispatch and terminal functions are identical to the application migrations.
The database/data are retained as verification evidence, never deployed.
"""

import os
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from threading import Barrier, Event, Lock
from uuid import uuid4

import psycopg
import pytest
from phase3_exit_support import (
    DIGEST,
    assert_unique,
    concurrent_engine,
    execute_service,
    receipts,
    wait,
)
from psycopg import sql
from sqlalchemy import create_engine, text
from test_migrations import migrate_to
from test_rate_admission import redis_ready as redis_ready
from test_reservation_transactions import Actor, ReservationStore

from arbiter.config import DatabaseSettings
from arbiter.governance.capacity import CapacityGate
from arbiter.governance.rate import RateGate
from arbiter.governance.reservation import ReservationDenied
from arbiter.operations.policy import PolicyInput
from arbiter.persistence.operator import OperatorRepository, operator_transaction
from arbiter.persistence.policy import PolicyRepository
from arbiter.persistence.workload import KeyBinding
from arbiter.providers.double import DeterministicProvider
from arbiter.providers.port import ProviderRequest, ProviderResult

pytestmark = pytest.mark.skipif(
    any(
        os.environ.get(flag) != "1"
        for flag in ("ARBITER_TEST_DATABASE", "ARBITER_TEST_MIGRATIONS", "ARBITER_TEST_REDIS")
    ),
    reason="requires real PostgreSQL/Redis and privileged disposable database setup",
)


@pytest.fixture(scope="module")
def allocation_store() -> Iterator[ReservationStore]:
    settings = DatabaseSettings()
    name = f"arbiter_p34_allocation_{uuid4().hex}"
    with psycopg.connect(
        host=settings.host,
        port=settings.port,
        dbname=settings.name,
        user="arbiter_bootstrap",
        password=settings.password("bootstrap").get_secret_value(),
        connect_timeout=5,
        autocommit=True,
    ) as admin:
        admin.execute(sql.SQL("CREATE DATABASE {}").format(sql.Identifier(name)))
        admin.execute(sql.SQL("REVOKE ALL ON DATABASE {} FROM PUBLIC").format(sql.Identifier(name)))
        admin.execute(
            sql.SQL("GRANT CONNECT, CREATE ON DATABASE {} TO arbiter_migration").format(
                sql.Identifier(name)
            )
        )
        admin.execute(
            sql.SQL(
                "GRANT CONNECT ON DATABASE {} TO "
                "arbiter_runtime,arbiter_operator,arbiter_maintenance"
            ).format(sql.Identifier(name))
        )
    with psycopg.connect(
        host=settings.host,
        port=settings.port,
        dbname=name,
        user="arbiter_bootstrap",
        password=settings.password("bootstrap").get_secret_value(),
        connect_timeout=5,
    ) as initial:
        initial.execute("REVOKE ALL ON SCHEMA public FROM PUBLIC")
        initial.execute("GRANT USAGE, CREATE ON SCHEMA public TO arbiter_migration")
    engines = tuple(
        create_engine(
            settings.url(role).set(database=name), hide_parameters=True, pool_size=1, max_overflow=0
        )
        for role in ("runtime", "operator", "migration")
    )
    runtime, operator, migration = engines
    try:
        migrate_to(migration, "head")
        with migration.begin() as connection:
            check_name, check_definition = connection.execute(
                text("""
                SELECT conname,pg_get_constraintdef(oid) FROM pg_constraint
                WHERE conrelid='arbiter.tenant_policies'::regclass AND contype='c'
                    AND pg_get_constraintdef(oid) LIKE '%concurrency%'
            """)
            ).one()
            assert "<= 2" in check_definition
            connection.exec_driver_sql(
                sql.SQL("ALTER TABLE arbiter.tenant_policies DROP CONSTRAINT {}")
                .format(sql.Identifier(check_name))
                .as_string()
            )
            connection.exec_driver_sql(
                "ALTER TABLE arbiter.tenant_policies ADD CONSTRAINT "
                "p34_test_capacity CHECK (concurrency BETWEEN 0 AND 256)"
            )
            definition: str = connection.execute(
                text("""
                SELECT pg_get_functiondef(
                    'arbiter.assert_policy_limits(uuid,bigint,bigint,bigint)'::regprocedure)
            """)
            ).scalar_one()
            old, new = "p_concurrency NOT BETWEEN 0 AND 2", "p_concurrency NOT BETWEEN 0 AND 256"
            assert definition.count(old) == 1
            replacement = definition.replace(old, new)
            assert replacement.replace(new, old) == definition
            connection.exec_driver_sql(replacement)
            model, alias = uuid4(), "p34-allocation-" + uuid4().hex
            connection.execute(
                text("""
                INSERT INTO arbiter.provider_models
                    (id,alias,adapter,model_digest,context_cap,output_cap,credit_charge,revision,active)
                VALUES (:id,:alias,'ollama',:digest,4096,256,10,1,true)
            """),
                {"id": model, "alias": alias, "digest": DIGEST},
            )
        # Check the application database still has its original ceiling.
        with concurrent_engine("migration") as production, production.connect() as connection:
            assert (
                connection.execute(
                    text("""
                SELECT pg_get_functiondef(
                    'arbiter.assert_policy_limits(uuid,bigint,bigint,bigint)'::regprocedure)
            """)
                )
                .scalar_one()
                .count(old)
                == 1
            )
            assert (
                connection.execute(
                    text("""
                SELECT pg_get_constraintdef(oid) FROM pg_constraint
                WHERE conrelid='arbiter.tenant_policies'::regclass AND contype='c'
                    AND pg_get_constraintdef(oid) LIKE '%concurrency%'
            """)
                ).scalar_one()
                == check_definition
            )
        with pytest.raises(ValueError, match="unvalidated deployment concurrency"):
            PolicyInput(concurrency=256)
        yield ReservationStore(runtime, operator, migration, model, alias)
    finally:
        for engine in engines:
            engine.dispose()
        # Retain this explicitly named fresh database and all accepted evidence.


def load_policy(store: ReservationStore, actor: Actor, *, quota: int, budget: int) -> None:
    with operator_transaction(store.operator, actor.tenant) as transaction:
        operator = OperatorRepository(transaction)
        tenant = operator.lock_tenant()
        repository = PolicyRepository(transaction)
        repository.validate_limits(quota, budget, 256)
        repository.validate_aliases((store.alias,))
        revision, policy_id = tenant.policy_revision + 1, uuid4()
        repository.advance_revision(tenant.policy_revision, revision)
        audit = operator.append_audit(
            action="tenant_policy_set", target_id=policy_id, revision=revision, correlation=uuid4()
        )
        repository.insert(
            policy_id=policy_id,
            revision=revision,
            audit_id=audit,
            limits=(512, 512, quota, budget, 256),
            aliases=(store.alias,),
        )


@pytest.mark.parametrize("boundary", ["quota", "budget", "combined", "independent_tenants"])
def test_100_simultaneous_allocations_never_overshoot(
    allocation_store: ReservationStore, monkeypatch: pytest.MonkeyPatch, boundary: str
) -> None:
    store = allocation_store
    actors = [store.actor() for _ in range(2 if boundary == "independent_tenants" else 1)]
    for actor in actors:
        load_policy(
            store,
            actor,
            quota=1000 if boundary == "budget" else 10,
            budget=10000 if boundary == "quota" else 100,
        )
    attempts, successes = 100 * len(actors), 10 * len(actors)
    all_preflight, start = Barrier(attempts), Barrier(attempts + 1)
    denied_all, providers_all, finish = Event(), Event(), Event()
    lock, denied, called = Lock(), 0, 0
    actual = RateGate.admit

    def preflight(gate: RateGate, binding: KeyBinding, tenant: int, key: int) -> None:
        assert tenant == key == 512
        all_preflight.wait(timeout=60)
        actual(gate, binding, tenant, key)

    monkeypatch.setattr(RateGate, "admit", preflight)

    class HeldDouble(DeterministicProvider):
        def generate(self, request: ProviderRequest, deadline: datetime) -> ProviderResult:
            nonlocal called
            result = super().generate(request, deadline)
            with lock:
                called += 1
                if called == successes:
                    providers_all.set()
            wait(finish)
            return result

    provider, gate = HeldDouble(store.model, DIGEST, 256), CapacityGate(256)
    database = store.runtime.url.database
    with (
        concurrent_engine(database=database) as engine,
        ThreadPoolExecutor(max_workers=attempts) as pool,
    ):
        service = execute_service(store, provider, gate, engine)

        def attempt(index: int) -> str:
            nonlocal denied
            start.wait(timeout=60)
            try:
                return service.execute(
                    actors[index % len(actors)].credential, uuid4().hex, store.request()
                ).state
            except ReservationDenied as error:
                with lock:
                    denied += 1
                    if denied == attempts - successes:
                        denied_all.set()
                return error.code

        futures = [pool.submit(attempt, index) for index in range(attempts)]
        try:
            start.wait(timeout=60)
            wait(denied_all)
            wait(providers_all)
            # All admitted providers are still running: terminal releases cannot
            # mask a quota, budget or durable occupancy race.
            assert gate.occupied == len(provider.calls) == successes
            for actor in actors:
                assert store.totals(actor) == (10, 0, 100, 0)
                rows = receipts(store, actor)
                assert len(rows) == 10 and all(row.state == "dispatched" for row in rows)
        finally:
            finish.set()
        results = [future.result(timeout=90) for future in futures]
    denial = "budget_exhausted" if boundary == "budget" else "quota_exhausted"
    assert results.count("succeeded") == successes
    assert results.count(denial) == attempts - successes
    assert gate.occupied == 0 and len(set(provider.calls)) == successes
    for actor in actors:
        assert store.totals(actor) == (10, 0, 100, 0)
        for row in receipts(store, actor):
            assert_unique(row)
            assert row.state == "succeeded" and row.commit_events == row.terminal_audits == 1
            assert row.release_events == 0
