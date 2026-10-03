"""Operator-owned native binding and durable dispatch target on real PostgreSQL."""

import os
from collections.abc import Iterator, Sequence
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from threading import Barrier, Event
from time import monotonic, sleep
from typing import Any
from uuid import uuid4

import pytest
from sqlalchemy import create_engine, event, text
from sqlalchemy.engine import Connection, Engine
from sqlalchemy.exc import DBAPIError
from sqlalchemy.pool import NullPool
from test_dispatch_authorization import acquire
from test_migrations import migrate_to
from test_registry_input import approval_values
from test_reservation_transactions import ReservationStore

from arbiter.config import DatabaseSettings
from arbiter.governance.capacity import CapacityGate
from arbiter.governance.dispatch import DispatchRejected, DispatchService
from arbiter.identity.context import TenantContext
from arbiter.operations.registry import (
    ModelApproval,
    ModelInput,
    NativeBindingInput,
    RegistryConflict,
    RegistryService,
)
from arbiter.persistence.dispatch import DispatchRepository
from arbiter.persistence.provider_binding import (
    PinnedModelIdentity,
    ProviderBindingUnavailable,
    dispatched_ollama_binding,
)
from arbiter.persistence.registry import RegistryRepository, registry_transaction
from arbiter.persistence.tenant import tenant_transaction
from arbiter.persistence.workload import KeyBinding
from arbiter.providers.double import DeterministicProvider
from arbiter.providers.ollama import OllamaProvider

pytestmark = pytest.mark.skipif(
    os.environ.get("ARBITER_TEST_DATABASE") != "1"
    or os.environ.get("ARBITER_TEST_MIGRATIONS") != "1",
    reason="requires real PostgreSQL and disposable migration database",
)
pytest_plugins = ("test_migrations",)
DIGEST = "sha256:" + "d" * 64
LOCAL_NAMES = ("fixture:one", "llama3.2:latest", "qwen3:4b")
CLOUD_NAMES = (
    "fixture:cloud",
    "gpt-oss:120b-cloud",
    "fixture:tag-cloud",
    "fixture:CLOUD",
    "gpt-oss:120b-Cloud",
    "fixture:TAG-CLOUD",
)


@pytest.fixture
def binding_store(disposable_database: Engine) -> Iterator[tuple[ReservationStore, ModelApproval]]:
    migrate_to(disposable_database, "head")
    settings = DatabaseSettings()
    runtime, operator = (
        create_engine(
            settings.url(role).set(database=disposable_database.url.database),
            poolclass=NullPool,
            hide_parameters=True,
        )
        for role in ("runtime", "operator")
    )
    proof = ModelApproval.model_validate({**approval_values(), "model_digest": DIGEST})
    alias = "bound-" + uuid4().hex
    registered = RegistryService(operator).provision(
        ModelInput(alias, "ollama", DIGEST, 4096, 256, 10, True), proof
    )
    try:
        yield (
            ReservationStore(runtime, operator, disposable_database, registered.model_id, alias),
            proof,
        )
    finally:
        runtime.dispose()
        operator.dispose()


def bind(store: ReservationStore, proof: ModelApproval, revision: int, name: str) -> int:
    result = RegistryService(store.operator).bind_native_model(
        NativeBindingInput(store.model, revision, "ollama", name), proof
    )
    assert result.model_id == store.model
    return result.revision


@pytest.mark.parametrize(
    "kind,name",
    [
        ("remote", "fixture:one"),
        ("ollama", ""),
        ("ollama", "https://host/model:one"),
        ("ollama", "host:11434/model:one"),
        ("ollama", "fixture:cloud"),
        *(("ollama", name) for name in CLOUD_NAMES[1:]),
        ("ollama", "fixture:one two"),
        ("ollama", "fixture:\nother"),
    ],
)
def test_binding_input_rejects_untrusted_kind_or_tag(kind: str, name: str) -> None:
    with pytest.raises(ValueError):
        NativeBindingInput(uuid4(), 1, kind, name)


@pytest.mark.parametrize("name", LOCAL_NAMES)
def test_binding_input_accepts_local_name(name: str) -> None:
    assert NativeBindingInput(uuid4(), 1, "ollama", name).native_name == name


@pytest.mark.parametrize("name", LOCAL_NAMES)
def test_database_binding_accepts_local_name(
    binding_store: tuple[ReservationStore, ModelApproval], name: str
) -> None:
    store, proof = binding_store
    assert bind(store, proof, 1, name) == 2


@pytest.mark.parametrize("name", CLOUD_NAMES)
def test_database_binding_function_rejects_cloud_name_without_python(
    binding_store: tuple[ReservationStore, ModelApproval], name: str
) -> None:
    store, proof = binding_store
    with pytest.raises(DBAPIError):
        with registry_transaction(store.operator) as connection:
            connection.execute(
                text("""
                SELECT * FROM arbiter.bind_provider_model(
                    :model,1,'ollama',:name,:digest,4096,256,:approval,:journal,:correlation)
                """),
                {
                    "model": store.model,
                    "name": name,
                    "digest": DIGEST,
                    "approval": proof.digest(),
                    "journal": uuid4(),
                    "correlation": uuid4(),
                },
            ).all()
    with store.migration.begin() as connection:
        assert (
            connection.execute(
                text("SELECT revision FROM arbiter.provider_models WHERE id=:model"),
                {"model": store.model},
            ).scalar_one()
            == 1
        )


@pytest.mark.parametrize("name", ("gpt-oss:120b-cloud", "fixture:TAG-CLOUD"))
def test_database_check_rejects_cloud_name_without_python(
    binding_store: tuple[ReservationStore, ModelApproval], name: str
) -> None:
    store, _proof = binding_store
    # Grant only inside this disposable database to reach the CHECK past the
    # operator-only trigger; the ordinary operator role cannot insert directly.
    with store.migration.begin() as connection:
        connection.execute(
            text("GRANT INSERT ON arbiter.provider_model_bindings TO arbiter_operator")
        )
    try:
        with pytest.raises(DBAPIError, match="provider_model_bindings_native_name_check"):
            with store.operator.begin() as connection:
                connection.execute(
                    text("""
                    INSERT INTO arbiter.provider_model_bindings
                        (model_id,revision,provider_kind,native_name)
                    VALUES (:model,2,'ollama',:name)
                    """),
                    {"model": store.model, "name": name},
                )
    finally:
        with store.migration.begin() as connection:
            connection.execute(
                text("REVOKE INSERT ON arbiter.provider_model_bindings FROM arbiter_operator")
            )


def test_operator_binding_revision_evidence_uniqueness_and_privileges(
    binding_store: tuple[ReservationStore, ModelApproval],
) -> None:
    store, proof = binding_store
    assert bind(store, proof, 1, "fixture:one") == 2
    with store.migration.begin() as connection:
        row = connection.execute(
            text("""
            SELECT m.revision,b.provider_kind,b.native_name,j.action,j.native_name
            FROM arbiter.provider_models m JOIN arbiter.provider_model_bindings b
                ON b.model_id=m.id AND b.revision=m.revision
            JOIN arbiter.model_registry_journal j
                ON j.model_id=b.model_id AND j.revision=b.revision
            WHERE m.id=:model
        """),
            {"model": store.model},
        ).one()
    assert row == (2, "ollama", "fixture:one", "model_bound", "fixture:one")
    with pytest.raises(RegistryConflict):
        bind(store, proof, 1, "fixture:other")
    with pytest.raises(RegistryConflict):
        RegistryService(store.operator).bind_native_model(
            NativeBindingInput(uuid4(), 1, "ollama", "fixture:one"), proof
        )
    with store.operator.begin() as connection:
        assert not connection.execute(
            text(
                "SELECT has_table_privilege(current_user,"
                "'arbiter.provider_model_bindings','INSERT')"
            )
        ).scalar_one()
    with store.runtime.begin() as connection:
        assert not connection.execute(
            text("SELECT has_function_privilege(current_user,:function,'EXECUTE')"),
            {
                "function": "arbiter.bind_provider_model(uuid,bigint,text,text,text,bigint,"
                "bigint,text,uuid,uuid)"
            },
        ).scalar_one()
        assert not connection.execute(
            text(
                "SELECT has_table_privilege(current_user,"
                "'arbiter.provider_model_bindings','INSERT')"
            )
        ).scalar_one()
    assert bind(store, proof, 2, "fixture:two") == 3
    with store.migration.begin() as connection:
        names = connection.execute(
            text("""
            SELECT revision,native_name FROM arbiter.provider_model_bindings
            WHERE model_id=:model ORDER BY revision
        """),
            {"model": store.model},
        ).all()
    assert names == [(2, "fixture:one"), (3, "fixture:two")]


def test_binding_schema_is_model_keyed_and_empty_migration_round_trips(
    disposable_database: Engine,
) -> None:
    migrate_to(disposable_database, "0017_maintenance_recovery")
    migrate_to(disposable_database, "head")
    with disposable_database.begin() as connection:
        constraints: Sequence[str] = (
            connection.execute(
                text("""
            SELECT pg_get_constraintdef(c.oid) FROM pg_constraint c
            WHERE c.conrelid='arbiter.provider_model_bindings'::regclass
        """)
            )
            .scalars()
            .all()
        )
        assert any(
            "FOREIGN KEY (model_id) REFERENCES arbiter.provider_models" in c for c in constraints
        )
        assert any(
            "FOREIGN KEY (model_id, revision, provider_kind, native_name)" in c for c in constraints
        )
        assert connection.execute(
            text("""
            SELECT relrowsecurity AND relforcerowsecurity FROM pg_class
            WHERE oid='arbiter.dispatched_provider_bindings'::regclass
        """)
        ).scalar_one()
    migrate_to(disposable_database, "0017_maintenance_recovery", downgrade=True)
    migrate_to(disposable_database, "head")


def test_invalid_database_binding_does_not_advance_revision(
    binding_store: tuple[ReservationStore, ModelApproval],
) -> None:
    store, proof = binding_store
    with pytest.raises(DBAPIError):
        with registry_transaction(store.operator) as connection:
            connection.execute(
                text("""
                SELECT * FROM arbiter.bind_provider_model(
                    :model,1,'remote','https://host/model','sha256:' || repeat('d',64),
                    4096,1024,:approval,:journal,:correlation)
            """),
                {
                    "model": store.model,
                    "approval": proof.digest(),
                    "journal": uuid4(),
                    "correlation": uuid4(),
                },
            ).all()
    with store.migration.begin() as connection:
        assert (
            connection.execute(
                text("SELECT revision FROM arbiter.provider_models WHERE id=:model"),
                {"model": store.model},
            ).scalar_one()
            == 1
        )
        assert (
            connection.execute(
                text("""
            SELECT count(*) FROM arbiter.model_registry_journal
            WHERE model_id=:model
        """),
                {"model": store.model},
            ).scalar_one()
            == 1
        )


def test_binding_update_rejects_old_reservation_before_provider(
    binding_store: tuple[ReservationStore, ModelApproval],
) -> None:
    store, proof = binding_store
    assert bind(store, proof, 1, "fixture:one") == 2
    actor, gate = store.actor(), CapacityGate(1)
    lease = acquire(store, actor, gate)
    provider = DeterministicProvider(store.model, DIGEST, 256)
    assert bind(store, proof, 2, "fixture:two") == 3
    with pytest.raises(DispatchRejected) as rejected:
        DispatchService(store.runtime).authorize(lease)
    assert rejected.value.reason == "authorization_changed"
    assert provider.calls == () and gate.occupied == 0
    with store.migration.begin() as connection:
        assert (
            connection.execute(
                text("""
            SELECT count(*) FROM arbiter.dispatched_provider_bindings
            WHERE tenant_id=:tenant AND request_id=:request
        """),
                {"tenant": actor.tenant, "request": lease.result.request_id},
            ).scalar_one()
            == 0
        )


def test_authorized_dispatch_keeps_old_tag_after_binding_update(
    binding_store: tuple[ReservationStore, ModelApproval],
) -> None:
    store, proof = binding_store
    assert bind(store, proof, 1, "fixture:one") == 2
    actor, gate = store.actor(), CapacityGate(1)
    lease = acquire(store, actor, gate)
    DispatchService(store.runtime).authorize(lease)
    assert bind(store, proof, 2, "fixture:two") == 3
    pinned = PinnedModelIdentity(store.model, DIGEST, 2)
    key = KeyBinding(actor.key, actor.tenant, ("inference:write",))
    with tenant_transaction(store.runtime, TenantContext(actor.tenant)) as transaction:
        selection = dispatched_ollama_binding(transaction, key, lease.result.request_id, pinned)
        assert selection is not None
        assert selection.provider_kind == "ollama"
        assert selection.ollama_binding.native_name == "fixture:one"
        assert selection.ollama_binding.native_name != store.alias
        assert selection.ollama_binding.model_id == store.model
        assert selection.ollama_binding.digest == DIGEST
        assert isinstance(selection.provider(), OllamaProvider)
        with pytest.raises(RuntimeError):
            dispatched_ollama_binding(
                transaction,
                key,
                lease.result.request_id,
                replace(pinned, model_id=uuid4()),
            )
        with pytest.raises(RuntimeError):
            dispatched_ollama_binding(
                transaction,
                key,
                lease.result.request_id,
                replace(pinned, digest="sha256:" + "e" * 64),
            )


def test_missing_or_foreign_binding_has_no_default_or_cross_tenant_resolution(
    binding_store: tuple[ReservationStore, ModelApproval],
) -> None:
    store, _proof = binding_store
    actor, foreign, gate = store.actor(), store.actor(), CapacityGate(1)
    lease = acquire(store, actor, gate)
    DispatchService(store.runtime).authorize(lease)
    pinned = PinnedModelIdentity(store.model, DIGEST, 1)
    with tenant_transaction(store.runtime, TenantContext(actor.tenant)) as transaction:
        with pytest.raises(ProviderBindingUnavailable):
            dispatched_ollama_binding(
                transaction,
                KeyBinding(actor.key, actor.tenant, ("inference:write",)),
                lease.result.request_id,
                pinned,
            )
    with tenant_transaction(store.runtime, TenantContext(foreign.tenant)) as transaction:
        with pytest.raises(ProviderBindingUnavailable):
            dispatched_ollama_binding(
                transaction,
                KeyBinding(foreign.key, foreign.tenant, ("inference:write",)),
                lease.result.request_id,
                pinned,
            )


def test_concurrent_binding_updates_have_one_revision_winner(
    binding_store: tuple[ReservationStore, ModelApproval],
) -> None:
    store, proof = binding_store
    assert bind(store, proof, 1, "fixture:one") == 2
    barrier = Barrier(2)

    def update(name: str) -> bool:
        barrier.wait(timeout=5)
        try:
            bind(store, proof, 2, name)
            return True
        except RegistryConflict:
            return False

    with ThreadPoolExecutor(max_workers=2) as pool:
        assert sorted(pool.map(update, ("fixture:two", "fixture:three"))) == [False, True]
    with store.migration.begin() as connection:
        assert (
            connection.execute(
                text("SELECT revision FROM arbiter.provider_models WHERE id=:model"),
                {"model": store.model},
            ).scalar_one()
            == 3
        )
        assert (
            connection.execute(
                text("""
            SELECT count(*) FROM arbiter.provider_model_bindings WHERE model_id=:model
        """),
                {"model": store.model},
            ).scalar_one()
            == 2
        )


def test_binding_migration_refuses_lossy_downgrade(
    binding_store: tuple[ReservationStore, ModelApproval],
) -> None:
    store, proof = binding_store
    assert bind(store, proof, 1, "fixture:one") == 2
    with pytest.raises(Exception, match="provider binding downgrade would lose evidence"):
        migrate_to(store.migration, "0017_maintenance_recovery", downgrade=True)


@pytest.mark.parametrize("winner", ["binding", "dispatch"])
def test_binding_dispatch_lock_race_has_only_pinned_outcomes(
    binding_store: tuple[ReservationStore, ModelApproval], winner: str
) -> None:
    store, proof = binding_store
    assert bind(store, proof, 1, "fixture:one") == 2
    actor, gate = store.actor(), CapacityGate(1)
    lease = acquire(store, actor, gate)
    observed = Event()
    pids: list[int] = []
    contender = store.runtime if winner == "binding" else store.operator

    def observe(
        connection: Connection,
        cursor: Any,
        statement: str,
        parameters: Any,
        context: Any,
        executemany: bool,
    ) -> None:
        del cursor, parameters, context, executemany
        sought = (
            "arbiter.authorize_dispatch" if winner == "binding" else "arbiter.bind_provider_model"
        )
        if sought in statement:
            driver: Any = connection.connection.driver_connection
            pids.append(driver.info.backend_pid)
            observed.set()

    def wait_for_lock() -> None:
        assert observed.wait(10)
        deadline = monotonic() + 10
        while monotonic() < deadline:
            with store.migration.connect() as connection:
                blocked: bool = connection.execute(
                    text("SELECT cardinality(pg_blocking_pids(:pid))>0"),
                    {"pid": pids[-1]},
                ).scalar_one()
            if blocked:
                return
            sleep(0.02)
        pytest.fail("expected PostgreSQL model-row lock contention")

    event.listen(contender, "before_cursor_execute", observe)
    try:
        with ThreadPoolExecutor(max_workers=1) as pool:
            if winner == "binding":
                with registry_transaction(store.operator) as connection:
                    RegistryRepository(connection).bind_native_model(
                        model_id=store.model,
                        expected=2,
                        provider_kind="ollama",
                        native_name="fixture:two",
                        digest=DIGEST,
                        context=proof.context_cap,
                        output=proof.output_cap,
                        approval=proof.digest(),
                        journal_id=uuid4(),
                        correlation=uuid4(),
                    )
                    dispatch_future = pool.submit(DispatchService(store.runtime).authorize, lease)
                    wait_for_lock()
                    assert not dispatch_future.done()
                with pytest.raises(DispatchRejected) as rejected:
                    dispatch_future.result(timeout=10)
                assert rejected.value.reason == "authorization_changed"
                assert gate.occupied == 0
            else:
                with tenant_transaction(store.runtime, TenantContext(actor.tenant)) as tx:
                    decision = DispatchRepository(tx).authorize(
                        lease._binding, lease.result.request_id
                    )
                    assert decision.decision == "authorized"
                    binding_future = pool.submit(bind, store, proof, 2, "fixture:two")
                    wait_for_lock()
                    assert not binding_future.done()
                assert binding_future.result(timeout=10) == 3
                key = KeyBinding(actor.key, actor.tenant, ("inference:write",))
                with tenant_transaction(store.runtime, TenantContext(actor.tenant)) as tx:
                    selection = dispatched_ollama_binding(
                        tx,
                        key,
                        lease.result.request_id,
                        PinnedModelIdentity(store.model, DIGEST, 2),
                    )
                assert selection is not None
                assert selection.ollama_binding.native_name == "fixture:one"
    finally:
        event.remove(contender, "before_cursor_execute", observe)
