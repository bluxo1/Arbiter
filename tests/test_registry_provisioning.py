"""Real PostgreSQL global operator journal, atomicity, revisions and tenant catalogs."""

import json
import os
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from pathlib import Path
from threading import Barrier
from typing import Any
from uuid import uuid4

import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError, IntegrityError
from test_provisioning import LocalStore, audits
from test_provisioning import local as local
from test_registry_input import approval, approval_values, configuration

import arbiter.operations.provision as cli
from arbiter.config import DatabaseSettings
from arbiter.identity.context import TenantContext
from arbiter.identity.model_cursor import ModelCursor
from arbiter.main import create_app
from arbiter.operations.models import ModelCatalog
from arbiter.operations.policy import PolicyInput, PolicyService
from arbiter.operations.registry import RegistryConflict, RegistryService
from arbiter.persistence.operator import OperatorAccessDenied, operator_engine
from arbiter.persistence.registry import RegistryRepository, registry_transaction
from arbiter.persistence.tenant import tenant_transaction

pytestmark = pytest.mark.skipif(
    os.environ.get("ARBITER_TEST_DATABASE") != "1", reason="real PostgreSQL required"
)


@pytest.fixture
def registry(local: LocalStore) -> Iterator[tuple[LocalStore, str]]:
    alias = "registry-fixture-" + uuid4().hex
    try:
        yield local, alias
    finally:
        with local.migration.begin() as connection:
            for tenant in local.tenants:
                connection.execute(
                    text("SELECT set_config('arbiter.tenant_id',:tenant,true)"),
                    {"tenant": str(tenant)},
                )
                connection.execute(
                    text("DELETE FROM arbiter.tenant_policies WHERE tenant_id=:tenant"),
                    {"tenant": tenant},
                )
            connection.execute(
                text("DELETE FROM arbiter.provider_models WHERE alias=:alias"), {"alias": alias}
            )
        # Committed journals are intentionally retained, including disposable-fixture history.


def history(store: LocalStore, alias: str) -> list[dict[str, Any]]:
    with store.operator.begin() as connection:
        return [
            dict(row)
            for row in connection.execute(
                text(
                    "SELECT * FROM arbiter.model_registry_journal "
                    "WHERE alias=:alias ORDER BY revision"
                ),
                {"alias": alias},
            ).mappings()
        ]


def test_register_update_revision_and_atomic_exact_evidence(
    registry: tuple[LocalStore, str],
) -> None:
    store, alias = registry
    service = RegistryService(store.operator)
    first = service.provision(configuration(alias), approval())
    second = service.provision(
        replace(configuration(alias), active=False, credit_charge=7),
        approval(),
        expected_revision=1,
    )
    assert first.model_id == second.model_id and [first.revision, second.revision] == [1, 2]
    events = history(store, alias)
    assert [row["action"] for row in events] == ["model_registered", "model_updated"]
    assert [row["id"] for row in events] == [first.journal_id, second.journal_id]
    assert events[-1]["active"] is False and events[-1]["credit_charge"] == 7
    assert all(
        row["actor_reference"] == "arbiter_operator"
        and row["outcome"] == "succeeded"
        and row["approval_digest"] == approval().digest()
        and row["occurred_at"].tzinfo is not None
        for row in events
    )
    assert "tenant_id" not in events[0]
    with store.operator.begin() as connection:
        row = connection.execute(
            text("SELECT id,revision,journal_id FROM arbiter.provider_models WHERE alias=:alias"),
            {"alias": alias},
        ).one()
        assert row == (second.model_id, 2, second.journal_id)
    assert all(len(audits(store, tenant)) == 1 for tenant in store.tenants)


def test_duplicate_stale_missing_and_invalid_updates_leave_no_journal(
    registry: tuple[LocalStore, str],
) -> None:
    store, alias = registry
    service = RegistryService(store.operator)
    service.provision(configuration(alias), approval())
    for model, expected in (
        (configuration(alias), None),
        (configuration(alias), 2),
        (configuration(alias + "-missing"), 1),
    ):
        with pytest.raises(RegistryConflict):
            service.provision(model, approval(), expected_revision=expected)
    assert len(history(store, alias)) == 1 and history(store, alias + "-missing") == []
    for revision in (0, -1, True, 2**63 - 1):
        with pytest.raises(ValueError):
            service.provision(configuration(alias), approval(), expected_revision=revision)


def test_failure_after_mutation_rolls_back_both_create_and_update(
    registry: tuple[LocalStore, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    store, alias = registry
    service = RegistryService(store.operator)
    original = RegistryRepository.provision

    def fail(self: RegistryRepository, **values: Any) -> Any:
        original(self, **values)
        raise RuntimeError("injected after database mutation")

    with monkeypatch.context() as patch:
        patch.setattr(RegistryRepository, "provision", fail)
        with pytest.raises(RuntimeError):
            service.provision(configuration(alias), approval())
    assert history(store, alias) == []
    with store.operator.begin() as connection:
        assert (
            connection.execute(
                text("SELECT count(*) FROM arbiter.provider_models WHERE alias=:alias"),
                {"alias": alias},
            ).scalar_one()
            == 0
        )
    first = service.provision(configuration(alias), approval())
    with monkeypatch.context() as patch:
        patch.setattr(RegistryRepository, "provision", fail)
        with pytest.raises(RuntimeError):
            service.provision(
                replace(configuration(alias), active=False), approval(), expected_revision=1
            )
    assert len(history(store, alias)) == 1
    with store.operator.begin() as connection:
        assert connection.execute(
            text(
                "SELECT revision,active,journal_id FROM arbiter.provider_models WHERE alias=:alias"
            ),
            {"alias": alias},
        ).one() == (1, True, first.journal_id)


@pytest.mark.parametrize("role", ["runtime", "migration"])
def test_service_requires_actual_operator_credential(
    registry: tuple[LocalStore, str], role: str
) -> None:
    store, alias = registry
    with pytest.raises(OperatorAccessDenied):
        RegistryService(getattr(store, role)).provision(configuration(alias), approval())
    assert history(store, alias) == []


@pytest.mark.parametrize(
    "statement",
    [
        "SELECT * FROM arbiter.model_registry_journal",
        "INSERT INTO arbiter.provider_models DEFAULT VALUES",
        "UPDATE arbiter.provider_models SET active=false",
        "DELETE FROM arbiter.provider_models",
        "UPDATE arbiter.model_registry_journal SET active=false",
        "DELETE FROM arbiter.model_registry_journal",
        "TRUNCATE arbiter.model_registry_journal",
        "TRUNCATE arbiter.provider_models,arbiter.model_registry_journal CASCADE",
        "SELECT * FROM arbiter.provision_model('fixture','ollama',"
        "NULL,1,1,1,true,NULL,NULL,NULL,NULL,NULL)",
    ],
)
def test_runtime_cannot_read_global_journal_or_mutate_registry(
    registry: tuple[LocalStore, str], statement: str
) -> None:
    store, _ = registry
    with pytest.raises(DBAPIError) as failure:
        with store.runtime.begin() as connection:
            connection.execute(text(statement))
    assert getattr(failure.value.orig, "sqlstate", None) == "42501"


@pytest.mark.parametrize("role", ["operator", "migration"])
@pytest.mark.parametrize(
    "operation",
    [
        "UPDATE arbiter.model_registry_journal SET active=false WHERE id=:id",
        "DELETE FROM arbiter.model_registry_journal WHERE id=:id",
        "TRUNCATE arbiter.model_registry_journal",
        "TRUNCATE arbiter.provider_models,arbiter.model_registry_journal CASCADE",
    ],
)
def test_journal_is_immutable_even_for_table_owner(
    registry: tuple[LocalStore, str], role: str, operation: str
) -> None:
    store, alias = registry
    result = RegistryService(store.operator).provision(configuration(alias), approval())
    with pytest.raises(DBAPIError) as failure:
        with getattr(store, role).begin() as connection:
            connection.execute(text(operation), {"id": result.journal_id})
    expected = (
        "0A000"
        if role == "migration" and operation == "TRUNCATE arbiter.model_registry_journal"
        else "42501"
    )
    assert getattr(failure.value.orig, "sqlstate", None) == expected
    assert len(history(store, alias)) == 1


def test_exact_revision_journal_foreign_key_rejects_mismatched_configuration(
    registry: tuple[LocalStore, str],
) -> None:
    store, alias = registry
    service = RegistryService(store.operator)
    first = service.provision(configuration(alias), approval())
    second = service.provision(
        replace(configuration(alias), active=False), approval(), expected_revision=1
    )
    with pytest.raises(IntegrityError) as failure:
        with store.migration.begin() as connection:
            connection.execute(
                text(
                    "UPDATE arbiter.provider_models SET revision=3,journal_id=:event WHERE id=:id"
                ),
                {"event": first.journal_id, "id": second.model_id},
            )
    assert getattr(failure.value.orig, "sqlstate", None) == "23503"
    assert len(history(store, alias)) == 2


def test_inactive_models_leave_only_authorized_current_catalogs(
    registry: tuple[LocalStore, str],
) -> None:
    store, alias = registry
    service = RegistryService(store.operator)
    service.provision(configuration(alias), approval())
    PolicyService(store.operator).set_policy(store.tenants[0], PolicyInput(aliases=(alias,)))
    PolicyService(store.operator).set_policy(store.tenants[1], PolicyInput())
    catalog = ModelCatalog(ModelCursor(bytes(32)))

    def names(tenant: Any) -> list[str]:
        with tenant_transaction(store.runtime, TenantContext(tenant)) as scoped:
            return [row.alias for row in catalog.read(scoped, []).data]

    assert names(store.tenants[0]) == [alias] and names(store.tenants[1]) == []
    service.provision(replace(configuration(alias), active=False), approval(), expected_revision=1)
    assert names(store.tenants[0]) == names(store.tenants[1]) == []
    service.provision(configuration(alias), approval(), expected_revision=2)
    assert names(store.tenants[0]) == [alias] and names(store.tenants[1]) == []
    assert all(len(audits(store, tenant)) == 2 for tenant in store.tenants)


def test_concurrent_updates_compare_revisions_without_lost_audits(
    registry: tuple[LocalStore, str],
) -> None:
    store, alias = registry
    RegistryService(store.operator).provision(configuration(alias), approval())
    engines = [operator_engine(DatabaseSettings()) for _ in range(2)]
    barrier = Barrier(2)

    def update(index: int) -> bool:
        barrier.wait(timeout=5)
        try:
            RegistryService(engines[index]).provision(
                replace(configuration(alias), credit_charge=7 + index),
                approval(),
                expected_revision=1,
            )
            return True
        except RegistryConflict:
            return False

    try:
        with ThreadPoolExecutor(max_workers=2) as executor:
            assert sorted(executor.map(update, range(2))) == [False, True]
        assert [row["revision"] for row in history(store, alias)] == [1, 2]
    finally:
        for engine in engines:
            engine.dispose()


def test_operator_pool_global_and_tenant_context_do_not_mix(
    registry: tuple[LocalStore, str],
) -> None:
    store, alias = registry
    with registry_transaction(store.operator) as connection:
        backend: int = connection.execute(text("SELECT pg_backend_pid()")).scalar_one()
        assert (
            connection.execute(
                text("SELECT NULLIF(current_setting('arbiter.tenant_id',true),'')")
            ).scalar_one()
            is None
        )
    RegistryService(store.operator).provision(configuration(alias), approval())
    with store.operator.begin() as connection:
        connection.execute(
            text("SELECT set_config('arbiter.tenant_id',:tenant,false)"),
            {"tenant": str(store.tenants[0])},
        )
    with pytest.raises(OperatorAccessDenied):
        RegistryService(store.operator).provision(
            configuration(alias), approval(), expected_revision=1
        )
    with registry_transaction(store.operator) as connection:
        assert connection.execute(text("SELECT pg_backend_pid()")).scalar_one() != backend
    assert len(history(store, alias)) == 1


def test_cli_approved_file_and_sanitized_errors(
    registry: tuple[LocalStore, str],
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    caplog: pytest.LogCaptureFixture,
) -> None:
    store, alias = registry
    path = tmp_path / "attestation.json"
    path.write_text(json.dumps(approval_values()))
    args = [
        "--alias",
        alias,
        "--adapter",
        "ollama",
        "--digest",
        configuration().model_digest,
        "--context-cap",
        "4096",
        "--output-cap",
        "256",
        "--credit-charge",
        "10",
        "--state",
        "active",
        "--approval",
        str(path),
    ]
    cli.main(["register-model", *args])
    output = capsys.readouterr().out
    result = json.loads(output)
    assert (
        set(result) == {"model_id", "revision", "journal_id", "correlation_id"}
        and result["revision"] == 1
    )
    cli.main(["update-model", *args, "--expected-revision", "1"])
    assert json.loads(capsys.readouterr().out)["revision"] == 2
    path.write_text(json.dumps({**approval_values(), "secret": "rejected-secret-marker"}))
    with pytest.raises(SystemExit) as failure:
        cli.main(["update-model", *args, "--expected-revision", "2"])
    assert "rejected-secret-marker" not in str(
        failure.value
    ) + capsys.readouterr().out + caplog.text + json.dumps(history(store, alias), default=str)
    with pytest.raises(SystemExit) as failure:
        cli.main(
            ["register-model", *args, "--provider-url", "https://rejected-secret-marker.invalid"]
        )
    assert "rejected-secret-marker" not in str(failure.value)


def test_owner_search_path_acl_and_no_operator_direct_dml(registry: tuple[LocalStore, str]) -> None:
    store, _ = registry
    with store.migration.begin() as connection:
        assert connection.execute(
            text(
                "SELECT prosecdef,proconfig,pg_get_userbyid(proowner) FROM pg_proc "
                "WHERE pronamespace='arbiter'::regnamespace AND proname='provision_model'"
            )
        ).one() == (True, ["search_path=pg_catalog"], "arbiter_migration")
        assert (
            connection.execute(
                text(
                    "SELECT count(*) FROM pg_proc p,LATERAL aclexplode(p.proacl) a "
                    "WHERE p.pronamespace='arbiter'::regnamespace "
                    "AND p.proname='provision_model' AND a.grantee=0"
                )
            ).scalar_one()
            == 0
        )
    for statement in (
        "UPDATE arbiter.provider_models SET active=false",
        "INSERT INTO arbiter.model_registry_journal DEFAULT VALUES",
    ):
        with pytest.raises(DBAPIError) as failure:
            with store.operator.begin() as connection:
                connection.execute(text(statement))
        assert getattr(failure.value.orig, "sqlstate", None) == "42501"
    assert all(
        "operator" not in getattr(route, "path", "")
        and "registry" not in getattr(route, "path", "")
        for route in create_app().routes
    )


def test_inactive_registration_and_approved_digest_update(registry: tuple[LocalStore, str]) -> None:
    store, alias = registry
    service = RegistryService(store.operator)
    first = service.provision(replace(configuration(alias), active=False), approval())
    assert history(store, alias)[0]["active"] is False
    changed = approval().model_copy(update={"model_digest": "sha256:" + "d" * 64})
    second = service.provision(
        replace(configuration(alias), model_digest=changed.model_digest),
        changed,
        expected_revision=1,
    )
    assert second.model_id == first.model_id and second.revision == 2
    assert history(store, alias)[1]["model_digest"] == changed.model_digest


def test_unapproved_update_leaves_exact_old_evidence(registry: tuple[LocalStore, str]) -> None:
    store, alias = registry
    service = RegistryService(store.operator)
    service.provision(configuration(alias), approval())
    before = history(store, alias)
    with pytest.raises(ValueError, match="unapproved model configuration"):
        service.provision(
            replace(configuration(alias), model_digest="sha256:" + "d" * 64),
            approval(),
            expected_revision=1,
        )
    assert history(store, alias) == before


def test_migration_cannot_manufacture_operator_journal(registry: tuple[LocalStore, str]) -> None:
    store, alias = registry
    RegistryService(store.operator).provision(configuration(alias), approval())
    with pytest.raises(DBAPIError) as failure:
        with store.migration.begin() as connection:
            connection.execute(
                text(
                    "INSERT INTO arbiter.model_registry_journal "
                    "SELECT * FROM arbiter.model_registry_journal WHERE alias=:alias"
                ),
                {"alias": alias},
            )
    assert getattr(failure.value.orig, "sqlstate", None) == "42501"
    assert len(history(store, alias)) == 1
