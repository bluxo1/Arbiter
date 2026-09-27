"""Real PostgreSQL policy ownership, restricted privileges and audit atomicity."""

import json
import os
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor
from uuid import UUID, uuid4

import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError, IntegrityError
from test_provisioning import LocalStore, audits
from test_provisioning import local as local

import arbiter.persistence.operator as operator_module
from arbiter.config import DatabaseSettings
from arbiter.identity.context import TenantContext
from arbiter.operations.policy import PolicyInput, PolicyService
from arbiter.operations.provision import main
from arbiter.persistence.operator import (
    OperatorAccessDenied,
    ProvisioningNotFound,
    operator_engine,
    operator_transaction,
)
from arbiter.persistence.policy import PolicyRepository
from arbiter.persistence.tenant import tenant_transaction

pytestmark = pytest.mark.skipif(
    os.environ.get("ARBITER_TEST_DATABASE") != "1", reason="requires provisioned real PostgreSQL"
)


@pytest.fixture
def policies(local: LocalStore) -> Iterator[LocalStore]:
    try:
        yield local
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


@pytest.fixture
def aliases(policies: LocalStore) -> Iterator[tuple[str, str]]:
    names = (f"approved-{uuid4().hex}", f"inactive-{uuid4().hex}")
    with policies.migration.begin() as connection:
        for alias, active in zip(names, (True, False), strict=True):
            connection.execute(
                text("""
                    INSERT INTO arbiter.provider_models
                        (id,alias,adapter,model_digest,context_cap,output_cap,credit_charge,
                         revision,active)
                    VALUES (:id,:alias,'ollama',:digest,4096,1024,10,1,:active)
                """),
                {"id": uuid4(), "alias": alias, "digest": "sha256:" + "a" * 64, "active": active},
            )
    try:
        yield names
    finally:
        with policies.migration.begin() as connection:
            connection.execute(
                text("DELETE FROM arbiter.provider_models WHERE alias=ANY(:aliases)"),
                {"aliases": list(names)},
            )


def rows(store: LocalStore, tenant: UUID) -> list[dict[str, object]]:
    with tenant_transaction(store.runtime, TenantContext(tenant)) as transaction:
        return [
            dict(row)
            for row in transaction.connection()
            .execute(
                text(
                    "SELECT * FROM arbiter.tenant_policies "
                    "WHERE tenant_id=:tenant ORDER BY revision"
                ),
                {"tenant": tenant},
            )
            .mappings()
        ]


def revision(store: LocalStore, tenant: UUID) -> int:
    with tenant_transaction(store.runtime, TenantContext(tenant)) as transaction:
        return int(
            transaction.connection()
            .execute(
                text(
                    "SELECT policy_revision FROM arbiter.tenants "
                    "WHERE id=:tenant AND tenant_id=:tenant"
                ),
                {"tenant": tenant},
            )
            .scalar_one()
        )


def test_provision_update_preserves_history_and_atomic_audits(policies: LocalStore) -> None:
    tenant, other = policies.tenants
    service = PolicyService(policies.operator)
    first = service.set_policy(tenant, PolicyInput())
    second = service.set_policy(tenant, PolicyInput(0, 0, 0, 0, 0))
    third = service.set_policy(tenant, PolicyInput(0, 0, 0, 0, 0))
    assert [first.revision, second.revision, third.revision] == [2, 3, 4]
    history = rows(policies, tenant)
    assert len(history) == 3 and history[0]["tenant_rate"] == 60
    assert history[0]["key_rate"] == 30 and history[0]["daily_quota"] == 1000
    assert history[0]["monthly_budget"] == 10000 and history[0]["concurrency"] == 1
    for result, row, event in zip(
        (first, second, third), history, audits(policies, tenant)[1:], strict=True
    ):
        assert row["id"] == result.policy_id and row["audit_id"] == result.audit_id
        assert event["target_id"] == result.policy_id and event["id"] == result.audit_id
        assert event["policy_revision"] == result.revision == row["revision"]
        assert event["request_id"] == result.correlation_id
        assert event["actor_type"] == "operator" and event["actor_reference"] == "arbiter_operator"
        assert event["action"] == "tenant_policy_set" and event["outcome"] == "succeeded"
    assert revision(policies, tenant) == 4
    assert rows(policies, other) == [] and revision(policies, other) == 1


def test_active_registry_aliases_only(policies: LocalStore, aliases: tuple[str, str]) -> None:
    tenant = policies.tenants[0]
    PolicyService(policies.operator).set_policy(tenant, PolicyInput(aliases=(aliases[0],)))
    assert rows(policies, tenant)[0]["model_aliases"] == [aliases[0]]
    for alias in (aliases[1], "unknown"):
        with pytest.raises(ValueError, match="model alias unavailable"):
            PolicyService(policies.operator).set_policy(tenant, PolicyInput(aliases=(alias,)))
    assert len(rows(policies, tenant)) == 1 and revision(policies, tenant) == 2
    assert len(audits(policies, tenant)) == 2


def test_nonexistent_target_no_changes(policies: LocalStore) -> None:
    with pytest.raises(ProvisioningNotFound):
        PolicyService(policies.operator).set_policy(uuid4(), PolicyInput())
    assert all(revision(policies, tenant) == 1 for tenant in policies.tenants)


def test_runtime_service_and_repository_denied(policies: LocalStore) -> None:
    tenant = policies.tenants[0]
    with pytest.raises(OperatorAccessDenied):
        PolicyService(policies.runtime).set_policy(tenant, PolicyInput())
    with tenant_transaction(policies.runtime, TenantContext(tenant)) as transaction:
        with pytest.raises(OperatorAccessDenied):
            PolicyRepository(transaction).validate_aliases(())
    assert revision(policies, tenant) == 1 and len(audits(policies, tenant)) == 1


@pytest.mark.parametrize(
    "statement",
    [
        "UPDATE arbiter.tenant_policies SET tenant_rate=999",
        "DELETE FROM arbiter.tenant_policies",
        "INSERT INTO arbiter.tenant_policies (id) VALUES (:id)",
        "UPDATE arbiter.tenants SET policy_revision=999",
        "SELECT * FROM arbiter.provider_models",
        "INSERT INTO arbiter.provider_models (id) VALUES (:id)",
        "SET ROLE arbiter_operator",
        "SET ROLE arbiter_migration",
        "ALTER TABLE arbiter.tenant_policies DISABLE ROW LEVEL SECURITY",
        "SELECT arbiter.lock_policy_aliases('{}')",
    ],
)
def test_runtime_privilege_escalation_denied(policies: LocalStore, statement: str) -> None:
    with pytest.raises(DBAPIError) as failure:
        with tenant_transaction(
            policies.runtime, TenantContext(policies.tenants[0])
        ) as transaction:
            transaction.connection().execute(text(statement), {"id": uuid4()})
    assert getattr(failure.value.orig, "sqlstate", None) == "42501"


def test_policy_audit_failure_rolls_back_revision_and_record(
    policies: LocalStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    tenant = policies.tenants[0]
    existing_id = audits(policies, tenant)[0]["id"]
    with monkeypatch.context() as patch:
        patch.setattr(operator_module, "uuid4", lambda: existing_id)
        with pytest.raises(IntegrityError):
            PolicyService(policies.operator).set_policy(tenant, PolicyInput())
    assert rows(policies, tenant) == [] and revision(policies, tenant) == 1
    assert len(audits(policies, tenant)) == 1
    PolicyService(policies.operator).set_policy(tenant, PolicyInput())
    assert revision(policies, tenant) == 2


def test_policy_failure_after_audit_rolls_back_all(
    policies: LocalStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    tenant = policies.tenants[0]
    original = PolicyRepository.insert

    def fail(self: PolicyRepository, **kwargs: object) -> None:
        raise RuntimeError("synthetic failure")

    monkeypatch.setattr(PolicyRepository, "insert", fail)
    with pytest.raises(RuntimeError, match="synthetic failure"):
        PolicyService(policies.operator).set_policy(tenant, PolicyInput())
    assert rows(policies, tenant) == [] and revision(policies, tenant) == 1
    assert len(audits(policies, tenant)) == 1
    monkeypatch.setattr(PolicyRepository, "insert", original)


def test_outer_rollback_and_uncommitted_visibility(policies: LocalStore) -> None:
    tenant = policies.tenants[0]
    with pytest.raises(RuntimeError, match="rollback"):
        with operator_transaction(policies.operator, tenant) as transaction:
            repository = PolicyRepository(transaction)
            operator_module.OperatorRepository(transaction).lock_tenant()
            repository.advance_revision(1, 2)
            policy_id = uuid4()
            audit = operator_module.OperatorRepository(transaction).append_audit(
                action="tenant_policy_set", target_id=policy_id, revision=2, correlation=uuid4()
            )
            repository.insert(
                policy_id=policy_id,
                revision=2,
                audit_id=audit,
                limits=(60, 30, 1000, 10000, 1),
                aliases=(),
            )
            assert rows(policies, tenant) == [] and revision(policies, tenant) == 1
            assert len(audits(policies, tenant)) == 1
            raise RuntimeError("rollback")
    assert rows(policies, tenant) == [] and revision(policies, tenant) == 1


def test_orphan_policy_deferred_audit_fk_rejected(policies: LocalStore) -> None:
    tenant = policies.tenants[0]
    with pytest.raises(IntegrityError) as failure:
        with operator_transaction(policies.operator, tenant) as transaction:
            operator_module.OperatorRepository(transaction).lock_tenant()
            repository = PolicyRepository(transaction)
            repository.advance_revision(1, 2)
            repository.insert(
                policy_id=uuid4(),
                revision=2,
                audit_id=uuid4(),
                limits=(60, 30, 1000, 10000, 1),
                aliases=(),
            )
    assert getattr(failure.value.orig, "sqlstate", None) == "23503"
    assert revision(policies, tenant) == 1


def test_cross_tenant_and_missing_context_reads_writes_denied(policies: LocalStore) -> None:
    a, b = policies.tenants
    PolicyService(policies.operator).set_policy(b, PolicyInput())
    for engine in (policies.runtime, policies.operator, policies.migration):
        with engine.begin() as connection:
            assert connection.execute(text("SELECT id FROM arbiter.tenant_policies")).all() == []
        with tenant_transaction(engine, TenantContext(a)) as transaction:
            assert (
                transaction.connection()
                .execute(text("SELECT id FROM arbiter.tenant_policies"))
                .all()
                == []
            )
    with operator_transaction(policies.operator, a) as transaction:
        with pytest.raises(DBAPIError):
            transaction.connection().execute(
                text("""
                INSERT INTO arbiter.tenant_policies
                    (id,tenant_id,revision,audit_id,tenant_rate,key_rate,daily_quota,
                     monthly_budget,concurrency,model_aliases)
                VALUES (:id,:tenant,2,:audit,60,30,1000,10000,1,'{}')
            """),
                {"id": uuid4(), "tenant": b, "audit": uuid4()},
            )
    assert revision(policies, a) == 1 and len(rows(policies, b)) == 1


@pytest.mark.parametrize(
    "limits",
    [
        (-1, 30, 1000, 10000, 1),
        (60, -1, 1000, 10000, 1),
        (60, 30, -1, 10000, 1),
        (60, 30, 1000, -1, 1),
        (60, 30, 1000, 10000, 3),
    ],
)
def test_database_rejects_invalid_limits(
    policies: LocalStore, limits: tuple[int, int, int, int, int]
) -> None:
    tenant = policies.tenants[0]
    with pytest.raises(IntegrityError) as failure:
        with operator_transaction(policies.operator, tenant) as transaction:
            operator_module.OperatorRepository(transaction).lock_tenant()
            repository = PolicyRepository(transaction)
            repository.advance_revision(1, 2)
            repository.insert(
                policy_id=uuid4(), revision=2, audit_id=uuid4(), limits=limits, aliases=()
            )
    assert getattr(failure.value.orig, "sqlstate", None) == "23514"
    assert revision(policies, tenant) == 1 and rows(policies, tenant) == []


def test_concurrent_updates_serialize_revisions(policies: LocalStore) -> None:
    engines = [operator_engine(DatabaseSettings()) for _ in range(2)]
    try:

        def update(index: int) -> int:
            return (
                PolicyService(engines[index % 2])
                .set_policy(policies.tenants[0], PolicyInput(daily_quota=1000 + index))
                .revision
            )

        with ThreadPoolExecutor(max_workers=2) as pool:
            assert sorted(pool.map(update, range(8))) == list(range(2, 10))
        assert len(rows(policies, policies.tenants[0])) == 8
        assert len(audits(policies, policies.tenants[0])) == 9
    finally:
        for engine in engines:
            engine.dispose()


def test_cli_metadata_only_and_pool_context_cleared(
    policies: LocalStore, capsys: pytest.CaptureFixture[str], caplog: pytest.LogCaptureFixture
) -> None:
    for tenant in (policies.tenants[0], policies.tenants[1], policies.tenants[0]):
        main(
            [
                "set-tenant-policy",
                "--tenant",
                str(tenant),
                "--tenant-rate",
                "60",
                "--key-rate",
                "30",
                "--daily-quota",
                "1000",
                "--monthly-budget",
                "10000",
                "--concurrency",
                "1",
            ]
        )
        result = json.loads(capsys.readouterr().out)
        assert set(result) == {"tenant_id", "policy_id", "revision", "audit_id", "correlation_id"}
        assert UUID(result["tenant_id"]) == tenant
        with policies.operator.begin() as connection:
            assert (
                connection.execute(
                    text("SELECT NULLIF(current_setting('arbiter.tenant_id',true),'')")
                ).scalar_one()
                is None
            )
            assert connection.execute(text("SELECT id FROM arbiter.tenant_policies")).all() == []
    assert "api_key_pepper" not in caplog.text


@pytest.mark.parametrize(
    "aliases", [("unregistered",), ("native:latest",), ("duplicate", "duplicate")]
)
def test_database_alias_validation_is_not_only_cli_validation(
    policies: LocalStore, aliases: tuple[str, ...]
) -> None:
    tenant = policies.tenants[0]
    with pytest.raises(IntegrityError) as failure:
        with operator_transaction(policies.operator, tenant) as transaction:
            operator_module.OperatorRepository(transaction).lock_tenant()
            repository = PolicyRepository(transaction)
            repository.advance_revision(1, 2)
            repository.insert(
                policy_id=uuid4(),
                revision=2,
                audit_id=uuid4(),
                limits=(60, 30, 1000, 10000, 1),
                aliases=aliases,
            )
    assert getattr(failure.value.orig, "sqlstate", None) == "23514"
    assert revision(policies, tenant) == 1


def test_foreign_audit_relationship_rejected(policies: LocalStore) -> None:
    a, b = policies.tenants
    foreign = PolicyService(policies.operator).set_policy(b, PolicyInput())
    with pytest.raises(IntegrityError) as failure:
        with operator_transaction(policies.operator, a) as transaction:
            operator_module.OperatorRepository(transaction).lock_tenant()
            repository = PolicyRepository(transaction)
            repository.advance_revision(1, 2)
            repository.insert(
                policy_id=uuid4(),
                revision=2,
                audit_id=foreign.audit_id,
                limits=(60, 30, 1000, 10000, 1),
                aliases=(),
            )
    assert getattr(failure.value.orig, "sqlstate", None) == "23503"
    assert revision(policies, a) == 1


def test_policy_history_immutable_and_owner_forced_rls(policies: LocalStore) -> None:
    tenant = policies.tenants[0]
    result = PolicyService(policies.operator).set_policy(tenant, PolicyInput())
    for engine in (policies.operator, policies.runtime):
        with pytest.raises(DBAPIError) as failure:
            with tenant_transaction(engine, TenantContext(tenant)) as transaction:
                transaction.connection().execute(
                    text(
                        "UPDATE arbiter.tenant_policies SET concurrency=2 WHERE tenant_id=:tenant"
                    ),
                    {"tenant": tenant},
                )
        assert getattr(failure.value.orig, "sqlstate", None) == "42501"
    with pytest.raises(IntegrityError) as failure:
        with tenant_transaction(policies.migration, TenantContext(tenant)) as transaction:
            transaction.connection().execute(
                text(
                    "UPDATE arbiter.tenant_policies SET tenant_id=:other "
                    "WHERE id=:id AND tenant_id=:tenant"
                ),
                {"other": policies.tenants[1], "id": result.policy_id, "tenant": tenant},
            )
    assert getattr(failure.value.orig, "sqlstate", None) == "23514"
    with policies.migration.begin() as connection:
        assert connection.execute(text("SELECT id FROM arbiter.tenant_policies")).all() == []
        assert (
            connection.execute(
                text(
                    "SELECT relrowsecurity AND relforcerowsecurity FROM pg_class "
                    "WHERE oid='arbiter.tenant_policies'::regclass"
                )
            ).scalar_one()
            is True
        )


def test_accounting_aware_guard_preserves_empty_tenant_policy_updates(policies: LocalStore) -> None:
    result = PolicyService(policies.operator).set_policy(policies.tenants[0], PolicyInput())
    assert result.revision == 2
    with policies.runtime.begin() as connection:
        assert (
            connection.execute(
                text("""
            SELECT has_function_privilege(current_user,
                'arbiter.assert_policy_limits(uuid,bigint,bigint,bigint)','EXECUTE')
        """)
            ).scalar_one()
            is False
        )


def test_bad_cli_policy_does_not_expose_content_or_create_evidence(
    policies: LocalStore, capsys: pytest.CaptureFixture[str], caplog: pytest.LogCaptureFixture
) -> None:
    marker = "sensitive-placeholder-content"
    for option, value in (("--model-alias", marker), ("--monthly-budget", "-1")):
        args = [
            "set-tenant-policy",
            "--tenant",
            str(policies.tenants[0]),
            "--tenant-rate",
            "60",
            "--key-rate",
            "30",
            "--daily-quota",
            "1000",
            "--monthly-budget",
            "10000",
            "--concurrency",
            "1",
        ]
        if option in args:
            args[args.index(option) + 1] = value
        else:
            args.extend([option, value])
        with pytest.raises(SystemExit) as failure:
            main(args)
        assert marker not in str(failure.value) + capsys.readouterr().out + caplog.text
    assert revision(policies, policies.tenants[0]) == 1
    assert len(audits(policies, policies.tenants[0])) == 1


def test_registry_lock_helper_privileges_and_update_order(
    policies: LocalStore, aliases: tuple[str, str]
) -> None:
    with policies.migration.begin() as connection:
        row = connection.execute(
            text("""
            SELECT prosecdef,proconfig,pg_get_userbyid(proowner)
            FROM pg_proc WHERE oid='arbiter.lock_policy_aliases(text[])'::regprocedure
        """)
        ).one()
        assert row == (True, ["search_path=pg_catalog"], "arbiter_migration")
        grants = connection.execute(
            text("""
            SELECT r.rolname,a.privilege_type FROM pg_proc p
            CROSS JOIN LATERAL aclexplode(p.proacl) a
            LEFT JOIN pg_roles r ON r.oid=a.grantee
            WHERE p.oid='arbiter.lock_policy_aliases(text[])'::regprocedure
        """)
        ).all()
        assert set(grants) == {("arbiter_migration", "EXECUTE"), ("arbiter_operator", "EXECUTE")}
    for statement in (
        "SELECT arbiter.lock_policy_aliases('{}')",
        "UPDATE arbiter.provider_models SET active=true",
        "INSERT INTO arbiter.provider_models(id) VALUES (:id)",
        "SELECT alias FROM arbiter.provider_models FOR SHARE",
    ):
        with pytest.raises(DBAPIError) as failure:
            with policies.operator.begin() as connection:
                connection.execute(text(statement), {"id": uuid4()})
        assert getattr(failure.value.orig, "sqlstate", None) == "42501"
    with operator_transaction(policies.operator, policies.tenants[0]) as transaction:
        operator_module.OperatorRepository(transaction).lock_tenant()
        PolicyRepository(transaction).validate_aliases((aliases[0],))
        # A registry writer cannot deactivate a checked alias before policy commit.
        with pytest.raises(DBAPIError) as failure:
            with policies.migration.begin() as connection:
                connection.execute(text("SET LOCAL lock_timeout='100ms'"))
                connection.execute(
                    text("UPDATE arbiter.provider_models SET active=false WHERE alias=:alias"),
                    {"alias": aliases[0]},
                )
        assert getattr(failure.value.orig, "sqlstate", None) == "55P03"


def test_reused_operator_backend_never_retains_tenant_context(policies: LocalStore) -> None:
    service = PolicyService(policies.operator)
    backends: list[int] = []
    for tenant in (policies.tenants[0], policies.tenants[1], policies.tenants[0]):
        service.set_policy(tenant, PolicyInput())
        with policies.operator.begin() as connection:
            backends.append(connection.execute(text("SELECT pg_backend_pid()")).scalar_one())
            assert (
                connection.execute(
                    text("SELECT NULLIF(current_setting('arbiter.tenant_id',true),'')")
                ).scalar_one()
                is None
            )
            assert connection.execute(text("SELECT id FROM arbiter.tenant_policies")).all() == []
    assert len(set(backends)) == 1
    with policies.operator.begin() as connection:
        connection.execute(
            text("SELECT set_config('arbiter.tenant_id',:tenant,false)"),
            {"tenant": str(policies.tenants[1])},
        )
    with pytest.raises(RuntimeError, match="unexpected session"):
        service.set_policy(policies.tenants[0], PolicyInput())
    service.set_policy(policies.tenants[0], PolicyInput())
    with policies.operator.begin() as connection:
        assert connection.execute(text("SELECT pg_backend_pid()")).scalar_one() != backends[0]


def test_revision_overflow_and_suspended_tenant_handling(policies: LocalStore) -> None:
    a, b = policies.tenants
    policies.service.set_tenant_status(a, "suspended")
    PolicyService(policies.operator).set_policy(a, PolicyInput())
    with tenant_transaction(policies.runtime, TenantContext(a)) as transaction:
        assert (
            transaction.connection()
            .execute(
                text("SELECT status FROM arbiter.tenants WHERE id=:tenant AND tenant_id=:tenant"),
                {"tenant": a},
            )
            .scalar_one()
            == "suspended"
        )
    with operator_transaction(policies.operator, b) as transaction:
        transaction.connection().execute(
            text(
                "UPDATE arbiter.tenants SET policy_revision=9223372036854775807 "
                "WHERE id=:tenant AND tenant_id=:tenant"
            ),
            {"tenant": b},
        )
    with pytest.raises(ValueError, match="revision exhausted"):
        PolicyService(policies.operator).set_policy(b, PolicyInput())
    assert rows(policies, b) == [] and len(audits(policies, b)) == 1
