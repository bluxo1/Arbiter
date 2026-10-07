"""Provisioning and atomic audit evidence using restricted roles on real PostgreSQL."""

import json
import os
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from threading import Barrier
from typing import cast
from uuid import UUID, uuid4

import pytest
from retention_cleanup import delete_fixture_audits
from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine
from sqlalchemy.exc import DBAPIError, IntegrityError
from sqlalchemy.pool import NullPool

import arbiter.operations.provision as provision_module
import arbiter.persistence.operator as operator_module
from arbiter.config import DatabaseSettings
from arbiter.identity.context import TenantContext
from arbiter.operations.provision import (
    MemberInput,
    MemberRole,
    ProvisioningConflict,
    ProvisioningService,
    TenantStatus,
    main,
)
from arbiter.persistence.operator import (
    OperatorAccessDenied,
    OperatorRepository,
    ProvisioningNotFound,
    operator_engine,
    operator_transaction,
)
from arbiter.persistence.repositories import MembershipRepository, TenantRepository
from arbiter.persistence.tenant import runtime_engine, tenant_transaction

pytestmark = pytest.mark.skipif(
    os.environ.get("ARBITER_TEST_DATABASE") != "1", reason="requires provisioned real PostgreSQL"
)


@dataclass
class LocalStore:
    operator: Engine
    runtime: Engine
    migration: Engine
    tenants: list[UUID]
    issuer: str

    @property
    def service(self) -> ProvisioningService:
        return ProvisioningService(self.operator)


@pytest.fixture
def local() -> Iterator[LocalStore]:
    settings = DatabaseSettings()
    value = LocalStore(
        operator_engine(settings),
        runtime_engine(settings),
        create_engine(settings.url("migration"), poolclass=NullPool, hide_parameters=True),
        [],
        f"https://{uuid4().hex}.fixture.invalid",
    )
    try:
        for _ in range(2):
            value.tenants.append(value.service.create_tenant().tenant_id)
        yield value
    finally:
        with value.migration.begin() as connection:
            for tenant in value.tenants:
                connection.execute(
                    text("SELECT set_config('arbiter.tenant_id', :tenant, true)"),
                    {"tenant": str(tenant)},
                )
                delete_fixture_audits(connection, tenant)
                connection.execute(
                    text("DELETE FROM arbiter.memberships WHERE tenant_id=:tenant"),
                    {"tenant": tenant},
                )
                connection.execute(
                    text("DELETE FROM arbiter.tenants WHERE tenant_id=:tenant"),
                    {"tenant": tenant},
                )
            connection.execute(
                text("DELETE FROM arbiter.principals WHERE issuer=:issuer"),
                {"issuer": value.issuer},
            )
        for engine in (value.operator, value.runtime, value.migration):
            engine.dispose()


def audits(local: LocalStore, tenant: UUID) -> list[dict[str, object]]:
    with tenant_transaction(local.runtime, TenantContext(tenant)) as transaction:
        return [
            dict(row)
            for row in transaction.connection()
            .execute(
                text("""
            SELECT id, tenant_id, actor_type, actor_reference, actor_membership_id,
                   action, target_id, policy_revision, request_id, outcome, occurred_at
            FROM arbiter.audit_events WHERE tenant_id=:tenant ORDER BY occurred_at, id
        """),
                {"tenant": tenant},
            )
            .mappings()
        ]


def test_successful_tenant_creation_has_operator_audit(local: LocalStore) -> None:
    tenant = local.tenants[0]
    with tenant_transaction(local.runtime, TenantContext(tenant)) as transaction:
        row = TenantRepository(transaction).get()
        assert row is not None and row.status == "active" and row.policy_revision == 1
    events = audits(local, tenant)
    assert len(events) == 1
    event = events[0]
    assert event["actor_type"] == "operator" and event["actor_reference"] == "arbiter_operator"
    assert event["actor_membership_id"] is None
    assert event["action"] == "tenant_created" and event["target_id"] == tenant
    assert event["request_id"] is not None and event["outcome"] == "succeeded"


def test_status_mutation_is_scoped_audited_and_idempotent(local: LocalStore) -> None:
    tenant, other = local.tenants
    for status in ("suspended", "active"):
        result = local.service.set_tenant_status(tenant, status)
        assert result.changed and result.audit_id is not None
        with tenant_transaction(local.runtime, TenantContext(tenant)) as transaction:
            row = TenantRepository(transaction).get()
            assert row is not None and row.status == status
        event = audits(local, tenant)[-1]
        assert event["id"] == result.audit_id and event["action"] == f"tenant_{status}"
        assert event["request_id"] == result.correlation_id
    count = len(audits(local, tenant))
    assert local.service.set_tenant_status(tenant, "active").changed is False
    assert len(audits(local, tenant)) == count
    assert len(audits(local, other)) == 1
    with tenant_transaction(local.runtime, TenantContext(other)) as transaction:
        row = TenantRepository(transaction).get()
        assert row is not None and row.status == "active"


@pytest.mark.parametrize("role", ["member", "admin"])
def test_member_provisioning_and_shared_global_identity(
    local: LocalStore, role: MemberRole
) -> None:
    tenant, other = local.tenants
    binding = MemberInput(local.issuer, "opaque-subject", role)
    first = local.service.create_member(tenant, binding)
    second = local.service.create_member(other, binding)
    principal_ids: list[UUID] = []
    for result in (first, second):
        with tenant_transaction(local.runtime, TenantContext(result.tenant_id)) as transaction:
            member = MembershipRepository(transaction).get(result.object_id)
            assert member is not None and member.active and member.role == role
            principal_ids.append(member.principal_id)
        event = audits(local, result.tenant_id)[-1]
        assert event["action"] == "member_created" and event["target_id"] == result.object_id
        assert event["id"] == result.audit_id and event["request_id"] == result.correlation_id
    assert principal_ids[0] == principal_ids[1]
    with tenant_transaction(local.runtime, TenantContext(tenant)) as transaction:
        assert MembershipRepository(transaction).get(second.object_id) is None


def test_duplicate_member_and_tenant_collision_leave_no_extra_audit(
    local: LocalStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    tenant = local.tenants[0]
    binding = MemberInput(local.issuer, "duplicate-subject")
    local.service.create_member(tenant, binding)
    before = audits(local, tenant)
    with pytest.raises(ProvisioningConflict):
        local.service.create_member(tenant, binding)
    assert audits(local, tenant) == before
    monkeypatch.setattr(provision_module, "uuid4", lambda: tenant)
    with pytest.raises(ProvisioningConflict):
        local.service.create_tenant()
    assert audits(local, tenant) == before


def test_missing_tenant_and_mixed_scope_do_not_provision(local: LocalStore) -> None:
    tenant, other = local.tenants
    absent = uuid4()
    with pytest.raises(ProvisioningNotFound):
        local.service.create_member(absent, MemberInput(local.issuer, "not-created"))
    with pytest.raises(ProvisioningNotFound):
        local.service.set_tenant_status(absent, "suspended")
    with pytest.raises(DBAPIError) as failure:
        with operator_transaction(local.operator, tenant) as transaction:
            transaction.connection().execute(
                text("""
                INSERT INTO arbiter.audit_events
                (id, tenant_id, actor_type, actor_reference, action, target_id,
                 policy_revision, outcome)
                VALUES (:id, :other, 'operator', 'arbiter_operator', 'tenant_suspended',
                        :other, 1, 'succeeded')
            """),
                {"id": uuid4(), "other": other},
            )
    assert getattr(failure.value.orig, "sqlstate", None) == "42501"
    assert len(audits(local, tenant)) == 1 and len(audits(local, other)) == 1
    with local.operator.begin() as connection:
        assert (
            connection.execute(
                text("SELECT id FROM arbiter.principals WHERE issuer=:issuer"),
                {"issuer": local.issuer},
            ).all()
            == []
        )


@pytest.mark.parametrize("operation", ["tenant", "member", "status"])
def test_real_database_audit_failure_rolls_back_every_mutation(
    local: LocalStore, operation: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    tenant = local.tenants[0]
    before = audits(local, tenant)
    existing_audit = cast(UUID, before[0]["id"])
    # Inject a genuine PostgreSQL audit uniqueness failure, not a mocked audit sink.
    monkeypatch.setattr(operator_module, "uuid4", lambda: existing_audit)
    if operation == "tenant":
        failed_tenant = uuid4()
        local.tenants.append(failed_tenant)
        monkeypatch.setattr(provision_module, "uuid4", lambda: failed_tenant)
        with pytest.raises(ProvisioningConflict):
            local.service.create_tenant()
        with tenant_transaction(local.runtime, TenantContext(failed_tenant)) as transaction:
            assert TenantRepository(transaction).get() is None
    elif operation == "member":
        with pytest.raises(ProvisioningConflict):
            local.service.create_member(tenant, MemberInput(local.issuer, "rolled-back-subject"))
        with local.operator.begin() as connection:
            assert (
                connection.execute(
                    text("SELECT id FROM arbiter.principals WHERE issuer=:issuer"),
                    {"issuer": local.issuer},
                ).all()
                == []
            )
        with tenant_transaction(local.runtime, TenantContext(tenant)) as transaction:
            assert (
                transaction.connection().execute(text("SELECT id FROM arbiter.memberships")).all()
                == []
            )
    else:
        with pytest.raises(IntegrityError):
            local.service.set_tenant_status(tenant, "suspended")
        with tenant_transaction(local.runtime, TenantContext(tenant)) as transaction:
            row = TenantRepository(transaction).get()
            assert row is not None and row.status == "active"
    assert audits(local, tenant) == before


@pytest.mark.parametrize("operation", ["tenant", "member", "status", "repository"])
def test_runtime_cannot_use_operator_services(local: LocalStore, operation: str) -> None:
    service = ProvisioningService(local.runtime)
    with pytest.raises(OperatorAccessDenied):
        if operation == "tenant":
            service.create_tenant()
        elif operation == "member":
            service.create_member(local.tenants[0], MemberInput(local.issuer, "forbidden"))
        elif operation == "status":
            service.set_tenant_status(local.tenants[0], "suspended")
        else:
            with tenant_transaction(local.runtime, TenantContext(local.tenants[0])) as transaction:
                OperatorRepository(transaction).create_tenant()
    assert all(len(audits(local, tenant)) == 1 for tenant in local.tenants)


def test_runtime_cannot_forge_operator_audit(local: LocalStore) -> None:
    tenant = local.tenants[0]
    with pytest.raises(DBAPIError) as failure:
        with tenant_transaction(local.runtime, TenantContext(tenant)) as transaction:
            transaction.connection().execute(
                text("""
                INSERT INTO arbiter.audit_events
                (id, tenant_id, actor_type, actor_reference, action, target_id,
                 policy_revision, outcome)
                VALUES (:id, :tenant, 'operator', 'arbiter_operator', 'tenant_created',
                        :tenant, 1, 'succeeded')
            """),
                {"id": uuid4(), "tenant": tenant},
            )
    assert getattr(failure.value.orig, "sqlstate", None) == "42501"


def test_parallel_duplicate_member_creates_one_binding_and_audit(local: LocalStore) -> None:
    engines = [operator_engine(DatabaseSettings()) for _ in range(2)]
    barrier = Barrier(2)

    def provision(index: int) -> bool:
        barrier.wait(timeout=5)
        try:
            ProvisioningService(engines[index]).create_member(
                local.tenants[0], MemberInput(local.issuer, "parallel-duplicate")
            )
            return True
        except ProvisioningConflict:
            return False

    try:
        with ThreadPoolExecutor(max_workers=2) as executor:
            assert sorted(executor.map(provision, range(2))) == [False, True]
        assert [event["action"] for event in audits(local, local.tenants[0])] == [
            "tenant_created",
            "member_created",
        ]
    finally:
        for engine in engines:
            engine.dispose()


def test_subject_is_opaque_and_parameterized(local: LocalStore) -> None:
    subject = " opaque-subject'; SELECT pg_sleep(99); -- "
    result = local.service.create_member(local.tenants[0], MemberInput(local.issuer, subject))
    with local.operator.begin() as connection:
        assert (
            connection.execute(
                text("SELECT subject FROM arbiter.principals WHERE issuer=:issuer"),
                {"issuer": local.issuer},
            ).scalar_one()
            == subject
        )
    assert audits(local, result.tenant_id)[-1]["target_id"] == result.object_id


def test_invalid_status_has_no_mutation_or_audit(local: LocalStore) -> None:
    before = audits(local, local.tenants[0])
    with pytest.raises(ValueError, match="invalid tenant status"):
        local.service.set_tenant_status(local.tenants[0], cast(TenantStatus, "deleted"))
    assert audits(local, local.tenants[0]) == before


def test_local_cli_returns_only_ids_after_commit(
    local: LocalStore, capsys: pytest.CaptureFixture[str]
) -> None:
    main(["create-tenant"])
    result = json.loads(capsys.readouterr().out)
    tenant = UUID(result["tenant_id"])
    local.tenants.append(tenant)
    assert result["changed"] is True and len(audits(local, tenant)) == 1
    main(
        [
            "create-member",
            "--tenant",
            str(tenant),
            "--issuer",
            local.issuer,
            "--subject",
            "cli-subject",
            "--role",
            "admin",
        ]
    )
    output = capsys.readouterr().out
    member = json.loads(output)
    assert "cli-subject" not in output and local.issuer not in output
    assert audits(local, tenant)[-1]["target_id"] == UUID(member["object_id"])
    main(["set-tenant-status", "--tenant", str(tenant), "--status", "suspended"])
    assert json.loads(capsys.readouterr().out)["changed"] is True
