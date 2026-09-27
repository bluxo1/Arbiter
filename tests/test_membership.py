"""Signed identity -> active membership -> scoped data, using real PostgreSQL."""

import os
from collections.abc import Iterator
from dataclasses import dataclass
from time import time
from uuid import UUID, uuid4

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from sqlalchemy import create_engine, event, text
from sqlalchemy.engine import Engine
from sqlalchemy.exc import DBAPIError
from sqlalchemy.pool import NullPool

from arbiter.config import DatabaseSettings, OidcSettings
from arbiter.identity.access import (
    AuthorizedMember,
    InsufficientRole,
    ManagementAccess,
    MembershipUnavailable,
)
from arbiter.identity.oidc import InvalidIdentity, OidcVerifier, VerifiedPrincipal
from arbiter.operations.provision import MemberInput, ProvisioningService
from arbiter.persistence.identity import InaccessibleTenant, resolve_membership
from arbiter.persistence.operator import OperatorRepository, operator_engine, operator_transaction
from arbiter.persistence.repositories import MembershipRepository, TenantRepository
from arbiter.persistence.tenant import TenantTransaction, runtime_engine

ISSUER = "https://localhost:18443/realms/arbiter"
pytestmark = [
    pytest.mark.anyio,
    pytest.mark.skipif(
        os.environ.get("ARBITER_TEST_DATABASE") != "1", reason="real PostgreSQL required"
    ),
]


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@dataclass
class Members:
    runtime: Engine
    operator: Engine
    migration: Engine
    tenant_a: UUID
    tenant_b: UUID
    member_a: UUID
    member_b: UUID
    subject_a: str
    subject_b: str
    key: rsa.RSAPrivateKey

    def token(self, *, subject: str | None = None, **extra: object) -> str:
        return jwt.encode(
            {
                "iss": ISSUER,
                "aud": "arbiter-api",
                "sub": subject or self.subject_a,
                "exp": int(time()) + 300,
                **extra,
            },
            self.key,
            algorithm="RS256",
            headers={"kid": "fixture"},
        )

    def verifier(self) -> OidcVerifier:
        public = jwt.algorithms.RSAAlgorithm.to_jwk(self.key.public_key(), as_dict=True)
        public.update({"kid": "fixture", "alg": "RS256", "use": "sig"})
        return OidcVerifier(
            OidcSettings(
                issuer=ISSUER,
                audience="arbiter-api",
                jwks_url="https://fixture.invalid/keys",
                clock_skew_seconds=0,
            ),
            transport=httpx.MockTransport(lambda r: httpx.Response(200, json={"keys": [public]})),
        )


@pytest.fixture
def members() -> Iterator[Members]:
    config = DatabaseSettings()
    operator = operator_engine(config)
    migration = create_engine(config.url("migration"), poolclass=NullPool, hide_parameters=True)
    service = ProvisioningService(operator)
    tenant_a, tenant_b = service.create_tenant().tenant_id, service.create_tenant().tenant_id
    subject_a, subject_b = f"fixture-{uuid4()}", f"fixture-{uuid4()}"
    member_a = service.create_member(tenant_a, MemberInput(ISSUER, subject_a, "member")).object_id
    member_b = service.create_member(tenant_b, MemberInput(ISSUER, subject_b, "admin")).object_id
    service.create_member(tenant_b, MemberInput("https://other-issuer.invalid", subject_a, "admin"))
    value = Members(
        runtime_engine(config),
        operator,
        migration,
        tenant_a,
        tenant_b,
        member_a,
        member_b,
        subject_a,
        subject_b,
        rsa.generate_private_key(public_exponent=65537, key_size=2048),
    )
    try:
        yield value
    finally:
        with migration.begin() as connection:
            for tenant in (tenant_a, tenant_b):
                connection.execute(
                    text("SELECT set_config('arbiter.tenant_id', :tenant, true)"),
                    {"tenant": str(tenant)},
                )
                for query in (
                    "DELETE FROM arbiter.api_keys WHERE tenant_id=:tenant",
                    "DELETE FROM arbiter.audit_events WHERE tenant_id=:tenant",
                    "DELETE FROM arbiter.memberships WHERE tenant_id=:tenant",
                    "DELETE FROM arbiter.tenants WHERE tenant_id=:tenant",
                ):
                    connection.execute(text(query), {"tenant": tenant})
            connection.execute(
                text("DELETE FROM arbiter.principals WHERE subject IN (:a,:b)"),
                {"a": subject_a, "b": subject_b},
            )
        value.runtime.dispose()
        operator.dispose()
        migration.dispose()


def read_member(member: AuthorizedMember, scoped: TenantTransaction) -> tuple[UUID, str]:
    tenant = TenantRepository(scoped).get()
    assert tenant is not None and tenant.id == member.binding.tenant_id
    assert MembershipRepository(scoped).get(member.binding.membership_id) is not None
    return tenant.id, member.binding.role


async def test_active_membership_authorizes_scoped_service(members: Members) -> None:
    async with members.verifier() as verifier:
        service = ManagementAccess(verifier, members.runtime)
        assert await service.run(members.token(), members.tenant_a, read_member) == (
            members.tenant_a,
            "member",
        )
        assert await service.run(
            members.token(subject=members.subject_b),
            members.tenant_b,
            read_member,
            require_admin=True,
        ) == (members.tenant_b, "admin")


async def test_forged_claims_cannot_grant_membership_or_admin(members: Members) -> None:
    async with members.verifier() as verifier:
        service = ManagementAccess(verifier, members.runtime)
        token = members.token(tenant_id=str(members.tenant_b), roles=["admin"], role="admin")
        with pytest.raises(InaccessibleTenant, match="^inaccessible tenant$"):
            await service.run(token, members.tenant_b, read_member)
        with pytest.raises(InsufficientRole):
            await service.run(token, members.tenant_a, read_member, require_admin=True)
        assert await service.run(token, members.tenant_a, read_member) == (
            members.tenant_a,
            "member",
        )


async def test_inaccessible_and_missing_tenants_are_indistinguishable(members: Members) -> None:
    async with members.verifier() as verifier:
        service = ManagementAccess(verifier, members.runtime)
        for tenant in (members.tenant_b, uuid4()):
            with pytest.raises(InaccessibleTenant, match="^inaccessible tenant$"):
                await service.run(members.token(), tenant, read_member)
        with pytest.raises(InaccessibleTenant):
            await service.run(
                members.token(subject="not-provisioned"), members.tenant_a, read_member
            )


async def test_suspension_is_rechecked_without_authorization_cache(members: Members) -> None:
    async with members.verifier() as verifier:
        service = ManagementAccess(verifier, members.runtime)
        token = members.token()
        await service.run(token, members.tenant_a, read_member)
        ProvisioningService(members.operator).set_tenant_status(members.tenant_a, "suspended")
        with pytest.raises(InaccessibleTenant):
            await service.run(token, members.tenant_a, read_member)
        ProvisioningService(members.operator).set_tenant_status(members.tenant_a, "active")
        await service.run(token, members.tenant_a, read_member)


async def test_inactive_member_is_denied_without_cache(members: Members) -> None:
    async with members.verifier() as verifier:
        service = ManagementAccess(verifier, members.runtime)
        token = members.token()
        await service.run(token, members.tenant_a, read_member)
        with operator_transaction(members.operator, members.tenant_a) as scoped:
            repository = OperatorRepository(scoped)
            tenant = repository.lock_tenant()
            scoped.connection().execute(
                text(
                    "UPDATE arbiter.memberships SET active=false "
                    "WHERE tenant_id=:tenant AND id=:member"
                ),
                {"tenant": members.tenant_a, "member": members.member_a},
            )
            repository.append_audit(
                action="fixture_membership_disabled",
                target_id=members.member_a,
                revision=tenant.policy_revision,
                correlation=uuid4(),
            )
        with pytest.raises(InaccessibleTenant):
            await service.run(token, members.tenant_a, read_member)


async def test_invalid_token_does_not_touch_database_or_callback(members: Members) -> None:
    statements: list[str] = []

    def observe(*args: object) -> None:
        statements.append(str(args[2]))

    event.listen(members.runtime, "before_cursor_execute", observe)
    try:
        async with members.verifier() as verifier:
            service = ManagementAccess(verifier, members.runtime)
            with pytest.raises(InvalidIdentity):
                await service.run(members.token(exp=1), members.tenant_a, read_member)
        assert statements == []
    finally:
        event.remove(members.runtime, "before_cursor_execute", observe)


async def test_authorized_a_still_cannot_read_b(members: Members) -> None:
    def read_b(member: AuthorizedMember, scoped: TenantTransaction) -> None:
        assert MembershipRepository(scoped).get(members.member_b) is None
        assert scoped.connection().execute(
            text("SELECT id FROM arbiter.tenants")
        ).scalars().all() == [members.tenant_a]

    async with members.verifier() as verifier:
        await ManagementAccess(verifier, members.runtime).run(
            members.token(), members.tenant_a, read_b
        )
    with members.runtime.begin() as connection:
        assert (
            connection.execute(
                text("SELECT NULLIF(current_setting('arbiter.tenant_id',true),'')")
            ).scalar_one()
            is None
        )
        assert connection.execute(text("SELECT id FROM arbiter.tenants")).all() == []


def test_lookup_does_not_set_context_or_grant_directory_access(members: Members) -> None:
    with members.runtime.begin() as connection:
        binding = resolve_membership(
            connection, VerifiedPrincipal(ISSUER, members.subject_a), members.tenant_a
        )
        assert binding.membership_id == members.member_a
        assert (
            connection.execute(
                text("SELECT NULLIF(current_setting('arbiter.tenant_id',true),'')")
            ).scalar_one()
            is None
        )
        assert connection.execute(text("SELECT id FROM arbiter.tenants")).all() == []
    for sql in ("SELECT id FROM arbiter.principals", "SET ROLE arbiter_identity_lookup"):
        with members.runtime.begin() as connection, pytest.raises(DBAPIError) as failure:
            connection.execute(text(sql))
        assert getattr(failure.value.orig, "sqlstate", None) == "42501"


def test_lookup_owner_and_grants_are_narrow(members: Members) -> None:
    with members.migration.begin() as connection:
        assert connection.execute(
            text("""
            SELECT pg_get_userbyid(proowner),prosecdef,proconfig
            FROM pg_proc WHERE oid='arbiter.resolve_membership(uuid,text,text)'::regprocedure
        """)
        ).one() == ("arbiter_identity_lookup", True, ["search_path=pg_catalog"])
        assert connection.execute(
            text("""
            SELECT rolcanlogin,rolsuper,rolbypassrls,rolcreatedb,rolcreaterole,rolinherit
            FROM pg_roles WHERE rolname='arbiter_identity_lookup'
        """)
        ).one() == (False, False, False, False, False, False)
        assert (
            connection.execute(
                text("SELECT has_schema_privilege('arbiter_identity_lookup','arbiter','CREATE')")
            ).scalar_one()
            is False
        )
        assert (
            connection.execute(
                text(
                    "SELECT has_function_privilege('arbiter_operator',"
                    "'arbiter.resolve_membership(uuid,text,text)','EXECUTE')"
                )
            ).scalar_one()
            is False
        )
        assert (
            connection.execute(
                text(
                    "SELECT count(*) FROM pg_auth_members WHERE member="
                    "(SELECT oid FROM pg_roles WHERE rolname='arbiter_runtime')"
                )
            ).scalar_one()
            == 0
        )
        assert (
            connection.execute(
                text("""
          SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
          WHERE n.nspname='arbiter' AND c.relrowsecurity AND c.relforcerowsecurity
        """)
            ).scalar_one()
            == 5
        )


async def test_session_poison_is_discarded_before_authorization(members: Members) -> None:
    # Limit to one backend so the next request must encounter the injected session value.
    engine = create_engine(
        DatabaseSettings().url("runtime"), pool_size=1, max_overflow=0, hide_parameters=True
    )
    try:
        with engine.begin() as connection:
            connection.execute(
                text("SELECT set_config('arbiter.tenant_id',:tenant,false)"),
                {"tenant": str(members.tenant_b)},
            )
        async with members.verifier() as verifier:
            service = ManagementAccess(verifier, engine)
            with pytest.raises(MembershipUnavailable):
                await service.run(members.token(), members.tenant_a, read_member)
            assert await service.run(members.token(), members.tenant_a, read_member) == (
                members.tenant_a,
                "member",
            )
    finally:
        engine.dispose()
