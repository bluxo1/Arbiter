"""Real restricted PostgreSQL workload boundary; fixture HTTP route exists only in tests."""

import asyncio
import base64
import os
import secrets
from collections.abc import AsyncIterator, Iterator
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import uuid4

import httpx
import pytest
from fastapi import Request
from fastapi.responses import JSONResponse
from pydantic import SecretStr
from sqlalchemy import create_engine, event, text
from sqlalchemy.exc import DBAPIError
from test_audit_endpoint import assert_error, auth
from test_membership import Members
from test_membership import members as members

from arbiter.config import DatabaseSettings
from arbiter.identity.access import ManagementAccess
from arbiter.identity.keys import InvalidKey, IssuedKey, KeyIssuer, KeyVerifier
from arbiter.identity.workload import MissingScope, WorkloadAccess, WorkloadUnavailable
from arbiter.main import create_app
from arbiter.operations.key_revocation import KeyRevocationService
from arbiter.operations.provision import ProvisioningService
from arbiter.persistence.repositories import MembershipRepository, TenantRepository
from arbiter.persistence.tenant import TenantTransaction
from arbiter.persistence.workload import KeyBinding
from arbiter.transport.workload import run_workload

pytestmark = [
    pytest.mark.anyio,
    pytest.mark.skipif(os.environ.get("ARBITER_TEST_DATABASE") != "1", reason="real PostgreSQL"),
]
CALL = "SELECT key_id,tenant_id,scopes FROM arbiter.resolve_api_key(:public,:candidate,:version)"


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@dataclass
class Workloads:
    members: Members
    pepper: bytes
    key_a: IssuedKey
    key_b: IssuedKey
    expired: IssuedKey
    old_version: IssuedKey
    access: WorkloadAccess


@pytest.fixture
def workloads(members: Members) -> Iterator[Workloads]:
    pepper = secrets.token_bytes(32)
    issuer = KeyIssuer(pepper, 3)
    key_a, key_b, expired = (issuer.issue() for _ in range(3))
    old_version = KeyIssuer(pepper, 2).issue()
    for tenant, actor, issued, scopes, expires in (
        (members.tenant_a, members.member_a, key_a, ["usage:read"], False),
        (members.tenant_b, members.member_b, key_b, ["inference:write", "usage:read"], False),
        (members.tenant_a, members.member_a, expired, ["usage:read"], True),
        (members.tenant_a, members.member_a, old_version, ["usage:read"], False),
    ):
        audit = uuid4()
        now = datetime.now(UTC) - (timedelta(days=60) if expires else timedelta(seconds=1))
        with members.migration.begin() as connection:
            connection.execute(
                text("SELECT set_config('arbiter.tenant_id',:tenant,true)"), {"tenant": str(tenant)}
            )
            connection.execute(
                text("""
                INSERT INTO arbiter.api_keys (id,tenant_id,public_id,label,verifier,pepper_version,
                    scopes,created_at,expires_at,created_by_membership_id,creation_audit_id)
                VALUES (:key,:tenant,:public,'workload-fixture',:verifier,:version,:scopes,
                    :created,:expires,:actor,:audit)
            """),
                {
                    "key": issued.id,
                    "tenant": tenant,
                    "public": issued.public_id,
                    "verifier": issued.verifier.get_secret_value(),
                    "version": issued.pepper_version,
                    "scopes": scopes,
                    "created": now,
                    "expires": now + timedelta(days=30),
                    "actor": actor,
                    "audit": audit,
                },
            )
            connection.execute(
                text("""
                INSERT INTO arbiter.audit_events (id,tenant_id,actor_type,actor_reference,
                    actor_membership_id,action,target_id,policy_revision,outcome)
                VALUES (:audit,:tenant,'member',:reference,:actor,'api_key_created',
                        :key,1,'succeeded')
            """),
                {
                    "audit": audit,
                    "tenant": tenant,
                    "reference": str(actor),
                    "actor": actor,
                    "key": issued.id,
                },
            )
    yield Workloads(
        members,
        pepper,
        key_a,
        key_b,
        expired,
        old_version,
        WorkloadAccess(KeyVerifier(pepper, 3), members.runtime),
    )


def inspect_binding(binding: KeyBinding, scoped: TenantTransaction) -> dict[str, str]:
    tenant = TenantRepository(scoped).get()
    assert tenant is not None and tenant.id == binding.tenant_id == scoped.context.tenant_id
    return {"tenant_id": str(tenant.id), "key_id": str(binding.key_id)}


@pytest.fixture
async def client(workloads: Workloads) -> AsyncIterator[httpx.AsyncClient]:
    app = create_app(workload_access=workloads.access)

    @app.post("/fixture/{selector}")
    async def fixture(selector: str, request: Request) -> JSONResponse:
        # Untrusted route/body/header values never enter the auth boundary or callback.
        result = await run_workload(request, inspect_binding, required_scope="usage:read")
        return result if isinstance(result, JSONResponse) else JSONResponse(result)

    @app.post("/fixture-write")
    async def fixture_write(request: Request) -> JSONResponse:
        result = await run_workload(request, inspect_binding, required_scope="inference:write")
        return result if isinstance(result, JSONResponse) else JSONResponse(result)

    async with (
        app.router.lifespan_context(app),
        httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="https://arbiter.invalid"
        ) as http,
    ):
        yield http


async def test_active_key_derives_only_its_binding_and_scopes(workloads: Workloads) -> None:
    for key, tenant in (
        (workloads.key_a, workloads.members.tenant_a),
        (workloads.key_b, workloads.members.tenant_b),
    ):
        data = await workloads.access.run(
            key.credential, inspect_binding, required_scope="usage:read"
        )
        assert data == {"tenant_id": str(tenant), "key_id": str(key.id)}
    assert await workloads.access.run(
        workloads.key_b.credential, inspect_binding, required_scope="inference:write"
    )
    with pytest.raises(MissingScope, match="^permission denied$"):
        await workloads.access.run(
            workloads.key_a.credential, inspect_binding, required_scope="inference:write"
        )


async def test_forged_body_route_header_model_input_cannot_select_tenant(
    client: httpx.AsyncClient, workloads: Workloads
) -> None:
    other = str(workloads.members.tenant_b)
    response = await client.post(
        f"/fixture/{other}",
        headers={
            **auth(workloads.key_a.credential.get_secret_value()),
            "X-Tenant-ID": other,
            "X-Role": "admin",
        },
        json={"tenant_id": other, "model": {"tenant_id": other}},
    )
    assert response.status_code == 200 and response.json() == {
        "tenant_id": str(workloads.members.tenant_a),
        "key_id": str(workloads.key_a.id),
    }
    assert (
        await client.post(
            "/v1/models", headers=auth(workloads.key_a.credential.get_secret_value()), json={}
        )
    ).status_code == 405
    for path in ("/v1/chat/completions", "/v1/usage"):
        assert (
            await client.post(
                path, headers=auth(workloads.key_a.credential.get_secret_value()), json={}
            )
        ).status_code == 404
    assert (await client.get("/health/ready")).status_code == 503


async def test_invalid_id_secret_malformed_expired_and_version_are_identical_401(
    client: httpx.AsyncClient, workloads: Workloads
) -> None:
    wrong = KeyIssuer(workloads.pepper, 3).issue()
    encoded = workloads.key_a.credential.get_secret_value().split(".")[2]
    bad_secret = wrong.credential.get_secret_value().split(".")[2]
    credentials = [
        "malformed",
        f"arb1.{uuid4().hex}.{encoded}",
        f"arb1.{workloads.key_a.public_id}.{bad_secret}",
        workloads.expired.credential.get_secret_value(),
        workloads.old_version.credential.get_secret_value(),
        workloads.members.token(),
    ]
    errors = []
    for value in credentials:
        response = await client.post("/fixture/forged", headers=auth(value))
        assert_error(response, 401, "invalid_credentials")
        errors.append(response.json()["error"])
    assert all(error == errors[0] for error in errors)


@pytest.mark.parametrize(
    "headers",
    [
        {},
        {"Authorization": "Basic inert"},
        {"X-API-Key": "inert"},
        {"Authorization": "Bearer inert", "X-API-Key": "inert"},
    ],
)
async def test_missing_invalid_mixed_credentials(
    client: httpx.AsyncClient, headers: dict[str, str]
) -> None:
    assert_error(await client.post("/fixture/unused", headers=headers), 401, "invalid_credentials")


async def test_duplicate_headers_and_malformed_key_never_reach_database(
    client: httpx.AsyncClient, workloads: Workloads
) -> None:
    statements: list[str] = []

    def observe(*args: Any) -> None:
        statements.append(str(args[2]))

    event.listen(workloads.members.runtime, "before_cursor_execute", observe)
    try:
        token = workloads.key_a.credential.get_secret_value()
        for headers in (
            [("Authorization", f"Bearer {token}"), ("authorization", f"Bearer {token}")],
            [("Authorization", "Bearer malformed")],
            [("Authorization", f"Bearer {token}"), ("X-API-Key", "inert")],
        ):
            assert_error(
                await client.post("/fixture/unused", headers=headers), 401, "invalid_credentials"
            )
        assert statements == []
    finally:
        event.remove(workloads.members.runtime, "before_cursor_execute", observe)


async def test_real_admin_creation_then_committed_revocation_is_not_cached(
    workloads: Workloads,
) -> None:
    members = workloads.members
    async with members.verifier() as verifier:
        from arbiter.operations.keys import KeyService

        created = await KeyService(
            ManagementAccess(verifier, members.runtime), KeyIssuer(workloads.pepper, 3)
        ).create(
            members.token(subject=members.subject_b),
            members.tenant_b,
            b'{"label":"real-issued","scopes":["usage:read"]}',
        )
        for _ in range(2):
            assert await workloads.access.run(
                created.api_key, inspect_binding, required_scope="usage:read"
            )
        await KeyRevocationService(ManagementAccess(verifier, members.runtime)).revoke(
            members.token(subject=members.subject_b), members.tenant_b, str(created.id)
        )
        for _ in range(2):
            with pytest.raises(InvalidKey, match="^invalid credentials$"):
                await workloads.access.run(
                    created.api_key, inspect_binding, required_scope="usage:read"
                )


async def test_suspension_is_rechecked_and_missing_scope_cannot_run_operation(
    workloads: Workloads,
) -> None:
    assert await workloads.access.run(workloads.key_a.credential, inspect_binding)
    ProvisioningService(workloads.members.operator).set_tenant_status(
        workloads.members.tenant_a, "suspended"
    )
    with pytest.raises(InvalidKey):
        await workloads.access.run(workloads.key_a.credential, inspect_binding)
    assert await workloads.access.run(workloads.key_b.credential, inspect_binding)
    ProvisioningService(workloads.members.operator).set_tenant_status(
        workloads.members.tenant_a, "active"
    )
    assert await workloads.access.run(workloads.key_a.credential, inspect_binding)

    def forbidden(binding: KeyBinding, scoped: TenantTransaction) -> None:
        pytest.fail("missing scope ran operation")

    with pytest.raises(MissingScope):
        await workloads.access.run(
            workloads.key_a.credential, forbidden, required_scope="inference:write"
        )


async def test_cross_tenant_object_reads_stay_scoped(workloads: Workloads) -> None:
    def read(binding: KeyBinding, scoped: TenantTransaction) -> None:
        assert scoped.context.tenant_id == workloads.members.tenant_a
        assert MembershipRepository(scoped).get(workloads.members.member_b) is None
        assert (
            scoped.connection()
            .execute(
                text("SELECT id FROM arbiter.api_keys WHERE id=:id"), {"id": workloads.key_b.id}
            )
            .all()
            == []
        )

    await workloads.access.run(workloads.key_a.credential, read, required_scope="usage:read")


async def test_http_scope_and_committed_revocation_denials(
    client: httpx.AsyncClient, workloads: Workloads
) -> None:
    assert_error(
        await client.post(
            "/fixture-write", headers=auth(workloads.key_a.credential.get_secret_value())
        ),
        403,
        "permission_denied",
    )
    assert (
        await client.post(
            "/fixture-write", headers=auth(workloads.key_b.credential.get_secret_value())
        )
    ).status_code == 200
    members = workloads.members
    async with members.verifier() as verifier:
        await KeyRevocationService(ManagementAccess(verifier, members.runtime)).revoke(
            members.token(subject=members.subject_b), members.tenant_b, str(workloads.key_b.id)
        )
    for _ in range(2):
        assert_error(
            await client.post(
                "/fixture/unused", headers=auth(workloads.key_b.credential.get_secret_value())
            ),
            401,
            "invalid_credentials",
        )


async def test_secret_transplant_across_existing_tenant_keys_is_denied(
    client: httpx.AsyncClient, workloads: Workloads
) -> None:
    encoded = workloads.key_a.credential.get_secret_value().split(".")[2]
    response = await client.post(
        "/fixture/unused", headers=auth(f"arb1.{workloads.key_b.public_id}.{encoded}")
    )
    assert_error(response, 401, "invalid_credentials")


async def test_runtime_cannot_get_verifier_assume_owner_or_mutate_lookup(
    workloads: Workloads,
) -> None:
    members = workloads.members
    for statement in (
        "SELECT verifier FROM arbiter.api_keys",
        "SELECT pepper_version FROM arbiter.api_keys",
        "SET ROLE arbiter_key_lookup",
        "ALTER TABLE arbiter.api_keys DISABLE ROW LEVEL SECURITY",
        "GRANT arbiter_key_lookup TO arbiter_runtime",
        "CREATE TABLE arbiter.forbidden_workload (id int)",
    ):
        with members.runtime.begin() as connection, pytest.raises(DBAPIError) as failure:
            connection.execute(text(statement))
        assert getattr(failure.value.orig, "sqlstate", None) == "42501"
    for engine in (members.operator, members.migration):
        with engine.begin() as connection, pytest.raises(DBAPIError) as failure:
            connection.execute(
                text(CALL),
                {
                    "public": workloads.key_a.public_id,
                    "candidate": workloads.key_a.verifier.get_secret_value(),
                    "version": 3,
                },
            )
        assert getattr(failure.value.orig, "sqlstate", None) == "42501"
    with members.runtime.begin() as connection, pytest.raises(DBAPIError) as failure:
        connection.execute(
            text("SELECT set_config('arbiter.tenant_id',:tenant,true)"),
            {"tenant": str(members.tenant_b)},
        )
        connection.execute(
            text(CALL),
            {
                "public": workloads.key_a.public_id,
                "candidate": workloads.key_a.verifier.get_secret_value(),
                "version": 3,
            },
        )
    assert getattr(failure.value.orig, "sqlstate", None) == "42501"


async def test_fixed_width_comparison_denies_every_mismatch_position(workloads: Workloads) -> None:
    with workloads.members.runtime.begin() as connection:
        values = {
            "public": workloads.key_a.public_id,
            "candidate": workloads.key_a.verifier.get_secret_value(),
            "version": 3,
        }
        assert connection.execute(text(CALL), values).one() == (
            workloads.key_a.id,
            workloads.members.tenant_a,
            ["usage:read"],
        )
        for index in range(32):
            altered = bytearray(workloads.key_a.verifier.get_secret_value())
            altered[index] ^= 1
            assert (
                connection.execute(text(CALL), {**values, "candidate": bytes(altered)}).all() == []
            )
        for invalid in (None, b"", bytes(31), bytes(33)):
            assert connection.execute(text(CALL), {**values, "candidate": invalid}).all() == []
        assert (
            connection.execute(
                text(CALL), {**values, "public": uuid4().hex, "candidate": bytes(32)}
            ).all()
            == []
        )


async def test_lookup_catalog_has_no_general_read_write_or_public_execute(
    workloads: Workloads,
) -> None:
    with workloads.members.migration.begin() as connection:
        assert connection.execute(
            text(
                "SELECT pg_get_userbyid(proowner),prosecdef,proconfig "
                "FROM pg_proc WHERE oid='arbiter.resolve_api_key(text,bytea,integer)'::regprocedure"
            )
        ).one() == ("arbiter_key_lookup", True, ["search_path=pg_catalog"])
        assert connection.execute(
            text(
                "SELECT rolcanlogin,rolsuper,rolbypassrls,rolcreatedb,rolcreaterole,rolinherit "
                "FROM pg_roles WHERE rolname='arbiter_key_lookup'"
            )
        ).one() == (False, False, False, False, False, False)
        assert (
            connection.execute(
                text(
                    "SELECT count(*) FROM pg_proc p,LATERAL aclexplode(p.proacl) a "
                    "WHERE p.oid='arbiter.resolve_api_key(text,bytea,integer)'::regprocedure "
                    "AND a.grantee=0"
                )
            ).scalar_one()
            == 0
        )
        for privilege in ("INSERT", "UPDATE", "DELETE", "TRUNCATE"):
            assert not connection.execute(
                text(
                    "SELECT has_table_privilege('arbiter_key_lookup','arbiter.api_keys',:privilege)"
                ),
                {"privilege": privilege},
            ).scalar_one()
        assert not connection.execute(
            text("SELECT has_schema_privilege('arbiter_key_lookup','arbiter','CREATE')")
        ).scalar_one()
        source: str = connection.execute(
            text(
                "SELECT prosrc FROM pg_proc "
                "WHERE oid='arbiter.resolve_api_key(text,bytea,integer)'::regprocedure"
            )
        ).scalar_one()
        comparison = source.split("FOR i IN 0..31 LOOP", 1)[1].split("END LOOP", 1)[0]
        assert "get_byte(v_stored,i) # get_byte(p_candidate,i)" in comparison
        assert "RETURN" not in comparison and "IF" not in comparison
        assert "COALESCE(v_stored" in source
        assert (
            connection.execute(
                text(
                    "SELECT count(*) FROM pg_policies WHERE policyname='key_lookup_read' "
                    "AND cmd='SELECT' AND roles=ARRAY['arbiter_key_lookup']::name[]"
                )
            ).scalar_one()
            == 2
        )


async def test_pool_context_cleared_and_poisoned_connection_discarded(workloads: Workloads) -> None:
    engine = create_engine(
        DatabaseSettings().url("runtime"), pool_size=1, max_overflow=0, hide_parameters=True
    )
    access = WorkloadAccess(KeyVerifier(workloads.pepper, 3), engine)
    observed: list[int] = []
    try:
        for key in (workloads.key_a, workloads.key_b, workloads.key_a):
            await access.run(key.credential, inspect_binding)
            with engine.begin() as connection:
                assert (
                    connection.execute(
                        text("SELECT NULLIF(current_setting('arbiter.tenant_id',true),'')")
                    ).scalar_one()
                    is None
                )
                assert connection.execute(text("SELECT id FROM arbiter.api_keys")).all() == []
                observed.append(connection.execute(text("SELECT pg_backend_pid()")).scalar_one())
        assert len(set(observed)) == 1
        with pytest.raises(InvalidKey):
            await access.run(SecretStr("malformed"), inspect_binding)
        with pytest.raises(MissingScope):
            await access.run(
                workloads.key_a.credential, inspect_binding, required_scope="inference:write"
            )
        with engine.begin() as connection:
            connection.execute(
                text("SELECT set_config('arbiter.tenant_id',:tenant,false)"),
                {"tenant": str(workloads.members.tenant_b)},
            )
        with pytest.raises(WorkloadUnavailable):
            await access.run(workloads.key_a.credential, inspect_binding)
        await access.run(workloads.key_a.credential, inspect_binding)
        with engine.begin() as connection:
            assert connection.execute(text("SELECT pg_backend_pid()")).scalar_one() != observed[0]
    finally:
        engine.dispose()


async def test_refused_database_returns_generic_unavailable(workloads: Workloads) -> None:
    engine = create_engine(
        DatabaseSettings().url("runtime").set(port=1),
        hide_parameters=True,
        connect_args={"connect_timeout": 1},
        pool_size=1,
        max_overflow=0,
    )
    try:
        with pytest.raises(WorkloadUnavailable, match="^workload verification unavailable$"):
            await WorkloadAccess(KeyVerifier(workloads.pepper, 3), engine).run(
                workloads.key_a.credential, inspect_binding
            )
    finally:
        engine.dispose()


async def test_no_credential_verifier_or_auth_mutation_leakage(
    client: httpx.AsyncClient, workloads: Workloads, caplog: pytest.LogCaptureFixture
) -> None:
    responses = [
        await client.post(
            "/fixture/forged", headers=auth(workloads.key_a.credential.get_secret_value())
        ),
        await client.post(
            "/fixture/forged", headers=auth(workloads.expired.credential.get_secret_value())
        ),
        await client.post("/fixture/forged", headers=auth("malformed")),
    ]
    with workloads.members.migration.begin() as connection:
        connection.execute(
            text("SELECT set_config('arbiter.tenant_id',:tenant,true)"),
            {"tenant": str(workloads.members.tenant_a)},
        )
        audit = connection.execute(
            text("SELECT * FROM arbiter.audit_events WHERE tenant_id=:tenant"),
            {"tenant": workloads.members.tenant_a},
        ).all()
        assert not any(
            row.action not in {"tenant_created", "member_created", "api_key_created"}
            for row in audit
        )
    for key in (workloads.key_a, workloads.key_b, workloads.expired, workloads.old_version):
        value = key.credential.get_secret_value()
        for sensitive in (
            value,
            value.split(".")[2],
            key.verifier.get_secret_value().hex(),
            base64.b64encode(key.verifier.get_secret_value()).decode(),
        ):
            if (
                sensitive in caplog.text
                or sensitive in str(audit)
                or any(sensitive in response.text for response in responses)
            ):
                pytest.fail("credential/verifier leaked")


async def test_concurrent_independent_tenants_do_not_share_context(workloads: Workloads) -> None:
    results = await asyncio.gather(
        *(
            workloads.access.run(key.credential, inspect_binding)
            for key in (workloads.key_a, workloads.key_b) * 6
        )
    )
    assert [row["tenant_id"] for row in results] == [
        str(tenant) for tenant in (workloads.members.tenant_a, workloads.members.tenant_b) * 6
    ]
