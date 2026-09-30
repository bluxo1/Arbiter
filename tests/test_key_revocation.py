"""OIDC admin revocation, real PostgreSQL atomicity, locking and privilege denials."""

import asyncio
import base64
import os
import secrets
from collections.abc import AsyncIterator
from threading import Event
from typing import Any
from uuid import UUID, uuid4

import httpx
import pytest
from sqlalchemy import create_engine, event, text
from sqlalchemy.exc import DBAPIError
from test_audit_endpoint import assert_error, auth
from test_key_creation import VALID, inspect_keys
from test_membership import ISSUER, Members
from test_membership import members as members

from arbiter.config import DatabaseSettings
from arbiter.identity.access import ManagementAccess
from arbiter.identity.audit_cursor import AuditCursor
from arbiter.identity.key_cursor import KeyCursor
from arbiter.identity.keys import KeyIssuer
from arbiter.main import create_app
from arbiter.operations.audit import AuditService
from arbiter.operations.key_listing import KeyListService
from arbiter.operations.key_revocation import KeyRevocationService
from arbiter.operations.keys import KeyService
from arbiter.operations.provision import MemberInput, ProvisioningService
from arbiter.persistence.operator import OperatorRepository, operator_transaction

pytestmark = [
    pytest.mark.anyio,
    pytest.mark.skipif(os.environ.get("ARBITER_TEST_DATABASE") != "1", reason="real PostgreSQL"),
]
CALL = (
    "SELECT revoked_at FROM arbiter.revoke_api_key(:tenant,:actor,:principal,:key,:audit,:request)"
)


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.fixture
async def client(members: Members) -> AsyncIterator[httpx.AsyncClient]:
    async with members.verifier() as verifier:
        access = ManagementAccess(verifier, members.runtime)
        cursor_key = secrets.token_bytes(32)
        app = create_app(
            audit_service=AuditService(access, AuditCursor(cursor_key)),
            key_service=KeyService(access, KeyIssuer(secrets.token_bytes(32), 1)),
            key_list_service=KeyListService(access, KeyCursor(cursor_key)),
            key_revocation_service=KeyRevocationService(access),
        )
        async with (
            app.router.lifespan_context(app),
            httpx.AsyncClient(
                transport=httpx.ASGITransport(app=app), base_url="https://arbiter.invalid"
            ) as http,
        ):
            yield http


def url(tenant: UUID, key: UUID | str) -> str:
    return f"/v1/tenants/{tenant}/keys/{key}/revoke"


def admin(members: Members) -> dict[str, str]:
    return auth(members.token(subject=members.subject_b))


async def create(client: httpx.AsyncClient, members: Members, tenant: UUID | None = None) -> UUID:
    response = await client.post(
        f"/v1/tenants/{tenant or members.tenant_b}/keys", headers=admin(members), json=VALID
    )
    assert response.status_code == 201
    return UUID(response.json()["id"])


def audits(members: Members, tenant: UUID) -> list[Any]:
    with members.migration.begin() as connection:
        connection.execute(
            text("SELECT set_config('arbiter.tenant_id',:tenant,true)"), {"tenant": str(tenant)}
        )
        return list(
            connection.execute(
                text(
                    "SELECT * FROM arbiter.audit_events WHERE tenant_id=:tenant "
                    "AND action='api_key_revoked'"
                ),
                {"tenant": tenant},
            )
        )


async def test_success_and_repeat_preserve_one_timestamp_and_one_atomic_audit(
    client: httpx.AsyncClient, members: Members
) -> None:
    key = await create(client, members)
    before = inspect_keys(members, members.tenant_b)[0]
    responses = [
        await client.post(url(members.tenant_b, key), headers=admin(members)) for _ in range(2)
    ]
    for response in responses:
        assert response.status_code == 200
        assert set(response.json()) == {"id", "revoked_at"}
        assert response.headers["cache-control"] == "no-store"
    assert responses[0].json() == responses[1].json()
    row = inspect_keys(members, members.tenant_b)[0]
    assert row.revoked_at is not None
    assert {k: v for k, v in row._mapping.items() if k != "revoked_at"} == {
        k: v for k, v in before._mapping.items() if k != "revoked_at"
    }
    audit = audits(members, members.tenant_b)
    assert len(audit) == 1
    assert (audit[0].target_id, audit[0].actor_membership_id, audit[0].actor_reference) == (
        key,
        members.member_b,
        str(members.member_b),
    )
    assert audit[0].outcome == "succeeded" and audit[0].policy_revision == 1
    assert audit[0].request_id is not None and audit[0].occurred_at == row.revoked_at
    listed = await client.get(f"/v1/tenants/{members.tenant_b}/keys", headers=admin(members))
    assert listed.json()["data"][0]["revoked_at"] == responses[0].json()["revoked_at"]


async def test_parallel_repeats_create_exactly_one_security_mutation(
    client: httpx.AsyncClient, members: Members
) -> None:
    key = await create(client, members)
    responses = await asyncio.gather(
        *(client.post(url(members.tenant_b, key), headers=admin(members)) for _ in range(12))
    )
    assert all(response.status_code == 200 for response in responses)
    assert len({response.text for response in responses}) == 1
    assert len(audits(members, members.tenant_b)) == 1


async def test_member_forged_claims_and_foreign_tenants_are_denied(
    client: httpx.AsyncClient, members: Members
) -> None:
    key = await create(client, members)
    forged = auth(members.token(role="admin", roles=["admin"], tenant_id=str(members.tenant_b)))
    assert_error(
        await client.post(url(members.tenant_a, key), headers=forged), 403, "permission_denied"
    )
    responses = [
        await client.post(url(tenant, key), headers=forged)
        for tenant in (members.tenant_b, uuid4())
    ]
    assert all(response.status_code == 404 for response in responses)
    assert responses[0].json()["error"] == responses[1].json()["error"]
    assert inspect_keys(members, members.tenant_b)[0].revoked_at is None
    assert audits(members, members.tenant_b) == []


async def test_foreign_and_nonexistent_keys_have_identical_errors(
    client: httpx.AsyncClient, members: Members
) -> None:
    ProvisioningService(members.operator).create_member(
        members.tenant_a, MemberInput(ISSUER, members.subject_b, "admin")
    )
    foreign = await create(client, members, members.tenant_a)
    responses = [
        await client.post(url(members.tenant_b, key), headers=admin(members))
        for key in (foreign, uuid4())
    ]
    for response in responses:
        assert_error(response, 404, "not_found")
    assert responses[0].json()["error"] == responses[1].json()["error"]
    assert inspect_keys(members, members.tenant_a)[0].revoked_at is None
    assert audits(members, members.tenant_a) == audits(members, members.tenant_b) == []


@pytest.mark.parametrize(
    "headers", [{}, {"Authorization": "Bearer malformed"}, {"Authorization": "Basic inert"}]
)
async def test_missing_invalid_credentials(
    client: httpx.AsyncClient, members: Members, headers: dict[str, str]
) -> None:
    assert_error(
        await client.post(url(members.tenant_b, uuid4()), headers=headers),
        401,
        "invalid_credentials",
    )


async def test_invalid_signed_and_mixed_credentials_never_reach_database(
    client: httpx.AsyncClient, members: Members
) -> None:
    statements: list[str] = []

    def observe(*args: Any) -> None:
        statements.append(str(args[2]))

    event.listen(members.runtime, "before_cursor_execute", observe)
    try:
        for claims in (
            {"exp": 1},
            {"aud": "wrong"},
            {"nbf": 4102444800},
            {"iss": "https://wrong.invalid"},
        ):
            assert_error(
                await client.post(
                    url(members.tenant_b, uuid4()), headers=auth(members.token(**claims))
                ),
                401,
                "invalid_credentials",
            )
        token = members.token(subject=members.subject_b)
        for headers in (
            [("Authorization", f"Bearer {token}"), ("Authorization", f"Bearer {token}")],
            [("Authorization", f"Bearer {token}"), ("X-API-Key", "inert")],
        ):
            assert_error(
                await client.post(url(members.tenant_b, uuid4()), headers=headers),
                401,
                "invalid_credentials",
            )
        assert statements == []
    finally:
        event.remove(members.runtime, "before_cursor_execute", observe)


@pytest.mark.parametrize("key", ["malformed", "arb1.inert.secret"])
async def test_bad_object_selector_is_validated_after_authorization(
    client: httpx.AsyncClient, members: Members, key: str
) -> None:
    assert_error(
        await client.post(url(members.tenant_b, key), headers=admin(members)), 422, "invalid_fields"
    )
    assert_error(
        await client.post(url(members.tenant_a, key), headers=auth(members.token())),
        403,
        "permission_denied",
    )
    assert_error(await client.post(url(uuid4(), key), headers=admin(members)), 404, "not_found")
    assert_error(
        await client.post(f"/v1/tenants/forged/keys/{key}/revoke", headers=admin(members)),
        422,
        "invalid_fields",
    )


@pytest.mark.parametrize(
    "options",
    [
        {"json": {}},
        {"json": {"tenant_id": "forged"}},
        {"params": {"key_id": "forged"}},
        {"headers": {"Content-Encoding": "gzip"}},
    ],
)
async def test_no_body_or_options_contract(
    client: httpx.AsyncClient, members: Members, options: dict[str, Any]
) -> None:
    key = await create(client, members)
    headers = {**admin(members), **options.get("headers", {})}
    options = {name: value for name, value in options.items() if name != "headers"}
    assert_error(
        await client.post(url(members.tenant_b, key), headers=headers, **options),
        422,
        "invalid_fields",
    )
    assert inspect_keys(members, members.tenant_b)[0].revoked_at is None


async def test_real_audit_failure_rolls_back_revocation_and_connection_recovers(
    client: httpx.AsyncClient, members: Members, monkeypatch: pytest.MonkeyPatch
) -> None:
    key = await create(client, members)
    duplicate = inspect_keys(members, members.tenant_b)[0].creation_audit_id
    import arbiter.operations.key_revocation as operations

    monkeypatch.setattr(operations, "uuid4", lambda: duplicate)
    assert_error(
        await client.post(url(members.tenant_b, key), headers=admin(members)), 503, "unavailable"
    )
    assert inspect_keys(members, members.tenant_b)[0].revoked_at is None
    assert audits(members, members.tenant_b) == []
    monkeypatch.setattr(operations, "uuid4", uuid4)
    assert (
        await client.post(url(members.tenant_b, key), headers=admin(members))
    ).status_code == 200
    assert len(audits(members, members.tenant_b)) == 1


async def test_enclosing_transaction_abort_rolls_back_both_records(
    client: httpx.AsyncClient, members: Members
) -> None:
    key = await create(client, members)
    with members.runtime.connect() as connection:
        transaction = connection.begin()
        connection.execute(
            text("SELECT set_config('arbiter.tenant_id',:tenant,true)"),
            {"tenant": str(members.tenant_b)},
        )
        principal: UUID = connection.execute(
            text(
                "SELECT principal_id FROM arbiter.memberships WHERE id=:actor AND tenant_id=:tenant"
            ),
            {"actor": members.member_b, "tenant": members.tenant_b},
        ).scalar_one()
        assert (
            connection.execute(
                text(CALL),
                {
                    "tenant": members.tenant_b,
                    "actor": members.member_b,
                    "principal": principal,
                    "key": key,
                    "audit": uuid4(),
                    "request": uuid4(),
                },
            ).scalar_one()
            is not None
        )
        assert (
            connection.execute(
                text(
                    "SELECT count(*) FROM arbiter.audit_events WHERE tenant_id=:tenant "
                    "AND action='api_key_revoked'"
                ),
                {"tenant": members.tenant_b},
            ).scalar_one()
            == 1
        )
        # A second connection cannot see either uncommitted change.
        assert inspect_keys(members, members.tenant_b)[0].revoked_at is None
        assert audits(members, members.tenant_b) == []
        transaction.rollback()
    assert inspect_keys(members, members.tenant_b)[0].revoked_at is None
    assert audits(members, members.tenant_b) == []


async def test_runtime_direct_writes_role_switch_and_unsafe_function_calls_denied(
    client: httpx.AsyncClient, members: Members
) -> None:
    key = await create(client, members)
    for statement in (
        "UPDATE arbiter.api_keys SET revoked_at=clock_timestamp()",
        "DELETE FROM arbiter.api_keys",
        "SELECT verifier FROM arbiter.api_keys",
        "SET ROLE arbiter_key_writer",
        "ALTER TABLE arbiter.api_keys DISABLE ROW LEVEL SECURITY",
    ):
        with members.runtime.begin() as connection, pytest.raises(DBAPIError) as failure:
            connection.execute(text(statement))
        assert getattr(failure.value.orig, "sqlstate", None) == "42501"
    for context, actor, code in (
        (None, members.member_b, "42501"),
        (members.tenant_a, members.member_b, "42501"),
        (members.tenant_b, members.member_a, "P0002"),
        (members.tenant_b, members.member_b, "P0002"),
    ):
        with members.runtime.begin() as connection, pytest.raises(DBAPIError) as failure:
            if context is not None:
                connection.execute(
                    text("SELECT set_config('arbiter.tenant_id',:tenant,true)"),
                    {"tenant": str(context)},
                )
            connection.execute(
                text(CALL),
                {
                    "tenant": members.tenant_b,
                    "actor": actor,
                    "principal": uuid4(),
                    "key": key,
                    "audit": uuid4(),
                    "request": uuid4(),
                },
            )
        assert getattr(failure.value.orig, "sqlstate", None) == code
    with members.operator.begin() as connection, pytest.raises(DBAPIError) as failure:
        connection.execute(
            text(CALL),
            {
                "tenant": members.tenant_b,
                "actor": members.member_b,
                "principal": uuid4(),
                "key": key,
                "audit": uuid4(),
                "request": uuid4(),
            },
        )
    assert getattr(failure.value.orig, "sqlstate", None) == "42501"
    assert inspect_keys(members, members.tenant_b)[0].revoked_at is None


async def test_catalog_and_revocation_cannot_be_reversed(
    client: httpx.AsyncClient, members: Members
) -> None:
    key = await create(client, members)
    assert (
        await client.post(url(members.tenant_b, key), headers=admin(members))
    ).status_code == 200
    with members.migration.begin() as connection:
        row = connection.execute(
            text(
                "SELECT pg_get_userbyid(proowner),prosecdef,proconfig FROM pg_proc "
                "WHERE oid='arbiter.revoke_api_key(uuid,uuid,uuid,uuid,uuid,uuid)'::regprocedure"
            )
        ).one()
        assert tuple(row) == ("arbiter_key_writer", True, ["search_path=pg_catalog"])
        acl = connection.execute(
            text(
                "SELECT grantee FROM pg_proc p, LATERAL aclexplode(p.proacl) a "
                "WHERE p.oid='arbiter.revoke_api_key(uuid,uuid,uuid,uuid,uuid,uuid)'::regprocedure "
                "AND a.grantee=0"
            )
        ).all()
        assert acl == []
        assert not connection.execute(
            text(
                "SELECT has_function_privilege('arbiter_operator',"
                "'arbiter.revoke_api_key(uuid,uuid,uuid,uuid,uuid,uuid)','EXECUTE')"
            )
        ).scalar_one()
    for value in ("NULL", "clock_timestamp()"):
        with members.migration.begin() as connection, pytest.raises(DBAPIError) as failure:
            connection.execute(
                text("SELECT set_config('arbiter.tenant_id',:tenant,true)"),
                {"tenant": str(members.tenant_b)},
            )
            # Static alternatives only; no caller value is interpolated into SQL.
            statement = (
                "UPDATE arbiter.api_keys SET revoked_at=NULL WHERE tenant_id=:tenant"
                if value == "NULL"
                else "UPDATE arbiter.api_keys SET revoked_at=clock_timestamp() "
                "WHERE tenant_id=:tenant"
            )
            connection.execute(text(statement), {"tenant": members.tenant_b})
        assert getattr(failure.value.orig, "sqlstate", None) == "23514"


@pytest.mark.parametrize("change,expected", [("role", 403), ("active", 404), ("status", 404)])
async def test_authority_is_rechecked_after_waiting_on_tenant_lock(
    client: httpx.AsyncClient, members: Members, change: str, expected: int
) -> None:
    key = await create(client, members)
    reached = Event()

    def observe(*args: Any) -> None:
        if "arbiter.revoke_api_key" in str(args[2]):
            reached.set()

    event.listen(members.runtime, "before_cursor_execute", observe)
    try:
        with operator_transaction(members.operator, members.tenant_b) as scoped:
            repository = OperatorRepository(scoped)
            tenant = repository.lock_tenant()
            task = asyncio.create_task(
                client.post(url(members.tenant_b, key), headers=admin(members))
            )
            assert await asyncio.to_thread(reached.wait, 2)
            assert not task.done()
            if change == "role":
                statement = (
                    "UPDATE arbiter.memberships SET role='member' "
                    "WHERE tenant_id=:tenant AND id=:actor"
                )
            elif change == "active":
                statement = (
                    "UPDATE arbiter.memberships SET active=false "
                    "WHERE tenant_id=:tenant AND id=:actor"
                )
            else:
                statement = "UPDATE arbiter.tenants SET status='suspended' WHERE tenant_id=:tenant"
            scoped.connection().execute(
                text(statement), {"tenant": members.tenant_b, "actor": members.member_b}
            )
            repository.append_audit(
                action="fixture_authority_change",
                target_id=members.member_b,
                revision=tenant.policy_revision,
                correlation=uuid4(),
            )
        assert_error(await task, expected, "permission_denied" if expected == 403 else "not_found")
    finally:
        event.remove(members.runtime, "before_cursor_execute", observe)
    assert inspect_keys(members, members.tenant_b)[0].revoked_at is None
    assert audits(members, members.tenant_b) == []


async def test_post_commit_tenant_then_key_lock_observes_revoked_state(
    client: httpx.AsyncClient, members: Members
) -> None:
    key = await create(client, members)
    response = await client.post(url(members.tenant_b, key), headers=admin(members))
    assert response.status_code == 200
    # Persistence ordering evidence only: no dispatch/admission implementation exists.
    with members.migration.begin() as connection:
        connection.execute(
            text("SELECT set_config('arbiter.tenant_id',:tenant,true)"),
            {"tenant": str(members.tenant_b)},
        )
        connection.execute(
            text("SELECT id FROM arbiter.tenants WHERE tenant_id=:tenant FOR UPDATE"),
            {"tenant": members.tenant_b},
        ).one()
        assert (
            connection.execute(
                text(
                    "SELECT revoked_at IS NULL FROM arbiter.api_keys "
                    "WHERE tenant_id=:tenant AND id=:key FOR UPDATE"
                ),
                {"tenant": members.tenant_b, "key": key},
            ).scalar_one()
            is False
        )


async def test_expired_key_can_be_revoked_without_becoming_usable(
    client: httpx.AsyncClient, members: Members
) -> None:
    from test_key_listing import seed

    keys = seed(members, members.tenant_b, count=3)
    expired = next(
        row for row in inspect_keys(members, members.tenant_b) if row.label == "metadata-1"
    )
    assert expired.id in keys and expired.revoked_at is None
    response = await client.post(url(members.tenant_b, expired.id), headers=admin(members))
    assert response.status_code == 200
    after = next(row for row in inspect_keys(members, members.tenant_b) if row.id == expired.id)
    assert after.revoked_at is not None and after.expires_at == expired.expires_at


async def test_direct_function_rejects_active_member_and_nonexistent_key(
    client: httpx.AsyncClient, members: Members
) -> None:
    key = await create(client, members)
    for tenant, actor, expected in (
        (members.tenant_a, members.member_a, "42501"),
        (members.tenant_b, members.member_b, "P0002"),
    ):
        with members.runtime.begin() as connection, pytest.raises(DBAPIError) as failure:
            connection.execute(
                text("SELECT set_config('arbiter.tenant_id',:tenant,true)"), {"tenant": str(tenant)}
            )
            principal: UUID = connection.execute(
                text(
                    "SELECT principal_id FROM arbiter.memberships "
                    "WHERE tenant_id=:tenant AND id=:actor"
                ),
                {"tenant": tenant, "actor": actor},
            ).scalar_one()
            connection.execute(
                text(CALL),
                {
                    "tenant": tenant,
                    "actor": actor,
                    "principal": principal,
                    "key": uuid4() if tenant == members.tenant_b else key,
                    "audit": uuid4(),
                    "request": uuid4(),
                },
            )
        assert getattr(failure.value.orig, "sqlstate", None) == expected
    assert inspect_keys(members, members.tenant_b)[0].revoked_at is None


async def test_secret_verifier_absence_and_workload_routes_remain_unavailable(
    client: httpx.AsyncClient, members: Members, caplog: pytest.LogCaptureFixture
) -> None:
    created = await client.post(
        f"/v1/tenants/{members.tenant_b}/keys", headers=admin(members), json=VALID
    )
    data = created.json()
    stored = inspect_keys(members, members.tenant_b)[0]
    revoked = await client.post(url(members.tenant_b, data["id"]), headers=admin(members))
    responses = [
        revoked,
        await client.post(url(members.tenant_b, data["id"]), headers=admin(members)),
        await client.get(f"/v1/tenants/{members.tenant_b}/audit", headers=admin(members)),
        await client.post(url(members.tenant_b, data["api_key"]), headers=admin(members)),
    ]
    for sensitive in (
        data["api_key"],
        data["api_key"].split(".")[2],
        bytes(stored.verifier).hex(),
        base64.b64encode(bytes(stored.verifier)).decode(),
    ):
        if (
            sensitive in caplog.text
            or sensitive in str(audits(members, members.tenant_b))
            or any(sensitive in response.text for response in responses)
        ):
            pytest.fail("key secret/verifier reached a protected surface")
    assert_error(
        await client.post(url(members.tenant_b, data["id"]), headers=auth(data["api_key"])),
        401,
        "invalid_credentials",
    )
    credential = auth(data["api_key"])
    # Inference remains absent (404); GET-only metadata routes reject POST with 405.
    response = await client.post("/v1/chat/completions", headers=credential, json={})
    assert response.status_code == 404
    assert (await client.post("/v1/usage", headers=credential, json={})).status_code == 405
    assert (
        await client.post("/v1/models", headers=auth(data["api_key"]), json={})
    ).status_code == 405


async def test_one_connection_pool_clears_context_across_tenants_and_discards_poison(
    client: httpx.AsyncClient, members: Members
) -> None:
    ProvisioningService(members.operator).create_member(
        members.tenant_a, MemberInput(ISSUER, members.subject_b, "admin")
    )
    keys = [
        await create(client, members, tenant)
        for tenant in (members.tenant_a, members.tenant_b, members.tenant_a)
    ]
    engine = create_engine(
        DatabaseSettings().url("runtime"), pool_size=1, max_overflow=0, hide_parameters=True
    )
    try:
        async with members.verifier() as verifier:
            service = KeyRevocationService(ManagementAccess(verifier, engine))
            observed: list[int] = []
            for tenant, key in zip(
                (members.tenant_a, members.tenant_b, members.tenant_a), keys, strict=True
            ):
                assert (
                    await service.revoke(members.token(subject=members.subject_b), tenant, str(key))
                )[0] == key
                with engine.begin() as connection:
                    assert (
                        connection.execute(
                            text("SELECT NULLIF(current_setting('arbiter.tenant_id',true),'')")
                        ).scalar_one()
                        is None
                    )
                    assert connection.execute(text("SELECT id FROM arbiter.api_keys")).all() == []
                    observed.append(
                        connection.execute(text("SELECT pg_backend_pid()")).scalar_one()
                    )
            assert len(set(observed)) == 1
            with engine.begin() as connection:
                connection.execute(
                    text("SELECT set_config('arbiter.tenant_id',:tenant,false)"),
                    {"tenant": str(members.tenant_b)},
                )
            from arbiter.identity.access import MembershipUnavailable

            with pytest.raises(MembershipUnavailable):
                await service.revoke(
                    members.token(subject=members.subject_b), members.tenant_a, str(keys[0])
                )
            await service.revoke(
                members.token(subject=members.subject_b), members.tenant_a, str(keys[0])
            )
            with engine.begin() as connection:
                assert (
                    connection.execute(text("SELECT pg_backend_pid()")).scalar_one() != observed[0]
                )
    finally:
        engine.dispose()
