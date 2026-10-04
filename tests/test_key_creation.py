"""Creation-only HTTP, real PostgreSQL isolation and real constraint-failure atomicity."""

import asyncio
import base64
import hashlib
import hmac
import os
import secrets
from collections.abc import AsyncIterator
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from threading import Event
from typing import Any
from uuid import UUID, uuid4

import httpx
import pytest
from sqlalchemy import create_engine, event, text
from sqlalchemy.exc import DBAPIError
from test_audit_endpoint import assert_error, auth
from test_membership import Members
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
from arbiter.persistence.operator import OperatorRepository, operator_transaction

pytestmark = [
    pytest.mark.anyio,
    pytest.mark.skipif(os.environ.get("ARBITER_TEST_DATABASE") != "1", reason="real PostgreSQL"),
]
VALID = {"label": "creation-fixture", "scopes": ["inference:write", "usage:read"]}


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.fixture
def pepper() -> bytes:
    return secrets.token_bytes(32)


@pytest.fixture
async def client(members: Members, pepper: bytes) -> AsyncIterator[httpx.AsyncClient]:
    async with members.verifier() as verifier:
        access = ManagementAccess(verifier, members.runtime)
        app = create_app(
            audit_service=AuditService(access, AuditCursor(secrets.token_bytes(32))),
            key_service=KeyService(access, KeyIssuer(pepper, 3)),
            key_list_service=KeyListService(access, KeyCursor(secrets.token_bytes(32))),
            key_revocation_service=KeyRevocationService(access),
        )
        async with (
            app.router.lifespan_context(app),
            httpx.AsyncClient(
                transport=httpx.ASGITransport(app=app), base_url="https://arbiter.invalid"
            ) as http,
        ):
            yield http


def path(tenant: UUID) -> str:
    return f"/v1/tenants/{tenant}/keys"


def inspect_keys(members: Members, tenant: UUID) -> list[Any]:
    with members.migration.begin() as connection:
        connection.execute(
            text("SELECT set_config('arbiter.tenant_id',:tenant,true)"), {"tenant": str(tenant)}
        )
        return list(
            connection.execute(
                text("SELECT * FROM arbiter.api_keys WHERE tenant_id=:tenant"), {"tenant": tenant}
            ).all()
        )


async def test_success_returns_only_once_and_persists_hmac_with_matching_audit(
    client: httpx.AsyncClient, members: Members, pepper: bytes, caplog: pytest.LogCaptureFixture
) -> None:
    response = await client.post(
        path(members.tenant_b), headers=auth(members.token(subject=members.subject_b)), json=VALID
    )
    assert response.status_code == 201
    data = response.json()
    assert set(data) == {
        "id",
        "public_id",
        "label",
        "scopes",
        "created_at",
        "expires_at",
        "api_key",
        "request_id",
    }
    value = data["api_key"]
    _, public, encoded = value.split(".")
    secret = base64.urlsafe_b64decode(encoded + "=")
    assert len(secret) == 32 and public == data["public_id"]
    assert datetime.fromisoformat(data["expires_at"]) - datetime.fromisoformat(
        data["created_at"]
    ) == timedelta(days=30)
    assert response.headers["cache-control"] == "no-store"
    rows = inspect_keys(members, members.tenant_b)
    assert len(rows) == 1
    row = rows[0]
    assert row.id == UUID(data["id"]) and row.pepper_version == 3 and row.revoked_at is None
    expected = hmac.digest(
        pepper, b"arbiter/api-key/v1\0" + public.encode() + b"\0" + secret, hashlib.sha256
    )
    assert hmac.compare_digest(expected, bytes(row.verifier))
    with members.migration.begin() as connection:
        connection.execute(
            text("SELECT set_config('arbiter.tenant_id',:tenant,true)"),
            {"tenant": str(members.tenant_b)},
        )
        audit = connection.execute(
            text("SELECT * FROM arbiter.audit_events WHERE tenant_id=:tenant AND id=:id"),
            {"tenant": members.tenant_b, "id": row.creation_audit_id},
        ).one()
        assert audit.target_id == row.id and audit.actor_membership_id == members.member_b
        assert audit.action == "api_key_created" and audit.outcome == "succeeded"
        assert audit.request_id == UUID(data["request_id"])
        assert (
            connection.execute(
                text(
                    "SELECT count(*) FROM arbiter.api_keys k LEFT JOIN arbiter.audit_events a "
                    "ON a.tenant_id=k.tenant_id AND a.id=k.creation_audit_id AND a.target_id=k.id "
                    "AND a.actor_membership_id=k.created_by_membership_id "
                    "WHERE k.tenant_id=:tenant AND a.id IS NULL"
                ),
                {"tenant": members.tenant_b},
            ).scalar_one()
            == 0
        )
    audit_response = await client.get(
        f"/v1/tenants/{members.tenant_b}/audit",
        headers=auth(members.token(subject=members.subject_b)),
    )
    for sensitive in (value, encoded, secret.hex()):
        if (
            sensitive in str(rows)
            or sensitive in str(audit)
            or sensitive in caplog.text
            or sensitive in audit_response.text
        ):
            pytest.fail("plaintext secret reached a protected surface")
    assert (
        await client.get(
            path(members.tenant_b), headers=auth(members.token(subject=members.subject_b))
        )
    ).status_code == 200
    assert (
        await client.post(
            f"{path(members.tenant_b)}/{row.id}/revoke",
            headers=auth(members.token(subject=members.subject_b)),
        )
    ).status_code == 200
    assert (
        await client.post("/v1/chat/completions", headers=auth(value), json={})
    ).status_code == 422
    assert_error(
        await client.get(f"/v1/tenants/{members.tenant_b}/audit", headers=auth(value)),
        401,
        "invalid_credentials",
    )


async def test_member_forgery_and_cross_tenant_denials(
    client: httpx.AsyncClient, members: Members
) -> None:
    token = members.token(role="admin", roles=["admin"], tenant_id=str(members.tenant_b))
    assert_error(
        await client.post(path(members.tenant_a), headers=auth(token), json=VALID),
        403,
        "permission_denied",
    )
    responses = [
        await client.post(path(tenant), headers=auth(token), json=VALID)
        for tenant in (members.tenant_b, uuid4())
    ]
    for response in responses:
        assert_error(response, 404, "not_found")
    assert responses[0].json()["error"] == responses[1].json()["error"]
    assert (
        inspect_keys(members, members.tenant_a) == []
        and inspect_keys(members, members.tenant_b) == []
    )


@pytest.mark.parametrize(
    "headers", [{}, {"Authorization": "Bearer malformed"}, {"Authorization": "Basic inert"}]
)
async def test_authentication_denied(
    client: httpx.AsyncClient, members: Members, headers: dict[str, str]
) -> None:
    assert_error(
        await client.post(path(members.tenant_b), headers=headers, json=VALID),
        401,
        "invalid_credentials",
    )


@pytest.mark.parametrize(
    "changes",
    [
        {"scopes": []},
        {"scopes": ["admin"]},
        {"scopes": ["usage:read", "usage:read"]},
        {"scopes": "usage:read"},
        {"scopes": [1]},
        {"label": ""},
        {"label": "x" * 65},
        {"label": "x\n"},
        {"tenant_id": "forged"},
        {"public_id": "forged"},
        {"api_key": "inert"},
        {"expires_at": None},
        {"expires_at": 123},
        {"expires_at": "bad"},
        {"expires_at": (datetime.now(UTC) - timedelta(days=1)).isoformat()},
        {"expires_at": (datetime.now(UTC) + timedelta(days=91)).isoformat()},
        {"expires_at": "2026-10-01T12:00:00"},
    ],
)
async def test_invalid_fields_create_neither_key_nor_success_audit(
    client: httpx.AsyncClient, members: Members, changes: dict[str, Any]
) -> None:
    response = await client.post(
        path(members.tenant_b),
        headers=auth(members.token(subject=members.subject_b)),
        json={**VALID, **changes},
    )
    assert_error(response, 422, "invalid_fields")
    assert inspect_keys(members, members.tenant_b) == []
    with members.migration.begin() as connection:
        connection.execute(
            text("SELECT set_config('arbiter.tenant_id',:tenant,true)"),
            {"tenant": str(members.tenant_b)},
        )
        assert (
            connection.execute(
                text(
                    "SELECT count(*) FROM arbiter.audit_events WHERE tenant_id=:tenant "
                    "AND action='api_key_created'"
                ),
                {"tenant": members.tenant_b},
            ).scalar_one()
            == 0
        )


async def test_expiration_boundary_and_repeated_valid_requests(
    client: httpx.AsyncClient, members: Members
) -> None:
    expiration = datetime.now(UTC) + timedelta(days=90)
    responses = [
        await client.post(
            path(members.tenant_b),
            headers=auth(members.token(subject=members.subject_b)),
            json={**VALID, "expires_at": expiration.isoformat()},
        )
        for _ in range(2)
    ]
    for response in responses:
        if response.status_code != 201:
            pytest.fail(f"creation failed: {response.status_code} {response.text}")
    assert responses[0].json()["id"] != responses[1].json()["id"]
    if hmac.compare_digest(responses[0].json()["api_key"], responses[1].json()["api_key"]):
        pytest.fail("valid creation replayed a credential")
    overlong = datetime.now(UTC) + timedelta(days=90, minutes=1)
    assert_error(
        await client.post(
            path(members.tenant_b),
            headers=auth(members.token(subject=members.subject_b)),
            json={**VALID, "expires_at": overlong.isoformat()},
        ),
        422,
        "invalid_fields",
    )
    assert len(inspect_keys(members, members.tenant_b)) == 2


@pytest.mark.parametrize(
    "body",
    [
        b"{",
        b"[]",
        b'{"label":"x","label":"y","scopes":["usage:read"]}',
        b'{"label":"x","scopes":["usage:read"],"scopes":["inference:write"]}',
    ],
)
async def test_duplicate_malformed_json(
    client: httpx.AsyncClient, members: Members, body: bytes
) -> None:
    response = await client.post(
        path(members.tenant_b),
        headers={
            **auth(members.token(subject=members.subject_b)),
            "Content-Type": "application/json",
        },
        content=body,
    )
    assert_error(response, 422, "invalid_fields")
    assert inspect_keys(members, members.tenant_b) == []


async def test_declared_and_chunked_body_limits(
    client: httpx.AsyncClient, members: Members
) -> None:
    headers = {**auth(members.token(subject=members.subject_b)), "Content-Type": "application/json"}
    assert_error(
        await client.post(path(members.tenant_b), headers=headers, content=b"x" * 65537),
        413,
        "body_too_large",
    )

    async def chunks() -> AsyncIterator[bytes]:
        yield b"x" * 32768
        yield b"x" * 32769

    assert_error(
        await client.post(path(members.tenant_b), headers=headers, content=chunks()),
        413,
        "body_too_large",
    )
    assert inspect_keys(members, members.tenant_b) == []


async def test_real_audit_failure_rolls_back_key_then_connection_recovers(
    client: httpx.AsyncClient, members: Members, monkeypatch: pytest.MonkeyPatch
) -> None:
    with members.migration.begin() as connection:
        connection.execute(
            text("SELECT set_config('arbiter.tenant_id',:tenant,true)"),
            {"tenant": str(members.tenant_b)},
        )
        duplicate: UUID = connection.execute(
            text("SELECT id FROM arbiter.audit_events WHERE tenant_id=:tenant LIMIT 1"),
            {"tenant": members.tenant_b},
        ).scalar_one()
    import arbiter.operations.keys as operations

    original = uuid4
    monkeypatch.setattr(operations, "uuid4", lambda: duplicate)
    denied = await client.post(
        path(members.tenant_b), headers=auth(members.token(subject=members.subject_b)), json=VALID
    )
    assert_error(denied, 409, "creation_conflict")
    assert inspect_keys(members, members.tenant_b) == []
    monkeypatch.setattr(operations, "uuid4", original)
    assert (
        await client.post(
            path(members.tenant_b),
            headers=auth(members.token(subject=members.subject_b)),
            json=VALID,
        )
    ).status_code == 201


async def test_runtime_privileges_and_cross_tenant_metadata(
    client: httpx.AsyncClient, members: Members
) -> None:
    created = await client.post(
        path(members.tenant_b), headers=auth(members.token(subject=members.subject_b)), json=VALID
    )
    assert created.status_code == 201
    with members.runtime.begin() as connection:
        assert connection.execute(text("SELECT id FROM arbiter.api_keys")).all() == []
        connection.execute(
            text("SELECT set_config('arbiter.tenant_id',:tenant,true)"),
            {"tenant": str(members.tenant_a)},
        )
        assert (
            connection.execute(
                text("SELECT id FROM arbiter.api_keys WHERE id=:id"),
                {"id": UUID(created.json()["id"])},
            ).all()
            == []
        )
    for statement in (
        "INSERT INTO arbiter.api_keys (id) VALUES (gen_random_uuid())",
        "UPDATE arbiter.api_keys SET scopes=ARRAY['inference:write','usage:read']",
        "DELETE FROM arbiter.api_keys",
        "SELECT verifier FROM arbiter.api_keys",
        "SELECT pepper_version FROM arbiter.api_keys",
        "SET ROLE arbiter_key_writer",
    ):
        with members.runtime.begin() as connection, pytest.raises(DBAPIError) as failure:
            connection.execute(text(statement))
        assert getattr(failure.value.orig, "sqlstate", None) == "42501"
    with members.migration.begin() as connection, pytest.raises(DBAPIError) as failure:
        connection.execute(
            text("SELECT set_config('arbiter.tenant_id',:tenant,true)"),
            {"tenant": str(members.tenant_b)},
        )
        connection.execute(
            text("UPDATE arbiter.api_keys SET scopes=ARRAY['usage:read'] WHERE tenant_id=:tenant"),
            {"tenant": members.tenant_b},
        )
    assert getattr(failure.value.orig, "sqlstate", None) == "23514"


@pytest.mark.parametrize(
    "scopes", [["usage:read"], ["inference:write"], ["usage:read", "inference:write"]]
)
async def test_all_allowed_scope_sets(
    client: httpx.AsyncClient, members: Members, scopes: list[str]
) -> None:
    response = await client.post(
        path(members.tenant_b),
        headers=auth(members.token(subject=members.subject_b)),
        json={**VALID, "scopes": scopes},
    )
    assert response.status_code == 201 and response.json()["scopes"] == sorted(scopes)


async def test_database_rejects_orphan_and_mixed_tenant_relationships(
    client: httpx.AsyncClient, members: Members
) -> None:
    response = await client.post(
        path(members.tenant_b), headers=auth(members.token(subject=members.subject_b)), json=VALID
    )
    assert response.status_code == 201
    existing = inspect_keys(members, members.tenant_b)[0]
    for actor, audit in (
        (members.member_a, uuid4()),
        (members.member_b, uuid4()),
        (members.member_b, existing.creation_audit_id),
    ):
        with pytest.raises(DBAPIError) as failure, members.migration.begin() as connection:
            connection.execute(
                text("SELECT set_config('arbiter.tenant_id',:tenant,true)"),
                {"tenant": str(members.tenant_b)},
            )
            connection.execute(
                text("""
                INSERT INTO arbiter.api_keys (id,tenant_id,public_id,label,verifier,pepper_version,
                    scopes,created_at,expires_at,created_by_membership_id,creation_audit_id)
                SELECT :id,tenant_id,:public,label,verifier,pepper_version,scopes,
                    created_at,expires_at,:actor,:audit FROM arbiter.api_keys
                WHERE tenant_id=:tenant AND id=:existing
            """),
                {
                    "id": uuid4(),
                    "public": uuid4().hex,
                    "actor": actor,
                    "audit": audit,
                    "tenant": members.tenant_b,
                    "existing": existing.id,
                },
            )
        assert getattr(failure.value.orig, "sqlstate", None) == "23503"
    assert len(inspect_keys(members, members.tenant_b)) == 1


async def test_helper_requires_context_and_cannot_be_used_by_operator(members: Members) -> None:
    query = text(
        "SELECT * FROM arbiter.create_api_key(:tenant,:actor,:principal,:id,:public,:label,"
        ":verifier,1,ARRAY['usage:read'],NULL,:audit,:request)"
    )
    with members.migration.begin() as connection:
        connection.execute(
            text("SELECT set_config('arbiter.tenant_id',:tenant,true)"),
            {"tenant": str(members.tenant_b)},
        )
        principal: UUID = connection.execute(
            text(
                "SELECT principal_id FROM arbiter.memberships WHERE tenant_id=:tenant AND id=:actor"
            ),
            {"tenant": members.tenant_b, "actor": members.member_b},
        ).scalar_one()
    values = {
        "tenant": members.tenant_b,
        "actor": members.member_b,
        "principal": principal,
        "id": uuid4(),
        "public": uuid4().hex,
        "label": "inert",
        "verifier": bytes(32),
        "audit": uuid4(),
        "request": uuid4(),
    }
    for engine, context in (
        (members.runtime, None),
        (members.runtime, members.tenant_a),
        (members.operator, members.tenant_b),
    ):
        with engine.begin() as connection, pytest.raises(DBAPIError) as failure:
            if context is not None:
                connection.execute(
                    text("SELECT set_config('arbiter.tenant_id',:tenant,true)"),
                    {"tenant": str(context)},
                )
            connection.execute(query, values)
        assert getattr(failure.value.orig, "sqlstate", None) == "42501"
    with members.migration.begin() as connection:
        flags = connection.execute(
            text(
                "SELECT rolcanlogin,rolsuper,rolbypassrls,rolcreaterole,rolcreatedb "
                "FROM pg_roles WHERE rolname='arbiter_key_writer'"
            )
        ).one()
        assert flags == (False, False, False, False, False)
        assert (
            connection.execute(
                text(
                    "SELECT count(*) FROM pg_auth_members WHERE member="
                    "(SELECT oid FROM pg_roles WHERE rolname='arbiter_runtime')"
                )
            ).scalar_one()
            == 0
        )
        assert connection.execute(
            text(
                "SELECT relrowsecurity,relforcerowsecurity FROM pg_class "
                "WHERE oid='arbiter.api_keys'::regclass"
            )
        ).one() == (True, True)
        assert not connection.execute(
            text("SELECT has_schema_privilege('arbiter_key_writer','arbiter','CREATE')")
        ).scalar_one()
    assert inspect_keys(members, members.tenant_b) == []


async def test_admin_downgrade_under_tenant_lock_blocks_creation(
    client: httpx.AsyncClient, members: Members
) -> None:
    reached = Event()

    def before_execute(*args: Any) -> None:
        if "arbiter.create_api_key" in str(args[2]):
            reached.set()

    event.listen(members.runtime, "before_cursor_execute", before_execute)
    try:
        with operator_transaction(members.operator, members.tenant_b) as scoped:
            repository = OperatorRepository(scoped)
            tenant = repository.lock_tenant()
            task = asyncio.create_task(
                client.post(
                    path(members.tenant_b),
                    headers=auth(members.token(subject=members.subject_b)),
                    json=VALID,
                )
            )
            assert await asyncio.to_thread(reached.wait, 2)
            scoped.connection().execute(
                text(
                    "UPDATE arbiter.memberships SET role='member' "
                    "WHERE tenant_id=:tenant AND id=:member"
                ),
                {"tenant": members.tenant_b, "member": members.member_b},
            )
            repository.append_audit(
                action="fixture_admin_downgrade",
                target_id=members.member_b,
                revision=tenant.policy_revision,
                correlation=uuid4(),
            )
        assert_error(await task, 403, "permission_denied")
    finally:
        event.remove(members.runtime, "before_cursor_execute", before_execute)
    assert inspect_keys(members, members.tenant_b) == []


async def test_created_secret_is_not_echoed_by_validation_or_errors(
    client: httpx.AsyncClient, members: Members, caplog: pytest.LogCaptureFixture
) -> None:
    response = await client.post(
        path(members.tenant_b), headers=auth(members.token(subject=members.subject_b)), json=VALID
    )
    assert response.status_code == 201
    value = response.json()["api_key"]
    errors = [
        await client.post(
            path(members.tenant_b),
            headers=auth(members.token(subject=members.subject_b)),
            json={**VALID, "api_key": value},
        ),
        await client.post(
            path(members.tenant_b),
            headers=auth(members.token(subject=members.subject_b)),
            json={**VALID, "label": value},
        ),
    ]
    for denied in errors:
        assert_error(denied, 422, "invalid_fields")
        if value in denied.text or value in caplog.text:
            pytest.fail("credential leaked through validation")
    assert len(inspect_keys(members, members.tenant_b)) == 1


async def test_suspension_and_inactive_membership_deny_creation(
    client: httpx.AsyncClient, members: Members
) -> None:
    from arbiter.operations.provision import ProvisioningService

    service = ProvisioningService(members.operator)
    service.set_tenant_status(members.tenant_b, "suspended")
    assert_error(
        await client.post(
            path(members.tenant_b),
            headers=auth(members.token(subject=members.subject_b)),
            json=VALID,
        ),
        404,
        "not_found",
    )
    service.set_tenant_status(members.tenant_b, "active")
    with operator_transaction(members.operator, members.tenant_b) as scoped:
        repository = OperatorRepository(scoped)
        tenant = repository.lock_tenant()
        scoped.connection().execute(
            text(
                "UPDATE arbiter.memberships SET active=false WHERE tenant_id=:tenant AND id=:member"
            ),
            {"tenant": members.tenant_b, "member": members.member_b},
        )
        repository.append_audit(
            action="fixture_member_deactivation",
            target_id=members.member_b,
            revision=tenant.policy_revision,
            correlation=uuid4(),
        )
    assert_error(
        await client.post(
            path(members.tenant_b),
            headers=auth(members.token(subject=members.subject_b)),
            json=VALID,
        ),
        404,
        "not_found",
    )
    assert inspect_keys(members, members.tenant_b) == []


async def test_invalid_signed_tokens_never_touch_database(
    client: httpx.AsyncClient, members: Members
) -> None:
    queries: list[str] = []

    def observe(*args: Any) -> None:
        queries.append(str(args[2]))

    event.listen(members.runtime, "before_cursor_execute", observe)
    try:
        for claims in (
            {"exp": 1},
            {"aud": "wrong"},
            {"nbf": 4102444800},
            {"iss": "https://wrong.invalid"},
        ):
            denied = await client.post(
                path(members.tenant_b),
                headers=auth(members.token(subject=members.subject_b, **claims)),
                json=VALID,
            )
            assert_error(denied, 401, "invalid_credentials")
        assert queries == []
    finally:
        event.remove(members.runtime, "before_cursor_execute", observe)


async def test_public_identifier_collision_rolls_back_audit(
    client: httpx.AsyncClient, members: Members, monkeypatch: pytest.MonkeyPatch
) -> None:
    material = KeyIssuer(secrets.token_bytes(32), 3).issue()
    monkeypatch.setattr(KeyIssuer, "issue", lambda self: replace(material, id=uuid4()))
    first = await client.post(
        path(members.tenant_b), headers=auth(members.token(subject=members.subject_b)), json=VALID
    )
    assert first.status_code == 201
    denied = await client.post(
        path(members.tenant_b), headers=auth(members.token(subject=members.subject_b)), json=VALID
    )
    assert_error(denied, 409, "creation_conflict")
    if material.credential.get_secret_value() in denied.text:
        pytest.fail("collision response leaked credential")
    assert len(inspect_keys(members, members.tenant_b)) == 1
    with members.migration.begin() as connection:
        connection.execute(
            text("SELECT set_config('arbiter.tenant_id',:tenant,true)"),
            {"tenant": str(members.tenant_b)},
        )
        assert (
            connection.execute(
                text(
                    "SELECT count(*) FROM arbiter.audit_events WHERE tenant_id=:tenant "
                    "AND action='api_key_created'"
                ),
                {"tenant": members.tenant_b},
            ).scalar_one()
            == 1
        )


async def test_creation_pool_reuse_clears_context_and_discards_poisoned_session(
    members: Members,
) -> None:
    from test_membership import ISSUER

    from arbiter.operations.provision import MemberInput, ProvisioningService

    ProvisioningService(members.operator).create_member(
        members.tenant_a, MemberInput(ISSUER, members.subject_b, "admin")
    )
    engine = create_engine(
        DatabaseSettings().url("runtime"), pool_size=1, max_overflow=0, hide_parameters=True
    )
    observed: list[tuple[int, str]] = []

    def observe(*args: Any) -> None:
        if "arbiter.create_api_key" in str(args[2]):
            row = (
                args[0]
                .execute(text("SELECT pg_backend_pid(),current_setting('arbiter.tenant_id')"))
                .one()
            )
            observed.append((row[0], row[1]))

    event.listen(engine, "before_cursor_execute", observe)
    try:
        async with members.verifier() as verifier:
            app = create_app(
                key_service=KeyService(
                    ManagementAccess(verifier, engine), KeyIssuer(secrets.token_bytes(32), 1)
                )
            )
            async with (
                app.router.lifespan_context(app),
                httpx.AsyncClient(
                    transport=httpx.ASGITransport(app=app), base_url="https://arbiter.invalid"
                ) as http,
            ):
                for tenant in (members.tenant_a, members.tenant_b, members.tenant_a):
                    assert (
                        await http.post(
                            path(tenant),
                            headers=auth(members.token(subject=members.subject_b)),
                            json=VALID,
                        )
                    ).status_code == 201
                    with engine.begin() as connection:
                        assert (
                            connection.execute(
                                text("SELECT NULLIF(current_setting('arbiter.tenant_id',true),'')")
                            ).scalar_one()
                            is None
                        )
                        assert (
                            connection.execute(text("SELECT id FROM arbiter.api_keys")).all() == []
                        )
                assert len({pid for pid, _ in observed}) == 1
                assert [tenant for _, tenant in observed] == list(
                    map(str, (members.tenant_a, members.tenant_b, members.tenant_a))
                )
                with engine.begin() as connection:
                    connection.execute(
                        text("SELECT set_config('arbiter.tenant_id',:tenant,false)"),
                        {"tenant": str(members.tenant_b)},
                    )
                assert_error(
                    await http.post(
                        path(members.tenant_a),
                        headers=auth(members.token(subject=members.subject_b)),
                        json=VALID,
                    ),
                    503,
                    "unavailable",
                )
                assert (
                    await http.post(
                        path(members.tenant_a),
                        headers=auth(members.token(subject=members.subject_b)),
                        json=VALID,
                    )
                ).status_code == 201
                assert observed[-1][0] != observed[0][0]
    finally:
        event.remove(engine, "before_cursor_execute", observe)
        engine.dispose()
