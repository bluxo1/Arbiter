"""Admin-only metadata, pagination and pooled RLS evidence on real PostgreSQL."""

import base64
import os
import secrets
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID, uuid4

import httpx
import pytest
from sqlalchemy import create_engine, event, text
from sqlalchemy.engine import Connection
from sqlalchemy.exc import DBAPIError
from test_audit_endpoint import assert_error, auth
from test_membership import ISSUER, Members
from test_membership import members as members

from arbiter.config import DatabaseSettings
from arbiter.identity.access import ManagementAccess
from arbiter.identity.audit_cursor import AuditCursor, AuditPosition
from arbiter.identity.context import TenantContext
from arbiter.identity.key_cursor import KeyCursor
from arbiter.identity.keys import KeyIssuer
from arbiter.main import create_app
from arbiter.operations.audit import AuditService
from arbiter.operations.key_listing import KeyListService
from arbiter.operations.keys import KeyService
from arbiter.operations.provision import MemberInput, ProvisioningService
from arbiter.persistence.keys import KeyRepository
from arbiter.persistence.operator import OperatorRepository, operator_transaction
from arbiter.persistence.tenant import bind_tenant_transaction

pytestmark = [
    pytest.mark.anyio,
    pytest.mark.skipif(os.environ.get("ARBITER_TEST_DATABASE") != "1", reason="real PostgreSQL"),
]
FIELDS = {"id", "public_id", "label", "scopes", "created_at", "expires_at", "revoked_at"}


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.fixture
def cursor_key() -> bytes:
    return secrets.token_bytes(32)


@pytest.fixture
async def client(members: Members, cursor_key: bytes) -> AsyncIterator[httpx.AsyncClient]:
    async with members.verifier() as verifier:
        access = ManagementAccess(verifier, members.runtime)
        app = create_app(
            audit_service=AuditService(access, AuditCursor(cursor_key)),
            key_service=KeyService(access, KeyIssuer(secrets.token_bytes(32), 1)),
            key_list_service=KeyListService(access, KeyCursor(cursor_key)),
        )
        async with (
            app.router.lifespan_context(app),
            httpx.AsyncClient(
                transport=httpx.ASGITransport(app=app), base_url="https://arbiter.invalid"
            ) as http,
        ):
            yield http


def url(tenant: UUID) -> str:
    return f"/v1/tenants/{tenant}/keys"


def seed(members: Members, tenant: UUID, count: int = 115) -> list[UUID]:
    ids = [uuid4() for _ in range(count)]
    now = datetime.now(UTC)
    with members.migration.begin() as connection:
        connection.execute(
            text("SELECT set_config('arbiter.tenant_id',:tenant,true)"), {"tenant": str(tenant)}
        )
        actor: UUID = connection.execute(
            text(
                "SELECT id FROM arbiter.memberships WHERE tenant_id=:tenant "
                "AND role='admin' AND active LIMIT 1"
            ),
            {"tenant": tenant},
        ).scalar_one()
        for index, identifier in enumerate(ids):
            created = now - timedelta(days=60) if index == 1 else now
            audit = uuid4()
            # Disposable metadata fixtures use random verifier bytes, not usable secrets.
            connection.execute(
                text("""
                INSERT INTO arbiter.api_keys (id,tenant_id,public_id,label,verifier,pepper_version,
                    scopes,created_at,expires_at,revoked_at,created_by_membership_id,creation_audit_id)
                VALUES (:id,:tenant,:public,:label,:verifier,1,:scopes,:created,:expires,
                        :revoked,:actor,:audit)
            """),
                {
                    "id": identifier,
                    "tenant": tenant,
                    "public": uuid4().hex,
                    "label": f"metadata-{index}",
                    "verifier": secrets.token_bytes(32),
                    "scopes": ["usage:read"]
                    if index % 2 == 0
                    else ["inference:write", "usage:read"],
                    "created": created,
                    "expires": created + timedelta(days=30),
                    "revoked": now if index == 2 else None,
                    "actor": actor,
                    "audit": audit,
                },
            )
            connection.execute(
                text("""
                INSERT INTO arbiter.audit_events (id,tenant_id,actor_type,actor_reference,
                    actor_membership_id,action,target_id,policy_revision,request_id,outcome)
                VALUES (:audit,:tenant,'member',:reference,:actor,'api_key_created',:id,
                        1,:request,'succeeded')
            """),
                {
                    "audit": audit,
                    "tenant": tenant,
                    "reference": str(actor),
                    "actor": actor,
                    "id": identifier,
                    "request": uuid4(),
                },
            )
    return sorted(ids)


async def test_defaults_maximum_complete_pages_and_metadata_states(
    client: httpx.AsyncClient, members: Members
) -> None:
    ids = seed(members, members.tenant_b)
    headers = auth(members.token(subject=members.subject_b))
    first = await client.get(url(members.tenant_b), headers=headers)
    assert first.status_code == 200 and first.headers["cache-control"] == "no-store"
    data = first.json()
    assert set(data) == {"data", "next_cursor"} and len(data["data"]) == 50
    seen = [item["id"] for item in data["data"]]
    for item in data["data"]:
        assert set(item) == FIELDS
    while data["next_cursor"] is not None:
        page = await client.get(
            url(members.tenant_b), headers=headers, params={"cursor": data["next_cursor"]}
        )
        assert page.status_code == 200
        data = page.json()
        seen.extend(item["id"] for item in data["data"])
    assert seen == list(map(str, ids)) and len(set(seen)) == 115
    maximum = await client.get(url(members.tenant_b), headers=headers, params={"page_size": "100"})
    assert maximum.status_code == 200 and len(maximum.json()["data"]) == 100
    states = []
    cursor = None
    while True:
        params = {"page_size": "100"} if cursor is None else {"page_size": "100", "cursor": cursor}
        response = await client.get(url(members.tenant_b), headers=headers, params=params)
        states.extend(response.json()["data"])
        cursor = response.json()["next_cursor"]
        if cursor is None:
            break
    expired = next(item for item in states if item["label"] == "metadata-1")
    revoked = next(item for item in states if item["label"] == "metadata-2")
    assert datetime.fromisoformat(expired["expires_at"]) < datetime.now(UTC)
    assert revoked["revoked_at"] is not None
    assert expired["scopes"] == ["inference:write", "usage:read"]
    assert revoked["scopes"] == ["usage:read"]
    with members.migration.begin() as connection:
        connection.execute(
            text("SELECT set_config('arbiter.tenant_id',:tenant,true)"),
            {"tenant": str(members.tenant_b)},
        )
        rows = connection.execute(
            text(
                "SELECT id,public_id,label,scopes,created_at,expires_at,revoked_at "
                "FROM arbiter.api_keys WHERE tenant_id=:tenant ORDER BY id"
            ),
            {"tenant": members.tenant_b},
        ).all()
    for item, row in zip(states, rows, strict=True):
        assert item["id"] == str(row.id) and item["public_id"] == row.public_id
        assert item["label"] == row.label and item["scopes"] == row.scopes
        assert datetime.fromisoformat(item["created_at"]) == row.created_at
        assert datetime.fromisoformat(item["expires_at"]) == row.expires_at
        assert (
            None if item["revoked_at"] is None else datetime.fromisoformat(item["revoked_at"])
        ) == row.revoked_at


async def test_empty_tenant_has_no_keys(client: httpx.AsyncClient, members: Members) -> None:
    response = await client.get(
        url(members.tenant_b), headers=auth(members.token(subject=members.subject_b))
    )
    assert response.status_code == 200 and response.json() == {"data": [], "next_cursor": None}


async def test_member_forged_claims_and_foreign_tenants_are_denied(
    client: httpx.AsyncClient, members: Members
) -> None:
    seed(members, members.tenant_b, 2)
    token = members.token(role="admin", roles=["admin"], tenant_id=str(members.tenant_b))
    assert_error(
        await client.get(url(members.tenant_a), headers=auth(token)), 403, "permission_denied"
    )
    denied = [
        await client.get(url(tenant), headers=auth(token), params={"cursor": "malformed"})
        for tenant in (members.tenant_b, uuid4())
    ]
    for response in denied:
        assert_error(response, 404, "not_found")
        assert str(members.tenant_b) not in response.text
    assert denied[0].json()["error"] == denied[1].json()["error"]


@pytest.mark.parametrize(
    "credential", [None, "Basic inert", "Bearer malformed", "Bearer a.b.c", "Bearer "]
)
async def test_invalid_authentication(
    client: httpx.AsyncClient, members: Members, credential: str | None
) -> None:
    headers = {} if credential is None else {"Authorization": credential}
    assert_error(
        await client.get(url(members.tenant_b), headers=headers), 401, "invalid_credentials"
    )


async def test_invalid_signed_tokens_and_mixed_credentials_never_query_db(
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
            {"iss": "https://wrong.invalid"},
            {"nbf": 4102444800},
        ):
            assert_error(
                await client.get(
                    url(members.tenant_b),
                    headers=auth(members.token(subject=members.subject_b, **claims)),
                ),
                401,
                "invalid_credentials",
            )
        token = members.token(subject=members.subject_b)
        for headers in (
            [("Authorization", "Bearer " + token), ("Authorization", "Bearer " + token)],
            [("Authorization", "Bearer " + token), ("X-API-Key", "inert")],
        ):
            assert_error(
                await client.get(url(members.tenant_b), headers=headers), 401, "invalid_credentials"
            )
        assert statements == []
    finally:
        event.remove(members.runtime, "before_cursor_execute", observe)


@pytest.mark.parametrize(
    "query",
    [
        {"page_size": "0"},
        {"page_size": "101"},
        {"page_size": "-1"},
        {"page_size": "1.0"},
        {"page_size": " 1"},
        {"page_size": "1000"},
        {"cursor": ""},
        {"cursor": "malformed"},
        {"tenant_id": "forged"},
        {"key_id": "foreign"},
        {"include_secret": "true"},
        [("page_size", "1"), ("page_size", "2")],
        [("cursor", "x"), ("cursor", "y")],
    ],
)
async def test_invalid_queries_are_sanitized_after_admin_authorization(
    client: httpx.AsyncClient, members: Members, query: Any
) -> None:
    assert_error(
        await client.get(
            url(members.tenant_b),
            headers=auth(members.token(subject=members.subject_b)),
            params=query,
        ),
        422,
        "invalid_fields",
    )
    assert_error(
        await client.get(url(members.tenant_a), headers=auth(members.token()), params=query),
        403,
        "permission_denied",
    )


async def test_foreign_altered_and_audit_cursors_cannot_enumerate_keys(
    client: httpx.AsyncClient, members: Members, cursor_key: bytes
) -> None:
    ProvisioningService(members.operator).create_member(
        members.tenant_a, MemberInput(ISSUER, members.subject_b, "admin")
    )
    ids_a, ids_b = seed(members, members.tenant_a, 3), seed(members, members.tenant_b, 3)
    headers = auth(members.token(subject=members.subject_b))
    first = await client.get(url(members.tenant_a), headers=headers, params={"page_size": "1"})
    cursor = first.json()["next_cursor"]
    assert str(ids_a[0]) not in cursor and str(members.tenant_a) not in cursor
    foreign = await client.get(url(members.tenant_b), headers=headers, params={"cursor": cursor})
    altered = await client.get(
        url(members.tenant_b),
        headers=headers,
        params={"cursor": ("A" if cursor[0] != "A" else "B") + cursor[1:]},
    )
    for response in (foreign, altered):
        assert_error(response, 422, "invalid_fields")
        assert cursor not in response.text and str(ids_a[0]) not in response.text
    assert foreign.json()["error"] == altered.json()["error"]
    audit = AuditCursor(cursor_key).encode(
        members.tenant_b, AuditPosition(datetime.now(UTC), uuid4())
    )
    assert_error(
        await client.get(url(members.tenant_b), headers=headers, params={"cursor": audit}),
        422,
        "invalid_fields",
    )
    normal = await client.get(url(members.tenant_b), headers=headers)
    assert [item["id"] for item in normal.json()["data"]] == list(map(str, ids_b))
    for key_id in (ids_a[0], uuid4()):
        assert (
            await client.get(url(members.tenant_b) + f"/{key_id}", headers=headers)
        ).status_code == 404
        assert_error(
            await client.get(
                url(members.tenant_b), headers=headers, params={"key_id": str(key_id)}
            ),
            422,
            "invalid_fields",
        )
        assert (
            await client.post(url(members.tenant_b) + f"/{key_id}/revoke", headers=headers)
        ).status_code == 404


async def test_secrets_verifiers_and_internal_fields_never_reach_listing(
    client: httpx.AsyncClient,
    members: Members,
    caplog: pytest.LogCaptureFixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    headers = auth(members.token(subject=members.subject_b))
    created = await client.post(
        url(members.tenant_b),
        headers=headers,
        json={"label": "secret-probe", "scopes": ["usage:read"]},
    )
    assert created.status_code == 201
    value = created.json()["api_key"]
    encoded = value.split(".")[2]
    raw = base64.urlsafe_b64decode(encoded + "=")

    def forbidden_issue(self: KeyIssuer) -> Any:
        raise AssertionError("listing must not issue key material")

    monkeypatch.setattr(KeyIssuer, "issue", forbidden_issue)
    with members.migration.begin() as connection:
        connection.execute(
            text("SELECT set_config('arbiter.tenant_id',:tenant,true)"),
            {"tenant": str(members.tenant_b)},
        )
        verifier: bytes = bytes(
            connection.execute(
                text("SELECT verifier FROM arbiter.api_keys WHERE tenant_id=:tenant"),
                {"tenant": members.tenant_b},
            ).scalar_one()
        )
    response = await client.get(url(members.tenant_b), headers=headers)
    assert response.status_code == 200 and set(response.json()["data"][0]) == FIELDS
    denied = await client.get(url(members.tenant_b), headers=headers, params={"cursor": value})
    assert_error(denied, 422, "invalid_fields")
    for sensitive in (
        value,
        encoded,
        raw.hex(),
        verifier.hex(),
        base64.b64encode(verifier).decode(),
    ):
        if sensitive in response.text or sensitive in denied.text or sensitive in caplog.text:
            pytest.fail("secret or verifier leaked")
    for statement in (
        "SELECT verifier FROM arbiter.api_keys",
        "SELECT pepper_version FROM arbiter.api_keys",
    ):
        with members.runtime.begin() as connection, pytest.raises(DBAPIError) as failure:
            connection.execute(text(statement))
        assert getattr(failure.value.orig, "sqlstate", None) == "42501"


async def test_suspended_and_inactive_membership_fail_closed(
    client: httpx.AsyncClient, members: Members
) -> None:
    headers = auth(members.token(subject=members.subject_b))
    seed(members, members.tenant_b, 1)
    service = ProvisioningService(members.operator)
    service.set_tenant_status(members.tenant_b, "suspended")
    assert_error(await client.get(url(members.tenant_b), headers=headers), 404, "not_found")
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
    assert_error(await client.get(url(members.tenant_b), headers=headers), 404, "not_found")


async def test_query_projection_tenant_scope_and_connection_pool_cleanup(
    members: Members, cursor_key: bytes
) -> None:
    ProvisioningService(members.operator).create_member(
        members.tenant_a, MemberInput(ISSUER, members.subject_b, "admin")
    )
    ids_a, ids_b = seed(members, members.tenant_a, 2), seed(members, members.tenant_b, 2)
    engine = create_engine(
        DatabaseSettings().url("runtime"), pool_size=1, max_overflow=0, hide_parameters=True
    )
    observed: list[tuple[int, str]] = []

    def observe(
        connection: Connection,
        cursor: Any,
        statement: str,
        parameters: Any,
        context: Any,
        many: bool,
    ) -> None:
        if (
            "FROM arbiter.api_keys WHERE tenant_id=" in statement
            and "ORDER BY id LIMIT" in statement
        ):
            assert (
                "SELECT id, public_id, label, scopes, created_at, expires_at, revoked_at"
                in statement
            )
            assert "verifier" not in statement and "pepper_version" not in statement
            row = connection.execute(
                text("SELECT pg_backend_pid(),current_setting('arbiter.tenant_id')")
            ).one()
            assert row[1] == str(parameters["tenant"]) and parameters["limit"] == 51
            observed.append((row[0], row[1]))

    event.listen(engine, "before_cursor_execute", observe)
    try:
        async with members.verifier() as verifier:
            app = create_app(
                key_list_service=KeyListService(
                    ManagementAccess(verifier, engine), KeyCursor(cursor_key)
                )
            )
            async with (
                app.router.lifespan_context(app),
                httpx.AsyncClient(
                    transport=httpx.ASGITransport(app=app), base_url="https://arbiter.invalid"
                ) as client,
            ):
                for tenant, ids in (
                    (members.tenant_a, ids_a),
                    (members.tenant_b, ids_b),
                    (members.tenant_a, ids_a),
                ):
                    response = await client.get(
                        url(tenant), headers=auth(members.token(subject=members.subject_b))
                    )
                    assert response.status_code == 200 and [
                        item["id"] for item in response.json()["data"]
                    ] == list(map(str, ids))
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
                with engine.begin() as connection:
                    connection.execute(
                        text("SELECT set_config('arbiter.tenant_id',:tenant,false)"),
                        {"tenant": str(members.tenant_b)},
                    )
                assert_error(
                    await client.get(
                        url(members.tenant_a),
                        headers=auth(members.token(subject=members.subject_b)),
                    ),
                    503,
                    "unavailable",
                )
                assert (
                    await client.get(
                        url(members.tenant_a),
                        headers=auth(members.token(subject=members.subject_b)),
                    )
                ).status_code == 200
                assert observed[-1][0] != observed[0][0]
    finally:
        event.remove(engine, "before_cursor_execute", observe)
        engine.dispose()
    with members.runtime.begin() as connection, pytest.raises(DBAPIError) as failure:
        connection.execute(
            text("SELECT set_config('arbiter.tenant_id',:tenant,true)"),
            {"tenant": str(members.tenant_a)},
        )
        connection.execute(
            text(
                "UPDATE arbiter.api_keys SET revoked_at=clock_timestamp() WHERE tenant_id=:tenant"
            ),
            {"tenant": members.tenant_b},
        )
    assert getattr(failure.value.orig, "sqlstate", None) == "42501"
    with members.runtime.connect() as connection, connection.begin() as transaction:
        scoped = bind_tenant_transaction(connection, transaction, TenantContext(members.tenant_a))
        for size in (0, 101):
            with pytest.raises(ValueError):
                KeyRepository(scoped).list_page(page_size=size, after=None)


async def test_cursor_recreation_and_deleted_anchor_do_not_query_foreign_objects(
    client: httpx.AsyncClient,
    members: Members,
    cursor_key: bytes,
) -> None:
    ids = seed(members, members.tenant_b, 3)
    headers = auth(members.token(subject=members.subject_b))
    first = await client.get(url(members.tenant_b), headers=headers, params={"page_size": "1"})
    cursor = first.json()["next_cursor"]
    assert KeyCursor(cursor_key).decode(members.tenant_b, cursor) == ids[0]
    with members.migration.begin() as connection:
        connection.execute(
            text("SELECT set_config('arbiter.tenant_id',:tenant,true)"),
            {"tenant": str(members.tenant_b)},
        )
        connection.execute(
            text("DELETE FROM arbiter.api_keys WHERE tenant_id=:tenant AND id=:id"),
            {"tenant": members.tenant_b, "id": ids[0]},
        )
    async with members.verifier() as verifier:
        app = create_app(
            key_list_service=KeyListService(
                ManagementAccess(verifier, members.runtime), KeyCursor(cursor_key)
            )
        )
        async with (
            app.router.lifespan_context(app),
            httpx.AsyncClient(
                transport=httpx.ASGITransport(app=app),
                base_url="https://arbiter.invalid",
            ) as restarted,
        ):
            response = await restarted.get(
                url(members.tenant_b),
                headers=headers,
                params={"cursor": cursor, "page_size": "100"},
            )
            assert response.status_code == 200
            assert [row["id"] for row in response.json()["data"]] == list(map(str, ids[1:]))
            assert response.json()["next_cursor"] is None
            exhausted = KeyCursor(cursor_key).encode(members.tenant_b, ids[-1])
            empty = await restarted.get(
                url(members.tenant_b), headers=headers, params={"cursor": exhausted}
            )
            assert empty.status_code == 200 and empty.json() == {"data": [], "next_cursor": None}


async def test_database_connection_failure_is_sanitized_and_inference_unavailable(
    members: Members,
    cursor_key: bytes,
) -> None:
    engine = create_engine(
        DatabaseSettings().url("runtime").set(port=1),
        connect_args={"connect_timeout": 2},
        hide_parameters=True,
    )
    try:
        async with members.verifier() as verifier:
            app = create_app(
                key_list_service=KeyListService(
                    ManagementAccess(verifier, engine), KeyCursor(cursor_key)
                )
            )
            async with (
                app.router.lifespan_context(app),
                httpx.AsyncClient(
                    transport=httpx.ASGITransport(app=app),
                    base_url="https://arbiter.invalid",
                ) as http,
            ):
                response = await http.get(
                    url(members.tenant_b), headers=auth(members.token(subject=members.subject_b))
                )
                assert_error(response, 503, "unavailable")
                assert "postgres" not in response.text and "password" not in response.text
                assert (await http.get("/health/live")).status_code == 200
                assert (await http.get("/health/ready")).status_code == 503
                assert (await http.post("/v1/chat/completions", json={})).status_code == 404
    finally:
        engine.dispose()
