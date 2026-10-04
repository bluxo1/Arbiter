"""HTTP identity and audit isolation evidence with real restricted PostgreSQL."""

import os
import secrets
from collections.abc import AsyncIterator
from datetime import UTC, datetime
from typing import Any
from uuid import UUID, uuid4

import httpx
import pytest
from sqlalchemy import create_engine, event, text
from sqlalchemy.engine import Connection
from test_membership import Members
from test_membership import members as members

from arbiter.config import DatabaseSettings, OidcSettings
from arbiter.identity.access import ManagementAccess
from arbiter.identity.audit_cursor import AuditCursor
from arbiter.identity.oidc import OidcVerifier
from arbiter.main import create_app
from arbiter.operations.audit import AuditService
from arbiter.operations.provision import ProvisioningService
from arbiter.persistence.operator import operator_transaction

pytestmark = [
    pytest.mark.anyio,
    pytest.mark.skipif(os.environ.get("ARBITER_TEST_DATABASE") != "1", reason="real PostgreSQL"),
]


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.fixture
async def client(members: Members) -> AsyncIterator[httpx.AsyncClient]:
    async with members.verifier() as verifier:
        service = AuditService(
            ManagementAccess(verifier, members.runtime), AuditCursor(secrets.token_bytes(32))
        )
        app = create_app(audit_service=service)
        async with (
            app.router.lifespan_context(app),
            httpx.AsyncClient(
                transport=httpx.ASGITransport(app=app), base_url="https://arbiter.invalid"
            ) as http,
        ):
            yield http


def url(tenant: UUID) -> str:
    return f"/v1/tenants/{tenant}/audit"


def auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def assert_error(response: httpx.Response, status: int, code: str) -> None:
    assert response.status_code == status
    body = response.json()
    assert set(body) == {"error", "request_id"}
    assert set(body["error"]) == {"code", "message"}
    assert body["error"]["code"] == code
    UUID(body["request_id"])
    assert response.headers["cache-control"] == "no-store"


def seed(members: Members, tenant: UUID, count: int = 115) -> list[str]:
    ids = [uuid4() for _ in range(count)]
    with operator_transaction(members.operator, tenant) as scoped:
        scoped.connection().execute(
            text("""
                INSERT INTO arbiter.audit_events
                (id,tenant_id,actor_type,actor_reference,action,target_id,policy_revision,
                 request_id,occurred_at,outcome)
                VALUES (:id,:tenant,'operator','arbiter_operator','fixture_audit',:target,
                        1,:request,:time,'succeeded')
            """),
            [
                {
                    "id": identifier,
                    "tenant": tenant,
                    "target": tenant,
                    "request": uuid4(),
                    "time": datetime(2026, 9, 26, tzinfo=UTC),
                }
                for identifier in ids
            ],
        )
    return [str(identifier) for identifier in sorted(ids)]


async def test_member_admin_content_free_metadata(
    client: httpx.AsyncClient, members: Members
) -> None:
    fields = {
        "id",
        "actor_type",
        "actor_membership_id",
        "action",
        "target_id",
        "policy_revision",
        "request_id",
        "occurred_at",
        "outcome",
    }
    for tenant, token, expected in (
        (members.tenant_a, members.token(), 2),
        (members.tenant_b, members.token(subject=members.subject_b), 3),
    ):
        response = await client.get(url(tenant), headers=auth(token))
        assert response.status_code == 200
        assert set(response.json()) == {"data", "next_cursor"}
        assert response.json()["next_cursor"] is None
        assert len(response.json()["data"]) == expected
        for item in response.json()["data"]:
            assert set(item) == fields
            assert item["actor_type"] == "operator"
            assert item["outcome"] == "succeeded"
            assert datetime.fromisoformat(item["occurred_at"]).utcoffset() is not None
        assert members.subject_a not in response.text and members.subject_b not in response.text
        assert response.headers["cache-control"] == "no-store"
    assert (await client.get("/health/ready")).status_code == 503
    assert (await client.post("/v1/chat/completions", json={})).status_code == 401


async def test_tenant_headers_do_not_replace_membership_selector(
    client: httpx.AsyncClient, members: Members
) -> None:
    headers = {**auth(members.token()), "X-Tenant-ID": str(members.tenant_b), "X-Role": "admin"}
    response = await client.get(url(members.tenant_a), headers=headers)
    assert response.status_code == 200
    assert str(members.tenant_b) not in response.text
    assert str(members.member_b) not in response.text
    assert_error(await client.get(url(members.tenant_b), headers=headers), 404, "not_found")


async def test_empty_page_and_cursor_after_deleted_anchor(
    client: httpx.AsyncClient, members: Members
) -> None:
    token = members.token()
    first = await client.get(url(members.tenant_a), headers=auth(token), params={"page_size": "1"})
    anchor = UUID(first.json()["data"][0]["id"])
    cursor = first.json()["next_cursor"]
    with members.migration.begin() as connection:
        connection.execute(
            text("SELECT set_config('arbiter.tenant_id',:tenant,true)"),
            {"tenant": str(members.tenant_a)},
        )
        connection.execute(
            text("DELETE FROM arbiter.audit_events WHERE tenant_id=:tenant AND id=:id"),
            {"tenant": members.tenant_a, "id": anchor},
        )
    next_page = await client.get(
        url(members.tenant_a), headers=auth(token), params={"cursor": cursor}
    )
    assert next_page.status_code == 200 and len(next_page.json()["data"]) == 1
    assert next_page.json()["data"][0]["id"] != str(anchor)
    with members.migration.begin() as connection:
        connection.execute(
            text("SELECT set_config('arbiter.tenant_id',:tenant,true)"),
            {"tenant": str(members.tenant_a)},
        )
        connection.execute(
            text("DELETE FROM arbiter.audit_events WHERE tenant_id=:tenant"),
            {"tenant": members.tenant_a},
        )
    empty = await client.get(url(members.tenant_a), headers=auth(token))
    assert empty.status_code == 200 and empty.json() == {"data": [], "next_cursor": None}


async def test_member_event_reference_metadata_only(
    client: httpx.AsyncClient, members: Members
) -> None:
    with operator_transaction(members.operator, members.tenant_a) as scoped:
        scoped.connection().execute(
            text("""
            INSERT INTO arbiter.audit_events
            (id,tenant_id,actor_type,actor_reference,actor_membership_id,action,target_id,
             policy_revision,request_id,outcome)
            VALUES (:id,:tenant,'member',:reference,:member,'fixture_member',
                    :member,1,:request,'denied')
        """),
            {
                "id": uuid4(),
                "tenant": members.tenant_a,
                "reference": str(members.member_a),
                "member": members.member_a,
                "request": uuid4(),
            },
        )
    response = await client.get(url(members.tenant_a), headers=auth(members.token()))
    member_event = next(
        item for item in response.json()["data"] if item["action"] == "fixture_member"
    )
    assert member_event["actor_type"] == "member"
    assert member_event["actor_membership_id"] == str(members.member_a)
    assert member_event["outcome"] == "denied"
    assert "actor_reference" not in member_event


@pytest.mark.parametrize(
    "credential", [None, "Basic x", "Bearer malformed", "Bearer a.b.c", "Bearer "]
)
async def test_missing_invalid_authentication(
    client: httpx.AsyncClient, members: Members, credential: str | None
) -> None:
    headers = {} if credential is None else {"Authorization": credential}
    response = await client.get(url(members.tenant_a), headers=headers)
    assert_error(response, 401, "invalid_credentials")
    assert response.headers["www-authenticate"] == "Bearer"


async def test_invalid_expired_tokens_do_not_query_audit(
    client: httpx.AsyncClient, members: Members
) -> None:
    queries: list[str] = []

    def observe(*args: object) -> None:
        queries.append(str(args[2]))

    event.listen(members.runtime, "before_cursor_execute", observe)
    try:
        for token in (
            members.token(exp=1),
            members.token(aud="wrong"),
            members.token(iss="https://wrong.invalid"),
        ):
            response = await client.get(url(members.tenant_a), headers=auth(token))
            assert_error(response, 401, "invalid_credentials")
        assert queries == []
    finally:
        event.remove(members.runtime, "before_cursor_execute", observe)


async def test_duplicate_mixed_credentials_denied(
    client: httpx.AsyncClient, members: Members
) -> None:
    token = members.token()
    for headers in (
        [("Authorization", f"Bearer {token}"), ("authorization", f"Bearer {token}")],
        [("Authorization", f"Bearer {token}"), ("X-API-Key", "inert-fixture")],
    ):
        assert_error(
            await client.get(url(members.tenant_a), headers=headers), 401, "invalid_credentials"
        )


async def test_forged_selectors_do_not_disclose_existence(
    client: httpx.AsyncClient, members: Members
) -> None:
    token = members.token(tenant_id=str(members.tenant_b), role="admin", roles=["admin"])
    responses = [
        await client.get(url(tenant), headers=auth(token), params={"cursor": "malformed"})
        for tenant in (members.tenant_b, uuid4())
    ]
    for response in responses:
        assert_error(response, 404, "not_found")
        assert str(members.tenant_b) not in response.text
    assert responses[0].json()["error"] == responses[1].json()["error"]
    good = await client.get(url(members.tenant_a), headers=auth(token), params={"page_size": "1"})
    assert good.status_code == 200
    assert (
        await client.get(
            url(members.tenant_b), headers=auth(members.token(subject=members.subject_b))
        )
    ).status_code == 200


async def test_unprovisioned_and_suspended_membership_denied(
    client: httpx.AsyncClient, members: Members
) -> None:
    assert_error(
        await client.get(
            url(members.tenant_a), headers=auth(members.token(subject="not-provisioned"))
        ),
        404,
        "not_found",
    )
    token = members.token()
    assert (await client.get(url(members.tenant_a), headers=auth(token))).status_code == 200
    ProvisioningService(members.operator).set_tenant_status(members.tenant_a, "suspended")
    assert_error(await client.get(url(members.tenant_a), headers=auth(token)), 404, "not_found")


async def test_keyset_pages_default_max_and_timestamp_ties(
    client: httpx.AsyncClient, members: Members
) -> None:
    expected = seed(members, members.tenant_a)
    foreign = seed(members, members.tenant_b)
    token = members.token()
    response = await client.get(url(members.tenant_a), headers=auth(token))
    assert len(response.json()["data"]) == 50
    seen: list[str] = []
    while True:
        assert response.status_code == 200
        seen.extend(item["id"] for item in response.json()["data"])
        cursor = response.json()["next_cursor"]
        if cursor is None:
            break
        response = await client.get(
            url(members.tenant_a), headers=auth(token), params={"cursor": cursor}
        )
    assert seen[:115] == expected
    assert len(seen) == len(set(seen)) == 117
    assert set(seen).isdisjoint(foreign)
    maximum = await client.get(
        url(members.tenant_a), headers=auth(token), params={"page_size": "100"}
    )
    assert len(maximum.json()["data"]) == 100


@pytest.mark.parametrize(
    "query",
    [
        "page_size=0",
        "page_size=101",
        "page_size=-1",
        "page_size=1.5",
        "page_size=x",
        "page_size=99999999999999999",
        "page_size=1&page_size=2",
        "cursor=",
        "cursor=malformed",
        "cursor=x&cursor=y",
        "tenant_id=forged",
        "offset=1",
    ],
)
async def test_malformed_list_inputs_are_sanitized(
    client: httpx.AsyncClient, members: Members, query: str
) -> None:
    response = await client.get(url(members.tenant_a) + "?" + query, headers=auth(members.token()))
    assert_error(response, 422, "invalid_fields")
    assert query not in response.text


async def test_foreign_tampered_and_oversized_cursor_denied(
    client: httpx.AsyncClient, members: Members
) -> None:
    a = await client.get(
        url(members.tenant_a), headers=auth(members.token()), params={"page_size": "1"}
    )
    cursor = a.json()["next_cursor"]
    changed = ("A" if cursor[0] != "A" else "B") + cursor[1:]
    token_b = members.token(subject=members.subject_b)
    for token in (cursor, changed, "x" * 10000):
        response = await client.get(
            url(members.tenant_b), headers=auth(token_b), params={"cursor": token}
        )
        assert_error(response, 422, "invalid_fields")
        assert cursor not in response.text and str(members.tenant_a) not in response.text


async def test_repository_query_is_bound_after_context_and_pool_clears(members: Members) -> None:
    engine = create_engine(
        DatabaseSettings().url("runtime"), pool_size=1, max_overflow=0, hide_parameters=True
    )
    observed: list[tuple[int, str]] = []

    def observe(
        connection: Connection,
        cursor: object,
        statement: str,
        parameters: Any,
        context: object,
        many: bool,
    ) -> None:
        if "ORDER BY occurred_at, id LIMIT" in statement:
            assert "FROM arbiter.audit_events" in statement and "WHERE tenant_id=" in statement
            assert parameters["tenant"] in (members.tenant_a, members.tenant_b)
            row = connection.execute(
                text("SELECT pg_backend_pid(), current_setting('arbiter.tenant_id')")
            ).one()
            assert row[1] == str(parameters["tenant"])
            observed.append((row[0], row[1]))

    event.listen(engine, "before_cursor_execute", observe)
    try:
        async with members.verifier() as verifier:
            app = create_app(
                audit_service=AuditService(
                    ManagementAccess(verifier, engine), AuditCursor(secrets.token_bytes(32))
                )
            )
            async with (
                app.router.lifespan_context(app),
                httpx.AsyncClient(
                    transport=httpx.ASGITransport(app=app), base_url="https://arbiter.invalid"
                ) as http,
            ):
                for tenant, token in (
                    (members.tenant_a, members.token()),
                    (members.tenant_b, members.token(subject=members.subject_b)),
                    (members.tenant_a, members.token()),
                ):
                    response = await http.get(url(tenant), headers=auth(token))
                    assert response.status_code == 200
                with engine.begin() as connection:
                    assert (
                        connection.execute(
                            text("SELECT NULLIF(current_setting('arbiter.tenant_id',true),'')")
                        ).scalar_one()
                        is None
                    )
                    assert (
                        connection.execute(text("SELECT id FROM arbiter.audit_events")).all() == []
                    )
                    connection.execute(
                        text("SELECT set_config('arbiter.tenant_id',:tenant,false)"),
                        {"tenant": str(members.tenant_b)},
                    )
                assert_error(
                    await http.get(url(members.tenant_a), headers=auth(members.token())),
                    503,
                    "unavailable",
                )
                assert (
                    await http.get(url(members.tenant_a), headers=auth(members.token()))
                ).status_code == 200
        assert len({pid for pid, tenant in observed[:3]}) == 1
        assert observed[3][0] != observed[0][0]
    finally:
        event.remove(engine, "before_cursor_execute", observe)
        engine.dispose()


async def test_unavailable_jwks_is_sanitized_and_never_queries_database(members: Members) -> None:
    queries: list[str] = []

    def observe(*args: object) -> None:
        queries.append(str(args[2]))

    event.listen(members.runtime, "before_cursor_execute", observe)
    try:
        async with OidcVerifier(
            OidcSettings(
                issuer="https://localhost:18443/realms/arbiter",
                audience="arbiter-api",
                jwks_url="https://fixture.invalid/keys",
            ),
            transport=httpx.MockTransport(
                lambda request: httpx.Response(503, text="private detail")
            ),
        ) as verifier:
            service = AuditService(
                ManagementAccess(verifier, members.runtime), AuditCursor(secrets.token_bytes(32))
            )
            app = create_app(audit_service=service)
            async with (
                app.router.lifespan_context(app),
                httpx.AsyncClient(
                    transport=httpx.ASGITransport(app=app), base_url="https://arbiter.invalid"
                ) as http,
            ):
                response = await http.get(url(members.tenant_a), headers=auth(members.token()))
                assert_error(response, 503, "unavailable")
                assert "private detail" not in response.text
        assert queries == []
    finally:
        event.remove(members.runtime, "before_cursor_execute", observe)
