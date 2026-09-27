"""Real restricted PostgreSQL catalogs for OIDC members and workload keys."""

import asyncio
import os
import secrets
import socket
from collections.abc import AsyncIterator, Iterator, Sequence
from dataclasses import dataclass
from time import time
from typing import Any
from uuid import UUID, uuid4

import httpx
import pytest
from sqlalchemy import create_engine, event, text
from sqlalchemy.exc import DBAPIError
from test_audit_endpoint import assert_error, auth
from test_membership import Members
from test_membership import members as members
from test_workload_access import Workloads
from test_workload_access import workloads as workloads

from arbiter.config import DatabaseSettings
from arbiter.identity.access import ManagementAccess
from arbiter.identity.context import TenantContext
from arbiter.identity.keys import KeyIssuer, KeyVerifier
from arbiter.identity.model_cursor import ModelCursor
from arbiter.identity.workload import WorkloadAccess
from arbiter.main import create_app
from arbiter.operations.keys import KeyService
from arbiter.operations.models import ManagementModels, ModelCatalog, ModelPage
from arbiter.operations.policy import PolicyInput, PolicyService
from arbiter.operations.provision import ProvisioningService
from arbiter.persistence.tenant import TenantTransaction, tenant_transaction

pytestmark = [
    pytest.mark.anyio,
    pytest.mark.skipif(os.environ.get("ARBITER_TEST_DATABASE") != "1", reason="real PostgreSQL"),
]


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@dataclass
class Catalogs:
    workloads: Workloads
    names: list[str]
    cursor: ModelCursor

    @property
    def members(self) -> Members:
        return self.workloads.members


@pytest.fixture
def catalogs(workloads: Workloads) -> Iterator[Catalogs]:
    store = workloads.members
    names = [f"fixture-{uuid4().hex}-{index:02}" for index in range(34)]
    names.sort()
    params = [{"id": uuid4(), "alias": alias, "active": True} for alias in names]
    with store.migration.begin() as connection:
        connection.execute(
            text("""
            INSERT INTO arbiter.provider_models
                (id,alias,adapter,model_digest,context_cap,output_cap,credit_charge,revision,active)
            VALUES (:id,:alias,'ollama',:digest,9876543,256,7,321,:active)
        """),
            [{**param, "digest": "sha256:" + "b" * 64} for param in params],
        )
    policy = PolicyService(store.operator)
    policy.set_policy(store.tenant_a, PolicyInput(aliases=tuple(names[:3])))
    policy.set_policy(store.tenant_b, PolicyInput(aliases=tuple(names[32:])))
    try:
        yield Catalogs(workloads, names, ModelCursor(secrets.token_bytes(32)))
    finally:
        with store.migration.begin() as connection:
            for tenant in (store.tenant_a, store.tenant_b):
                connection.execute(
                    text("SELECT set_config('arbiter.tenant_id',:tenant,true)"),
                    {"tenant": str(tenant)},
                )
                connection.execute(
                    text("DELETE FROM arbiter.tenant_policies WHERE tenant_id=:tenant"),
                    {"tenant": tenant},
                )
            connection.execute(
                text("DELETE FROM arbiter.provider_models WHERE alias=ANY(:aliases)"),
                {"aliases": names},
            )


@pytest.fixture
async def client(catalogs: Catalogs) -> AsyncIterator[httpx.AsyncClient]:
    async with catalogs.members.verifier() as verifier:
        catalog = ModelCatalog(catalogs.cursor)
        app = create_app(
            workload_access=catalogs.workloads.access,
            model_catalog=catalog,
            management_models=ManagementModels(
                ManagementAccess(verifier, catalogs.members.runtime), catalog
            ),
        )
        async with (
            app.router.lifespan_context(app),
            httpx.AsyncClient(
                transport=httpx.ASGITransport(app=app), base_url="https://arbiter.invalid"
            ) as http,
        ):
            yield http


def url(tenant: UUID) -> str:
    return f"/v1/tenants/{tenant}/models"


def workload_headers(catalogs: Catalogs, tenant: str = "a") -> dict[str, str]:
    key = catalogs.workloads.key_a if tenant == "a" else catalogs.workloads.key_b
    return auth(key.credential.get_secret_value())


async def test_member_admin_and_workload_share_only_their_current_catalog(
    client: httpx.AsyncClient, catalogs: Catalogs
) -> None:
    for tenant, headers, names in (
        (catalogs.members.tenant_a, auth(catalogs.members.token()), catalogs.names[:3]),
        (
            catalogs.members.tenant_b,
            auth(catalogs.members.token(subject=catalogs.members.subject_b)),
            catalogs.names[32:],
        ),
    ):
        response = await client.get(url(tenant), headers=headers)
        assert response.status_code == 200
        expected = [
            {"alias": alias, "output_cap": 256, "credit_charge": 7, "policy_revision": 2}
            for alias in names
        ]
        assert response.json() == {"data": expected, "next_cursor": None}
        work = await client.get(
            "/v1/models",
            headers=workload_headers(catalogs, "a" if tenant == catalogs.members.tenant_a else "b"),
        )
        assert work.json() == response.json() and work.status_code == 200
        assert (
            response.headers["cache-control"] == "no-store"
            and work.headers["cache-control"] == "no-store"
        )


async def test_full_approved_inventory_paginates_safely(
    client: httpx.AsyncClient, catalogs: Catalogs
) -> None:
    PolicyService(catalogs.members.operator).set_policy(
        catalogs.members.tenant_a, PolicyInput(aliases=tuple(catalogs.names[:32]))
    )
    headers = workload_headers(catalogs)
    seen: list[str] = []
    cursor = None
    while True:
        params = {"page_size": "2"}
        if cursor is not None:
            params["cursor"] = cursor
        page = await client.get("/v1/models", headers=headers, params=params)
        assert page.status_code == 200
        seen.extend(row["alias"] for row in page.json()["data"])
        assert all(row["policy_revision"] == 3 for row in page.json()["data"])
        cursor = page.json()["next_cursor"]
        if cursor is None:
            break
    assert seen == catalogs.names[:32] and len(set(seen)) == 32
    for params in ({}, {"page_size": "100"}):
        response = await client.get("/v1/models", headers=headers, params=params)
        assert len(response.json()["data"]) == 32 and response.json()["next_cursor"] is None


@pytest.mark.parametrize("path", ["management", "workload"])
@pytest.mark.parametrize("credential", [None, "invalid", "Basic invalid"])
async def test_missing_invalid_authentication(
    client: httpx.AsyncClient, catalogs: Catalogs, path: str, credential: str | None
) -> None:
    target = url(catalogs.members.tenant_a) if path == "management" else "/v1/models"
    headers = {} if credential is None else {"Authorization": credential}
    assert_error(await client.get(target, headers=headers), 401, "invalid_credentials")


async def test_forged_tenant_roles_and_inaccessible_selector_do_not_reveal_existence(
    client: httpx.AsyncClient, catalogs: Catalogs
) -> None:
    token = catalogs.members.token(tenant_id=str(catalogs.members.tenant_b), role="admin")
    responses = [
        await client.get(url(tenant), headers=auth(token))
        for tenant in (catalogs.members.tenant_b, uuid4())
    ]
    for response in responses:
        assert_error(response, 404, "not_found")
    assert responses[0].json()["error"] == responses[1].json()["error"]
    assert_error(
        await client.get(
            url(catalogs.members.tenant_a),
            headers=auth(catalogs.members.token(subject="absent-subject")),
        ),
        404,
        "not_found",
    )
    assert_error(
        await client.get(url(catalogs.members.tenant_a), headers=workload_headers(catalogs)),
        401,
        "invalid_credentials",
    )
    assert_error(
        await client.get("/v1/models", headers=auth(catalogs.members.token())),
        401,
        "invalid_credentials",
    )


@pytest.mark.parametrize(
    "extra",
    [
        {"iss": "https://forged.invalid"},
        {"aud": "foreign"},
        {"exp": int(time()) - 300},
        {"nbf": int(time()) + 3600},
    ],
)
async def test_bad_signed_jwt_claims_rejected(
    client: httpx.AsyncClient, catalogs: Catalogs, extra: dict[str, Any]
) -> None:
    assert_error(
        await client.get(
            url(catalogs.members.tenant_a), headers=auth(catalogs.members.token(**extra))
        ),
        401,
        "invalid_credentials",
    )


async def test_workload_ignores_forged_header_body_tenant_and_scope(
    client: httpx.AsyncClient, catalogs: Catalogs
) -> None:
    headers = {
        **workload_headers(catalogs),
        "X-Tenant-ID": str(catalogs.members.tenant_b),
        "X-Role": "admin",
        "X-Scope": "inference:write",
    }
    response = await client.request(
        "GET",
        "/v1/models",
        headers=headers,
        json={"tenant_id": str(catalogs.members.tenant_b), "model": catalogs.names[-1]},
    )
    assert (
        response.status_code == 200
        and [row["alias"] for row in response.json()["data"]] == catalogs.names[:3]
    )
    assert_error(
        await client.get(
            "/v1/models", headers=headers, params={"tenant_id": str(catalogs.members.tenant_b)}
        ),
        422,
        "invalid_request",
    )


async def test_suspension_revocation_expiry_and_membership_are_fresh(
    client: httpx.AsyncClient, catalogs: Catalogs
) -> None:
    store = catalogs.members
    assert (await client.get("/v1/models", headers=workload_headers(catalogs))).status_code == 200
    ProvisioningService(store.operator).set_tenant_status(store.tenant_a, "suspended")
    assert_error(
        await client.get(url(store.tenant_a), headers=auth(store.token())), 404, "not_found"
    )
    assert_error(
        await client.get("/v1/models", headers=workload_headers(catalogs)),
        401,
        "invalid_credentials",
    )
    assert (
        await client.get("/v1/models", headers=workload_headers(catalogs, "b"))
    ).status_code == 200
    ProvisioningService(store.operator).set_tenant_status(store.tenant_a, "active")
    assert_error(
        await client.get(
            "/v1/models", headers=auth(catalogs.workloads.expired.credential.get_secret_value())
        ),
        401,
        "invalid_credentials",
    )
    with tenant_transaction(store.migration, TenantContext(store.tenant_a)) as scoped:
        scoped.connection().execute(
            text(
                "UPDATE arbiter.api_keys SET revoked_at=clock_timestamp() "
                "WHERE tenant_id=:tenant AND id=:id"
            ),
            {"tenant": store.tenant_a, "id": catalogs.workloads.key_a.id},
        )
        scoped.connection().execute(
            text("UPDATE arbiter.memberships SET active=false WHERE tenant_id=:tenant AND id=:id"),
            {"tenant": store.tenant_a, "id": store.member_a},
        )
    assert_error(
        await client.get("/v1/models", headers=workload_headers(catalogs)),
        401,
        "invalid_credentials",
    )
    assert_error(
        await client.get(url(store.tenant_a), headers=auth(store.token())), 404, "not_found"
    )


async def test_inactive_unregistered_and_old_policy_aliases_never_appear(
    client: httpx.AsyncClient, catalogs: Catalogs
) -> None:
    with catalogs.members.migration.begin() as connection:
        connection.execute(
            text("UPDATE arbiter.provider_models SET active=false WHERE alias=:alias"),
            {"alias": catalogs.names[0]},
        )
        connection.execute(
            text("DELETE FROM arbiter.provider_models WHERE alias=:alias"),
            {"alias": catalogs.names[1]},
        )
    response = await client.get("/v1/models", headers=workload_headers(catalogs))
    assert [row["alias"] for row in response.json()["data"]] == [catalogs.names[2]]
    PolicyService(catalogs.members.operator).set_policy(
        catalogs.members.tenant_a, PolicyInput(aliases=(catalogs.names[3],))
    )
    response = await client.get("/v1/models", headers=workload_headers(catalogs))
    assert response.json()["data"] == [
        {"alias": catalogs.names[3], "output_cap": 256, "credit_charge": 7, "policy_revision": 3}
    ]


@pytest.mark.parametrize(
    "query",
    [
        {"page_size": "0"},
        {"page_size": "101"},
        {"page_size": "-1"},
        {"page_size": "1.5"},
        {"cursor": "malformed"},
        {"model": "unapproved"},
    ],
)
async def test_bad_queries_are_sanitized_after_authentication(
    client: httpx.AsyncClient, catalogs: Catalogs, query: dict[str, str]
) -> None:
    for target, headers in (
        (url(catalogs.members.tenant_a), auth(catalogs.members.token())),
        ("/v1/models", workload_headers(catalogs)),
    ):
        assert_error(
            await client.get(target, headers=headers, params=query), 422, "invalid_request"
        )
        assert_error(await client.get(target, params=query), 401, "invalid_credentials")


async def test_duplicate_auth_query_and_foreign_cursor_denied(
    client: httpx.AsyncClient, catalogs: Catalogs
) -> None:
    for target, headers in (
        (url(catalogs.members.tenant_a), auth(catalogs.members.token())),
        ("/v1/models", workload_headers(catalogs)),
    ):
        assert_error(
            await client.get(target, headers={**headers, "X-API-Key": "mixed"}),
            401,
            "invalid_credentials",
        )
        assert_error(
            await client.get(target, headers=list(headers.items()) * 2), 401, "invalid_credentials"
        )
        assert_error(
            await client.get(
                target, headers=headers, params=[("page_size", "1"), ("page_size", "2")]
            ),
            422,
            "invalid_request",
        )
        foreign = catalogs.cursor.encode(catalogs.members.tenant_b, catalogs.names[-1])
        assert_error(
            await client.get(target, headers=headers, params={"cursor": foreign}),
            422,
            "invalid_request",
        )
    first = await client.get(
        url(catalogs.members.tenant_a),
        headers=auth(catalogs.members.token()),
        params={"page_size": "1"},
    )
    continued = await client.get(
        "/v1/models",
        headers=workload_headers(catalogs),
        params={"page_size": "1", "cursor": first.json()["next_cursor"]},
    )
    assert continued.json()["data"][0]["alias"] == catalogs.names[1]


async def test_public_projection_no_registry_secrets_or_read_audit_mutation(
    client: httpx.AsyncClient, catalogs: Catalogs, caplog: pytest.LogCaptureFixture
) -> None:
    store = catalogs.members
    with tenant_transaction(store.runtime, TenantContext(store.tenant_a)) as scoped:
        before: int = (
            scoped.connection()
            .execute(
                text("SELECT count(*) FROM arbiter.audit_events WHERE tenant_id=:tenant"),
                {"tenant": store.tenant_a},
            )
            .scalar_one()
        )
    response = await client.get(
        "/v1/models", headers=workload_headers(catalogs), params={"page_size": "1"}
    )
    assert set(response.json()) == {"data", "next_cursor"}
    assert set(response.json()["data"][0]) == {
        "alias",
        "output_cap",
        "credit_charge",
        "policy_revision",
    }
    for marker in (
        "sha256:" + "b" * 64,
        "9876543",
        "ollama",
        catalogs.names[-1],
        catalogs.workloads.key_a.credential.get_secret_value(),
        catalogs.workloads.key_a.verifier.get_secret_value().hex(),
    ):
        assert marker not in response.text + caplog.text
    with tenant_transaction(store.runtime, TenantContext(store.tenant_a)) as scoped:
        assert (
            scoped.connection()
            .execute(
                text("SELECT count(*) FROM arbiter.audit_events WHERE tenant_id=:tenant"),
                {"tenant": store.tenant_a},
            )
            .scalar_one()
            == before
        )


async def test_restricted_helper_context_role_and_direct_registry_reads(catalogs: Catalogs) -> None:
    store = catalogs.members
    for engine, statement, params in (
        (store.runtime, "SELECT * FROM arbiter.provider_models", {}),
        (
            store.runtime,
            "SELECT * FROM arbiter.list_tenant_models(:tenant,NULL,51)",
            {"tenant": store.tenant_a},
        ),
        (
            store.operator,
            "SELECT * FROM arbiter.list_tenant_models(:tenant,NULL,51)",
            {"tenant": store.tenant_a},
        ),
        (
            store.migration,
            "SELECT * FROM arbiter.list_tenant_models(:tenant,NULL,51)",
            {"tenant": store.tenant_a},
        ),
    ):
        with pytest.raises(DBAPIError) as failure:
            with engine.begin() as connection:
                connection.execute(text(statement), params)
        assert getattr(failure.value.orig, "sqlstate", None) == "42501"
    with pytest.raises(DBAPIError) as failure:
        with tenant_transaction(store.runtime, TenantContext(store.tenant_a)) as scoped:
            scoped.connection().execute(
                text("SELECT * FROM arbiter.list_tenant_models(:tenant,NULL,51)"),
                {"tenant": store.tenant_b},
            )
    assert getattr(failure.value.orig, "sqlstate", None) == "42501"
    with store.migration.begin() as connection:
        assert connection.execute(
            text(
                "SELECT prosecdef,proconfig,pg_get_userbyid(proowner) FROM pg_proc "
                "WHERE oid='arbiter.list_tenant_models(uuid,text,integer)'::regprocedure"
            )
        ).one() == (True, ["search_path=pg_catalog"], "arbiter_migration")
        assert (
            connection.execute(
                text(
                    "SELECT count(*) FROM pg_proc p, LATERAL aclexplode(p.proacl) a "
                    "WHERE p.oid='arbiter.list_tenant_models(uuid,text,integer)'::regprocedure "
                    "AND a.grantee=0"
                )
            ).scalar_one()
            == 0
        )


async def test_default_query_has_bound_context_and_limit_51(
    client: httpx.AsyncClient, catalogs: Catalogs
) -> None:
    observed: list[tuple[str, Any]] = []

    def capture(
        connection: Any, cursor: Any, statement: str, parameters: Any, context: Any, many: bool
    ) -> None:
        if "list_tenant_models" in statement:
            observed.append((statement, parameters))

    event.listen(catalogs.members.runtime, "before_cursor_execute", capture)
    try:
        assert (
            await client.get("/v1/models", headers=workload_headers(catalogs))
        ).status_code == 200
    finally:
        event.remove(catalogs.members.runtime, "before_cursor_execute", capture)
    assert len(observed) == 1 and observed[0][1]["tenant"] == catalogs.members.tenant_a
    assert observed[0][1]["limit"] == 51 and "provider_models" not in observed[0][0]


async def test_inference_and_operator_routes_remain_unavailable(
    client: httpx.AsyncClient, catalogs: Catalogs
) -> None:
    assert (
        await client.post("/v1/chat/completions", headers=workload_headers(catalogs), json={})
    ).status_code == 404
    assert (await client.get("/v1/operator/models")).status_code == 404
    assert (await client.get("/health/ready")).status_code == 503


async def test_pooled_backend_mixed_identity_paths_and_poison_recovery(catalogs: Catalogs) -> None:
    store = catalogs.members
    engine = create_engine(
        DatabaseSettings().url("runtime"),
        pool_size=1,
        max_overflow=0,
        hide_parameters=True,
        pool_reset_on_return="rollback",
    )
    observed: list[tuple[int, UUID]] = []

    class InspectCatalog(ModelCatalog):
        def read(self, scoped: TenantTransaction, query: Sequence[tuple[str, str]]) -> ModelPage:
            observed.append(
                (
                    scoped.connection().execute(text("SELECT pg_backend_pid()")).scalar_one(),
                    scoped.context.tenant_id,
                )
            )
            return super().read(scoped, query)

    try:
        async with store.verifier() as verifier:
            catalog = InspectCatalog(catalogs.cursor)
            app = create_app(
                model_catalog=catalog,
                management_models=ManagementModels(ManagementAccess(verifier, engine), catalog),
                workload_access=WorkloadAccess(KeyVerifier(catalogs.workloads.pepper, 3), engine),
            )
            async with (
                app.router.lifespan_context(app),
                httpx.AsyncClient(
                    transport=httpx.ASGITransport(app=app), base_url="https://arbiter.invalid"
                ) as http,
            ):
                for tenant, path, headers, names in (
                    (store.tenant_a, url(store.tenant_a), auth(store.token()), catalogs.names[:3]),
                    (
                        store.tenant_b,
                        "/v1/models",
                        workload_headers(catalogs, "b"),
                        catalogs.names[32:],
                    ),
                    (store.tenant_a, "/v1/models", workload_headers(catalogs), catalogs.names[:3]),
                    (
                        store.tenant_b,
                        url(store.tenant_b),
                        auth(store.token(subject=store.subject_b)),
                        catalogs.names[32:],
                    ),
                ):
                    response = await http.get(path, headers=headers)
                    assert (
                        response.status_code == 200
                        and [row["alias"] for row in response.json()["data"]] == names
                    )
                    assert observed[-1][1] == tenant
                    with engine.begin() as connection:
                        assert (
                            connection.execute(
                                text("SELECT NULLIF(current_setting('arbiter.tenant_id',true),'')")
                            ).scalar_one()
                            is None
                        )
                        assert (
                            connection.execute(text("SELECT id FROM arbiter.tenant_policies")).all()
                            == []
                        )
                assert len({item[0] for item in observed}) == 1
                assert_error(
                    await http.get(
                        "/v1/models", headers=workload_headers(catalogs), params={"cursor": "bad"}
                    ),
                    422,
                    "invalid_request",
                )
                with engine.begin() as connection:
                    connection.execute(
                        text("SELECT set_config('arbiter.tenant_id',:tenant,false)"),
                        {"tenant": str(store.tenant_b)},
                    )
                assert_error(
                    await http.get("/v1/models", headers=workload_headers(catalogs)),
                    503,
                    "unavailable",
                )
                assert (
                    await http.get(url(store.tenant_a), headers=auth(store.token()))
                ).status_code == 200
                assert observed[-1][0] != observed[0][0]
    finally:
        engine.dispose()


async def test_concurrent_tenant_catalogs_do_not_cross(
    client: httpx.AsyncClient, catalogs: Catalogs
) -> None:
    responses = await asyncio.gather(
        *(
            client.get(
                "/v1/models", headers=workload_headers(catalogs, "a" if index % 2 == 0 else "b")
            )
            for index in range(12)
        )
    )
    for index, response in enumerate(responses):
        expected = catalogs.names[:3] if index % 2 == 0 else catalogs.names[32:]
        assert (
            response.status_code == 200
            and [row["alias"] for row in response.json()["data"]] == expected
        )


async def test_empty_approvals_and_missing_current_policy_fail_closed(
    client: httpx.AsyncClient, catalogs: Catalogs
) -> None:
    store = catalogs.members
    PolicyService(store.operator).set_policy(store.tenant_a, PolicyInput())
    expected: dict[str, object] = {"data": [], "next_cursor": None}
    for target, headers in (
        (url(store.tenant_a), auth(store.token())),
        ("/v1/models", workload_headers(catalogs)),
    ):
        assert (await client.get(target, headers=headers)).json() == expected
    # A current revision without a policy must not fall back to approved history.
    with tenant_transaction(store.operator, TenantContext(store.tenant_b)) as scoped:
        scoped.connection().execute(
            text(
                "UPDATE arbiter.tenants SET policy_revision=3 "
                "WHERE tenant_id=:tenant AND id=:tenant"
            ),
            {"tenant": store.tenant_b},
        )
    assert (
        await client.get("/v1/models", headers=workload_headers(catalogs, "b"))
    ).json() == expected


async def test_scope_contract_permits_inference_only_catalog(
    client: httpx.AsyncClient, catalogs: Catalogs
) -> None:
    # Catalog itself needs a valid key, not usage/inference permission for an operation.
    store = catalogs.members
    async with store.verifier() as verifier:
        created = await KeyService(
            ManagementAccess(verifier, store.runtime),
            KeyIssuer(catalogs.workloads.pepper, 3),
        ).create(
            store.token(subject=store.subject_b),
            store.tenant_b,
            b'{"label":"catalog-inference-only","scopes":["inference:write"]}',
        )
    assert (
        await client.get("/v1/models", headers=auth(created.api_key.get_secret_value()))
    ).status_code == 200
    assert (await client.get("/v1/models", headers=workload_headers(catalogs))).status_code == 200
    assert (
        await client.get("/v1/models", headers=workload_headers(catalogs, "b"))
    ).status_code == 200


async def test_refused_database_errors_are_sanitized(catalogs: Catalogs) -> None:
    with socket.socket() as unused:
        unused.bind(("127.0.0.1", 0))
        engine = create_engine(
            DatabaseSettings().url("runtime").set(host="127.0.0.1", port=unused.getsockname()[1]),
            hide_parameters=True,
            connect_args={"connect_timeout": 1},
        )
        try:
            async with catalogs.members.verifier() as verifier:
                catalog = ModelCatalog(catalogs.cursor)
                app = create_app(
                    model_catalog=catalog,
                    management_models=ManagementModels(ManagementAccess(verifier, engine), catalog),
                    workload_access=WorkloadAccess(
                        KeyVerifier(catalogs.workloads.pepper, 3), engine
                    ),
                )
                async with (
                    app.router.lifespan_context(app),
                    httpx.AsyncClient(
                        transport=httpx.ASGITransport(app=app), base_url="https://arbiter.invalid"
                    ) as http,
                ):
                    assert_error(
                        await http.get("/v1/models", headers=workload_headers(catalogs)),
                        503,
                        "unavailable",
                    )
                    assert_error(
                        await http.get(
                            url(catalogs.members.tenant_a), headers=auth(catalogs.members.token())
                        ),
                        503,
                        "unavailable",
                    )
        finally:
            engine.dispose()
