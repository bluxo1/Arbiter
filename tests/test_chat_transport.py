"""Public chat crosses real admission, dispatch and terminal PostgreSQL/Redis paths."""

import json
import os
from collections.abc import AsyncIterator
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier
from typing import cast
from uuid import uuid4

import httpx
import pytest
from anyio import sleep
from fastapi.testclient import TestClient
from test_provider_binding import DIGEST, bind
from test_provider_binding import binding_store as binding_store
from test_rate_admission import redis_ready as redis_ready
from test_reservation_transactions import ReservationStore

from arbiter.config import RedisSettings
from arbiter.governance.capacity import CapacityGate, CapacityLease
from arbiter.governance.execution import GovernedExecutionService
from arbiter.governance.rate import RateGate
from arbiter.main import create_app
from arbiter.operations.policy import PolicyInput, PolicyService
from arbiter.operations.registry import ModelApproval
from arbiter.persistence.provider_binding import TrustedProviderSelection
from arbiter.providers.double import DeterministicProvider, DoubleMode

pytestmark = pytest.mark.skipif(
    os.environ.get("ARBITER_TEST_DATABASE") != "1"
    or os.environ.get("ARBITER_TEST_MIGRATIONS") != "1"
    or os.environ.get("ARBITER_TEST_REDIS") != "1",
    reason="requires real PostgreSQL, disposable migration database and Redis",
)
pytest_plugins = ("test_migrations",)


def _request(alias: str, content: str = "hello") -> dict[str, object]:
    return {
        "model": alias,
        "messages": [{"role": "user", "content": content}],
    }


def _headers(credential: str, key: str | None = None) -> dict[str, str]:
    return {
        "Authorization": f"Bearer {credential}",
        "Idempotency-Key": key or uuid4().hex,
    }


def _service(
    store: ReservationStore,
    mode: DoubleMode = "success",
    *,
    gate: CapacityGate | None = None,
) -> tuple[GovernedExecutionService, DeterministicProvider, list[str], CapacityGate]:
    provider = DeterministicProvider(store.model, DIGEST, 256, mode=mode)
    names: list[str] = []

    def factory(selection: TrustedProviderSelection) -> DeterministicProvider:
        assert selection.ollama_binding.model_id == store.model
        assert selection.ollama_binding.digest == DIGEST
        names.append(selection.ollama_binding.native_name)
        return provider

    capacity = gate or CapacityGate(2)
    return (
        GovernedExecutionService(
            store.runtime,
            store.verifier,
            store.fingerprint,
            RateGate(RedisSettings()),
            None,
            capacity,
            provider_factory=factory,
        ),
        provider,
        names,
        capacity,
    )


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.mark.anyio
async def test_slow_request_body_times_out_before_governance(
    binding_store: tuple[ReservationStore, ModelApproval],
    redis_ready: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store, proof = binding_store
    bind(store, proof, 1, "fixture:one")
    actor = store.actor()
    service, provider, names, capacity = _service(store)
    initial_counts = store.counts(actor)
    executions = 0

    def unexpected_execution(*_args: object) -> None:
        nonlocal executions
        executions += 1
        raise AssertionError("governance must not run before body completion")

    monkeypatch.setattr(service, "execute", unexpected_execution)
    body = json.dumps(_request(store.alias)).encode()

    async def slow_body() -> AsyncIterator[bytes]:
        yield body[:10]
        await sleep(5.5)
        yield body[10:]

    app = create_app(chat_service=service)
    async with (
        app.router.lifespan_context(app),
        httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="https://arbiter.invalid"
        ) as client,
    ):
        response = await client.post(
            "/v1/chat/completions",
            content=slow_body(),
            headers={
                **_headers(actor.credential.get_secret_value()),
                "Content-Type": "application/json",
            },
        )

    assert response.status_code == 503, response.text
    assert response.json()["error"] == {
        "code": "unavailable",
        "message": "Service unavailable",
    }
    assert executions == 0
    assert store.counts(actor) == initial_counts
    assert provider.calls == () and names == [] and capacity.occupied == 0


@pytest.mark.anyio
async def test_streamed_body_completed_within_bound_executes_normally(
    binding_store: tuple[ReservationStore, ModelApproval], redis_ready: None
) -> None:
    store, proof = binding_store
    bind(store, proof, 1, "fixture:one")
    actor = store.actor()
    service, provider, names, capacity = _service(store)
    body = json.dumps(_request(store.alias)).encode()

    async def prompt_body() -> AsyncIterator[bytes]:
        yield body[:10]
        await sleep(0.05)
        yield body[10:]

    app = create_app(chat_service=service)
    async with (
        app.router.lifespan_context(app),
        httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="https://arbiter.invalid"
        ) as client,
    ):
        response = await client.post(
            "/v1/chat/completions",
            content=prompt_body(),
            headers={
                **_headers(actor.credential.get_secret_value()),
                "Content-Type": "application/json",
            },
        )

    assert response.status_code == 200, response.text
    assert response.json()["message"] == {"role": "assistant", "content": "fixture response"}
    assert len(provider.calls) == 1 and names == ["fixture:one"]
    assert capacity.occupied == 0 and store.totals(actor) == (1, 0, 10, 0)


@pytest.mark.parametrize(
    "body,status,code",
    [
        (b"{" + b"x" * 65536, 413, "body_too_large"),
        (b"{", 422, "invalid_fields"),
    ],
)
def test_body_size_and_malformed_json_mappings_remain_unchanged(
    body: bytes, status: int, code: str
) -> None:
    with TestClient(create_app(chat_service=cast(GovernedExecutionService, object()))) as client:
        response = client.post(
            "/v1/chat/completions",
            content=body,
            headers={**_headers("invalid"), "Content-Type": "application/json"},
        )
    assert response.status_code == status, response.text
    assert response.json()["error"]["code"] == code


def test_governed_chat_success_and_matching_duplicate(
    binding_store: tuple[ReservationStore, ModelApproval], redis_ready: None
) -> None:
    store, proof = binding_store
    assert bind(store, proof, 1, "fixture:one") == 2
    actor = store.actor()
    service, provider, names, capacity = _service(store)
    headers = _headers(actor.credential.get_secret_value())
    with TestClient(create_app(chat_service=service)) as client:
        first = client.post("/v1/chat/completions", json=_request(store.alias), headers=headers)
        assert first.status_code == 200, first.text
        result = first.json()
        assert result["model"] == store.alias
        assert result["message"] == {"role": "assistant", "content": "fixture response"}
        assert result["input_tokens"] == 4 and result["output_tokens"] == 2
        assert result["charged_credits"] == 10
        assert "native_name" not in first.text and "fixture:one" not in first.text
        duplicate = client.post("/v1/chat/completions", json=_request(store.alias), headers=headers)
        assert duplicate.status_code == 409
        replay = duplicate.json()
        assert replay["error"]["code"] == "request_already_admitted"
        assert replay["request_id"] == result["request_id"]
        assert replay["state"] == "succeeded"
        assert replay["status_url"] == f"/v1/requests/{result['request_id']}"
        assert "message" not in replay
        conflict = client.post(
            "/v1/chat/completions", json=_request(store.alias, "different"), headers=headers
        )
        assert conflict.status_code == 409
        assert conflict.json()["error"]["code"] == "idempotency_conflict"
    assert names == ["fixture:one"]
    assert len(provider.calls) == 1 and str(provider.calls[0]) == result["request_id"]
    assert len(provider.deadlines) == 1 and provider.deadlines[0].tzinfo is not None
    assert capacity.occupied == 0
    assert store.totals(actor) == (1, 0, 10, 0)


def test_missing_binding_releases_before_dispatch(
    binding_store: tuple[ReservationStore, ModelApproval], redis_ready: None
) -> None:
    store, _proof = binding_store
    actor = store.actor()
    service, provider, names, capacity = _service(store)
    with TestClient(create_app(chat_service=service)) as client:
        result = client.post(
            "/v1/chat/completions",
            json=_request(store.alias),
            headers=_headers(actor.credential.get_secret_value()),
        )
    assert result.status_code == 503
    assert result.json()["error"]["code"] == "unavailable"
    assert provider.calls == () and names == [] and capacity.occupied == 0
    assert store.totals(actor) == (0, 0, 0, 0)


def test_auth_scope_and_alias_denials_make_no_provider_call(
    binding_store: tuple[ReservationStore, ModelApproval], redis_ready: None
) -> None:
    store, proof = binding_store
    bind(store, proof, 1, "fixture:one")
    actor = store.actor()
    no_scope = store.actor(scopes=("usage:read",))
    service, provider, names, _capacity = _service(store)
    with TestClient(create_app(chat_service=service)) as client:
        cases = (
            (_headers("invalid"), _request(store.alias), 401),
            (_headers(no_scope.credential.get_secret_value()), _request(store.alias), 403),
            (_headers(actor.credential.get_secret_value()), _request("unknown-model"), 403),
            (
                _headers(actor.credential.get_secret_value()),
                {"model": store.alias, "messages": [{"role": "tool", "content": "hi"}]},
                422,
            ),
            (
                _headers(actor.credential.get_secret_value()),
                {"model": store.alias, "messages": [{"role": "user", "content": "x"}] * 33},
                422,
            ),
            (
                _headers(actor.credential.get_secret_value()),
                _request(store.alias, "x" * 32769),
                422,
            ),
        )
        for headers, body, status in cases:
            response = client.post("/v1/chat/completions", json=body, headers=headers)
            assert response.status_code == status, response.text
    assert provider.calls == () and names == []


@pytest.mark.parametrize("denial", ["quota", "budget", "rate", "capacity"])
def test_admission_denials_make_no_provider_call(
    binding_store: tuple[ReservationStore, ModelApproval],
    redis_ready: None,
    denial: str,
) -> None:
    store, proof = binding_store
    bind(store, proof, 1, "fixture:one")
    actor = store.actor(
        quota=0 if denial == "quota" else 1000, budget=0 if denial == "budget" else 10000
    )
    if denial == "rate":
        PolicyService(store.operator).set_policy(
            actor.tenant, PolicyInput(tenant_rate=0, aliases=(store.alias,))
        )
    service, provider, names, capacity = _service(
        store, gate=CapacityGate(0) if denial == "capacity" else None
    )
    with TestClient(create_app(chat_service=service)) as client:
        response = client.post(
            "/v1/chat/completions",
            json=_request(store.alias),
            headers=_headers(actor.credential.get_secret_value()),
        )
    assert response.status_code == (503 if denial == "capacity" else 429), response.text
    assert provider.calls == () and names == [] and capacity.occupied == 0


def test_binding_update_before_authorization_rejects_old_reservation(
    binding_store: tuple[ReservationStore, ModelApproval],
    redis_ready: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store, proof = binding_store
    bind(store, proof, 1, "fixture:one")
    actor = store.actor()
    service, provider, names, capacity = _service(store)
    authorize = service._dispatch.authorize

    def update_then_authorize(lease: CapacityLease) -> object:
        bind(store, proof, 2, "fixture:two")
        return authorize(lease)

    monkeypatch.setattr(service._dispatch, "authorize", update_then_authorize)
    with TestClient(create_app(chat_service=service)) as client:
        response = client.post(
            "/v1/chat/completions",
            json=_request(store.alias),
            headers=_headers(actor.credential.get_secret_value()),
        )
    assert response.status_code == 409, response.text
    assert response.json()["error"]["code"] == "authorization_changed"
    assert provider.calls == () and names == [] and capacity.occupied == 0
    assert store.totals(actor) == (0, 0, 0, 0)


def test_binding_update_after_authorization_keeps_captured_tag(
    binding_store: tuple[ReservationStore, ModelApproval], redis_ready: None
) -> None:
    store, proof = binding_store
    bind(store, proof, 1, "fixture:one")
    actor = store.actor()
    provider = DeterministicProvider(store.model, DIGEST, 256)
    selected_tags: list[str] = []

    def factory(selection: TrustedProviderSelection) -> DeterministicProvider:
        selected_tags.append(selection.ollama_binding.native_name)
        bind(store, proof, 2, "fixture:two")
        return provider

    capacity = CapacityGate(1)
    service = GovernedExecutionService(
        store.runtime,
        store.verifier,
        store.fingerprint,
        RateGate(RedisSettings()),
        None,
        capacity,
        provider_factory=factory,
    )
    with TestClient(create_app(chat_service=service)) as client:
        response = client.post(
            "/v1/chat/completions",
            json=_request(store.alias),
            headers=_headers(actor.credential.get_secret_value()),
        )
    assert response.status_code == 200, response.text
    assert selected_tags == ["fixture:one"] and len(provider.calls) == 1
    assert capacity.occupied == 0


@pytest.mark.parametrize(
    "field,value",
    [
        ("stream", True),
        ("native_name", "fixture:one"),
        ("base_url", "http://example.invalid"),
        ("options", {"temperature": 1}),
        ("tools", []),
        ("fallback", "other"),
        ("timeout", 999),
    ],
)
def test_public_provider_controls_reject_before_governance(field: str, value: object) -> None:
    content = _request("fixture")
    content[field] = value
    with TestClient(create_app(chat_service=cast(GovernedExecutionService, object()))) as client:
        result = client.post(
            "/v1/chat/completions",
            json=content,
            headers=_headers("invalid"),
        )
    assert result.status_code == 422
    assert result.json()["error"]["code"] == "invalid_fields"


def test_chat_requires_bearer_and_idempotency_header() -> None:
    with TestClient(create_app(chat_service=cast(GovernedExecutionService, object()))) as client:
        assert client.post("/v1/chat/completions", json=_request("fixture")).status_code == 401
        result = client.post(
            "/v1/chat/completions",
            json=_request("fixture"),
            headers={"Authorization": "Bearer fixture"},
        )
    assert result.status_code == 422


@pytest.mark.parametrize(
    "mode,status",
    [
        ("definite_failure", 502),
        ("deadline", 504),
        ("malformed", 502),
        ("oversized", 502),
        ("unknown_model", 502),
        ("ambiguous", 503),
        ("unavailable", 503),
    ],
)
def test_provider_outcomes_keep_durable_state(
    binding_store: tuple[ReservationStore, ModelApproval],
    redis_ready: None,
    mode: DoubleMode,
    status: int,
) -> None:
    store, proof = binding_store
    bind(store, proof, 1, "fixture:one")
    actor = store.actor()
    service, provider, names, capacity = _service(store, mode)
    with TestClient(create_app(chat_service=service)) as client:
        result = client.post(
            "/v1/chat/completions",
            json=_request(store.alias),
            headers=_headers(actor.credential.get_secret_value()),
        )
    assert result.status_code == status, result.text
    if mode == "deadline":
        assert result.json()["error"] == {
            "code": "provider_deadline",
            "message": "Provider deadline exceeded",
        }
    assert len(provider.calls) == 1 and names == ["fixture:one"]
    if mode in {"definite_failure", "unknown_model"}:
        assert capacity.occupied == 0 and store.totals(actor) == (1, 0, 10, 0)
    else:
        assert capacity.occupied == 1 and not capacity.ready
        assert store.totals(actor) == (1, 0, 10, 0)


def test_concurrent_matching_requests_have_single_dispatch(
    binding_store: tuple[ReservationStore, ModelApproval], redis_ready: None
) -> None:
    store, proof = binding_store
    bind(store, proof, 1, "fixture:one")
    actor = store.actor()
    service, provider, names, capacity = _service(store)
    headers = _headers(actor.credential.get_secret_value())
    barrier = Barrier(4)
    with TestClient(create_app(chat_service=service)) as client:

        def send() -> int:
            barrier.wait(timeout=10)
            response = client.post(
                "/v1/chat/completions", json=_request(store.alias), headers=headers
            )
            return int(response.status_code)

        with ThreadPoolExecutor(max_workers=4) as pool:
            assert sorted(pool.map(lambda _: send(), range(4))) == [200, 409, 409, 409]
    assert len(provider.calls) == 1 and names == ["fixture:one"]
    assert capacity.occupied == 0 and store.totals(actor) == (1, 0, 10, 0)
