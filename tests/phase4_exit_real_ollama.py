"""Explicit Phase 4 exit proof against the already installed local Ollama model.

Run this file by path with the real PostgreSQL, Redis and Ollama test stack.
It is intentionally outside default test discovery because it requires the
operator-approved model and local provider service to be available.
"""

from datetime import datetime
from uuid import UUID, uuid4

import pytest
from fastapi.testclient import TestClient
from phase3_exit_support import receipts
from sqlalchemy import text
from test_provider_binding import binding_store as binding_store
from test_rate_admission import redis_ready as redis_ready
from test_registry_input import approval_values
from test_reservation_transactions import ReservationStore

from arbiter.config import RedisSettings
from arbiter.governance.capacity import CapacityGate
from arbiter.governance.execution import GovernedExecutionService
from arbiter.governance.rate import RateGate
from arbiter.identity.context import TenantContext
from arbiter.main import create_app
from arbiter.operations.registry import (
    ModelApproval,
    ModelInput,
    NativeBindingInput,
    RegistryService,
)
from arbiter.persistence.tenant import tenant_transaction
from arbiter.providers.ollama import OllamaProvider
from arbiter.providers.port import ProviderRequest, ProviderResult

pytest_plugins = ("test_migrations",)

NATIVE_NAME = "qwen3:4b-instruct-2507-q4_K_M"
MODEL_DIGEST = "sha256:0edcdef34593eac1aa2be9c7d06c432dcf81945adca5eca2f27662c18f168ba0"


def test_real_ollama_governed_chat_exit(
    binding_store: tuple[ReservationStore, ModelApproval],
    redis_ready: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store, _fixture_approval = binding_store
    approval = ModelApproval.model_validate({**approval_values(), "model_digest": MODEL_DIGEST})
    registry = RegistryService(store.operator)
    updated = registry.provision(
        ModelInput(store.alias, "ollama", MODEL_DIGEST, 512, 16, 10, True),
        approval,
        expected_revision=1,
    )
    assert updated.model_id == store.model and updated.revision == 2
    bound = registry.bind_native_model(
        NativeBindingInput(store.model, 2, "ollama", NATIVE_NAME), approval
    )
    assert bound.model_id == store.model and bound.revision == 3

    denied_actor = store.actor(quota=0)
    admitted_actor = store.actor()
    capacity = CapacityGate(1)
    service = GovernedExecutionService(
        store.runtime,
        store.verifier,
        store.fingerprint,
        RateGate(RedisSettings()),
        None,
        capacity,
    )
    generation_calls: list[UUID] = []
    generate = OllamaProvider.generate

    def counted_generate(
        provider: OllamaProvider, request: ProviderRequest, deadline: datetime
    ) -> ProviderResult:
        generation_calls.append(request.correlation)
        assert request.model_id == store.model and request.model_digest == MODEL_DIGEST
        assert provider._binding.native_name == NATIVE_NAME
        assert capacity.occupied == 1
        with tenant_transaction(store.runtime, TenantContext(admitted_actor.tenant)) as tx:
            state: str = (
                tx.connection()
                .execute(
                    text("""
                    SELECT state FROM arbiter.requests
                    WHERE tenant_id=:tenant AND id=:request
                """),
                    {"tenant": admitted_actor.tenant, "request": request.correlation},
                )
                .scalar_one()
            )
            captured = (
                tx.connection()
                .execute(
                    text("""
                    SELECT model_id,model_digest,model_revision,provider_kind,native_name
                    FROM arbiter.dispatched_provider_binding(:tenant,:key,:request)
                """),
                    {
                        "tenant": admitted_actor.tenant,
                        "key": admitted_actor.key,
                        "request": request.correlation,
                    },
                )
                .one()
            )
        assert state == "dispatched"
        assert tuple(captured) == (store.model, MODEL_DIGEST, 3, "ollama", NATIVE_NAME)
        return generate(provider, request, deadline)

    monkeypatch.setattr(OllamaProvider, "generate", counted_generate)
    body = {
        "model": store.alias,
        "messages": [{"role": "user", "content": "Reply with OK."}],
        "max_output_tokens": 8,
    }
    with TestClient(create_app(chat_service=service)) as client:
        denied = client.post(
            "/v1/chat/completions",
            json=body,
            headers={
                "Authorization": f"Bearer {denied_actor.credential.get_secret_value()}",
                "Idempotency-Key": uuid4().hex,
            },
        )
        assert denied.status_code == 429, denied.text
        assert generation_calls == [] and receipts(store, denied_actor) == ()
        assert capacity.occupied == 0

        headers = {
            "Authorization": f"Bearer {admitted_actor.credential.get_secret_value()}",
            "Idempotency-Key": uuid4().hex,
        }
        succeeded = client.post("/v1/chat/completions", json=body, headers=headers)
        assert succeeded.status_code == 200, succeeded.text
        result = succeeded.json()
        assert result["model"] == store.alias
        assert result["message"]["role"] == "assistant"
        assert isinstance(result["message"]["content"], str)
        assert result["message"]["content"].strip()
        assert isinstance(result["input_tokens"], int) and result["input_tokens"] > 0
        assert isinstance(result["output_tokens"], int)
        assert 0 <= result["output_tokens"] <= 8
        assert result["charged_credits"] == 10
        assert NATIVE_NAME not in succeeded.text and MODEL_DIGEST not in succeeded.text
        assert generation_calls == [UUID(result["request_id"])]

        duplicate = client.post("/v1/chat/completions", json=body, headers=headers)
        assert duplicate.status_code == 409, duplicate.text
        assert duplicate.json()["error"]["code"] == "request_already_admitted"
        assert duplicate.json()["request_id"] == result["request_id"]
        assert generation_calls == [UUID(result["request_id"])]

    (receipt,) = receipts(store, admitted_actor)
    assert receipt.request_id == UUID(result["request_id"])
    assert receipt.state == "succeeded"
    assert receipt.reserve_events == receipt.commit_events == 1
    assert receipt.dispatch_audits == receipt.terminal_audits == 1
    assert store.totals(admitted_actor) == (1, 0, 10, 0)
    assert capacity.occupied == 0
