"""Implementation-independent contract for one governed, non-streaming provider call.

Wire-format and HTTP transport checks belong to the later Ollama adapter slice.
"""

from collections.abc import Callable
from dataclasses import fields
from datetime import UTC, datetime, timedelta
from typing import Literal, Protocol
from uuid import UUID, uuid4

import pytest

from arbiter.governance.fingerprint import Message
from arbiter.providers.double import DeterministicProvider
from arbiter.providers.port import (
    ProviderAmbiguous,
    ProviderCapabilities,
    ProviderDeadline,
    ProviderMalformed,
    ProviderModelUnavailable,
    ProviderOversizedResponse,
    ProviderPort,
    ProviderRejectedInput,
    ProviderRequest,
    ProviderResult,
    ProviderUnavailable,
)

Scenario = Literal[
    "success", "unavailable", "deadline", "malformed", "oversized", "unknown_model", "ambiguous"
]
DIGEST = "sha256:" + "d" * 64


class ObservedProvider(ProviderPort, Protocol):
    @property
    def calls(self) -> tuple[UUID, ...]: ...

    @property
    def deadlines(self) -> tuple[datetime, ...]: ...


class ScriptedProvider:
    """An independent table-driven implementation, with no double inheritance."""

    def __init__(self, model_id: UUID, digest: str, cap: int, scenario: Scenario) -> None:
        self.model_id, self.digest, self.cap, self.scenario = model_id, digest, cap, scenario
        self._calls: list[UUID] = []
        self._deadlines: list[datetime] = []

    @property
    def calls(self) -> tuple[UUID, ...]:
        return tuple(self._calls)

    @property
    def deadlines(self) -> tuple[datetime, ...]:
        return tuple(self._deadlines)

    def capabilities(self) -> ProviderCapabilities:
        return ProviderCapabilities(self.scenario != "unavailable", (self.model_id,), self.cap)

    def validate(self, request: ProviderRequest) -> None:
        if request.model_id != self.model_id or request.model_digest != self.digest:
            raise ProviderModelUnavailable()
        if request.max_output_tokens > self.cap:
            raise ProviderRejectedInput()

    def generate(self, request: ProviderRequest, deadline: datetime) -> ProviderResult:
        self._calls.append(request.correlation)
        self._deadlines.append(deadline)
        if deadline.tzinfo is None or deadline <= datetime.now(UTC):
            raise ProviderDeadline()
        failures = {
            "unavailable": ProviderUnavailable,
            "deadline": ProviderDeadline,
            "malformed": ProviderMalformed,
            "oversized": ProviderOversizedResponse,
            "unknown_model": ProviderModelUnavailable,
            "ambiguous": ProviderAmbiguous,
        }
        if failure := failures.get(self.scenario):
            raise failure()
        return ProviderResult("fixture response", 4, 2, "stop")


@pytest.fixture(params=["double", "scripted"])
def provider_factory(
    request: pytest.FixtureRequest,
) -> Callable[[UUID, Scenario], ObservedProvider]:
    if request.param == "double":
        return lambda model, scenario: DeterministicProvider(model, DIGEST, 256, mode=scenario)
    return lambda model, scenario: ScriptedProvider(model, DIGEST, 256, scenario)


def _request(model: UUID) -> ProviderRequest:
    return ProviderRequest(model, DIGEST, uuid4(), (Message("user", "private fixture"),), 128)


def _assert_no_calls(provider: ObservedProvider) -> None:
    assert provider.calls == ()


def test_request_surface_is_closed() -> None:
    assert {field.name for field in fields(ProviderRequest)} == {
        "model_id",
        "model_digest",
        "correlation",
        "messages",
        "max_output_tokens",
    }
    assert "private fixture" not in repr(_request(uuid4()))


@pytest.mark.parametrize(
    "messages,cap",
    [
        ((), 128),
        ((Message("user", "x"),) * 33, 128),
        ((Message("user", "x" * 32769),), 128),
        ((Message("user", "x"),), 0),
        ((Message("user", "x"),), 1025),
    ],
)
def test_provider_request_rejects_unbounded_content(
    messages: tuple[Message, ...], cap: int
) -> None:
    with pytest.raises(ProviderRejectedInput):
        ProviderRequest(uuid4(), DIGEST, uuid4(), messages, cap)


def test_provider_request_rejects_unpinned_model_reference() -> None:
    with pytest.raises(ProviderRejectedInput):
        ProviderRequest(uuid4(), "native-model-name", uuid4(), (Message("user", "x"),), 128)


def test_success_mapping_and_one_call(
    provider_factory: Callable[[UUID, Scenario], ObservedProvider],
) -> None:
    model = uuid4()
    provider = provider_factory(model, "success")
    request = _request(model)
    deadline = datetime.now(UTC) + timedelta(seconds=120)
    assert isinstance(provider, ProviderPort)
    assert provider.capabilities().model_ids == (model,)
    assert provider.capabilities().output_cap == 256
    provider.validate(request)
    _assert_no_calls(provider)
    result = provider.generate(request, deadline)
    assert result == ProviderResult("fixture response", 4, 2, "stop")
    assert provider.calls == (request.correlation,)
    assert provider.deadlines == (deadline,)
    assert "private fixture" not in repr(result)


def test_expired_deadline_is_classified_without_retry(
    provider_factory: Callable[[UUID, Scenario], ObservedProvider],
) -> None:
    model = uuid4()
    provider = provider_factory(model, "success")
    request = _request(model)
    deadline = datetime.now(UTC) - timedelta(seconds=1)
    with pytest.raises(ProviderDeadline):
        provider.generate(request, deadline)
    assert provider.calls == (request.correlation,)
    assert provider.deadlines == (deadline,)


def test_model_and_cap_rejection_never_generate(
    provider_factory: Callable[[UUID, Scenario], ObservedProvider],
) -> None:
    model = uuid4()
    provider = provider_factory(model, "success")
    request = _request(model)
    with pytest.raises(ProviderModelUnavailable):
        provider.validate(
            ProviderRequest(uuid4(), DIGEST, request.correlation, request.messages, 128)
        )
    with pytest.raises(ProviderModelUnavailable):
        provider.validate(
            ProviderRequest(model, "sha256:" + "e" * 64, request.correlation, request.messages, 128)
        )
    with pytest.raises(ProviderRejectedInput):
        provider.validate(
            ProviderRequest(model, DIGEST, request.correlation, request.messages, 257)
        )
    assert provider.calls == ()


@pytest.mark.parametrize(
    "scenario,error",
    [
        ("unavailable", ProviderUnavailable),
        ("deadline", ProviderDeadline),
        ("malformed", ProviderMalformed),
        ("oversized", ProviderOversizedResponse),
        ("unknown_model", ProviderModelUnavailable),
        ("ambiguous", ProviderAmbiguous),
    ],
)
def test_classified_failure_is_one_call(
    provider_factory: Callable[[UUID, Scenario], ObservedProvider],
    scenario: Scenario,
    error: type[Exception],
) -> None:
    model = uuid4()
    provider = provider_factory(model, scenario)
    request = _request(model)
    deadline = datetime.now(UTC) + timedelta(seconds=120)
    provider.validate(request)
    with pytest.raises(error):
        provider.generate(request, deadline)
    assert provider.calls == (request.correlation,)
    assert provider.deadlines == (deadline,)
