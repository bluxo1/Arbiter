"""Implementation-independent contract for one governed, non-streaming provider call."""

from collections.abc import AsyncIterator, Callable
from dataclasses import fields
from datetime import UTC, datetime, timedelta
from typing import Literal, Protocol
from uuid import UUID, uuid4

import httpx
import pytest

from arbiter.governance.fingerprint import Message
from arbiter.providers.double import DeterministicProvider
from arbiter.providers.ollama import OllamaModelBinding, OllamaProvider
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


class ResponseStream(httpx.AsyncByteStream):
    def __init__(self, body: bytes) -> None:
        self.body = body

    async def __aiter__(self) -> AsyncIterator[bytes]:
        yield self.body


def streamed_response(status: int, body: bytes) -> httpx.Response:
    return httpx.Response(
        status, headers={"content-type": "application/json"}, stream=ResponseStream(body)
    )


class ObservedOllamaProvider:
    def __init__(self, model_id: UUID, scenario: Scenario) -> None:
        self._calls: list[UUID] = []
        self._deadlines: list[datetime] = []
        self.http_calls: list[httpx.Request] = []

        def respond(request: httpx.Request) -> httpx.Response:
            self.http_calls.append(request)
            if request.url.path == "/api/tags":
                return streamed_response(
                    200,
                    b'{"models":[{"name":"fixture:1","digest":"' + DIGEST[7:].encode() + b'"}]}',
                )
            if scenario == "unavailable":
                raise httpx.ConnectError("unavailable", request=request)
            if scenario == "deadline":
                raise httpx.ReadTimeout("timeout", request=request)
            if scenario == "malformed":
                return streamed_response(200, b"not json")
            if scenario == "oversized":
                return streamed_response(200, b"x" * (1024 * 1024 + 1))
            if scenario == "unknown_model":
                return streamed_response(404, b'{"error":"model \'fixture:1\' not found"}')
            if scenario == "ambiguous":
                return streamed_response(503, b'{"error":"server failure"}')
            return streamed_response(
                200,
                b'{"model":"fixture:1","message":{"role":"assistant",'
                b'"content":"fixture response"},"done":true,"done_reason":"stop",'
                b'"prompt_eval_count":4,"eval_count":2}',
            )

        self._provider = OllamaProvider(
            OllamaModelBinding(model_id, DIGEST, "fixture:1", 4096, 256),
            transport=httpx.MockTransport(respond),
        )

    @property
    def calls(self) -> tuple[UUID, ...]:
        return tuple(self._calls)

    @property
    def deadlines(self) -> tuple[datetime, ...]:
        return tuple(self._deadlines)

    def capabilities(self) -> ProviderCapabilities:
        return self._provider.capabilities()

    def validate(self, request: ProviderRequest) -> None:
        self._provider.validate(request)

    def generate(self, request: ProviderRequest, deadline: datetime) -> ProviderResult:
        self._calls.append(request.correlation)
        self._deadlines.append(deadline)
        return self._provider.generate(request, deadline)


@pytest.fixture(params=["double", "scripted", "ollama"])
def provider_factory(
    request: pytest.FixtureRequest,
) -> Callable[[UUID, Scenario], ObservedProvider]:
    if request.param == "double":
        return lambda model, scenario: DeterministicProvider(model, DIGEST, 256, mode=scenario)
    if request.param == "scripted":
        return lambda model, scenario: ScriptedProvider(model, DIGEST, 256, scenario)
    return lambda model, scenario: ObservedOllamaProvider(model, scenario)


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
