"""Counted, in-process HTTP transport tests for the local Ollama adapter."""

import json
from collections.abc import AsyncIterator, Callable
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import uuid4

import httpx
import pytest
from pydantic import ValidationError

from arbiter.config import OllamaSettings
from arbiter.governance.fingerprint import Message
from arbiter.providers.ollama import OllamaModelBinding, OllamaProvider
from arbiter.providers.port import (
    ProviderAmbiguous,
    ProviderDeadline,
    ProviderMalformed,
    ProviderModelUnavailable,
    ProviderOversizedResponse,
    ProviderRejectedInput,
    ProviderRequest,
    ProviderResult,
    ProviderUnavailable,
)

DIGEST = "sha256:" + "a" * 64
NAME = "fixture:1"
LIMIT = 1024 * 1024


class Chunks(httpx.AsyncByteStream):
    def __init__(self, body: bytes) -> None:
        self.body = body
        self.read = 0

    async def __aiter__(self) -> AsyncIterator[bytes]:
        for start in range(0, len(self.body), 8192):
            chunk = self.body[start : start + 8192]
            self.read += len(chunk)
            yield chunk


def response(
    status: int, body: bytes, *, content_type: str | None = "application/json", **headers: str
) -> httpx.Response:
    if content_type is not None:
        headers.setdefault("content-type", content_type)
    return httpx.Response(status, headers=headers, stream=Chunks(body))


def success(**changes: Any) -> bytes:
    data: dict[str, Any] = {
        "model": NAME,
        "message": {"role": "assistant", "content": "fixture response"},
        "done": True,
        "done_reason": "stop",
        "prompt_eval_count": 4,
        "eval_count": 2,
    }
    data.update(changes)
    return json.dumps(data, separators=(",", ":")).encode()


class FakeOllama:
    def __init__(self, chat: Callable[[httpx.Request], httpx.Response]) -> None:
        self.calls: list[httpx.Request] = []
        self.chat = chat

    def handle(self, request: httpx.Request) -> httpx.Response:
        self.calls.append(request)
        assert request.url.scheme == "http"
        assert request.url.host == "ollama"
        assert request.url.port == 11434
        if request.method == "GET" and request.url.path == "/api/tags":
            return response(
                200, json.dumps({"models": [{"name": NAME, "digest": DIGEST[7:]}]}).encode()
            )
        assert request.method == "POST" and request.url.path == "/api/chat"
        return self.chat(request)

    @property
    def generation_calls(self) -> list[httpx.Request]:
        return [call for call in self.calls if call.method == "POST"]


@pytest.fixture
def setup() -> Callable[
    [Callable[[httpx.Request], httpx.Response]], tuple[OllamaProvider, ProviderRequest, FakeOllama]
]:
    def build(
        chat: Callable[[httpx.Request], httpx.Response],
    ) -> tuple[OllamaProvider, ProviderRequest, FakeOllama]:
        model_id = uuid4()
        fake = FakeOllama(chat)
        provider = OllamaProvider(
            OllamaModelBinding(model_id, DIGEST, NAME, 4096, 256),
            transport=httpx.MockTransport(fake.handle),
        )
        request = ProviderRequest(
            model_id,
            DIGEST,
            uuid4(),
            (Message("system", "private system"), Message("user", "private user")),
            128,
        )
        return provider, request, fake

    return build


def future() -> datetime:
    return datetime.now(UTC) + timedelta(seconds=120)


def test_exact_single_chat_request_and_mapping(setup: Any) -> None:
    provider, request, fake = setup(lambda _: response(200, success()))
    assert provider.capabilities().healthy
    provider.validate(request)
    assert fake.generation_calls == []
    assert provider.generate(request, future()) == ProviderResult("fixture response", 4, 2, "stop")
    assert len(fake.generation_calls) == 1
    sent = fake.generation_calls[0]
    assert json.loads(sent.content) == {
        "model": NAME,
        "messages": [
            {"role": "system", "content": "private system"},
            {"role": "user", "content": "private user"},
        ],
        "stream": False,
        "think": False,
        "truncate": False,
        "options": {"num_ctx": 4096, "num_predict": 128},
    }
    assert len(sent.content) <= 65536
    assert sent.headers["accept-encoding"] == "identity"
    assert {call.url.path for call in fake.calls} <= {"/api/tags", "/api/chat"}


@pytest.mark.parametrize("content_type", ["application/json", "application/json; charset=utf-8"])
def test_nonstreaming_json_media_type_succeeds(setup: Any, content_type: str) -> None:
    provider, request, fake = setup(lambda _: response(200, success(), content_type=content_type))
    assert provider.generate(request, future()) == ProviderResult("fixture response", 4, 2, "stop")
    assert len(fake.generation_calls) == 1


@pytest.mark.parametrize(
    "content_type", ["application/x-ndjson", "text/event-stream", "text/plain", None]
)
def test_non_json_media_type_rejects_valid_looking_completion(
    setup: Any, content_type: str | None
) -> None:
    # A single terminal NDJSON event is also valid JSON text; the media type
    # must prevent it from being treated as a non-streaming completion.
    body = success() + b"\n"
    provider, request, fake = setup(lambda _: response(200, body, content_type=content_type))
    with pytest.raises(ProviderMalformed):
        provider.generate(request, future())
    assert len(fake.generation_calls) == 1


@pytest.mark.parametrize(
    "header_fields",
    [
        [("Content-Type", "application/json, application/x-ndjson")],
        [("Content-Type", "application/json; charset=utf-8, application/x-ndjson")],
        [
            ("Content-Type", "application/json"),
            ("Content-Type", "application/x-ndjson"),
        ],
        [
            ("Content-Type", "application/x-ndjson"),
            ("Content-Type", "application/json"),
        ],
        [("Content-Type", "application/json"), ("Content-Type", "application/json")],
    ],
)
def test_ambiguous_content_type_rejects_terminal_ndjson(
    setup: Any, header_fields: list[tuple[str, str]]
) -> None:
    wire_response = httpx.Response(200, headers=header_fields, stream=Chunks(success() + b"\n"))
    assert wire_response.headers.get_list("content-type") == [value for _, value in header_fields]
    assert wire_response.headers["content-type"] == ", ".join(value for _, value in header_fields)
    provider, request, fake = setup(lambda _: wire_response)
    with pytest.raises(ProviderMalformed):
        provider.generate(request, future())
    assert len(fake.generation_calls) == 1


def test_expired_deadline_has_no_http_request(setup: Any) -> None:
    provider, request, fake = setup(lambda _: response(200, success()))
    with pytest.raises(ProviderDeadline):
        provider.generate(request, datetime.now(UTC) - timedelta(seconds=1))
    assert fake.calls == []


def test_serialized_request_bound_rejects_escaped_expansion_before_http(setup: Any) -> None:
    provider, request, fake = setup(lambda _: response(200, success()))
    expanded = ProviderRequest(
        request.model_id,
        request.model_digest,
        request.correlation,
        (Message("user", "\x00" * 32768),),
        128,
    )
    with pytest.raises(ProviderRejectedInput):
        provider.generate(expanded, future())
    assert fake.calls == []


@pytest.mark.parametrize(
    "chat,error",
    [
        (
            lambda r: (_ for _ in ()).throw(httpx.ConnectError("refused", request=r)),
            ProviderUnavailable,
        ),
        (lambda r: (_ for _ in ()).throw(httpx.ReadTimeout("late", request=r)), ProviderDeadline),
        (
            lambda r: (_ for _ in ()).throw(httpx.RemoteProtocolError("lost", request=r)),
            ProviderAmbiguous,
        ),
        (lambda _: response(503, b'{"error":"server failure"}'), ProviderAmbiguous),
        (
            lambda _: response(404, b'{"error":"model \'fixture:1\' not found"}'),
            ProviderModelUnavailable,
        ),
        (lambda _: response(404, b"not json"), ProviderAmbiguous),
        (lambda _: response(404, b'{"error":"resource not found"}'), ProviderAmbiguous),
        (
            lambda _: response(404, b'{"error":"model \'fixture:1\' not found "}'),
            ProviderAmbiguous,
        ),
        (lambda _: response(302, b"", location="https://evil.invalid/chat"), ProviderAmbiguous),
    ],
)
def test_transport_status_and_no_retry(setup: Any, chat: Any, error: type[Exception]) -> None:
    provider, request, fake = setup(chat)
    with pytest.raises(error):
        provider.generate(request, future())
    assert len(fake.generation_calls) == 1


def test_absolute_deadline_during_response(setup: Any) -> None:
    class Slow(httpx.AsyncByteStream):
        async def __aiter__(self) -> AsyncIterator[bytes]:
            import asyncio

            await asyncio.sleep(0.1)
            yield success()

    provider, request, fake = setup(
        lambda _: httpx.Response(200, stream=Slow(), headers={"content-type": "application/json"})
    )
    with pytest.raises(ProviderDeadline):
        provider.generate(request, datetime.now(UTC) + timedelta(milliseconds=10))
    assert len(fake.generation_calls) == 1


@pytest.mark.parametrize(
    "body",
    [
        b"not json",
        b"\xff",
        b"{}\n{}",
        b'{"done":true,"done":false}',
        b'{"model":"fixture:1","done":true,"done_reason":"stop"}',
        b'{"model":"fixture:1","message":{"role":"assistant","content":"ok"},"done":true}',
        b'{"model":"fixture:1","message":{"role":"assistant","content":"\\ud800"},"done":true,"done_reason":"stop"}',
        b'{"model":"fixture:1","message":{"role":"assistant","content":"ok"},"done":true,"done_reason":NaN}',
        success(message={"role": "assistant"}),
        success(message={"role": "user", "content": "wrong"}),
        success(message={"role": "assistant", "content": 2}),
        success(message={"role": "assistant", "content": "x", "tool_calls": []}),
        success(message={"role": "assistant", "content": "x", "thinking": "private"}),
        success(model="other:1"),
        success(done=False),
        success(done_reason="unload"),
        success(done_reason=[]),
        success(prompt_eval_count=-1),
        success(eval_count=True),
        success(eval_count=1.5),
        success(eval_count=2**64),
        success(eval_count=129),
    ],
)
def test_malformed_response_is_unknown_capable(setup: Any, body: bytes) -> None:
    provider, request, fake = setup(lambda _: response(200, body))
    with pytest.raises(ProviderMalformed):
        provider.generate(request, future())
    assert len(fake.generation_calls) == 1


def test_missing_usage_stays_none_and_length_reason_maps(setup: Any) -> None:
    data = json.loads(success())
    del data["prompt_eval_count"], data["eval_count"]
    data["done_reason"] = "length"
    provider, request, _ = setup(lambda _: response(200, json.dumps(data).encode()))
    assert provider.generate(request, future()) == ProviderResult(
        "fixture response", None, None, "length"
    )


@pytest.mark.parametrize("size,oversize", [(LIMIT - 1, False), (LIMIT, False), (LIMIT + 1, True)])
def test_wire_response_byte_limit(setup: Any, size: int, oversize: bool) -> None:
    base = success()
    body = base + b" " * (size - len(base))
    provider, request, fake = setup(lambda _: response(200, body))
    if oversize:
        with pytest.raises(ProviderOversizedResponse):
            provider.generate(request, future())
    else:
        assert provider.generate(request, future()).assistant_text == "fixture response"
    assert len(fake.generation_calls) == 1


def test_content_length_and_compression_rejected_before_body_read(setup: Any) -> None:
    stream = Chunks(b"x" * 64)
    provider, request, _ = setup(
        lambda _: httpx.Response(
            200,
            stream=stream,
            headers={"content-length": str(LIMIT + 1), "content-type": "application/json"},
        )
    )
    with pytest.raises(ProviderOversizedResponse):
        provider.generate(request, future())
    assert stream.read == 0
    provider, request, _ = setup(lambda _: response(200, success(), **{"content-encoding": "gzip"}))
    with pytest.raises(ProviderMalformed):
        provider.generate(request, future())


def test_validation_and_capabilities_never_generate(setup: Any) -> None:
    provider, request, fake = setup(lambda _: response(200, success()))
    assert provider.capabilities().model_ids == (request.model_id,)
    provider.validate(request)
    assert [call.method for call in fake.calls] == ["GET", "GET"]


def test_unavailable_or_wrong_digest_model_never_generates(setup: Any) -> None:
    provider, request, fake = setup(lambda _: response(200, success()))
    with pytest.raises(ProviderModelUnavailable):
        provider.validate(
            ProviderRequest(uuid4(), DIGEST, request.correlation, request.messages, 128)
        )
    with pytest.raises(ProviderModelUnavailable):
        provider.validate(
            ProviderRequest(
                request.model_id, "sha256:" + "b" * 64, request.correlation, request.messages, 128
            )
        )
    with pytest.raises(ProviderRejectedInput):
        provider.validate(
            ProviderRequest(request.model_id, DIGEST, request.correlation, request.messages, 257)
        )
    assert fake.calls == []


@pytest.mark.parametrize("models", [[], [{"name": NAME, "digest": "b" * 64}]])
def test_local_model_absence_or_digest_mismatch_never_generates(models: list[Any]) -> None:
    calls: list[httpx.Request] = []

    def handle(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        assert request.method == "GET" and request.url.path == "/api/tags"
        return response(200, json.dumps({"models": models}).encode())

    model_id = uuid4()
    provider = OllamaProvider(
        OllamaModelBinding(model_id, DIGEST, NAME, 4096, 256),
        transport=httpx.MockTransport(handle),
    )
    request = ProviderRequest(model_id, DIGEST, uuid4(), (Message("user", "x"),), 128)
    assert provider.capabilities().model_ids == ()
    with pytest.raises(ProviderModelUnavailable):
        provider.validate(request)
    assert len(calls) == 2


def test_oversized_validation_metadata_fails_closed_without_generation() -> None:
    calls: list[httpx.Request] = []

    def handle(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        assert request.method == "GET" and request.url.path == "/api/tags"
        return response(200, b"x" * (LIMIT + 1))

    model_id = uuid4()
    provider = OllamaProvider(
        OllamaModelBinding(model_id, DIGEST, NAME, 4096, 256),
        transport=httpx.MockTransport(handle),
    )
    request = ProviderRequest(model_id, DIGEST, uuid4(), (Message("user", "x"),), 128)
    with pytest.raises(ProviderUnavailable):
        provider.validate(request)
    assert len(calls) == 1


def test_malformed_local_model_metadata_fails_closed_without_generation() -> None:
    calls: list[httpx.Request] = []

    def handle(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        assert request.method == "GET" and request.url.path == "/api/tags"
        return response(200, json.dumps({"models": [{"name": NAME, "digest": {}}]}).encode())

    model_id = uuid4()
    provider = OllamaProvider(
        OllamaModelBinding(model_id, DIGEST, NAME, 4096, 256),
        transport=httpx.MockTransport(handle),
    )
    request = ProviderRequest(model_id, DIGEST, uuid4(), (Message("user", "x"),), 128)
    with pytest.raises(ProviderUnavailable):
        provider.validate(request)
    assert len(calls) == 1


def test_disconnect_after_body_accepted_is_ambiguous(setup: Any) -> None:
    accepted: list[bytes] = []

    def disconnect(request: httpx.Request) -> httpx.Response:
        accepted.append(request.content)
        raise httpx.RemoteProtocolError("lost after body", request=request)

    provider, request, fake = setup(disconnect)
    with pytest.raises(ProviderAmbiguous):
        provider.generate(request, future())
    assert len(accepted) == 1 and b"private user" in accepted[0]
    assert len(fake.generation_calls) == 1


@pytest.mark.parametrize(
    "name", ["https://evil.invalid", "remote/model:1", "model:cloud", "model@evil:1"]
)
def test_binding_rejects_remote_or_untrusted_model_name(name: str) -> None:
    with pytest.raises(ValueError):
        OllamaModelBinding(uuid4(), DIGEST, name, 4096, 256)


def test_endpoint_setting_rejects_override(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ARBITER_OLLAMA_BASE_URL", "https://evil.invalid")
    with pytest.raises(ValidationError):
        OllamaSettings()


def test_constructor_rejects_untrusted_settings_object() -> None:
    binding = OllamaModelBinding(uuid4(), DIGEST, NAME, 4096, 256)
    with pytest.raises(ValueError):
        OllamaProvider(binding, settings=object())  # type: ignore[arg-type]


def test_no_tools_pull_fallback_or_option_passthrough(setup: Any) -> None:
    provider, request, fake = setup(lambda _: response(200, success()))
    provider.generate(request, future())
    assert len(fake.generation_calls) == 1
    body = json.loads(fake.generation_calls[0].content)
    assert set(body) == {"model", "messages", "stream", "think", "truncate", "options"}
    assert set(body["options"]) == {"num_ctx", "num_predict"}
    assert {call.url.path for call in fake.calls} == {"/api/chat"}
