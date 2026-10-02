"""Local Ollama implementation of the existing governed provider port.

Only an operator-constructed binding supplies the native model name. The HTTP
destination is fixed to the private Compose service and is never request data.
"""

import asyncio
import json
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

import httpx

from arbiter.config import OllamaSettings
from arbiter.providers.port import (
    ProviderAmbiguous,
    ProviderCapabilities,
    ProviderDeadline,
    ProviderMalformed,
    ProviderModelUnavailable,
    ProviderOversizedResponse,
    ProviderRejectedInput,
    ProviderRequest,
    ProviderResult,
    ProviderUnavailable,
)

_BASE_URL = "http://ollama:11434"
_WIRE_LIMIT = 1024 * 1024
_REQUEST_LIMIT = 65536
_TAG_DEADLINE_SECONDS = 5.0
_HEADERS = {"accept": "application/json", "accept-encoding": "identity"}


@dataclass(frozen=True, slots=True)
class OllamaModelBinding:
    """Trusted operator selection; never assembled from public request fields."""

    model_id: UUID
    digest: str
    native_name: str
    context_cap: int
    output_cap: int

    def __post_init__(self) -> None:
        if (
            not isinstance(self.model_id, UUID)
            or type(self.digest) is not str
            or re.fullmatch(r"sha256:[0-9a-f]{64}", self.digest) is None
            or type(self.native_name) is not str
            or re.fullmatch(r"[A-Za-z0-9_-]{1,64}:[A-Za-z0-9_.-]{1,80}", self.native_name) is None
            or self.native_name.lower().endswith(":cloud")
            or type(self.context_cap) is not int
            or not 1 <= self.context_cap <= 32768
            or type(self.output_cap) is not int
            or not 1 <= self.output_cap <= 1024
            or self.output_cap > self.context_cap
        ):
            raise ValueError("invalid trusted Ollama model binding")


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _reject_constant(_: str) -> None:
    raise ValueError("non-finite JSON value")


def _json_object(body: bytes) -> dict[str, Any]:
    try:
        parsed = json.loads(
            body.decode("utf-8", errors="strict"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_constant,
        )
    except (UnicodeError, json.JSONDecodeError, ValueError):
        raise ProviderMalformed() from None
    if type(parsed) is not dict:
        raise ProviderMalformed()
    return parsed


def _count(value: Any) -> int | None:
    if value is None:
        return None
    if type(value) is not int or not 0 <= value <= 9223372036854775807:
        raise ProviderMalformed()
    return value


class OllamaProvider:
    """One bounded POST per generation, with no transport retry or redirect."""

    def __init__(
        self,
        binding: OllamaModelBinding,
        *,
        settings: OllamaSettings | None = None,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        if not isinstance(binding, OllamaModelBinding):
            raise ValueError("trusted Ollama binding required")
        if settings is not None and (
            not isinstance(settings, OllamaSettings) or settings.base_url != _BASE_URL
        ):
            raise ValueError("private Ollama endpoint required")
        self._binding = binding
        self._settings = settings or OllamaSettings()
        # Transport injection is for an in-process test double, never request data.
        self._transport = transport

    def _client(self, timeout: httpx.Timeout) -> httpx.AsyncClient:
        return httpx.AsyncClient(
            base_url=self._settings.base_url,
            transport=self._transport or httpx.AsyncHTTPTransport(retries=0),
            timeout=timeout,
            follow_redirects=False,
            trust_env=False,
            headers=_HEADERS,
        )

    def _check_request(self, request: ProviderRequest) -> None:
        if not isinstance(request, ProviderRequest):
            raise ProviderRejectedInput()
        if (
            request.model_id != self._binding.model_id
            or request.model_digest != self._binding.digest
        ):
            raise ProviderModelUnavailable()
        if request.max_output_tokens > self._binding.output_cap:
            raise ProviderRejectedInput()

    async def _read(self, response: httpx.Response) -> bytes:
        if response.headers.get("content-encoding", "identity").lower() != "identity":
            raise ProviderMalformed()
        size = response.headers.get("content-length")
        if size is not None:
            try:
                declared_size = int(size)
                if declared_size < 0:
                    raise ProviderMalformed()
                if declared_size > _WIRE_LIMIT:
                    raise ProviderOversizedResponse()
            except ValueError:
                raise ProviderMalformed() from None
        body = bytearray()
        async for chunk in response.aiter_raw(chunk_size=8192):
            if len(body) + len(chunk) > _WIRE_LIMIT:
                raise ProviderOversizedResponse()
            body.extend(chunk)
        return bytes(body)

    async def _local_model_present(self) -> bool:
        timeout = httpx.Timeout(_TAG_DEADLINE_SECONDS, connect=_TAG_DEADLINE_SECONDS)
        try:
            async with asyncio.timeout(_TAG_DEADLINE_SECONDS):
                async with self._client(timeout) as client:
                    async with client.stream("GET", "/api/tags") as response:
                        if response.status_code != 200:
                            raise ProviderUnavailable()
                        body = await self._read(response)
        except (TimeoutError, httpx.HTTPError, ProviderMalformed):
            raise ProviderUnavailable() from None
        try:
            models = _json_object(body).get("models")
            if type(models) is not list:
                raise ProviderMalformed()
            for model in models:
                if type(model) is not dict:
                    raise ProviderMalformed()
                if model.get("name") == self._binding.native_name:
                    digest = model.get("digest")
                    if type(digest) is not str:
                        raise ProviderMalformed()
                    return digest in {self._binding.digest, self._binding.digest[7:]}
        except ProviderMalformed:
            raise ProviderUnavailable() from None
        return False

    def capabilities(self) -> ProviderCapabilities:
        try:
            available = asyncio.run(self._local_model_present())
        except ProviderUnavailable:
            available = False
        return ProviderCapabilities(
            available,
            (self._binding.model_id,) if available else (),
            self._binding.output_cap,
        )

    def validate(self, request: ProviderRequest) -> None:
        self._check_request(request)
        if not asyncio.run(self._local_model_present()):
            raise ProviderModelUnavailable()

    def generate(self, request: ProviderRequest, deadline: datetime) -> ProviderResult:
        self._check_request(request)
        if deadline.tzinfo is None or deadline <= datetime.now(UTC):
            raise ProviderDeadline()
        body = json.dumps(
            {
                "model": self._binding.native_name,
                "messages": [{"role": m.role, "content": m.content} for m in request.messages],
                "stream": False,
                "think": False,
                "truncate": False,
                "options": {
                    "num_ctx": self._binding.context_cap,
                    "num_predict": request.max_output_tokens,
                },
            },
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
        ).encode("utf-8")
        if len(body) > _REQUEST_LIMIT:
            raise ProviderRejectedInput()
        try:
            return asyncio.run(self._generate(body, deadline, request.max_output_tokens))
        except (TimeoutError, httpx.TimeoutException):
            raise ProviderDeadline() from None
        except httpx.ConnectError:
            raise ProviderUnavailable() from None
        except httpx.HTTPError:
            raise ProviderAmbiguous() from None

    async def _generate(
        self, body: bytes, deadline: datetime, max_output_tokens: int
    ) -> ProviderResult:
        # Recompute immediately before network I/O; asyncio.timeout bounds the
        # entire request, including DNS, connect, send, response, and body read.
        remaining = (deadline - datetime.now(UTC)).total_seconds()
        if remaining <= 0:
            raise ProviderDeadline()
        timeout = httpx.Timeout(remaining, connect=min(5.0, remaining))
        async with asyncio.timeout(remaining):
            async with self._client(timeout) as client:
                async with client.stream(
                    "POST", "/api/chat", content=body, headers={"content-type": "application/json"}
                ) as response:
                    if response.status_code == 200:
                        content_types = response.headers.get_list("content-type")
                        if len(content_types) != 1 or "," in content_types[0]:
                            raise ProviderMalformed()
                        if content_types[0].split(";", 1)[0].strip().lower() != "application/json":
                            raise ProviderMalformed()
                    wire = await self._read(response)
                    if response.status_code == 404:
                        try:
                            error = _json_object(wire).get("error")
                        except ProviderMalformed:
                            raise ProviderAmbiguous() from None
                        # Pinned Ollama ChatHandler returns this exact 404 before
                        # scheduling work. Other 404s are inconclusive.
                        if error == f"model '{self._binding.native_name}' not found":
                            raise ProviderModelUnavailable()
                    if response.status_code != 200:
                        raise ProviderAmbiguous()
        data = _json_object(wire)
        message = data.get("message")
        if (
            data.get("model") != self._binding.native_name
            or type(message) is not dict
            or message.get("role") != "assistant"
            or type(message.get("content")) is not str
            or data.get("done") is not True
            or type(data.get("done_reason")) is not str
            or data["done_reason"] not in {"stop", "length"}
            or any(key in message for key in ("tool_calls", "images", "thinking"))
        ):
            raise ProviderMalformed()
        try:
            message["content"].encode("utf-8")
        except UnicodeError:
            raise ProviderMalformed() from None
        input_tokens = _count(data.get("prompt_eval_count"))
        output_tokens = _count(data.get("eval_count"))
        if output_tokens is not None and output_tokens > max_output_tokens:
            raise ProviderMalformed()
        return ProviderResult(
            message["content"],
            input_tokens,
            output_tokens,
            data["done_reason"],
        )
