"""Deterministic, in-process Phase 3 double; never contacts a model or provider."""

from datetime import UTC, datetime
from typing import Literal
from uuid import UUID

from arbiter.providers.port import (
    ProviderAmbiguous,
    ProviderCapabilities,
    ProviderDeadline,
    ProviderDefiniteFailure,
    ProviderMalformed,
    ProviderModelUnavailable,
    ProviderOversizedResponse,
    ProviderRejectedInput,
    ProviderRequest,
    ProviderResult,
    ProviderUnavailable,
)

DoubleMode = Literal[
    "success",
    "definite_failure",
    "deadline",
    "malformed",
    "ambiguous",
    "unavailable",
    "oversized",
    "unknown_model",
]


class DeterministicProvider:
    def __init__(
        self,
        model_id: UUID,
        model_digest: str,
        output_cap: int,
        *,
        mode: DoubleMode = "success",
        input_tokens: int | None = 4,
        output_tokens: int | None = 2,
    ) -> None:
        if mode not in {
            "success",
            "definite_failure",
            "deadline",
            "malformed",
            "ambiguous",
            "unavailable",
            "oversized",
            "unknown_model",
        }:
            raise ValueError("invalid deterministic provider mode")
        self._model_id = model_id
        self._model_digest = model_digest
        self._output_cap = output_cap
        self._mode = mode
        self._input_tokens = input_tokens
        self._output_tokens = output_tokens
        self._calls: list[UUID] = []
        self._deadlines: list[datetime] = []

    @property
    def calls(self) -> tuple[UUID, ...]:
        return tuple(self._calls)

    @property
    def deadlines(self) -> tuple[datetime, ...]:
        return tuple(self._deadlines)

    def capabilities(self) -> ProviderCapabilities:
        return ProviderCapabilities(
            self._mode != "unavailable", (self._model_id,), self._output_cap
        )

    def validate(self, request: ProviderRequest) -> None:
        if request.model_id != self._model_id or request.model_digest != self._model_digest:
            raise ProviderModelUnavailable()
        if request.max_output_tokens > self._output_cap:
            raise ProviderRejectedInput()

    def generate(self, request: ProviderRequest, deadline: datetime) -> ProviderResult:
        # The double records only opaque correlation IDs, never messages or output.
        self._calls.append(request.correlation)
        self._deadlines.append(deadline)
        if deadline.tzinfo is None or deadline <= datetime.now(UTC):
            raise ProviderDeadline()
        if self._mode == "definite_failure":
            raise ProviderDefiniteFailure()
        if self._mode == "unavailable":
            raise ProviderUnavailable()
        if self._mode == "deadline":
            raise ProviderDeadline()
        if self._mode == "ambiguous":
            raise ProviderAmbiguous()
        if self._mode == "malformed":
            raise ProviderMalformed()
        if self._mode == "oversized":
            raise ProviderOversizedResponse()
        if self._mode == "unknown_model":
            raise ProviderModelUnavailable()
        return ProviderResult("fixture response", self._input_tokens, self._output_tokens, "stop")
