"""Deterministic, in-process Phase 3 double; never contacts a model or provider."""

from datetime import datetime
from typing import Literal
from uuid import UUID

from arbiter.providers.port import (
    ProviderAmbiguous,
    ProviderCapabilities,
    ProviderDeadline,
    ProviderDefiniteFailure,
    ProviderRequest,
    ProviderResult,
)

DoubleMode = Literal["success", "definite_failure", "deadline", "malformed", "ambiguous"]


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
        if mode not in {"success", "definite_failure", "deadline", "malformed", "ambiguous"}:
            raise ValueError("invalid deterministic provider mode")
        self._model_id = model_id
        self._model_digest = model_digest
        self._output_cap = output_cap
        self._mode = mode
        self._input_tokens = input_tokens
        self._output_tokens = output_tokens
        self._calls: list[UUID] = []

    @property
    def calls(self) -> tuple[UUID, ...]:
        return tuple(self._calls)

    def capabilities(self) -> ProviderCapabilities:
        return ProviderCapabilities(True, (self._model_id,), self._output_cap)

    def validate(self, request: ProviderRequest) -> None:
        if (
            request.model_id != self._model_id
            or request.model_digest != self._model_digest
            or request.max_output_tokens > self._output_cap
        ):
            raise ValueError("model unavailable")

    def generate(self, request: ProviderRequest, deadline: datetime) -> ProviderResult:
        # The double records only opaque correlation IDs, never messages or output.
        self._calls.append(request.correlation)
        if self._mode == "definite_failure":
            raise ProviderDefiniteFailure()
        if self._mode == "deadline":
            raise ProviderDeadline()
        if self._mode == "ambiguous":
            raise ProviderAmbiguous()
        if self._mode == "malformed":
            return ProviderResult("fixture response", finish_reason="invalid")
        return ProviderResult("fixture response", self._input_tokens, self._output_tokens, "stop")
