"""Transient, non-streaming provider contract; no persistence or network policy here."""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Protocol
from uuid import UUID

from arbiter.governance.fingerprint import Message


@dataclass(frozen=True, slots=True)
class ProviderRequest:
    model_id: UUID
    model_digest: str
    correlation: UUID
    messages: tuple[Message, ...] = field(repr=False)
    max_output_tokens: int = 256


@dataclass(frozen=True, slots=True)
class ProviderResult:
    assistant_text: str = field(repr=False)
    input_tokens: int | None = None
    output_tokens: int | None = None
    finish_reason: str = "stop"


@dataclass(frozen=True, slots=True)
class ProviderCapabilities:
    healthy: bool
    model_ids: tuple[UUID, ...]
    output_cap: int


class ProviderError(Exception):
    """Sanitized provider classification, never a raw response or request body."""

    def __init__(self) -> None:
        super().__init__("provider operation did not succeed")


class ProviderDefiniteFailure(ProviderError):
    """Provider positively confirmed failure; no work remains in flight."""


class ProviderDeadline(ProviderError):
    """The call timed out; execution may still be running."""


class ProviderMalformed(ProviderError):
    """Terminal response could not establish a safe completion."""


class ProviderAmbiguous(ProviderError):
    """Transport or execution result is inconclusive."""


class ProviderPort(Protocol):
    def capabilities(self) -> ProviderCapabilities: ...

    def validate(self, request: ProviderRequest) -> None: ...

    def generate(self, request: ProviderRequest, deadline: datetime) -> ProviderResult: ...
