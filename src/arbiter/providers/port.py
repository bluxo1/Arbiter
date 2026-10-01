"""Transient, non-streaming provider contract; no persistence or network policy here."""

import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Protocol, runtime_checkable
from uuid import UUID

from arbiter.governance.fingerprint import Message


@dataclass(frozen=True, slots=True)
class ProviderRequest:
    model_id: UUID
    model_digest: str
    correlation: UUID
    messages: tuple[Message, ...] = field(repr=False)
    max_output_tokens: int = 256

    def __post_init__(self) -> None:
        if (
            not isinstance(self.model_id, UUID)
            or type(self.model_digest) is not str
            or re.fullmatch(r"sha256:[0-9a-f]{64}", self.model_digest) is None
            or not isinstance(self.correlation, UUID)
            or type(self.max_output_tokens) is not int
            or not 1 <= self.max_output_tokens <= 1024
            or type(self.messages) is not tuple
            or not 1 <= len(self.messages) <= 32
            or any(not isinstance(message, Message) for message in self.messages)
        ):
            raise ProviderRejectedInput()
        try:
            if sum(len(message.content.encode("utf-8")) for message in self.messages) > 32768:
                raise ProviderRejectedInput()
        except UnicodeError:
            raise ProviderRejectedInput() from None


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


class ProviderRejectedInput(ProviderDefiniteFailure):
    """Normalized request violates registered provider capabilities before execution."""


class ProviderModelUnavailable(ProviderRejectedInput):
    """The approved, pinned model is unavailable; no model pull is attempted."""


class ProviderUnavailable(ProviderError):
    """Provider cannot be reached; after dispatch its execution status is uncertain."""


class ProviderDeadline(ProviderError):
    """The call timed out; execution may still be running."""


class ProviderMalformed(ProviderError):
    """Terminal response could not establish a safe completion."""


class ProviderOversizedResponse(ProviderMalformed):
    """Provider response exceeds the fixed 1 MiB bound."""


class ProviderAmbiguous(ProviderError):
    """Transport or execution result is inconclusive."""


@runtime_checkable
class ProviderPort(Protocol):
    def capabilities(self) -> ProviderCapabilities: ...

    def validate(self, request: ProviderRequest) -> None: ...

    def generate(self, request: ProviderRequest, deadline: datetime) -> ProviderResult: ...
