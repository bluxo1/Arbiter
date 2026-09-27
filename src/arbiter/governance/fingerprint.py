"""Bounded immutable request content and a separate, versioned keyed fingerprint.

Content is transient input, never a persistence argument or a logged representation.
There is no HTTP handler, provider validation or model invocation here.
"""

import hashlib
import hmac
import json
import re
from dataclasses import dataclass, field
from typing import Literal

from pydantic import SecretBytes


class InvalidReservation(Exception):
    code = "invalid_fields"
    status_code = 422

    def __init__(self) -> None:
        super().__init__("invalid reservation fields")


def validate_idempotency(value: str) -> None:
    if not isinstance(value, str) or re.fullmatch(r"[ -~]{16,128}", value) is None:
        raise InvalidReservation()


@dataclass(frozen=True, slots=True)
class Message:
    role: Literal["system", "user", "assistant"]
    content: str = field(repr=False)

    def __post_init__(self) -> None:
        if (
            type(self.role) is not str
            or self.role not in {"system", "user", "assistant"}
            or type(self.content) is not str
        ):
            raise InvalidReservation()


@dataclass(frozen=True, slots=True)
class ReservationInput:
    model_alias: str
    messages: tuple[Message, ...] = field(repr=False)
    max_output_tokens: int = 256

    def __post_init__(self) -> None:
        if (
            not isinstance(self.model_alias, str)
            or re.fullmatch(r"[a-z][a-z0-9_-]{0,63}", self.model_alias) is None
            or type(self.max_output_tokens) is not int
            or not 1 <= self.max_output_tokens <= 1024
            or type(self.messages) is not tuple
            or not 1 <= len(self.messages) <= 32
            or any(not isinstance(message, Message) for message in self.messages)
        ):
            raise InvalidReservation()
        try:
            if sum(len(message.content.encode("utf-8")) for message in self.messages) > 32768:
                raise InvalidReservation()
            if len(self.canonical()) > 65536:
                raise InvalidReservation()
        except UnicodeError:
            raise InvalidReservation() from None

    def canonical(self) -> bytes:
        return json.dumps(
            {
                "model": self.model_alias,
                "messages": [{"role": m.role, "content": m.content} for m in self.messages],
                "max_output_tokens": self.max_output_tokens,
            },
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")


@dataclass(frozen=True, slots=True)
class PayloadFingerprint:
    digest: SecretBytes
    version: int


class Fingerprinter:
    def __init__(self, key: bytes, version: int = 1) -> None:
        if len(key) != 32 or type(version) is not int or not 1 <= version <= 2147483647:
            raise ValueError("invalid fingerprint configuration")
        self._key = SecretBytes(key)
        self._version = version

    def compute(self, request: ReservationInput) -> PayloadFingerprint:
        if not isinstance(request, ReservationInput):
            raise InvalidReservation()
        # Explicit default output is canonical; message order and text remain significant.
        digest = hmac.digest(
            self._key.get_secret_value(),
            b"arbiter/request-fingerprint\0"
            + str(self._version).encode("ascii")
            + b"\0"
            + request.canonical(),
            hashlib.sha256,
        )
        return PayloadFingerprint(SecretBytes(digest), self._version)
