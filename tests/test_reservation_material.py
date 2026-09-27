"""Fingerprint canonicalization, bounded input, secret configuration and redaction."""

import base64
from dataclasses import FrozenInstanceError
from pathlib import Path
from typing import Any

import pytest

from arbiter.config import FingerprintSettings
from arbiter.governance.fingerprint import (
    Fingerprinter,
    InvalidReservation,
    Message,
    ReservationInput,
    validate_idempotency,
)


def content(text: str = "synthetic input", output: int = 256) -> ReservationInput:
    return ReservationInput("fixture", (Message("user", text),), output)


def test_fingerprint_is_keyed_versioned_and_canonical_with_explicit_defaults() -> None:
    first = Fingerprinter(bytes(range(32)))
    request = content()
    digest = first.compute(request)
    assert digest == first.compute(
        ReservationInput("fixture", (Message("user", "synthetic input"),))
    )
    assert digest != first.compute(content("other input"))
    assert digest != first.compute(content(output=128))
    assert digest != first.compute(ReservationInput("other", request.messages))
    assert digest != Fingerprinter(bytes(reversed(range(32)))).compute(request)
    assert digest != Fingerprinter(bytes(range(32)), 2).compute(request)
    assert digest.version == 1 and len(digest.digest.get_secret_value()) == 32
    assert "synthetic input" not in repr(request) and "synthetic input" not in repr(
        request.messages
    )
    assert "synthetic input" not in repr(digest)
    with pytest.raises(FrozenInstanceError):
        field = "max_output_tokens"
        setattr(request, field, 128)


def test_message_order_roles_and_unicode_are_significant() -> None:
    key = Fingerprinter(bytes(range(32)))
    left = ReservationInput("fixture", (Message("system", "rules"), Message("user", "hello")))
    right = ReservationInput("fixture", tuple(reversed(left.messages)))
    assert key.compute(left) != key.compute(right)
    assert key.compute(content("é")) != key.compute(content("e\u0301"))
    assert key.compute(content("hello")) != key.compute(
        ReservationInput("fixture", (Message("assistant", "hello"),))
    )


@pytest.mark.parametrize("value", ["x" * 15, "x" * 129, "é" * 16, "x" * 16 + "\n", "\x7f" * 16])
def test_invalid_idempotency(value: str) -> None:
    with pytest.raises(InvalidReservation) as failure:
        validate_idempotency(value)
    assert str(failure.value) == "invalid reservation fields"


@pytest.mark.parametrize("value", [" " * 16, "x" * 128, "!" * 16])
def test_printable_ascii_boundaries(value: str) -> None:
    validate_idempotency(value)


@pytest.mark.parametrize(
    "field,value",
    [
        ("model_alias", "https://invalid.example"),
        ("model_alias", "A"),
        ("model_alias", "x" * 65),
        ("max_output_tokens", -1),
        ("max_output_tokens", 0),
        ("max_output_tokens", True),
        ("max_output_tokens", 1025),
        ("messages", ()),
        ("messages", [Message("user", "fixture")]),
        ("messages", (Message("user", "fixture"),) * 33),
    ],
)
def test_invalid_input_is_generic(field: str, value: Any) -> None:
    values = {"model_alias": "fixture", "messages": (Message("user", "fixture"),), field: value}
    with pytest.raises(InvalidReservation) as failure:
        ReservationInput(**values)
    assert str(failure.value) == "invalid reservation fields"


@pytest.mark.parametrize("text", ["x" * 32769, "\ud800", "\x00" * 32768])
def test_oversize_utf8_or_canonical_payload_is_rejected(text: str) -> None:
    with pytest.raises(InvalidReservation):
        content(text)


def test_utf8_and_output_boundary() -> None:
    content("é" * 16384, 1024)
    with pytest.raises(InvalidReservation):
        content("é" * 16385)


@pytest.mark.parametrize("value", [b"invalid", base64.b64encode(bytes(31)), b"x" * 129])
def test_fingerprint_secret_fail_closed(tmp_path: Path, value: bytes) -> None:
    path = tmp_path / "key"
    path.write_bytes(value)
    with pytest.raises(ValueError, match="invalid fingerprint key file"):
        FingerprintSettings(key_file=path).key()


def test_fingerprint_secret_is_file_based(tmp_path: Path) -> None:
    path = tmp_path / "key"
    path.write_bytes(base64.b64encode(bytes(range(32))))
    settings = FingerprintSettings(key_file=path, version=1)
    assert settings.key() == bytes(range(32))
    assert settings.version == 1
