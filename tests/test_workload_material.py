"""Bounded canonical parsing, matching issuance HMAC and sanitized secret handling."""

import base64
import secrets

import pytest
from pydantic import SecretStr

from arbiter.identity.keys import InvalidKey, KeyIssuer, KeyVerifier


def test_issued_key_parses_to_matching_verifier_without_retaining_secret() -> None:
    pepper = secrets.token_bytes(32)
    issued = KeyIssuer(pepper, 4).issue()
    verifier = KeyVerifier(pepper, 4)
    candidate = verifier.candidate(issued.credential)
    assert candidate.public_id == issued.public_id and candidate.pepper_version == 4
    assert secrets.compare_digest(
        candidate.verifier.get_secret_value(), issued.verifier.get_secret_value()
    )
    credential = issued.credential.get_secret_value()
    for value in (
        credential,
        credential.split(".")[2],
        repr(pepper),
        issued.verifier.get_secret_value().hex(),
    ):
        if value in repr(candidate) or value in repr(verifier):
            pytest.fail("sensitive material reached a representation")


@pytest.mark.parametrize(
    "value",
    [
        "",
        "arb1",
        "arb1.inert.secret",
        "Bearer arb1.inert.secret",
        "jwt.inert.token",
        "arb2." + "a" * 32 + "." + "A" * 43,
        "arb1." + "A" * 32 + "." + "A" * 43,
        "arb1." + "g" * 32 + "." + "A" * 43,
        "arb1." + "a" * 32 + "." + "A" * 42,
        "arb1." + "a" * 32 + "." + "A" * 44,
        "arb1." + "a" * 32 + "." + "A" * 42 + "=",
        "arb1." + "a" * 32 + "." + "A" * 42 + "+",
        "arb1." + "a" * 32 + "." + "A" * 42 + "B",
        "arb1." + "a" * 32 + "." + "A" * 42 + "\n",
        "arb1." + "a" * 32 + "." + "A" * 42 + "é",
        "x" * 65537,
    ],
)
def test_malformed_key_is_generic_and_never_echoed(value: str) -> None:
    verifier = KeyVerifier(secrets.token_bytes(32), 1)
    with pytest.raises(InvalidKey, match="^invalid credentials$") as failure:
        verifier.candidate(SecretStr(value))
    assert str(failure.value) == "invalid credentials"


def test_noncanonical_final_padding_bits_rejected() -> None:
    issued = KeyIssuer(secrets.token_bytes(32), 1).issue()
    prefix, public, encoded = issued.credential.get_secret_value().split(".")
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
    index = alphabet.index(encoded[-1])
    assert index % 4 == 0
    modified = encoded[:-1] + alphabet[index + 1]
    assert base64.urlsafe_b64decode(encoded + "=") == base64.urlsafe_b64decode(modified + "=")
    with pytest.raises(InvalidKey):
        KeyVerifier(secrets.token_bytes(32), 1).candidate(
            SecretStr(f"{prefix}.{public}.{modified}")
        )


@pytest.mark.parametrize(
    "pepper,version", [(bytes(31), 1), (bytes(32), 0), (bytes(32), 2147483648)]
)
def test_invalid_verifier_configuration_fails_closed(pepper: bytes, version: int) -> None:
    with pytest.raises(ValueError, match="^invalid API key pepper configuration$"):
        KeyVerifier(pepper, version)
