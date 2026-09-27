import base64
import hashlib
import hmac
import json
import secrets
from pathlib import Path

import pytest

from arbiter.config import KeySettings
from arbiter.identity.keys import KeyIssuer
from arbiter.operations.keys import InvalidKeyRequest, parse_key_request


def test_key_material_is_random_versioned_hmac_and_repr_redacted() -> None:
    pepper = secrets.token_bytes(32)
    issuer = KeyIssuer(pepper, 7)
    first, second = issuer.issue(), issuer.issue()
    value = first.credential.get_secret_value()
    prefix, public, encoded = value.split(".")
    secret = base64.urlsafe_b64decode(encoded + "=")
    assert prefix == "arb1" and public == first.public_id and len(secret) == 32
    assert first.id != second.id and first.public_id != second.public_id
    assert not hmac.compare_digest(value, second.credential.get_secret_value())
    expected = hmac.digest(
        pepper, b"arbiter/api-key/v1\0" + public.encode() + b"\0" + secret, hashlib.sha256
    )
    assert hmac.compare_digest(expected, first.verifier.get_secret_value())
    assert first.pepper_version == 7
    if value in repr(first) or encoded in repr(first) or repr(pepper) in repr(issuer):
        pytest.fail("credential representation is not redacted")


@pytest.mark.parametrize(
    "body",
    [
        b"",
        b"[]",
        b"null",
        b"{",
        b"\xff",
        b"{}",
        b'{"label":"x","scopes":[]}',
        b'{"label":"x","scopes":["admin"]}',
        b'{"label":"x","scopes":["usage:read","usage:read"]}',
        b'{"label":"a","label":"b","scopes":["usage:read"]}',
        b'{"label":"x","scopes":["usage:read"],"expires_at":null}',
        b'{"label":"x","scopes":["usage:read"],"expires_at":123}',
        b'{"label":"x","scopes":["usage:read"],"expires_at":"2026-10-01"}',
        b'{"label":"x","scopes":["usage:read"],"tenant_id":"forged"}',
        b'{"label":"x","scopes":["usage:read"],"secret":"inert"}',
        b'{"label":"arb1.inert.credential","scopes":["usage:read"]}',
        b" " * 65537,
    ],
)
def test_invalid_requests_are_sanitized(body: bytes) -> None:
    with pytest.raises(InvalidKeyRequest, match="^invalid key request$"):
        parse_key_request(body)


def test_valid_request_and_label_bounds() -> None:
    assert parse_key_request(b'{"label":"dev app","scopes":["usage:read"]}').expires_at is None
    explicit = parse_key_request(
        b'{"label":"dev","scopes":["usage:read"],"expires_at":"2026-10-01T12:00:00Z"}'
    )
    assert explicit.expires_at is not None and explicit.expires_at.utcoffset() is not None
    for label in ("", " ", "x" * 65, "x\n", "non-ascii-\u00e9"):
        with pytest.raises(InvalidKeyRequest):
            parse_key_request(json.dumps({"label": label, "scopes": ["usage:read"]}).encode())


@pytest.mark.parametrize("value", [b"", b"invalid", b"x" * 129, base64.b64encode(bytes(16))])
def test_invalid_pepper_file_is_sanitized(tmp_path: Path, value: bytes) -> None:
    path = tmp_path / "pepper"
    path.write_bytes(value)
    with pytest.raises(ValueError, match="^invalid API key pepper file$"):
        KeySettings(pepper_file=path).pepper()


def test_pepper_file_and_configuration(tmp_path: Path) -> None:
    path = tmp_path / "pepper"
    pepper = secrets.token_bytes(32)
    path.write_bytes(base64.b64encode(pepper))
    assert KeySettings(pepper_file=path).pepper() == pepper
    path.unlink()
    with pytest.raises(FileNotFoundError):
        KeySettings(pepper_file=path).pepper()
    for version in (0, -1, 2147483648):
        with pytest.raises(ValueError):
            KeyIssuer(pepper, version)
