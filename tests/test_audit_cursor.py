import base64
import secrets
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

import pytest

from arbiter.config import AuditSettings
from arbiter.identity.audit_cursor import AuditCursor, AuditPosition, InvalidAuditQuery


def test_cursor_is_opaque_authenticated_and_survives_codec_recreation() -> None:
    key = secrets.token_bytes(32)
    tenant, event = uuid4(), uuid4()
    position = AuditPosition(datetime(2026, 9, 27, 1, 2, 3, 456789, tzinfo=UTC), event)
    codec = AuditCursor(key)
    token = codec.encode(tenant, position)
    assert AuditCursor(key).decode(tenant, token) == position
    assert token != codec.encode(tenant, position)
    assert tenant.bytes not in base64.urlsafe_b64decode(token)
    assert event.bytes not in base64.urlsafe_b64decode(token)
    for owner, cursor, decoder in (
        (uuid4(), token, codec),
        (tenant, token, AuditCursor(secrets.token_bytes(32))),
        (tenant, ("A" if token[0] != "A" else "B") + token[1:], codec),
    ):
        with pytest.raises(InvalidAuditQuery, match="^invalid audit query$"):
            decoder.decode(owner, cursor)


@pytest.mark.parametrize("token", ["", "x", "x" * 10000, "../cursor", "a" * 91, "=" * 92])
def test_malformed_cursors_are_denied(token: str) -> None:
    with pytest.raises(InvalidAuditQuery):
        AuditCursor(secrets.token_bytes(32)).decode(uuid4(), token)


def test_cursor_requires_aware_timestamp_and_full_key() -> None:
    with pytest.raises(ValueError):
        AuditCursor(bytes(16))
    with pytest.raises(ValueError):
        AuditCursor(secrets.token_bytes(32)).encode(
            uuid4(), AuditPosition(datetime(2026, 9, 27), uuid4())
        )


@pytest.mark.parametrize("value", [b"", b"not base64", b"a" * 129, base64.b64encode(bytes(16))])
def test_invalid_cursor_secret_is_sanitized(tmp_path: Path, value: bytes) -> None:
    path = tmp_path / "cursor-key"
    path.write_bytes(value)
    with pytest.raises(ValueError, match="^invalid audit cursor key file$"):
        AuditSettings(key_file=path).key()


def test_cursor_secret_load_and_missing_file(tmp_path: Path) -> None:
    path = tmp_path / "cursor-key"
    key = secrets.token_bytes(32)
    path.write_bytes(base64.b64encode(key))
    assert AuditSettings(key_file=path).key() == key
    path.unlink()
    with pytest.raises(FileNotFoundError):
        AuditSettings(key_file=path).key()
