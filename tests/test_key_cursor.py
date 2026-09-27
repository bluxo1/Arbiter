import base64
import secrets
from datetime import UTC, datetime
from uuid import uuid4

import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from arbiter.identity.audit_cursor import AuditCursor, AuditPosition, InvalidAuditQuery
from arbiter.identity.key_cursor import FORMAT, PURPOSE, InvalidKeyQuery, KeyCursor


def test_encrypted_tenant_position_recreation_and_purpose_separation() -> None:
    key = secrets.token_bytes(32)
    tenant, identifier = uuid4(), uuid4()
    codec = KeyCursor(key)
    cursor = codec.encode(tenant, identifier)
    assert KeyCursor(key).decode(tenant, cursor) == identifier
    assert cursor != codec.encode(tenant, identifier)
    raw = base64.urlsafe_b64decode(cursor + "==")
    assert tenant.bytes not in raw and identifier.bytes not in raw
    for decoder, owner, value in (
        (codec, uuid4(), cursor),
        (KeyCursor(secrets.token_bytes(32)), tenant, cursor),
        (codec, tenant, ("A" if cursor[0] != "A" else "B") + cursor[1:]),
    ):
        with pytest.raises(InvalidKeyQuery, match="^invalid key query$"):
            decoder.decode(owner, value)
    audit = AuditCursor(key)
    with pytest.raises(InvalidAuditQuery):
        audit.decode(tenant, cursor)
    with pytest.raises(InvalidKeyQuery):
        codec.decode(tenant, audit.encode(tenant, AuditPosition(datetime.now(UTC), uuid4())))
    nonce = secrets.token_bytes(12)
    encrypted = AESGCM(key).encrypt(
        nonce,
        FORMAT.pack(1, tenant.bytes, identifier.bytes),
        b"arbiter/audit-cursor/v1" + tenant.bytes,
    )
    with pytest.raises(InvalidKeyQuery):
        codec.decode(tenant, base64.urlsafe_b64encode(nonce + encrypted).decode().rstrip("="))


@pytest.mark.parametrize(
    "cursor", ["", "x", "x" * 10000, "../cursor", "=" * 82, "a" * 81, "a" * 83]
)
def test_malformed_cursor_denied(cursor: str) -> None:
    with pytest.raises(InvalidKeyQuery):
        KeyCursor(secrets.token_bytes(32)).decode(uuid4(), cursor)


def test_bad_key_noncanonical_wire_version_and_payload_binding() -> None:
    with pytest.raises(ValueError):
        KeyCursor(bytes(16))
    key = secrets.token_bytes(32)
    tenant, identifier = uuid4(), uuid4()
    codec = KeyCursor(key)
    cursor = codec.encode(tenant, identifier)
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
    last = alphabet.index(cursor[-1])
    with pytest.raises(InvalidKeyQuery):
        codec.decode(tenant, cursor[:-1] + alphabet[last + 1])
    for version, owner in ((2, tenant), (1, uuid4())):
        nonce = secrets.token_bytes(12)
        encrypted = AESGCM(key).encrypt(
            nonce,
            FORMAT.pack(version, owner.bytes, identifier.bytes),
            PURPOSE + tenant.bytes,
        )
        with pytest.raises(InvalidKeyQuery):
            codec.decode(tenant, base64.urlsafe_b64encode(nonce + encrypted).decode().rstrip("="))
