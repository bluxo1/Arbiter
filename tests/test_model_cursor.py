import base64
import secrets
from uuid import uuid4

import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from arbiter.identity.key_cursor import KeyCursor
from arbiter.identity.model_cursor import FORMAT, PURPOSE, InvalidModelQuery, ModelCursor


def test_encrypted_position_tenant_purpose_and_restart_binding() -> None:
    key = secrets.token_bytes(32)
    tenant = uuid4()
    codec = ModelCursor(key)
    cursor = codec.encode(tenant, "public-alias")
    assert len(cursor) == 146
    assert ModelCursor(key).decode(tenant, cursor) == "public-alias"
    assert cursor != codec.encode(tenant, "public-alias")
    raw = base64.urlsafe_b64decode(cursor + "==")
    assert b"public-alias" not in raw and tenant.bytes not in raw
    for decoder, owner, value in (
        (codec, uuid4(), cursor),
        (ModelCursor(secrets.token_bytes(32)), tenant, cursor),
        (codec, tenant, ("A" if cursor[0] != "A" else "B") + cursor[1:]),
        (codec, tenant, KeyCursor(key).encode(tenant, uuid4())),
    ):
        with pytest.raises(InvalidModelQuery, match="^invalid model query$"):
            decoder.decode(owner, value)


@pytest.mark.parametrize(
    "token", ["", "x", "x" * 10000, "../cursor", "=" * 146, "a" * 145, "a" * 147]
)
def test_malformed_cursor_denied(token: str) -> None:
    with pytest.raises(InvalidModelQuery):
        ModelCursor(secrets.token_bytes(32)).decode(uuid4(), token)


def test_authenticated_wrong_version_owner_purpose_and_alias_denied() -> None:
    key = secrets.token_bytes(32)
    tenant = uuid4()
    codec = ModelCursor(key)
    for payload, purpose in (
        (FORMAT.pack(2, tenant.bytes, b"alias"), PURPOSE + tenant.bytes),
        (FORMAT.pack(1, uuid4().bytes, b"alias"), PURPOSE + tenant.bytes),
        (FORMAT.pack(1, tenant.bytes, b"alias"), b"wrong-purpose" + tenant.bytes),
        (FORMAT.pack(1, tenant.bytes, b"bad:alias"), PURPOSE + tenant.bytes),
    ):
        nonce = secrets.token_bytes(12)
        raw = nonce + AESGCM(key).encrypt(nonce, payload, purpose)
        token = base64.urlsafe_b64encode(raw).decode().rstrip("=")
        with pytest.raises(InvalidModelQuery):
            codec.decode(tenant, token)
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
    canonical = codec.encode(tenant, "alias")
    with pytest.raises(InvalidModelQuery):
        codec.decode(tenant, canonical[:-1] + alphabet[alphabet.index(canonical[-1]) + 1])
    with pytest.raises(ValueError):
        ModelCursor(bytes(16))
    with pytest.raises(InvalidModelQuery):
        codec.encode(tenant, "bad:alias")
