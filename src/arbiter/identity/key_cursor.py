"""Encrypted UUID positions bound to a tenant and the key-metadata list purpose."""

import base64
import re
import secrets
import struct
from uuid import UUID

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

FORMAT = struct.Struct(">B16s16s")
PURPOSE = b"arbiter/key-cursor/v1"


class InvalidKeyQuery(Exception):
    def __init__(self) -> None:
        super().__init__("invalid key query")


class KeyCursor:
    def __init__(self, key: bytes) -> None:
        if len(key) != 32:
            raise ValueError("key cursor requires a 32-byte key")
        self._cipher = AESGCM(key)

    def encode(self, tenant: UUID, key_id: UUID) -> str:
        nonce = secrets.token_bytes(12)
        payload = FORMAT.pack(1, tenant.bytes, key_id.bytes)
        encrypted = self._cipher.encrypt(nonce, payload, PURPOSE + tenant.bytes)
        return base64.urlsafe_b64encode(nonce + encrypted).decode("ascii").rstrip("=")

    def decode(self, tenant: UUID, token: str) -> UUID:
        try:
            if len(token) != 82 or re.fullmatch(r"[A-Za-z0-9_-]+", token) is None:
                raise ValueError("invalid cursor encoding")
            raw = base64.urlsafe_b64decode(token + "==")
            if base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=") != token:
                raise ValueError("noncanonical cursor")
            payload = self._cipher.decrypt(raw[:12], raw[12:], PURPOSE + tenant.bytes)
            version, owner, key_id = FORMAT.unpack(payload)
            if version != 1 or owner != tenant.bytes:
                raise ValueError("invalid cursor binding")
            return UUID(bytes=key_id)
        except (ValueError, InvalidTag, struct.error):
            raise InvalidKeyQuery() from None
