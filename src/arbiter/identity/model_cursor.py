"""Encrypted public-alias positions bound to tenant and model-catalog purpose."""

import base64
import re
import secrets
import struct
from uuid import UUID

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

FORMAT = struct.Struct(">B16s64s")
PURPOSE = b"arbiter/model-cursor/v1"


class InvalidModelQuery(Exception):
    def __init__(self) -> None:
        super().__init__("invalid model query")


class ModelCursor:
    def __init__(self, key: bytes) -> None:
        if len(key) != 32:
            raise ValueError("model cursor requires a 32-byte key")
        self._cipher = AESGCM(key)

    def encode(self, tenant: UUID, alias: str) -> str:
        if re.fullmatch(r"[a-z][a-z0-9_-]{0,63}", alias) is None:
            raise InvalidModelQuery()
        nonce = secrets.token_bytes(12)
        payload = FORMAT.pack(1, tenant.bytes, alias.encode("ascii"))
        encrypted = self._cipher.encrypt(nonce, payload, PURPOSE + tenant.bytes)
        return base64.urlsafe_b64encode(nonce + encrypted).decode("ascii").rstrip("=")

    def decode(self, tenant: UUID, token: str) -> str:
        try:
            if len(token) != 146 or re.fullmatch(r"[A-Za-z0-9_-]+", token) is None:
                raise ValueError("invalid cursor encoding")
            raw = base64.urlsafe_b64decode(token + "==")
            if base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=") != token:
                raise ValueError("noncanonical cursor")
            payload = self._cipher.decrypt(raw[:12], raw[12:], PURPOSE + tenant.bytes)
            version, owner, padded = FORMAT.unpack(payload)
            if not isinstance(padded, bytes):
                raise ValueError("invalid cursor payload")
            alias = padded.rstrip(b"\0").decode("ascii")
            if version != 1 or owner != tenant.bytes or padded != alias.encode().ljust(64, b"\0"):
                raise ValueError("invalid cursor binding")
            if re.fullmatch(r"[a-z][a-z0-9_-]{0,63}", alias) is None:
                raise ValueError("invalid alias position")
            return alias
        except (ValueError, InvalidTag, struct.error):
            raise InvalidModelQuery() from None
