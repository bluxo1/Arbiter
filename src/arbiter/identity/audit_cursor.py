"""Authenticated opaque audit positions, bound to one tenant and one list purpose."""

import base64
import re
import secrets
import struct
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from uuid import UUID

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

EPOCH = datetime(1970, 1, 1, tzinfo=UTC)
FORMAT = struct.Struct(">B16sq16s")
PURPOSE = b"arbiter/audit-cursor/v1"


class InvalidAuditQuery(Exception):
    def __init__(self) -> None:
        super().__init__("invalid audit query")


@dataclass(frozen=True, slots=True)
class AuditPosition:
    occurred_at: datetime
    event_id: UUID


class AuditCursor:
    def __init__(self, key: bytes) -> None:
        if len(key) != 32:
            raise ValueError("audit cursor requires a 32-byte key")
        self._cipher = AESGCM(key)

    def encode(self, tenant: UUID, position: AuditPosition) -> str:
        if position.occurred_at.tzinfo is None:
            raise ValueError("aware audit timestamp required")
        micros = (position.occurred_at.astimezone(UTC) - EPOCH) // timedelta(microseconds=1)
        payload = FORMAT.pack(1, tenant.bytes, micros, position.event_id.bytes)
        nonce = secrets.token_bytes(12)
        encrypted = self._cipher.encrypt(nonce, payload, PURPOSE + tenant.bytes)
        return base64.urlsafe_b64encode(nonce + encrypted).decode("ascii").rstrip("=")

    def decode(self, tenant: UUID, token: str) -> AuditPosition:
        try:
            if len(token) != 92 or re.fullmatch(r"[A-Za-z0-9_-]+", token) is None:
                raise ValueError("invalid cursor encoding")
            raw = base64.urlsafe_b64decode(token)
            # Accept only the canonical wire representation.
            if base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=") != token:
                raise ValueError("noncanonical cursor")
            payload = self._cipher.decrypt(raw[:12], raw[12:], PURPOSE + tenant.bytes)
            version, owner, micros, event = FORMAT.unpack(payload)
            if version != 1 or owner != tenant.bytes:
                raise ValueError("invalid cursor binding")
            return AuditPosition(EPOCH + timedelta(microseconds=micros), UUID(bytes=event))
        except (ValueError, InvalidTag, struct.error, OverflowError):
            raise InvalidAuditQuery() from None
