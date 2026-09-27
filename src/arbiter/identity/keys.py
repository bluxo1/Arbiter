"""Creation-only key material. Plaintext exists only in the one-time result."""

import base64
import hashlib
import hmac
import secrets
from dataclasses import dataclass
from uuid import UUID, uuid4

from pydantic import SecretBytes, SecretStr


@dataclass(frozen=True, slots=True)
class IssuedKey:
    id: UUID
    public_id: str
    credential: SecretStr
    verifier: SecretBytes
    pepper_version: int


class KeyIssuer:
    def __init__(self, pepper: bytes, version: int) -> None:
        if len(pepper) != 32 or not 1 <= version <= 2147483647:
            raise ValueError("invalid API key pepper configuration")
        self._pepper = SecretBytes(pepper)
        self._version = version

    def issue(self) -> IssuedKey:
        public_id = uuid4().hex
        secret = secrets.token_bytes(32)
        verifier = hmac.digest(
            self._pepper.get_secret_value(),
            b"arbiter/api-key/v1\0" + public_id.encode("ascii") + b"\0" + secret,
            hashlib.sha256,
        )
        encoded = base64.urlsafe_b64encode(secret).decode("ascii").rstrip("=")
        return IssuedKey(
            uuid4(),
            public_id,
            SecretStr(f"arb1.{public_id}.{encoded}"),
            SecretBytes(verifier),
            self._version,
        )
