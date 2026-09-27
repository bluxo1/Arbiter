"""Key issuance and bounded parsing/HMAC; plaintext never reaches persistence."""

import base64
import hashlib
import hmac
import re
import secrets
from dataclasses import dataclass
from uuid import UUID, uuid4

from pydantic import SecretBytes, SecretStr


class InvalidKey(Exception):
    def __init__(self) -> None:
        super().__init__("invalid credentials")


@dataclass(frozen=True, slots=True)
class KeyCandidate:
    public_id: str
    verifier: SecretBytes
    pepper_version: int


def _verifier(pepper: SecretBytes, public_id: str, secret: bytes) -> bytes:
    return hmac.digest(
        pepper.get_secret_value(),
        b"arbiter/api-key/v1\0" + public_id.encode("ascii") + b"\0" + secret,
        hashlib.sha256,
    )


class KeyVerifier:
    def __init__(self, pepper: bytes, version: int) -> None:
        if len(pepper) != 32 or not 1 <= version <= 2147483647:
            raise ValueError("invalid API key pepper configuration")
        self._pepper = SecretBytes(pepper)
        self._version = version

    def candidate(self, credential: SecretStr) -> KeyCandidate:
        value = credential.get_secret_value()
        if len(value) != 81:
            raise InvalidKey()
        match = re.fullmatch(r"arb1\.([0-9a-f]{32})\.([A-Za-z0-9_-]{43})", value)
        if match is None:
            raise InvalidKey()
        public_id, encoded = match.groups()
        secret = base64.urlsafe_b64decode(encoded + "=")
        canonical = base64.urlsafe_b64encode(secret).decode("ascii").rstrip("=")
        if len(secret) != 32 or not hmac.compare_digest(canonical, encoded):
            raise InvalidKey()
        return KeyCandidate(
            public_id, SecretBytes(_verifier(self._pepper, public_id, secret)), self._version
        )


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
        verifier = _verifier(self._pepper, public_id, secret)
        encoded = base64.urlsafe_b64encode(secret).decode("ascii").rstrip("=")
        return IssuedKey(
            uuid4(),
            public_id,
            SecretStr(f"arb1.{public_id}.{encoded}"),
            SecretBytes(verifier),
            self._version,
        )
