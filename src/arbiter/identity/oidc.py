"""Bounded OIDC verification. Only configured trust establishes a principal."""

import base64
import json
import math
import re
import ssl
from collections.abc import Callable
from dataclasses import dataclass
from time import monotonic
from typing import Any

import httpx
import jwt
from anyio import CapacityLimiter, Lock, fail_after, to_thread
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey

from arbiter.config import OidcSettings


class InvalidIdentity(Exception):
    def __init__(self) -> None:
        super().__init__("invalid credentials")


class IdentityUnavailable(Exception):
    def __init__(self) -> None:
        super().__init__("identity verification unavailable")


@dataclass(frozen=True, slots=True)
class VerifiedPrincipal:
    issuer: str
    subject: str


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON member")
        result[key] = value
    return result


def _segment(value: str) -> dict[str, Any]:
    if re.fullmatch(r"[A-Za-z0-9_-]+", value) is None:
        raise ValueError("malformed JWT segment")
    decoded = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    result = json.loads(decoded, object_pairs_hook=_unique_object)
    if not isinstance(result, dict):
        raise ValueError("JWT object required")
    return result


class OidcVerifier:
    """One process-local, bounded JWKS cache; no token/authorization-result cache.

    Use as an async context manager. A transport/clock injection is only for tests;
    request input never selects either or changes deployment settings.
    """

    def __init__(
        self,
        settings: OidcSettings,
        *,
        transport: httpx.AsyncBaseTransport | None = None,
        clock: Callable[[], float] = monotonic,
        trust: ssl.SSLContext | None = None,
    ) -> None:
        self._settings = settings
        trust = trust if trust is not None else ssl.create_default_context(cafile=settings.ca_file)
        self._client = httpx.AsyncClient(
            verify=trust,
            trust_env=False,
            follow_redirects=False,
            timeout=httpx.Timeout(5.0, connect=2.0, pool=2.0),
            limits=httpx.Limits(max_connections=1, max_keepalive_connections=1),
            transport=transport,
        )
        self._clock = clock
        self._expires = 0.0
        self._keys: dict[str, RSAPublicKey] = {}
        self._refresh_lock = Lock()
        self._crypto_slots = CapacityLimiter(2)

    async def __aenter__(self) -> "OidcVerifier":
        return self

    async def __aexit__(self, *args: object) -> None:
        await self._client.aclose()

    async def _refresh(self) -> None:
        try:
            async with self._client.stream("GET", self._settings.jwks_url) as response:
                if response.status_code != 200:
                    raise ValueError("JWKS response unavailable")
                data = bytearray()
                async for chunk in response.aiter_bytes():
                    if len(data) + len(chunk) > 65536:
                        raise ValueError("oversized JWKS")
                    data.extend(chunk)
            payload = json.loads(data, object_pairs_hook=_unique_object)
            if not isinstance(payload, dict) or not isinstance(payload.get("keys"), list):
                raise ValueError("invalid JWKS")
            entries = payload["keys"]
            if not 1 <= len(entries) <= 64:
                raise ValueError("invalid JWKS key count")
            keys: dict[str, RSAPublicKey] = {}
            for entry in entries:
                if not isinstance(entry, dict):
                    raise ValueError("invalid JWK")
                if entry.get("kty") != "RSA" or entry.get("use", "sig") != "sig":
                    continue
                if entry.get("alg", "RS256") != "RS256":
                    continue
                if "key_ops" in entry and entry["key_ops"] != ["verify"]:
                    continue
                kid = entry.get("kid")
                if not isinstance(kid, str) or not 1 <= len(kid) <= 128 or kid in keys:
                    raise ValueError("invalid JWK identifier")
                key = jwt.PyJWK.from_dict(entry, algorithm="RS256").key
                if not isinstance(key, RSAPublicKey) or not 2048 <= key.key_size <= 4096:
                    raise ValueError("invalid RSA key")
                keys[kid] = key
            if not keys:
                raise ValueError("no allowed signing key")
            self._keys = keys
            self._expires = self._clock() + self._settings.cache_seconds
        except (
            httpx.HTTPError,
            ValueError,
            jwt.PyJWTError,
            KeyError,
            TypeError,
            RecursionError,
            OverflowError,
        ):
            raise IdentityUnavailable() from None

    async def verify(self, token: str) -> VerifiedPrincipal:
        try:
            if not isinstance(token, str) or not 1 <= len(token) <= 16384:
                raise ValueError("invalid token size")
            header_part, payload_part, signature = token.split(".")
            header, claims = _segment(header_part), _segment(payload_part)
            if re.fullmatch(r"[A-Za-z0-9_-]+", signature) is None:
                raise ValueError("invalid signature encoding")
            kid = header.get("kid")
            if (
                header.get("alg") not in self._settings.algorithms
                or not isinstance(kid, str)
                or not 1 <= len(kid) <= 128
                or "crit" in header
                or header.get("b64", True) is not True
            ):
                raise ValueError("invalid JOSE header")
            for name in ("exp", "nbf", "iat"):
                if name in claims and (
                    type(claims[name]) not in (int, float)
                    or not math.isfinite(claims[name])
                    or not 0 <= claims[name] <= 2**63 - 1
                ):
                    raise ValueError("invalid NumericDate")
        except (ValueError, TypeError, OverflowError, RecursionError):
            raise InvalidIdentity() from None
        # jku/x5u/header keys are never followed. Only this deployment's JWKS is used.
        try:
            with fail_after(5):
                async with self._refresh_lock:
                    if self._clock() >= self._expires or kid not in self._keys:
                        # One fetch when empty/expired, or one refresh for an unknown kid.
                        await self._refresh()
                    key = self._keys.get(kid)
                if key is None:
                    raise InvalidIdentity()
                return await to_thread.run_sync(
                    self._verify_signature, token, key, limiter=self._crypto_slots
                )
        except TimeoutError:
            raise IdentityUnavailable() from None

    def _verify_signature(self, token: str, key: RSAPublicKey) -> VerifiedPrincipal:
        try:
            claims = jwt.decode(
                token,
                key,
                algorithms=list(self._settings.algorithms),
                issuer=self._settings.issuer,
                audience=self._settings.audience,
                leeway=self._settings.clock_skew_seconds,
                options={"require": ["exp", "iss", "sub", "aud"], "verify_nbf": True},
            )
            subject = claims["sub"]
            if (
                not isinstance(subject, str)
                or not 1 <= len(subject) <= 255
                or any(ord(c) < 32 or ord(c) == 127 for c in subject)
            ):
                raise ValueError("invalid subject")
            return VerifiedPrincipal(issuer=claims["iss"], subject=subject)
        except (jwt.PyJWTError, ValueError, KeyError, TypeError, OverflowError):
            raise InvalidIdentity() from None
