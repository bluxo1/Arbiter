"""Synthetic signed tokens test verifier behavior; live issuer evidence is separate."""

import json
from time import time

import httpx
import jwt
import pytest
from anyio import create_task_group
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import Request
from pydantic import ValidationError

from arbiter.config import OidcSettings
from arbiter.identity.oidc import IdentityUnavailable, InvalidIdentity, OidcVerifier
from arbiter.transport.identity import management_bearer

ISSUER = "https://localhost:18443/realms/arbiter"
JWKS = "https://arbiter-p0-keycloak:8443/realms/arbiter/protocol/openid-connect/certs"
pytestmark = pytest.mark.anyio


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.fixture(scope="module")
def private_key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def public_jwk(key: rsa.RSAPrivateKey, kid: str = "fixture") -> dict[str, object]:
    value: dict[str, object] = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(key.public_key()))
    return {**value, "kid": kid, "use": "sig", "alg": "RS256"}


def settings() -> OidcSettings:
    return OidcSettings(issuer=ISSUER, audience="arbiter-api", jwks_url=JWKS, clock_skew_seconds=0)


def claims() -> dict[str, object]:
    return {
        "iss": ISSUER,
        "sub": "opaque-subject",
        "aud": "arbiter-api",
        "exp": int(time()) + 300,
        "nbf": int(time()) - 1,
    }


def signed(
    key: rsa.RSAPrivateKey,
    values: dict[str, object] | None = None,
    *,
    kid: str = "fixture",
    headers: dict[str, object] | None = None,
) -> str:
    return jwt.api_jws.PyJWS().encode(
        json.dumps(claims() if values is None else values).encode(),
        key,
        algorithm="RS256",
        headers={"kid": kid, **(headers or {})},
    )


def response_transport(key: rsa.RSAPrivateKey) -> httpx.MockTransport:
    return httpx.MockTransport(
        lambda request: httpx.Response(200, json={"keys": [public_jwk(key)]})
    )


async def test_verified_identity_ignores_roles_tenants_and_key_urls(
    private_key: rsa.RSAPrivateKey,
) -> None:
    requests: list[str] = []

    def fetch(request: httpx.Request) -> httpx.Response:
        requests.append(str(request.url))
        return httpx.Response(200, json={"keys": [public_jwk(private_key)]})

    forged = {
        **claims(),
        "tenant_id": "other-tenant",
        "roles": ["admin"],
        "email": "alias@example.invalid",
    }
    async with OidcVerifier(settings(), transport=httpx.MockTransport(fetch)) as verifier:
        result = await verifier.verify(
            signed(
                private_key,
                forged,
                headers={"jku": "https://evil.invalid/keys", "x5u": "https://evil.invalid/cert"},
            )
        )
        assert (result.issuer, result.subject) == (ISSUER, "opaque-subject")
        assert requests == [JWKS]
        assert not hasattr(result, "role") and not hasattr(result, "tenant_id")


@pytest.mark.parametrize(
    "name,value",
    [
        ("iss", "https://other.invalid"),
        ("aud", "other-audience"),
        ("exp", 1),
        ("nbf", 2**40),
        ("exp", "9999999999"),
        ("exp", True),
        ("exp", None),
        ("sub", ""),
        ("sub", 42),
        ("sub", "x" * 256),
        ("sub", "bad\nsubject"),
        ("aud", []),
        ("iss", None),
        ("nbf", "tomorrow"),
    ],
)
async def test_invalid_claims(private_key: rsa.RSAPrivateKey, name: str, value: object) -> None:
    async with OidcVerifier(settings(), transport=response_transport(private_key)) as verifier:
        with pytest.raises(InvalidIdentity, match="^invalid credentials$"):
            await verifier.verify(signed(private_key, {**claims(), name: value}))


@pytest.mark.parametrize("missing", ["exp", "iss", "sub", "aud"])
async def test_required_claims(private_key: rsa.RSAPrivateKey, missing: str) -> None:
    values = claims()
    del values[missing]
    async with OidcVerifier(settings(), transport=response_transport(private_key)) as verifier:
        with pytest.raises(InvalidIdentity):
            await verifier.verify(signed(private_key, values))


async def test_optional_nbf_and_audience_list(private_key: rsa.RSAPrivateKey) -> None:
    values = claims()
    del values["nbf"]
    values["aud"] = ["other", "arbiter-api"]
    async with OidcVerifier(settings(), transport=response_transport(private_key)) as verifier:
        assert (await verifier.verify(signed(private_key, values))).subject == "opaque-subject"


@pytest.mark.parametrize("algorithm", ["HS256", "none", "RS512"])
async def test_disallowed_algorithms(private_key: rsa.RSAPrivateKey, algorithm: str) -> None:
    key = private_key if algorithm == "RS512" else ("x" * 32 if algorithm == "HS256" else "")
    token = jwt.encode(claims(), key, algorithm=algorithm, headers={"kid": "fixture"})

    def no_fetch(request: httpx.Request) -> httpx.Response:
        raise AssertionError("invalid algorithm must fail before JWKS IO")

    async with OidcVerifier(settings(), transport=httpx.MockTransport(no_fetch)) as verifier:
        with pytest.raises(InvalidIdentity):
            await verifier.verify(token)


async def test_bad_signature(private_key: rsa.RSAPrivateKey) -> None:
    other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    async with OidcVerifier(settings(), transport=response_transport(private_key)) as verifier:
        with pytest.raises(InvalidIdentity):
            await verifier.verify(signed(other))


@pytest.mark.parametrize(
    "token",
    [
        "",
        "broken",
        "a.b.c",
        "a.b.c.d",
        "x" * 16385,
        "e30.e30.eA",
        "W10.e30.eA",
        "eyJhbGciOiJSUzI1NiIsImFsZyI6IlJTMjU2In0.e30.eA",
    ],
)
async def test_malformed_tokens(token: str, private_key: rsa.RSAPrivateKey) -> None:
    async with OidcVerifier(settings(), transport=response_transport(private_key)) as verifier:
        with pytest.raises(InvalidIdentity):
            await verifier.verify(token)


@pytest.mark.parametrize(
    "payload",
    [
        [],
        {},
        {"keys": []},
        {"keys": [None]},
        {"keys": [{"kty": "oct", "kid": "fixture", "k": "eA", "alg": "HS256"}]},
    ],
)
async def test_malformed_jwks(payload: object, private_key: rsa.RSAPrivateKey) -> None:
    async with OidcVerifier(
        settings(), transport=httpx.MockTransport(lambda r: httpx.Response(200, json=payload))
    ) as verifier:
        with pytest.raises(IdentityUnavailable):
            await verifier.verify(signed(private_key))


@pytest.mark.parametrize("status", [301, 302, 404, 500])
async def test_jwks_errors_and_redirects_fail_closed(
    status: int, private_key: rsa.RSAPrivateKey
) -> None:
    seen: list[str] = []

    def fetch(request: httpx.Request) -> httpx.Response:
        seen.append(str(request.url))
        return httpx.Response(status, headers={"Location": "https://evil.invalid"})

    async with OidcVerifier(settings(), transport=httpx.MockTransport(fetch)) as verifier:
        with pytest.raises(IdentityUnavailable):
            await verifier.verify(signed(private_key))
    assert seen == [JWKS]


async def test_duplicate_jwk_and_oversized_jwks(private_key: rsa.RSAPrivateKey) -> None:
    for response in (
        httpx.Response(200, json={"keys": [public_jwk(private_key)] * 2}),
        httpx.Response(200, content=b"x" * 65537),
    ):
        async with OidcVerifier(
            settings(), transport=httpx.MockTransport(lambda r, response=response: response)
        ) as verifier:
            with pytest.raises(IdentityUnavailable):
                await verifier.verify(signed(private_key))


async def test_expired_cache_never_falls_back_on_fetch_failure(
    private_key: rsa.RSAPrivateKey,
) -> None:
    now = [0.0]
    count = [0]

    def fetch(request: httpx.Request) -> httpx.Response:
        count[0] += 1
        return (
            httpx.Response(200, json={"keys": [public_jwk(private_key)]})
            if count[0] == 1
            else httpx.Response(503)
        )

    async with OidcVerifier(
        settings(), transport=httpx.MockTransport(fetch), clock=lambda: now[0]
    ) as verifier:
        await verifier.verify(signed(private_key))
        now[0] = 899
        await verifier.verify(signed(private_key))
        assert count[0] == 1
        now[0] = 900
        with pytest.raises(IdentityUnavailable):
            await verifier.verify(signed(private_key))
        assert count[0] == 2


async def test_unknown_kid_refreshes_once_and_key_rotation(private_key: rsa.RSAPrivateKey) -> None:
    other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    count = [0]

    def fetch(request: httpx.Request) -> httpx.Response:
        count[0] += 1
        return httpx.Response(
            200,
            json={
                "keys": [public_jwk(private_key)]
                if count[0] == 1
                else [public_jwk(other, "rotated")]
            },
        )

    async with OidcVerifier(settings(), transport=httpx.MockTransport(fetch)) as verifier:
        await verifier.verify(signed(private_key))
        await verifier.verify(signed(other, kid="rotated"))
        assert count[0] == 2
        with pytest.raises(InvalidIdentity):
            await verifier.verify(signed(other, kid="absent"))
        assert count[0] == 3


async def test_simultaneous_initial_verification_fetches_once(
    private_key: rsa.RSAPrivateKey,
) -> None:
    seen: list[str] = []

    def fetch(request: httpx.Request) -> httpx.Response:
        seen.append(str(request.url))
        return httpx.Response(200, json={"keys": [public_jwk(private_key)]})

    async with OidcVerifier(settings(), transport=httpx.MockTransport(fetch)) as verifier:
        async with create_task_group() as group:
            for _ in range(20):
                group.start_soon(verifier.verify, signed(private_key))
    assert seen == [JWKS]


@pytest.mark.parametrize(
    "value",
    [
        "http://issuer.invalid",
        "https://user:password@issuer.invalid",
        "https://issuer.invalid?token=bad",
        "https://issuer.invalid/#fragment",
    ],
)
def test_unsafe_deployment_urls(value: str) -> None:
    with pytest.raises(ValidationError):
        OidcSettings(issuer=value, audience="arbiter-api", jwks_url=JWKS)


@pytest.mark.parametrize(
    "headers",
    [
        [],
        [(b"authorization", b"Bearer a"), (b"authorization", b"Bearer b")],
        [(b"authorization", b"Bearer a"), (b"x-api-key", b"b")],
        [(b"authorization", b"Basic a")],
        [(b"authorization", b"Bearer a,b")],
        [(b"authorization", b"Bearer  a")],
    ],
)
def test_mixed_or_invalid_authentication_inputs(headers: list[tuple[bytes, bytes]]) -> None:
    request = Request({"type": "http", "headers": headers})
    with pytest.raises(InvalidIdentity):
        management_bearer(request)


async def test_configured_skew_is_bounded_and_applied(private_key: rsa.RSAPrivateKey) -> None:
    config = OidcSettings(
        issuer=ISSUER, audience="arbiter-api", jwks_url=JWKS, clock_skew_seconds=60
    )
    async with OidcVerifier(config, transport=response_transport(private_key)) as verifier:
        await verifier.verify(signed(private_key, {**claims(), "exp": int(time()) - 30}))
        await verifier.verify(signed(private_key, {**claims(), "nbf": int(time()) + 30}))
        with pytest.raises(InvalidIdentity):
            await verifier.verify(signed(private_key, {**claims(), "nbf": int(time()) + 120}))
    with pytest.raises(ValidationError):
        OidcSettings(issuer=ISSUER, audience="arbiter-api", jwks_url=JWKS, clock_skew_seconds=61)


async def test_signed_duplicate_claims_rejected_before_jwks(private_key: rsa.RSAPrivateKey) -> None:
    token = jwt.api_jws.PyJWS().encode(
        b'{"iss":"one","iss":"two"}', private_key, algorithm="RS256", headers={"kid": "fixture"}
    )

    def no_fetch(request: httpx.Request) -> httpx.Response:
        raise AssertionError("ambiguous payload must fail before network IO")

    async with OidcVerifier(settings(), transport=httpx.MockTransport(no_fetch)) as verifier:
        with pytest.raises(InvalidIdentity):
            await verifier.verify(token)


async def test_jwks_timeout_is_sanitized(private_key: rsa.RSAPrivateKey) -> None:
    def timeout(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("private transport details", request=request)

    async with OidcVerifier(settings(), transport=httpx.MockTransport(timeout)) as verifier:
        with pytest.raises(IdentityUnavailable, match="^identity verification unavailable$"):
            await verifier.verify(signed(private_key))
