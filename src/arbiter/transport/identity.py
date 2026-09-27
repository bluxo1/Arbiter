"""Authentication parsing for future management routes; no route is enabled here."""

import re

from fastapi import Request

from arbiter.identity.oidc import InvalidIdentity


def management_bearer(request: Request) -> str:
    headers: list[tuple[bytes, bytes]] = request.scope["headers"]
    credentials = [value for name, value in headers if name.lower() == b"authorization"]
    if len(credentials) != 1 or any(name.lower() == b"x-api-key" for name, _ in headers):
        raise InvalidIdentity()
    try:
        scheme, token = credentials[0].decode("ascii").split(" ")
    except (UnicodeDecodeError, ValueError):
        raise InvalidIdentity() from None
    if (
        scheme.lower() != "bearer"
        or not 1 <= len(token) <= 16384
        or re.fullmatch(r"[A-Za-z0-9_.-]+", token) is None
    ):
        raise InvalidIdentity()
    return token
