"""One narrow pre-context key resolver; no verifier or other key rows are returned."""

from dataclasses import dataclass
from typing import Literal
from uuid import UUID

from sqlalchemy import text
from sqlalchemy.engine import Connection

from arbiter.identity.keys import InvalidKey, KeyCandidate

KeyScope = Literal["inference:write", "usage:read"]


@dataclass(frozen=True, slots=True)
class KeyBinding:
    key_id: UUID
    tenant_id: UUID
    scopes: tuple[KeyScope, ...]


def resolve_key(connection: Connection, candidate: KeyCandidate) -> KeyBinding:
    row = connection.execute(
        text(
            "SELECT key_id,tenant_id,scopes "
            "FROM arbiter.resolve_api_key(:public,:candidate,:version)"
        ),
        {
            "public": candidate.public_id,
            "candidate": candidate.verifier.get_secret_value(),
            "version": candidate.pepper_version,
        },
    ).one_or_none()
    if row is None:
        raise InvalidKey()
    if (
        not isinstance(row.key_id, UUID)
        or not isinstance(row.tenant_id, UUID)
        or not row.scopes
        or any(scope not in {"inference:write", "usage:read"} for scope in row.scopes)
    ):
        raise InvalidKey()
    return KeyBinding(row.key_id, row.tenant_id, tuple(row.scopes))
