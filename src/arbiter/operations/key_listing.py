"""Admin-only metadata reads; no key issuer, verifier or pepper dependency."""

import re
from collections.abc import Sequence
from dataclasses import dataclass
from uuid import UUID

from arbiter.identity.access import AuthorizedMember, ManagementAccess
from arbiter.identity.key_cursor import InvalidKeyQuery, KeyCursor
from arbiter.persistence.keys import KeyMetadataRecord, KeyRepository
from arbiter.persistence.tenant import TenantTransaction


@dataclass(frozen=True, slots=True)
class KeyPage:
    data: tuple[KeyMetadataRecord, ...]
    next_cursor: str | None


class KeyListService:
    def __init__(self, access: ManagementAccess, cursors: KeyCursor) -> None:
        self._access = access
        self._cursors = cursors

    async def list(self, token: str, selector: UUID, query: Sequence[tuple[str, str]]) -> KeyPage:
        def read(member: AuthorizedMember, scoped: TenantTransaction) -> KeyPage:
            values: dict[str, str] = {}
            for name, value in query:
                if name not in {"page_size", "cursor"} or name in values:
                    raise InvalidKeyQuery()
                values[name] = value
            size = values.get("page_size", "50")
            if re.fullmatch(r"[0-9]{1,3}", size) is None or not 1 <= int(size) <= 100:
                raise InvalidKeyQuery()
            page_size = int(size)
            tenant = scoped.context.tenant_id
            after = self._cursors.decode(tenant, values["cursor"]) if "cursor" in values else None
            rows = KeyRepository(scoped).list_page(page_size=page_size, after=after)
            page = rows[:page_size]
            cursor = self._cursors.encode(tenant, page[-1].id) if len(rows) > page_size else None
            return KeyPage(tuple(page), cursor)

        return await self._access.run(token, selector, read, require_admin=True)
