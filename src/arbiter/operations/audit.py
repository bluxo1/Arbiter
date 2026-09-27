"""Read audit metadata only after identity, active membership and tenant binding."""

import re
from collections.abc import Sequence
from dataclasses import dataclass
from uuid import UUID

from arbiter.identity.access import AuthorizedMember, ManagementAccess
from arbiter.identity.audit_cursor import AuditCursor, AuditPosition, InvalidAuditQuery
from arbiter.persistence.repositories import AuditEvent, AuditRepository
from arbiter.persistence.tenant import TenantTransaction


@dataclass(frozen=True, slots=True)
class AuditPage:
    data: tuple[AuditEvent, ...]
    next_cursor: str | None


class AuditService:
    def __init__(self, access: ManagementAccess, cursors: AuditCursor) -> None:
        self._access = access
        self._cursors = cursors

    async def list(self, token: str, selector: UUID, query: Sequence[tuple[str, str]]) -> AuditPage:
        def read(member: AuthorizedMember, scoped: TenantTransaction) -> AuditPage:
            # Neither cursor nor query errors reveal whether an inaccessible tenant exists.
            values: dict[str, str] = {}
            for name, value in query:
                if name not in {"page_size", "cursor"} or name in values:
                    raise InvalidAuditQuery()
                values[name] = value
            size = values.get("page_size", "50")
            if re.fullmatch(r"[0-9]{1,3}", size) is None or not 1 <= int(size) <= 100:
                raise InvalidAuditQuery()
            page_size = int(size)
            tenant = scoped.context.tenant_id
            position = (
                self._cursors.decode(tenant, values["cursor"]) if "cursor" in values else None
            )
            events = AuditRepository(scoped).list_page(page_size=page_size, after=position)
            page = events[:page_size]
            cursor = None
            if len(events) > page_size:
                last = page[-1]
                cursor = self._cursors.encode(tenant, AuditPosition(last.occurred_at, last.id))
            return AuditPage(tuple(page), cursor)

        return await self._access.run(token, selector, read)
