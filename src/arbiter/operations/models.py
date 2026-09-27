"""Shared catalog pagination executed only within an authenticated tenant transaction."""

import re
from collections.abc import Sequence
from dataclasses import dataclass
from uuid import UUID

from arbiter.identity.access import AuthorizedMember, ManagementAccess
from arbiter.identity.model_cursor import InvalidModelQuery, ModelCursor
from arbiter.persistence.models import ModelMetadataRecord, ModelRepository
from arbiter.persistence.tenant import TenantTransaction


@dataclass(frozen=True, slots=True)
class ModelPage:
    data: tuple[ModelMetadataRecord, ...]
    next_cursor: str | None


class ModelCatalog:
    def __init__(self, cursors: ModelCursor) -> None:
        self._cursors = cursors

    def read(self, scoped: TenantTransaction, query: Sequence[tuple[str, str]]) -> ModelPage:
        values: dict[str, str] = {}
        for name, value in query:
            if name not in {"page_size", "cursor"} or name in values:
                raise InvalidModelQuery()
            values[name] = value
        size = values.get("page_size", "50")
        if re.fullmatch(r"[0-9]{1,3}", size) is None or not 1 <= int(size) <= 100:
            raise InvalidModelQuery()
        tenant = scoped.context.tenant_id
        after = self._cursors.decode(tenant, values["cursor"]) if "cursor" in values else None
        rows = ModelRepository(scoped).list_page(page_size=int(size), after=after)
        page = rows[: int(size)]
        cursor = self._cursors.encode(tenant, page[-1].alias) if len(rows) > int(size) else None
        return ModelPage(tuple(page), cursor)


class ManagementModels:
    def __init__(self, access: ManagementAccess, catalog: ModelCatalog) -> None:
        self._access = access
        self._catalog = catalog

    async def list(self, token: str, selector: UUID, query: Sequence[tuple[str, str]]) -> ModelPage:
        def read(member: AuthorizedMember, scoped: TenantTransaction) -> ModelPage:
            return self._catalog.read(scoped, query)

        return await self._access.run(token, selector, read)
