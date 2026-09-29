"""Scoped usage/request metadata reads; authorization happens in the access layers."""

from datetime import UTC, datetime
from uuid import UUID

from arbiter.identity.access import AuthorizedMember, ManagementAccess
from arbiter.persistence.tenant import TenantTransaction
from arbiter.persistence.usage import (
    RequestStatus,
    UsageRepository,
    UsageTotals,
    UsageUnit,
)


class InvalidUsageQuery(Exception):
    def __init__(self) -> None:
        super().__init__("invalid usage query")


def aligned_selector(window: str, start: str) -> tuple[UsageUnit, datetime]:
    """Parse a strict historical selector; reject anything the schema could not store.

    Stored window rows are CHECK-constrained to UTC day/month starts. A selector
    that is not exactly aligned can never match a stored window, so it is caller
    error (422), not an authoritative zero state. Future windows are not historical.
    """
    if window not in ("day", "month"):
        raise InvalidUsageQuery()
    unit: UsageUnit = "day" if window == "day" else "month"
    try:
        moment = datetime.fromisoformat(start)
    except ValueError:
        raise InvalidUsageQuery() from None
    if moment.tzinfo is None or moment.utcoffset() is None:
        raise InvalidUsageQuery()
    utc = moment.astimezone(UTC)
    if window == "day":
        aligned = utc.replace(hour=0, minute=0, second=0, microsecond=0)
    else:
        aligned = utc.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    if utc != aligned or aligned > datetime.now(UTC):
        raise InvalidUsageQuery()
    return unit, aligned


def current_window(unit: UsageUnit, now: datetime) -> datetime:
    utc = now.astimezone(UTC)
    if unit == "day":
        return utc.replace(hour=0, minute=0, second=0, microsecond=0)
    return utc.replace(day=1, hour=0, minute=0, second=0, microsecond=0)


class UsageReader:
    """Shared in-transaction reads for both identity paths; no per-caller branching."""

    def totals(self, scoped: TenantTransaction, unit: UsageUnit, start: datetime) -> UsageTotals:
        return UsageRepository(scoped).totals(unit, start)

    def request_status(self, scoped: TenantTransaction, request_id: UUID) -> RequestStatus | None:
        return UsageRepository(scoped).request_status(request_id)


class ManagementUsage:
    """Member/admin metadata reads; role enforcement belongs to ManagementAccess."""

    def __init__(self, access: ManagementAccess) -> None:
        self._access = access

    async def totals(
        self,
        token: str,
        selector: UUID,
        selector_window: str | None,
        selector_start: str | None,
    ) -> list[UsageTotals]:
        units: tuple[UsageUnit, ...]
        starts: dict[str, datetime]
        if selector_window is None and selector_start is None:
            units = ("day", "month")
            now = datetime.now(UTC)
            starts = {unit: current_window(unit, now) for unit in units}
        else:
            if selector_window is None or selector_start is None:
                raise InvalidUsageQuery()
            unit, start = aligned_selector(selector_window, selector_start)
            units, starts = (unit,), {unit: start}

        def read(member: AuthorizedMember, scoped: TenantTransaction) -> list[UsageTotals]:
            del member
            reader = UsageReader()
            return [reader.totals(scoped, unit, starts[unit]) for unit in units]

        return await self._access.run(token, selector, read, require_admin=False)

    async def request_status(
        self, token: str, selector: UUID, request_id: UUID
    ) -> RequestStatus | None:
        def read(member: AuthorizedMember, scoped: TenantTransaction) -> RequestStatus | None:
            del member
            return UsageReader().request_status(scoped, request_id)

        return await self._access.run(token, selector, read, require_admin=False)
