"""Immutable binding supplied by trusted services, never by an HTTP selector.

This value does not verify identity or membership. No authentication entry point
exists yet; later services must establish authority before constructing it.
"""

from dataclasses import dataclass
from uuid import UUID


@dataclass(frozen=True, slots=True)
class TenantContext:
    tenant_id: UUID

    def __post_init__(self) -> None:
        if not isinstance(self.tenant_id, UUID):
            raise TypeError("tenant context requires a UUID")
