"""Tenant-scoped read of the immutable provider target selected at dispatch."""

from dataclasses import dataclass
from typing import Literal
from uuid import UUID

from sqlalchemy import text

from arbiter.persistence.tenant import TenantTransaction
from arbiter.persistence.workload import KeyBinding
from arbiter.providers.ollama import OllamaModelBinding
from arbiter.providers.port import ProviderPort


class ProviderBindingUnavailable(Exception):
    """No trusted binding was captured for this dispatched request."""


@dataclass(frozen=True, slots=True)
class PinnedModelIdentity:
    model_id: UUID
    digest: str
    revision: int


@dataclass(frozen=True, slots=True)
class TrustedProviderSelection:
    provider_kind: Literal["ollama"]
    ollama_binding: OllamaModelBinding

    def provider(self) -> ProviderPort:
        """Explicit trusted composition, with no alias or caller-selected provider."""
        from arbiter.providers.ollama import OllamaProvider

        return OllamaProvider(self.ollama_binding)


def dispatched_ollama_binding(
    transaction: TenantTransaction,
    binding: KeyBinding,
    request_id: UUID,
    pinned: PinnedModelIdentity,
) -> TrustedProviderSelection:
    if binding.tenant_id != transaction.context.tenant_id:
        raise RuntimeError("provider binding tenant mismatch")
    row = (
        transaction.connection()
        .execute(
            text("""
            SELECT model_id,model_digest,model_revision,provider_kind,native_name,
                context_cap,output_cap
            FROM arbiter.dispatched_provider_binding(:tenant,:key,:request)
            """),
            {"tenant": binding.tenant_id, "key": binding.key_id, "request": request_id},
        )
        .one_or_none()
    )
    if row is None:
        raise ProviderBindingUnavailable()
    if (
        row.model_id != pinned.model_id
        or row.model_digest != pinned.digest
        or row.model_revision != pinned.revision
    ):
        raise RuntimeError("pinned provider identity mismatch")
    if row.provider_kind != "ollama":
        raise RuntimeError("unsupported trusted provider binding")
    return TrustedProviderSelection(
        "ollama",
        OllamaModelBinding(
            row.model_id, row.model_digest, row.native_name, row.context_cap, row.output_cap
        ),
    )
