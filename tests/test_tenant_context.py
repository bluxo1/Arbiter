"""Context value guardrails; PostgreSQL isolation is tested separately."""

from dataclasses import FrozenInstanceError
from typing import cast
from uuid import UUID, uuid4

import pytest
from sqlalchemy.engine import Engine

from arbiter.identity.context import TenantContext
from arbiter.persistence.tenant import tenant_transaction


def test_context_is_immutable() -> None:
    context = TenantContext(uuid4())
    field_name = "tenant_id"
    with pytest.raises(FrozenInstanceError):
        setattr(context, field_name, uuid4())


@pytest.mark.parametrize("invalid", [None, "caller-selected-text"])
def test_context_rejects_untyped_tenant_values(invalid: object) -> None:
    with pytest.raises(TypeError, match="requires a UUID"):
        TenantContext(cast(UUID, invalid))


def test_missing_context_is_rejected_before_connecting() -> None:
    with pytest.raises(TypeError, match="trusted tenant context"):
        with tenant_transaction(cast(Engine, None), cast(TenantContext, None)):
            pytest.fail("missing context accepted")
