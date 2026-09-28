"""Deterministic provider contract without a network, model, or database."""

from uuid import uuid4

import pytest

from arbiter.governance.fingerprint import Message
from arbiter.providers.double import DeterministicProvider
from arbiter.providers.port import ProviderRequest


def test_capabilities_and_validation_never_generate() -> None:
    model, request_id = uuid4(), uuid4()
    digest = "sha256:" + "d" * 64
    provider = DeterministicProvider(model, digest, 256)
    request = ProviderRequest(model, digest, request_id, (Message("user", "private fixture"),), 128)
    assert provider.capabilities().healthy
    provider.validate(request)
    assert provider.calls == ()
    with pytest.raises(ValueError, match="model unavailable"):
        provider.validate(ProviderRequest(uuid4(), digest, request_id, request.messages, 128))
    with pytest.raises(ValueError, match="model unavailable"):
        provider.validate(ProviderRequest(model, digest, request_id, request.messages, 257))
    assert provider.calls == ()
    assert "private fixture" not in repr(request)
    assert "private fixture" not in repr(provider)
