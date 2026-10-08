"""Capture the configured production sink rather than pytest's raw record formatter."""

import logging
from io import StringIO

import httpx
import pytest

from arbiter.observability import SafeFormatter


@pytest.fixture
def production_logs(client: httpx.AsyncClient, monkeypatch: pytest.MonkeyPatch) -> StringIO:
    # The client fixture configures the application's real logging handler first.
    del client
    handlers = [
        handler
        for handler in logging.getLogger().handlers
        if isinstance(handler, logging.StreamHandler)
        and isinstance(handler.formatter, SafeFormatter)
    ]
    assert len(handlers) == 1, "expected the configured production logging sink"
    output = StringIO()
    monkeypatch.setattr(handlers[0], "stream", output)
    return output
