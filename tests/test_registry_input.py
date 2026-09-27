"""Strict configuration/attestation validation without contacting a provider."""

import json
from dataclasses import replace
from pathlib import Path
from typing import Any, cast

import pytest
from sqlalchemy.engine import Engine

from arbiter.operations.registry import ModelApproval, ModelInput, RegistryService, read_approval


def approval_values() -> dict[str, Any]:
    return dict(
        adapter="ollama",
        model_digest="sha256:" + "a" * 64,
        runtime_digest="sha256:" + "b" * 64,
        verification_digest="sha256:" + "c" * 64,
        context_cap=4096,
        output_cap=1024,
        verified_text=True,
        license_accepted=True,
    )


def approval() -> ModelApproval:
    return ModelApproval.model_validate(approval_values())


def configuration(alias: str = "fixture-model") -> ModelInput:
    return ModelInput(alias, "ollama", "sha256:" + "a" * 64, 4096, 256, 10, True)


@pytest.mark.parametrize(
    "field,value",
    [
        ("alias", ""),
        ("alias", "Native:latest"),
        ("alias", "https://private.invalid"),
        ("alias", "a" * 65),
        ("adapter", "remote"),
        ("model_digest", "latest"),
        ("model_digest", "sha256:" + "A" * 64),
        ("context_cap", 0),
        ("context_cap", -1),
        ("context_cap", True),
        ("context_cap", 2**63),
        ("output_cap", 0),
        ("output_cap", 1025),
        ("credit_charge", 0),
        ("credit_charge", -1),
        ("credit_charge", 1.5),
        ("credit_charge", 2**63),
        ("active", "true"),
    ],
)
def test_invalid_registry_configuration(field: str, value: Any) -> None:
    with pytest.raises(ValueError):
        replace(configuration(), **{field: value})


@pytest.mark.parametrize(
    "field,value",
    [
        ("adapter", "remote"),
        ("model_digest", "latest"),
        ("runtime_digest", "missing"),
        ("verification_digest", "missing"),
        ("context_cap", 0),
        ("output_cap", 1025),
        ("verified_text", False),
        ("verified_text", "true"),
        ("license_accepted", False),
        ("license_accepted", 1),
        ("provider_url", "https://private.invalid"),
        ("secret", "rejected-marker"),
    ],
)
def test_invalid_or_unapproved_attestation(field: str, value: Any) -> None:
    with pytest.raises(ValueError):
        ModelApproval.model_validate({**approval_values(), field: value})


def test_approval_file_strict_bounded_duplicate_and_missing(tmp_path: Path) -> None:
    path = tmp_path / "approval.json"
    path.write_text(json.dumps(approval_values()))
    assert read_approval(path) == approval() and len(approval().digest()) == 71
    for content in ("not-json", "[]", '{"adapter":"ollama","adapter":"ollama"}', " " * 8193):
        path.write_text(content)
        with pytest.raises(ValueError):
            read_approval(path)
    with pytest.raises(OSError):
        read_approval(tmp_path / "absent")
    with pytest.raises(ValueError):
        replace(configuration(), context_cap=1)


@pytest.mark.parametrize(
    "field,value",
    [("model_digest", "sha256:" + "d" * 64), ("context_cap", 8192), ("output_cap", 1024)],
)
def test_unapproved_configuration_rejected_before_connection(field: str, value: Any) -> None:
    class NeverConnect:
        def connect(self) -> None:
            raise AssertionError("unapproved configuration reached database")

    # Real service validation, not a permissive provider mock.
    attestation = approval()
    if field == "output_cap":
        attestation = attestation.model_copy(update={"output_cap": 256})
    with pytest.raises(ValueError, match="unapproved model configuration"):
        RegistryService(cast(Engine, NeverConnect())).provision(
            replace(configuration(), **{field: value}), attestation
        )
