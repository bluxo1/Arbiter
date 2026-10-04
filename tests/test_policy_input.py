"""Offline validation/privacy and absence of an HTTP policy administrator."""

from dataclasses import replace
from pathlib import Path
from typing import cast
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from test_foundation import secret_directory as secret_directory

from arbiter.main import create_app
from arbiter.operations.policy import MAX_INTEGER, PolicyInput
from arbiter.operations.provision import main


@pytest.mark.parametrize("field", ["tenant_rate", "key_rate", "daily_quota", "monthly_budget"])
@pytest.mark.parametrize("value", [-1, True, 1.5, "60", MAX_INTEGER + 1])
def test_limits_are_checked_integers(field: str, value: object) -> None:
    with pytest.raises(ValueError):
        invalid = cast(int, value)
        if field == "tenant_rate":
            replace(PolicyInput(), tenant_rate=invalid)
        elif field == "key_rate":
            replace(PolicyInput(), key_rate=invalid)
        elif field == "daily_quota":
            replace(PolicyInput(), daily_quota=invalid)
        else:
            replace(PolicyInput(), monthly_budget=invalid)


@pytest.mark.parametrize("value", [-1, 3, 999, True, "1"])
def test_concurrency_cannot_exceed_measured_capacity(value: object) -> None:
    with pytest.raises(ValueError):
        replace(PolicyInput(), concurrency=cast(int, value))


@pytest.mark.parametrize(
    "aliases",
    [
        ("https://provider.invalid",),
        ("qwen:latest",),
        ("UPPER",),
        ("invalid alias",),
        ("x\n",),
        ("x" * 65,),
        ("duplicate", "duplicate"),
        tuple(f"alias-{index}" for index in range(33)),
        (None,),
        ["alias"],
    ],
)
def test_alias_input_is_bounded_and_canonical(aliases: object) -> None:
    with pytest.raises(ValueError):
        replace(PolicyInput(), aliases=cast(tuple[str, ...], aliases))


def test_zero_and_integer_boundaries_are_valid() -> None:
    assert PolicyInput(0, 0, 0, 0, 0).concurrency == 0
    assert PolicyInput(MAX_INTEGER, MAX_INTEGER, MAX_INTEGER, MAX_INTEGER, 2).concurrency == 2


@pytest.mark.parametrize("option", ["--tenant-rate", "--model-alias", "--role", "--provider-url"])
def test_cli_invalid_inputs_are_not_echoed(option: str, capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit):
        main(["set-tenant-policy", "--tenant", str(uuid4()), option, "sensitive-placeholder"])
    captured = capsys.readouterr()
    assert "sensitive-placeholder" not in captured.out + captured.err


def test_no_http_policy_superuser(secret_directory: Path) -> None:
    with TestClient(create_app()) as client:
        for path in (
            f"/v1/tenants/{uuid4()}/policy",
            "/v1/operator/policy",
        ):
            for response in (
                client.get(path),
                client.post(path, json={"role": "operator", "tenant_rate": 999}),
            ):
                assert response.status_code == 404
        assert client.get("/v1/chat/completions").status_code == 405
        assert client.post("/v1/chat/completions", json={"role": "operator"}).status_code == 401
        assert client.get("/health/ready").status_code == 503
