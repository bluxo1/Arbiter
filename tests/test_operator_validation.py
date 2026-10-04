"""Offline CLI input/error/privacy checks; isolation uses real PostgreSQL elsewhere."""

from pathlib import Path
from typing import cast

import pytest
from fastapi.testclient import TestClient
from test_foundation import secret_directory as secret_directory

from arbiter.main import create_app
from arbiter.operations.provision import MemberInput, MemberRole, main


@pytest.mark.parametrize(
    "issuer,subject,role",
    [
        ("http://issuer.invalid", "subject", "member"),
        ("https://user:credential@issuer.invalid", "subject", "member"),
        ("https://issuer.invalid?credential=value", "subject", "member"),
        ("https://issuer.invalid#fragment", "subject", "member"),
        ("https://issuer.invalid:99999", "subject", "member"),
        ("https://issuer.invalid", "", "member"),
        ("https://issuer.invalid", "subject\n", "member"),
        ("https://issuer.invalid", "x" * 256, "member"),
        ("https://issuer.invalid", "subject", "owner"),
    ],
)
def test_invalid_member_input(issuer: str, subject: str, role: str) -> None:
    with pytest.raises(ValueError):
        MemberInput(issuer, subject, cast(MemberRole, role))


@pytest.mark.parametrize(
    "arguments",
    [
        ["create-tenant", "--tenant", "credential-placeholder"],
        ["set-tenant-status", "--tenant", "credential-placeholder", "--status", "active"],
        ["create-member", "--tenant", "credential-placeholder"],
    ],
)
def test_argument_errors_do_not_echo_rejected_values(
    arguments: list[str], capsys: pytest.CaptureFixture[str]
) -> None:
    with pytest.raises(SystemExit, match="invalid arguments"):
        main(arguments)
    captured = capsys.readouterr()
    assert "credential-placeholder" not in captured.err + captured.out


def test_api_contains_no_operator_routes(
    secret_directory: Path,
) -> None:
    with TestClient(create_app()) as client:
        for path in (
            "/v1/operator",
            "/v1/tenants",
            "/v1/tenants/forged/members",
        ):
            assert client.get(path).status_code == 404
            assert client.post(path, json={"role": "operator"}).status_code == 404
        assert client.get("/v1/chat/completions").status_code == 405
        assert client.post("/v1/chat/completions", json={"role": "operator"}).status_code == 401
