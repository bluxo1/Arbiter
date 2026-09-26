from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from arbiter.config import DatabaseRole, DatabaseSettings
from arbiter.main import create_app


@pytest.fixture
def secret_directory(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    directory = tmp_path / "secrets"
    directory.mkdir()
    # Inert test credential only; never a deployment credential.
    (directory / "db_runtime_password").write_text("inert-test-password-" + "x" * 32)
    monkeypatch.setenv("ARBITER_DB_SECRET_DIRECTORY", str(directory))
    return directory


def test_health_stays_fail_closed(secret_directory: Path) -> None:
    with TestClient(create_app()) as client:
        assert client.get("/health/live").json() == {"status": "ok"}
        ready = client.get("/health/ready")
        assert ready.status_code == 503
        assert ready.json() == {"status": "not_ready"}


@pytest.mark.parametrize("path", ["/v1/chat/completions", "/v1/usage", "/v1/models"])
@pytest.mark.parametrize("tenant", ["tenant-a", "tenant-b"])
def test_no_tenant_or_provider_route(secret_directory: Path, path: str, tenant: str) -> None:
    with TestClient(create_app()) as client:
        response = client.post(path, headers={"X-Tenant-ID": tenant}, json={"tenant_id": tenant})
        assert response.status_code == 404


@pytest.mark.parametrize("path", ["/docs", "/redoc", "/openapi.json"])
def test_debug_documentation_disabled(secret_directory: Path, path: str) -> None:
    with TestClient(create_app()) as client:
        assert client.get(path).status_code == 404


def test_missing_runtime_secret_prevents_start(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("ARBITER_DB_SECRET_DIRECTORY", str(tmp_path))
    with pytest.raises(FileNotFoundError), TestClient(create_app()):
        pass


def test_runtime_secret_does_not_supply_privileged_credentials(secret_directory: Path) -> None:
    settings = DatabaseSettings()
    assert settings.url("runtime").username == "arbiter_runtime"
    assert settings.password("runtime").get_secret_value() not in str(settings.url("runtime"))
    roles: tuple[DatabaseRole, ...] = ("migration", "operator", "bootstrap")
    for role in roles:
        with pytest.raises(FileNotFoundError):
            settings.password(role)


def test_empty_secret_rejected(secret_directory: Path) -> None:
    (secret_directory / "db_runtime_password").write_text("")
    with pytest.raises(ValueError, match="database secret must contain"):
        DatabaseSettings().password("runtime")
