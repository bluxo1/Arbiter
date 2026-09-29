import base64
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
    key_file = directory / "audit_cursor_key"
    key_file.write_bytes(base64.b64encode(bytes(32)))
    monkeypatch.setenv("ARBITER_AUDIT_KEY_FILE", str(key_file))
    pepper_file = directory / "api_key_pepper"
    pepper_file.write_bytes(base64.b64encode(bytes(32)))
    monkeypatch.setenv("ARBITER_KEYS_PEPPER_FILE", str(pepper_file))
    monkeypatch.setenv("ARBITER_KEYS_PEPPER_VERSION", "1")
    monkeypatch.setenv("ARBITER_OIDC_ISSUER", "https://fixture.invalid/issuer")
    monkeypatch.setenv("ARBITER_OIDC_AUDIENCE", "arbiter-api")
    monkeypatch.setenv("ARBITER_OIDC_JWKS_URL", "https://fixture.invalid/keys")
    monkeypatch.delenv("ARBITER_OIDC_CA_FILE", raising=False)
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
        # GET-only metadata routes reject POST with 405; inference remains absent.
        assert response.status_code == (405 if path in {"/v1/models", "/v1/usage"} else 404)


def test_provider_invocation_stays_inside_dispatch_service() -> None:
    package = Path(__file__).resolve().parents[1] / "src" / "arbiter"
    callers = {
        path.relative_to(package).as_posix()
        for path in package.rglob("*.py")
        if ".generate(" in path.read_text(encoding="utf-8")
    }
    assert callers == {"governance/dispatch.py"}
    for path in (package / "transport").rglob("*.py"):
        assert "arbiter.providers" not in path.read_text(encoding="utf-8")


@pytest.mark.parametrize("path", ["/docs", "/redoc", "/openapi.json"])
def test_debug_documentation_disabled(secret_directory: Path, path: str) -> None:
    with TestClient(create_app()) as client:
        assert client.get(path).status_code == 404


def test_missing_runtime_secret_prevents_start(
    secret_directory: Path,
) -> None:
    (secret_directory / "db_runtime_password").unlink()
    with pytest.raises(FileNotFoundError), TestClient(create_app()):
        pass


def test_runtime_secret_does_not_supply_privileged_credentials(
    secret_directory: Path,
) -> None:
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


def test_missing_cursor_secret_prevents_start(secret_directory: Path) -> None:
    (secret_directory / "audit_cursor_key").unlink()
    with pytest.raises(FileNotFoundError), TestClient(create_app()):
        pass


def test_invalid_cursor_secret_prevents_start(secret_directory: Path) -> None:
    (secret_directory / "audit_cursor_key").write_text("invalid-base64")
    with (
        pytest.raises(ValueError, match="invalid audit cursor key file"),
        TestClient(create_app()),
    ):
        pass


def test_missing_pepper_prevents_start(secret_directory: Path) -> None:
    (secret_directory / "api_key_pepper").unlink()
    with pytest.raises(FileNotFoundError), TestClient(create_app()):
        pass


@pytest.mark.parametrize("value", [b"invalid-base64", base64.b64encode(bytes(31)), b"x" * 129])
def test_invalid_pepper_prevents_start(secret_directory: Path, value: bytes) -> None:
    (secret_directory / "api_key_pepper").write_bytes(value)
    with (
        pytest.raises(ValueError, match="invalid API key pepper file"),
        TestClient(create_app()),
    ):
        pass


def test_missing_oidc_configuration_prevents_start(
    secret_directory: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("ARBITER_OIDC_ISSUER")
    with pytest.raises(ValueError), TestClient(create_app()):
        pass
