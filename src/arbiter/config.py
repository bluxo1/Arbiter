"""Deployment configuration: secret values never come from environment strings."""

import base64
from pathlib import Path
from typing import Literal
from urllib.parse import urlsplit

from pydantic import Field, SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict
from sqlalchemy import URL

DatabaseRole = Literal["bootstrap", "migration", "operator", "runtime", "maintenance"]


class FingerprintSettings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="ARBITER_FINGERPRINT_", frozen=True)

    key_file: Path = Path("/run/secrets/request_fingerprint_key")
    version: int = Field(default=1, ge=1, le=2147483647)

    def key(self) -> bytes:
        try:
            with self.key_file.open("rb") as stream:
                encoded = stream.read(129)
            if len(encoded) > 128:
                raise ValueError("oversized fingerprint key file")
            key = base64.b64decode(encoded.strip(), validate=True)
            if len(key) != 32:
                raise ValueError("invalid fingerprint key length")
            return key
        except ValueError:
            raise ValueError("invalid fingerprint key file") from None


class KeySettings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="ARBITER_KEYS_", frozen=True)

    pepper_file: Path = Path("/run/secrets/api_key_pepper")
    pepper_version: int = Field(default=1, ge=1, le=2147483647)

    def pepper(self) -> bytes:
        try:
            with self.pepper_file.open("rb") as stream:
                encoded = stream.read(129)
            if len(encoded) > 128:
                raise ValueError("oversized pepper file")
            pepper = base64.b64decode(encoded.strip(), validate=True)
            if len(pepper) != 32:
                raise ValueError("invalid pepper length")
            return pepper
        except ValueError:
            raise ValueError("invalid API key pepper file") from None


class AuditSettings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="ARBITER_AUDIT_", frozen=True)

    key_file: Path = Path("/run/secrets/audit_cursor_key")

    def key(self) -> bytes:
        try:
            encoded = self.key_file.read_bytes()
            if len(encoded) > 128:
                raise ValueError("oversized key file")
            key = base64.b64decode(encoded.strip(), validate=True)
            if len(key) != 32:
                raise ValueError("invalid key length")
            return key
        except ValueError:
            raise ValueError("invalid audit cursor key file") from None


class OidcSettings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="ARBITER_OIDC_", frozen=True)

    issuer: str
    audience: str = Field(min_length=1, max_length=255)
    jwks_url: str
    ca_file: Path | None = None
    algorithms: tuple[Literal["RS256"]] = ("RS256",)
    clock_skew_seconds: int = Field(default=60, ge=0, le=60)
    cache_seconds: int = Field(default=900, ge=1, le=900)

    @field_validator("issuer", "jwks_url")
    @classmethod
    def public_https_url(cls, value: str) -> str:
        parsed = urlsplit(value)
        if (
            not 1 <= len(value) <= 2048
            or parsed.scheme != "https"
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
            or any(c.isspace() or ord(c) < 32 for c in value)
        ):
            raise ValueError("public HTTPS identity URL required")
        _ = parsed.port
        return value


class RedisSettings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="ARBITER_REDIS_", frozen=True)

    host: str = "redis"
    port: int = Field(default=6379, ge=1, le=65535)


class OllamaSettings(BaseSettings):
    """Only the private Compose Ollama service is an allowed destination."""

    model_config = SettingsConfigDict(env_prefix="ARBITER_OLLAMA_", frozen=True)

    base_url: Literal["http://ollama:11434"] = "http://ollama:11434"


class DatabaseSettings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="ARBITER_DB_", frozen=True)

    host: str = "postgres"
    port: int = Field(default=5432, ge=1, le=65535)
    name: str = "arbiter"
    secret_directory: Path = Path("/run/secrets")

    def password(self, role: DatabaseRole) -> SecretStr:
        # Fixed roles and filenames; requests cannot select a credential.
        value = (self.secret_directory / f"db_{role}_password").read_text(encoding="utf-8").strip()
        if not 32 <= len(value) <= 128 or any(character.isspace() for character in value):
            raise ValueError("database secret must contain 32-128 non-whitespace characters")
        return SecretStr(value)

    def url(self, role: DatabaseRole) -> URL:
        return URL.create(
            "postgresql+psycopg",
            username=f"arbiter_{role}",
            password=self.password(role).get_secret_value(),
            host=self.host,
            port=self.port,
            database=self.name,
        )
