"""Deployment configuration: secret values never come from environment strings."""

from pathlib import Path
from typing import Literal

from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict
from sqlalchemy import URL

DatabaseRole = Literal["bootstrap", "migration", "operator", "runtime"]


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
