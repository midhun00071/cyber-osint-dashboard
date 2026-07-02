from functools import lru_cache
from typing import List

from pydantic import Field, SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict
from sqlalchemy.engine import URL, make_url


class Settings(BaseSettings):
    """Application settings loaded from environment variables.

    Real secrets must be provided through local .env files or deployment
    environment variables. Do not hardcode secrets in source code.
    """

    app_name: str = Field(default="Cyber OSINT Dashboard", alias="APP_NAME")
    app_env: str = Field(default="development", alias="APP_ENV")
    debug: bool = Field(default=False, alias="DEBUG")
    log_level: str = Field(default="INFO", alias="LOG_LEVEL")

    backend_host: str = Field(default="0.0.0.0", alias="BACKEND_HOST")
    backend_port: int = Field(default=8000, alias="BACKEND_PORT")

    database_url: SecretStr | None = Field(default=None, alias="DATABASE_URL")
    postgres_host: str | None = Field(default=None, alias="POSTGRES_HOST")
    postgres_port: int | None = Field(
        default=None,
        alias="POSTGRES_PORT",
        ge=1,
        le=65535,
    )
    postgres_db: str | None = Field(default=None, alias="POSTGRES_DB")
    postgres_user: str | None = Field(default=None, alias="POSTGRES_USER")
    postgres_password: SecretStr | None = Field(default=None, alias="POSTGRES_PASSWORD")

    backend_cors_origins: str = Field(
        default="http://localhost:3000",
        alias="BACKEND_CORS_ORIGINS",
    )

    nvd_api_key: str | None = Field(default=None, alias="NVD_API_KEY")
    fetch_interval_minutes: int = Field(default=30, alias="FETCH_INTERVAL_MINUTES")
    enable_admin_ingestion: bool = Field(default=False, alias="ENABLE_ADMIN_INGESTION")

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        populate_by_name=True,
    )

    @field_validator(
        "app_name",
        "app_env",
        "log_level",
        "backend_host",
        "backend_cors_origins",
        "postgres_host",
        "postgres_db",
        "postgres_user",
        mode="before",
    )
    @classmethod
    def strip_string_settings(cls, value: object) -> object:
        """Trim non-secret string settings without changing passwords."""

        if isinstance(value, str):
            stripped_value = value.strip()
            return stripped_value or None

        return value

    @field_validator("database_url", mode="before")
    @classmethod
    def strip_database_url(cls, value: object) -> object:
        """Trim the optional URL override while preserving hidden representation."""

        if isinstance(value, str):
            stripped_value = value.strip()
            return stripped_value or None

        return value

    @property
    def cors_origins_list(self) -> List[str]:
        """Return CORS origins as a cleaned list.

        BACKEND_CORS_ORIGINS should be provided as a comma-separated string,
        for example: http://localhost:3000,http://127.0.0.1:3000
        """

        return [
            origin.strip()
            for origin in self.backend_cors_origins.split(",")
            if origin.strip()
        ]

    @property
    def sqlalchemy_database_url(self) -> URL:
        """Return the database URL for SQLAlchemy without exposing secrets."""

        if self.database_url is not None:
            return self._normalized_database_url(
                self.database_url.get_secret_value(),
            )

        missing_variables = self._missing_database_components()

        if missing_variables:
            missing_list = ", ".join(missing_variables)
            raise ValueError(f"Missing database configuration: {missing_list}")

        assert self.postgres_host is not None
        assert self.postgres_port is not None
        assert self.postgres_db is not None
        assert self.postgres_user is not None
        assert self.postgres_password is not None

        return URL.create(
            drivername="postgresql+psycopg",
            username=self.postgres_user,
            password=self.postgres_password.get_secret_value(),
            host=self.postgres_host,
            port=self.postgres_port,
            database=self.postgres_db,
        )

    def _missing_database_components(self) -> list[str]:
        missing_variables: list[str] = []

        if not self.postgres_host:
            missing_variables.append("POSTGRES_HOST")

        if self.postgres_port is None:
            missing_variables.append("POSTGRES_PORT")

        if not self.postgres_db:
            missing_variables.append("POSTGRES_DB")

        if not self.postgres_user:
            missing_variables.append("POSTGRES_USER")

        if (
            self.postgres_password is None
            or self.postgres_password.get_secret_value() == ""
        ):
            missing_variables.append("POSTGRES_PASSWORD")

        return missing_variables

    @staticmethod
    def _normalized_database_url(database_url: str) -> URL:
        parsed_url = make_url(database_url)

        if parsed_url.drivername == "postgresql":
            return parsed_url.set(drivername="postgresql+psycopg")

        if parsed_url.drivername == "postgresql+psycopg":
            return parsed_url

        raise ValueError("Unsupported database scheme. Use postgresql+psycopg.")


@lru_cache
def get_settings() -> Settings:
    """Return cached application settings."""

    return Settings()
