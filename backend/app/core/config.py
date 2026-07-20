import ipaddress
import re
import unicodedata
from functools import lru_cache
from typing import List
from urllib.parse import urlsplit

from pydantic import Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict
from sqlalchemy.engine import URL, make_url

from app.core.logging_config import normalize_log_level


DEFAULT_DEVELOPMENT_CORS_ALLOWED_ORIGINS = (
    "http://localhost:3000",
    "http://127.0.0.1:3000",
)
_ALLOWED_ORIGIN_SCHEMES = frozenset({"http", "https"})
_HOSTNAME_PATTERN = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*"
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$"
)


class Settings(BaseSettings):
    """Application settings loaded from environment variables.

    Real secrets must be provided through local .env files or deployment
    environment variables. Do not hardcode secrets in source code.
    """

    app_name: str = Field(default="Cyber OSINT Dashboard", alias="APP_NAME")
    app_version: str = Field(
        default="0.1.0",
        alias="APP_VERSION",
        min_length=1,
        max_length=64,
    )
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

    backend_cors_allowed_origins: str = Field(
        default=",".join(DEFAULT_DEVELOPMENT_CORS_ALLOWED_ORIGINS),
        alias="BACKEND_CORS_ALLOWED_ORIGINS",
    )

    nvd_api_key: SecretStr | None = Field(default=None, alias="NVD_API_KEY")
    fetch_interval_minutes: int = Field(default=30, alias="FETCH_INTERVAL_MINUTES")
    enable_admin_ingestion: bool = Field(default=False, alias="ENABLE_ADMIN_INGESTION")

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        hide_input_in_errors=True,
        populate_by_name=True,
    )

    @field_validator(
        "app_name",
        "app_version",
        "app_env",
        "log_level",
        "backend_host",
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

    @field_validator("log_level")
    @classmethod
    def validate_log_level(cls, value: str) -> str:
        """Normalize supported levels without exposing a rejected value."""

        return normalize_log_level(value)

    @field_validator("backend_cors_allowed_origins", mode="before")
    @classmethod
    def validate_cors_allowed_origins(cls, value: object) -> str:
        """Validate, normalize, and deduplicate exact comma-separated origins."""

        if not isinstance(value, str):
            raise ValueError("BACKEND_CORS_ALLOWED_ORIGINS must be comma-separated.")

        entries = value.split(",")
        trimmed_entries = [entry.strip(" ") for entry in entries]
        if not trimmed_entries or any(not entry for entry in trimmed_entries):
            raise ValueError("BACKEND_CORS_ALLOWED_ORIGINS contains an empty origin.")

        normalized_origins: list[str] = []
        seen_origins: set[str] = set()
        for entry in trimmed_entries:
            normalized_origin = cls._normalize_cors_origin(entry)
            if normalized_origin not in seen_origins:
                seen_origins.add(normalized_origin)
                normalized_origins.append(normalized_origin)

        return ",".join(normalized_origins)

    @model_validator(mode="after")
    def require_secure_production_cors(self) -> "Settings":
        """Require explicit non-loopback HTTPS frontend origins in production."""

        if self.app_env.lower() == "production":
            if self.debug:
                raise ValueError("DEBUG must be disabled when APP_ENV=production.")
            for origin in self.cors_origins_list:
                parsed = urlsplit(origin)
                host = parsed.hostname
                if (
                    parsed.scheme != "https"
                    or host is None
                    or self._is_loopback_origin_host(host)
                ):
                    raise ValueError(
                        "BACKEND_CORS_ALLOWED_ORIGINS must contain explicit "
                        "non-loopback HTTPS origins when APP_ENV=production."
                    )

        return self

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
        """Return the validated exact CORS origin allow-list.

        BACKEND_CORS_ALLOWED_ORIGINS is a comma-separated string,
        for example: http://localhost:3000,http://127.0.0.1:3000
        """

        return self.backend_cors_allowed_origins.split(",")

    @staticmethod
    def _normalize_cors_origin(origin: str) -> str:
        """Return one canonical origin after rejecting unsafe raw characters."""

        if any(
            character.isspace()
            or not character.isprintable()
            or unicodedata.category(character) in {"Cc", "Cf"}
            for character in origin
        ):
            raise ValueError(
                "BACKEND_CORS_ALLOWED_ORIGINS contains invalid characters."
            )

        try:
            parsed = urlsplit(origin)
            port = parsed.port
        except ValueError as exc:
            raise ValueError(
                "BACKEND_CORS_ALLOWED_ORIGINS contains a malformed origin."
            ) from exc

        scheme = parsed.scheme.lower()
        host = parsed.hostname
        if (
            scheme not in _ALLOWED_ORIGIN_SCHEMES
            or host is None
            or parsed.username is not None
            or parsed.password is not None
            or parsed.path
            or parsed.query
            or parsed.fragment
            or "*" in parsed.netloc
            or parsed.netloc.endswith(":")
            or port == 0
        ):
            raise ValueError(
                "BACKEND_CORS_ALLOWED_ORIGINS contains an invalid origin."
            )

        normalized_host = host.lower()
        try:
            parsed_ip = ipaddress.ip_address(normalized_host)
        except ValueError:
            if _HOSTNAME_PATTERN.fullmatch(normalized_host) is None:
                raise ValueError(
                    "BACKEND_CORS_ALLOWED_ORIGINS contains an invalid host."
                )
            rendered_host = normalized_host
        else:
            canonical_ip = str(parsed_ip)
            rendered_host = (
                f"[{canonical_ip}]" if parsed_ip.version == 6 else canonical_ip
            )

        default_port = 80 if scheme == "http" else 443
        rendered_port = f":{port}" if port not in {None, default_port} else ""
        return f"{scheme}://{rendered_host}{rendered_port}"

    @staticmethod
    def _is_loopback_origin_host(host: str) -> bool:
        normalized_host = host.lower()
        if normalized_host == "localhost" or normalized_host.endswith(".localhost"):
            return True

        try:
            return ipaddress.ip_address(normalized_host).is_loopback
        except ValueError:
            return False

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
