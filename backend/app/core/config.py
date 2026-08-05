import ipaddress
import re
import stat
import unicodedata
from functools import lru_cache
from pathlib import Path
from typing import List, Literal
from urllib.parse import urlsplit

from pydantic import Field, SecretStr, field_validator, model_validator
from pydantic_settings import (
    BaseSettings,
    DotEnvSettingsSource,
    EnvSettingsSource,
    PydanticBaseSettingsSource,
    SettingsConfigDict,
)
from sqlalchemy.engine import URL, make_url
from sqlalchemy.exc import ArgumentError

from app.core.logging_config import normalize_log_level


EnvironmentIdentity = Literal["local", "test", "staging", "production"]
DEFAULT_LOCAL_CORS_ALLOWED_ORIGINS = (
    "http://localhost:3000",
    "http://127.0.0.1:3000",
)
DEFAULT_LOCAL_TRUSTED_HOSTS = (
    "localhost",
    "127.0.0.1",
    "[::1]",
    "testserver",
)
PROTECTED_ENVIRONMENTS = frozenset({"staging", "production"})
SUPPORTED_ENVIRONMENTS = frozenset(
    {"local", "test", "staging", "production", "development"}
)
_ALLOWED_ORIGIN_SCHEMES = frozenset({"http", "https"})
_HOSTNAME_PATTERN = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*"
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$"
)
_POSTGRES_IDENTIFIER_PATTERN = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,62}$")
_MAX_PASSWORD_FILE_BYTES = 4096
MAX_HTTP_HOST_HEADER_BYTES = 259
_STRICT_INTEGER_FIELD_NAMES = frozenset(
    {
        "database_pool_size",
        "database_max_overflow",
        "database_pool_timeout_seconds",
        "database_pool_recycle_seconds",
        "database_connect_timeout_seconds",
        "auth_session_ttl_minutes",
        "auth_session_absolute_ttl_minutes",
        "auth_max_active_sessions",
        "auth_login_failure_limit",
        "auth_login_failure_window_seconds",
        "auth_login_block_seconds",
    }
)
_STRICT_BOOLEAN_FIELD_NAMES = frozenset({"auth_cookie_secure"})


class _StrictPoolIntegerSourceMixin:
    """Parse canonical decimal values only at environment-source boundaries."""

    def prepare_field_value(self, field_name, field, value, value_is_complex):
        prepared = super().prepare_field_value(
            field_name,
            field,
            value,
            value_is_complex,
        )
        if (
            field_name in _STRICT_INTEGER_FIELD_NAMES
            and isinstance(prepared, str)
            and re.fullmatch(r"[0-9]+", prepared, flags=re.ASCII)
        ):
            return int(prepared)
        if field_name in _STRICT_BOOLEAN_FIELD_NAMES and isinstance(prepared, str):
            if prepared == "true":
                return True
            if prepared == "false":
                return False
        return prepared


class _StrictPoolEnvSettingsSource(
    _StrictPoolIntegerSourceMixin,
    EnvSettingsSource,
):
    pass


class _StrictPoolDotEnvSettingsSource(
    _StrictPoolIntegerSourceMixin,
    DotEnvSettingsSource,
):
    pass


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
    app_env: str = Field(default="local", alias="APP_ENV")
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
    postgres_password_file: str | None = Field(
        default=None,
        alias="POSTGRES_PASSWORD_FILE",
        max_length=4096,
    )
    database_pool_size: int = Field(
        default=5,
        alias="DATABASE_POOL_SIZE",
        strict=True,
        ge=1,
        le=20,
    )
    database_max_overflow: int = Field(
        default=5,
        alias="DATABASE_MAX_OVERFLOW",
        strict=True,
        ge=0,
        le=20,
    )
    database_pool_timeout_seconds: int = Field(
        default=30,
        alias="DATABASE_POOL_TIMEOUT_SECONDS",
        strict=True,
        ge=1,
        le=60,
    )
    database_pool_recycle_seconds: int = Field(
        default=1800,
        alias="DATABASE_POOL_RECYCLE_SECONDS",
        strict=True,
        ge=60,
        le=3600,
    )
    database_connect_timeout_seconds: int = Field(
        default=10,
        alias="DATABASE_CONNECT_TIMEOUT_SECONDS",
        strict=True,
        ge=1,
        le=30,
    )

    backend_cors_allowed_origins: str = Field(
        default=",".join(DEFAULT_LOCAL_CORS_ALLOWED_ORIGINS),
        alias="BACKEND_CORS_ALLOWED_ORIGINS",
    )
    backend_trusted_hosts: str = Field(
        default=",".join(DEFAULT_LOCAL_TRUSTED_HOSTS),
        alias="BACKEND_TRUSTED_HOSTS",
    )

    auth_cookie_secure: bool = Field(
        default=False,
        alias="AUTH_COOKIE_SECURE",
        strict=True,
    )
    auth_session_ttl_minutes: int = Field(
        default=60,
        alias="AUTH_SESSION_TTL_MINUTES",
        strict=True,
        ge=5,
        le=480,
    )
    auth_session_absolute_ttl_minutes: int = Field(
        default=480,
        alias="AUTH_SESSION_ABSOLUTE_TTL_MINUTES",
        strict=True,
        ge=30,
        le=1440,
    )
    auth_max_active_sessions: int = Field(
        default=5,
        alias="AUTH_MAX_ACTIVE_SESSIONS",
        strict=True,
        ge=1,
        le=20,
    )
    auth_login_failure_limit: int = Field(
        default=5,
        alias="AUTH_LOGIN_FAILURE_LIMIT",
        strict=True,
        ge=3,
        le=20,
    )
    auth_login_failure_window_seconds: int = Field(
        default=900,
        alias="AUTH_LOGIN_FAILURE_WINDOW_SECONDS",
        strict=True,
        ge=60,
        le=3600,
    )
    auth_login_block_seconds: int = Field(
        default=900,
        alias="AUTH_LOGIN_BLOCK_SECONDS",
        strict=True,
        ge=60,
        le=86400,
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

    @classmethod
    def settings_customise_sources(
        cls,
        settings_cls: type[BaseSettings],
        init_settings: PydanticBaseSettingsSource,
        env_settings: PydanticBaseSettingsSource,
        dotenv_settings: PydanticBaseSettingsSource,
        file_secret_settings: PydanticBaseSettingsSource,
    ) -> tuple[PydanticBaseSettingsSource, ...]:
        """Keep strict integers while accepting canonical environment syntax."""

        strict_env = _StrictPoolEnvSettingsSource(
            settings_cls,
            case_sensitive=env_settings.case_sensitive,
            env_prefix=env_settings.env_prefix,
            env_prefix_target=env_settings.env_prefix_target,
            env_nested_delimiter=env_settings.env_nested_delimiter,
            env_nested_max_split=env_settings.env_nested_max_split,
            env_ignore_empty=env_settings.env_ignore_empty,
            env_parse_none_str=env_settings.env_parse_none_str,
            env_parse_enums=env_settings.env_parse_enums,
        )
        strict_dotenv = _StrictPoolDotEnvSettingsSource(
            settings_cls,
            env_file=dotenv_settings.env_file,
            env_file_encoding=dotenv_settings.env_file_encoding,
            dotenv_filtering=dotenv_settings.dotenv_filtering,
            case_sensitive=dotenv_settings.case_sensitive,
            env_prefix=dotenv_settings.env_prefix,
            env_prefix_target=dotenv_settings.env_prefix_target,
            env_nested_delimiter=dotenv_settings.env_nested_delimiter,
            env_nested_max_split=dotenv_settings.env_nested_max_split,
            env_ignore_empty=dotenv_settings.env_ignore_empty,
            env_parse_none_str=dotenv_settings.env_parse_none_str,
            env_parse_enums=dotenv_settings.env_parse_enums,
        )
        return init_settings, strict_env, strict_dotenv, file_secret_settings

    @field_validator(
        "app_name",
        "app_version",
        "log_level",
        "backend_host",
        mode="before",
    )
    @classmethod
    def strip_string_settings(cls, value: object) -> object:
        """Trim non-secret string settings without changing passwords."""

        if isinstance(value, str):
            stripped_value = value.strip()
            return stripped_value or None

        return value

    @field_validator("postgres_host", mode="before")
    @classmethod
    def validate_postgres_host(cls, value: object) -> object:
        """Accept only a bare DNS name or IP address, never a URL or host:port."""

        if value is None:
            return None
        if not isinstance(value, str):
            raise ValueError("POSTGRES_HOST must be a valid database host.")
        if cls._contains_invalid_characters(value):
            raise ValueError("POSTGRES_HOST contains invalid characters.")

        normalized_host = value.strip().lower()
        if not normalized_host:
            return None
        if "://" in normalized_host or any(
            character in normalized_host for character in "/?#@\\%"
        ):
            raise ValueError("POSTGRES_HOST must be a bare database host.")

        ip_candidate = normalized_host
        if normalized_host.startswith("[") and normalized_host.endswith("]"):
            ip_candidate = normalized_host[1:-1]
        elif "[" in normalized_host or "]" in normalized_host:
            raise ValueError("POSTGRES_HOST must be a valid database host.")

        try:
            parsed_ip = ipaddress.ip_address(ip_candidate)
        except ValueError:
            if ":" in normalized_host or cls._is_ambiguous_numeric_host(
                normalized_host
            ):
                raise ValueError("POSTGRES_HOST must be a valid database host.")
            if _HOSTNAME_PATTERN.fullmatch(normalized_host) is None:
                raise ValueError("POSTGRES_HOST must be a valid database host.")
            return normalized_host

        return str(parsed_ip)

    @field_validator("postgres_db", "postgres_user", mode="before")
    @classmethod
    def validate_postgres_identifier(cls, value: object, info: object) -> object:
        """Constrain database and user names to safe PostgreSQL identifiers."""

        alias = "POSTGRES_DB" if getattr(info, "field_name", "") == "postgres_db" else "POSTGRES_USER"
        if value is None:
            return None
        if not isinstance(value, str):
            raise ValueError(f"{alias} must be a valid PostgreSQL identifier.")
        if cls._contains_invalid_characters(value):
            raise ValueError(f"{alias} contains invalid characters.")

        normalized_value = value.strip()
        if not normalized_value:
            return None
        if _POSTGRES_IDENTIFIER_PATTERN.fullmatch(normalized_value) is None:
            raise ValueError(f"{alias} must be a valid PostgreSQL identifier.")
        return normalized_value

    @field_validator("postgres_password_file", mode="before")
    @classmethod
    def validate_postgres_password_file_reference(cls, value: object) -> object:
        """Normalize only the non-secret file reference, never its contents."""

        if value is None:
            return None
        if not isinstance(value, str):
            raise ValueError("POSTGRES_PASSWORD_FILE must be a file reference.")
        if cls._contains_invalid_characters(value):
            raise ValueError("POSTGRES_PASSWORD_FILE contains invalid characters.")
        normalized_value = value.strip()
        return normalized_value or None

    @field_validator("log_level")
    @classmethod
    def validate_log_level(cls, value: str) -> str:
        """Normalize supported levels without exposing a rejected value."""

        return normalize_log_level(value)

    @field_validator("app_env", mode="before")
    @classmethod
    def validate_environment_identity(cls, value: object) -> str:
        """Normalize environment identity without falling back on bad input."""

        if not isinstance(value, str):
            raise ValueError("APP_ENV must name a supported environment.")

        normalized = value.strip().lower()
        if not normalized:
            raise ValueError("APP_ENV must not be blank.")
        if normalized not in SUPPORTED_ENVIRONMENTS:
            raise ValueError(
                "APP_ENV must be local, test, staging, or production."
            )
        return normalized

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

    @field_validator("backend_trusted_hosts", mode="before")
    @classmethod
    def validate_trusted_hosts(cls, value: object) -> str:
        """Validate and normalize an exact comma-separated Host allow-list."""

        if not isinstance(value, str):
            raise ValueError("BACKEND_TRUSTED_HOSTS must be comma-separated.")

        entries = [entry.strip(" ") for entry in value.split(",")]
        if not entries or any(not entry for entry in entries):
            raise ValueError("BACKEND_TRUSTED_HOSTS contains an empty host.")

        normalized_hosts: list[str] = []
        seen_hosts: set[str] = set()
        for entry in entries:
            normalized_host = cls._normalize_trusted_host(entry)
            if normalized_host not in seen_hosts:
                seen_hosts.add(normalized_host)
                normalized_hosts.append(normalized_host)

        return ",".join(normalized_hosts)

    @model_validator(mode="after")
    def require_secure_protected_environment(self) -> "Settings":
        """Fail closed on unsafe staging or production settings."""

        if self.database_pool_size + self.database_max_overflow > 30:
            raise ValueError(
                "DATABASE_POOL_SIZE plus DATABASE_MAX_OVERFLOW must not exceed 30."
            )

        if self.auth_session_ttl_minutes > self.auth_session_absolute_ttl_minutes:
            raise ValueError(
                "AUTH_SESSION_TTL_MINUTES must not exceed the absolute lifetime."
            )

        if self.postgres_password is not None and self.postgres_password_file:
            raise ValueError(
                "Configure only one of POSTGRES_PASSWORD or "
                "POSTGRES_PASSWORD_FILE."
            )

        if self.effective_environment in PROTECTED_ENVIRONMENTS:
            if "database_url" in self.model_fields_set:
                raise ValueError(
                    "DATABASE_URL is not permitted in staging or production; "
                    "use POSTGRES_* component settings."
                )
            if "postgres_password" in self.model_fields_set:
                raise ValueError(
                    "POSTGRES_PASSWORD is not permitted in staging or "
                    "production; use POSTGRES_PASSWORD_FILE."
                )
            if self.debug:
                raise ValueError(
                    "DEBUG must be disabled in staging and production."
                )
            if self.enable_admin_ingestion:
                raise ValueError(
                    "ENABLE_ADMIN_INGESTION must be disabled in staging and "
                    "production."
                )
            if "backend_cors_allowed_origins" not in self.model_fields_set:
                raise ValueError(
                    "BACKEND_CORS_ALLOWED_ORIGINS must be set explicitly in "
                    "staging and production."
                )
            if "backend_trusted_hosts" not in self.model_fields_set:
                raise ValueError(
                    "BACKEND_TRUSTED_HOSTS must be set explicitly in staging "
                    "and production."
                )
            for origin in self.cors_origins_list:
                parsed = urlsplit(origin)
                host = parsed.hostname
                if (
                    parsed.scheme != "https"
                    or host is None
                    or self._is_loopback_or_unspecified_host(host)
                ):
                    raise ValueError(
                        "BACKEND_CORS_ALLOWED_ORIGINS must contain explicit "
                        "non-loopback HTTPS origins in staging and production."
                    )
            for host in self.trusted_hosts_list:
                if self._is_loopback_or_unspecified_host(host.strip("[]")):
                    raise ValueError(
                        "BACKEND_TRUSTED_HOSTS must contain explicit "
                        "non-loopback hosts in staging and production."
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

    @property
    def trusted_hosts_list(self) -> List[str]:
        """Return the validated exact Host header allow-list."""

        return self.backend_trusted_hosts.split(",")

    @property
    def effective_environment(self) -> EnvironmentIdentity:
        """Return the canonical identity used for security decisions."""

        if self.app_env == "development":
            return "local"
        return self.app_env  # type: ignore[return-value]

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
            if Settings._is_ambiguous_numeric_host(normalized_host):
                raise ValueError(
                    "BACKEND_CORS_ALLOWED_ORIGINS contains an invalid host."
                )
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
    def _is_loopback_or_unspecified_host(host: str) -> bool:
        normalized_host = host.lower()
        if normalized_host == "localhost" or normalized_host.endswith(".localhost"):
            return True

        try:
            parsed_ip = ipaddress.ip_address(normalized_host)
            return parsed_ip.is_loopback or parsed_ip.is_unspecified
        except ValueError:
            return False

    @staticmethod
    def _contains_invalid_characters(value: str) -> bool:
        return any(
            character.isspace()
            and character != " "
            or not character.isprintable()
            or unicodedata.category(character) in {"Cc", "Cf"}
            for character in value
        )

    @staticmethod
    def _is_ambiguous_numeric_host(host: str) -> bool:
        """Reject legacy numeric forms that network stacks may reinterpret."""

        return bool(
            re.fullmatch(r"[0-9.]+", host)
            or host.startswith("0x")
            or any(label.startswith("0x") for label in host.split("."))
        )

    @staticmethod
    def _normalize_trusted_host(host: str) -> str:
        """Return one exact canonical host after rejecting wildcards/URLs."""

        if any(
            character.isspace()
            or not character.isprintable()
            or unicodedata.category(character) in {"Cc", "Cf"}
            for character in host
        ):
            raise ValueError("BACKEND_TRUSTED_HOSTS contains invalid characters.")
        if "*" in host or "://" in host or any(
            character in host for character in "/?#@"
        ):
            raise ValueError("BACKEND_TRUSTED_HOSTS contains an invalid host.")

        normalized_host = host.lower()
        ip_candidate = normalized_host
        if normalized_host.startswith("[") and normalized_host.endswith("]"):
            ip_candidate = normalized_host[1:-1]
        elif "[" in normalized_host or "]" in normalized_host:
            raise ValueError("BACKEND_TRUSTED_HOSTS contains an invalid host.")

        try:
            parsed_ip = ipaddress.ip_address(ip_candidate)
        except ValueError:
            if ":" in normalized_host or Settings._is_ambiguous_numeric_host(
                normalized_host
            ):
                raise ValueError("BACKEND_TRUSTED_HOSTS contains an invalid host.")
            if _HOSTNAME_PATTERN.fullmatch(normalized_host) is None:
                raise ValueError("BACKEND_TRUSTED_HOSTS contains an invalid host.")
            return normalized_host

        canonical_ip = str(parsed_ip)
        return f"[{canonical_ip}]" if parsed_ip.version == 6 else canonical_ip

    @staticmethod
    def normalize_http_host_header(host_header: str) -> str:
        """Return a configured-host-compatible value from one raw Host value."""

        if (
            not host_header
            or not host_header.isascii()
            or len(host_header) > MAX_HTTP_HOST_HEADER_BYTES
            or any(
                character.isspace()
                or not character.isprintable()
                or unicodedata.category(character) in {"Cc", "Cf"}
                for character in host_header
            )
            or any(
                character in host_header
                for character in "/?#@,\\%"
            )
        ):
            raise ValueError("Invalid Host header.")

        if host_header.startswith("["):
            if host_header.count("[") != 1 or host_header.count("]") != 1:
                raise ValueError("Invalid Host header.")
            closing_bracket = host_header.find("]")
            ip_candidate = host_header[1:closing_bracket]
            suffix = host_header[closing_bracket + 1 :]
            if not ip_candidate or (suffix and not suffix.startswith(":")):
                raise ValueError("Invalid Host header.")
            Settings._validate_http_host_port(suffix[1:] if suffix else None)
            try:
                parsed_ip = ipaddress.ip_address(ip_candidate)
            except ValueError:
                raise ValueError("Invalid Host header.") from None
            canonical_ip = str(parsed_ip)
            if parsed_ip.version != 6 or canonical_ip != ip_candidate.lower():
                raise ValueError("Invalid Host header.")
            return f"[{canonical_ip}]"

        if "[" in host_header or "]" in host_header or host_header.count(":") > 1:
            raise ValueError("Invalid Host header.")

        if ":" in host_header:
            host, port = host_header.split(":", maxsplit=1)
        else:
            host, port = host_header, None
        Settings._validate_http_host_port(port)
        normalized_host = host.lower()
        if not normalized_host:
            raise ValueError("Invalid Host header.")

        try:
            parsed_ip = ipaddress.ip_address(normalized_host)
        except ValueError:
            if Settings._is_ambiguous_numeric_host(normalized_host):
                raise ValueError("Invalid Host header.")
            if _HOSTNAME_PATTERN.fullmatch(normalized_host) is None:
                raise ValueError("Invalid Host header.")
            return normalized_host

        canonical_ip = str(parsed_ip)
        if parsed_ip.version != 4 or canonical_ip != normalized_host:
            raise ValueError("Invalid Host header.")
        return canonical_ip

    @staticmethod
    def _validate_http_host_port(port: str | None) -> None:
        if port is None:
            return
        if not port or not port.isascii() or not port.isdecimal():
            raise ValueError("Invalid Host header.")
        numeric_port = int(port)
        if numeric_port < 1 or numeric_port > 65535:
            raise ValueError("Invalid Host header.")

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
        database_password = self._database_password()

        return URL.create(
            drivername="postgresql+psycopg",
            username=self.postgres_user,
            password=database_password.get_secret_value(),
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

        if self.postgres_password_file is None and (
            self.postgres_password is None
            or self.postgres_password.get_secret_value() == ""
        ):
            if self.effective_environment in PROTECTED_ENVIRONMENTS:
                missing_variables.append("POSTGRES_PASSWORD_FILE")
            else:
                missing_variables.append("POSTGRES_PASSWORD")

        return missing_variables

    def _database_password(self) -> SecretStr:
        if self.postgres_password_file:
            try:
                password_path = Path(self.postgres_password_file)
                password_stat = password_path.stat()
                if not stat.S_ISREG(password_stat.st_mode):
                    raise ValueError
                with password_path.open("rb") as password_handle:
                    password_bytes = password_handle.read(_MAX_PASSWORD_FILE_BYTES + 1)
            except (OSError, ValueError):
                raise ValueError(
                    "POSTGRES_PASSWORD_FILE must reference a readable regular file."
                ) from None

            if len(password_bytes) > _MAX_PASSWORD_FILE_BYTES:
                raise ValueError(
                    "POSTGRES_PASSWORD_FILE exceeds the permitted size."
                )
            if not password_bytes or b"\x00" in password_bytes:
                raise ValueError(
                    "POSTGRES_PASSWORD_FILE contains invalid secret content."
                )

            normalized_password = password_bytes.rstrip(b"\r\n")
            if not normalized_password:
                raise ValueError(
                    "POSTGRES_PASSWORD_FILE contains invalid secret content."
                )
            try:
                decoded_password = normalized_password.decode("utf-8")
            except UnicodeDecodeError:
                raise ValueError(
                    "POSTGRES_PASSWORD_FILE contains invalid secret content."
                ) from None
            return SecretStr(decoded_password)

        assert self.postgres_password is not None
        return self.postgres_password

    @staticmethod
    def _normalized_database_url(database_url: str) -> URL:
        try:
            parsed_url = make_url(database_url)
            _ = parsed_url.port
        except (ArgumentError, TypeError, ValueError):
            raise ValueError(
                "DATABASE_URL must be a valid PostgreSQL URL."
            ) from None

        if parsed_url.drivername == "postgresql":
            parsed_url = parsed_url.set(drivername="postgresql+psycopg")
        elif parsed_url.drivername != "postgresql+psycopg":
            raise ValueError(
                "DATABASE_URL uses an unsupported database scheme; use "
                "postgresql+psycopg."
            )

        missing_categories: list[str] = []
        if not parsed_url.username:
            missing_categories.append("username")
        if parsed_url.password is None or parsed_url.password == "":
            missing_categories.append("password")
        if not parsed_url.host:
            missing_categories.append("host")
        if not parsed_url.database:
            missing_categories.append("database name")
        if missing_categories:
            raise ValueError(
                "DATABASE_URL is missing required configuration categories: "
                + ", ".join(missing_categories)
                + "."
            )

        return parsed_url

    def validate_startup(self) -> None:
        """Eagerly validate settings required before service availability."""

        if (
            self.effective_environment in PROTECTED_ENVIRONMENTS
            and not self.auth_cookie_secure
        ):
            raise ValueError(
                "AUTH_COOKIE_SECURE must be true in staging and production."
            )
        _ = self.sqlalchemy_database_url


@lru_cache
def get_settings() -> Settings:
    """Return cached application settings."""

    return Settings()
