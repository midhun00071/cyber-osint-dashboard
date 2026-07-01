from functools import lru_cache
from typing import List

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


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

    database_url: str = Field(
        default="postgresql://alpha_data_user:change_me_locally@localhost:5432/alpha_data_db",
        alias="DATABASE_URL",
    )

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


@lru_cache
def get_settings() -> Settings:
    """Return cached application settings."""

    return Settings()
