"""Strict authenticated system-health response models."""

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


HealthState = Literal["healthy", "degraded", "unhealthy", "stale", "disabled", "unknown"]


class HealthComponentResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: Literal[
        "backend",
        "database",
        "prefect_server",
        "prefect_worker",
        "ingestion_operations",
        "source_freshness",
        "storage",
        "deployment_identity",
    ]
    status: HealthState
    summary: str = Field(min_length=1, max_length=240)
    observations: dict[str, int | float | str | bool | None] = Field(default_factory=dict)


class SystemHealthResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: HealthState
    generated_at: datetime
    version: str = Field(min_length=1, max_length=64)
    commit_sha: str | None = Field(default=None, pattern=r"^[0-9a-f]{40}$")
    components: list[HealthComponentResponse] = Field(min_length=8, max_length=8)
