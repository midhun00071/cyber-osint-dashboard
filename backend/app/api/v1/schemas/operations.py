"""Strict allow-listed schemas for authenticated source operations."""

from __future__ import annotations

from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field


OperatorState = Literal["enabled", "paused", "disabled"]
EffectiveState = Literal[
    "not_implemented",
    "policy_disabled",
    "disabled",
    "paused",
    "licence_required",
    "credentials_required",
    "quota_unavailable",
    "rate_limited",
    "active",
    "eligible",
]


class StrictOperationRequest(BaseModel):
    """An intentionally empty JSON body that rejects mass assignment."""

    model_config = ConfigDict(extra="forbid", hide_input_in_errors=True)


class RunCountersResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")
    fetched: int = Field(ge=0)
    created: int = Field(ge=0)
    updated: int = Field(ge=0)
    unchanged: int = Field(ge=0)
    skipped: int = Field(ge=0)
    failed: int = Field(ge=0)
    error_count: int = Field(ge=0)


class RunResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")
    public_id: UUID
    cycle_public_id: UUID | None
    source_public_id: UUID
    source_slug: str
    source_name: str
    trigger_type: str
    status: str
    attempt_number: int
    retry_of_public_id: UUID | None
    accepted_at: datetime
    started_at: datetime
    finished_at: datetime | None
    duration_seconds: float | None = Field(ge=0)
    retryable: bool
    summary_message: str | None
    counters: RunCountersResponse


class RunListResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")
    items: list[RunResponse]
    total: int = Field(ge=0)
    limit: int = Field(ge=1, le=100)
    offset: int = Field(ge=0, le=100000)


class RunEventResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")
    sequence: int = Field(ge=1, le=100000)
    event_type: str
    from_status: str | None
    to_status: str | None
    message: str | None
    occurred_at: datetime


class RunEventListResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")
    items: list[RunEventResponse]
    total: int = Field(ge=0)
    limit: int = Field(ge=1, le=500)
    offset: int = Field(ge=0, le=100000)


class CycleResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")
    public_id: UUID
    trigger_type: str
    status: str
    started_at: datetime
    finished_at: datetime | None
    duration_seconds: float | None = Field(ge=0)
    sources_expected: int = Field(ge=0)
    sources_started: int = Field(ge=0)
    sources_completed: int = Field(ge=0)
    sources_successful: int = Field(ge=0)
    sources_non_successful: int = Field(ge=0)
    summary_message: str | None


class CycleListResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")
    items: list[CycleResponse]
    total: int = Field(ge=0)
    limit: int = Field(ge=1, le=100)
    offset: int = Field(ge=0, le=100000)


class SourceProgressResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")
    kind: Literal["none", "checkpoint", "watermark"]
    version: int | None = Field(default=None, ge=1)
    committed_at: datetime | None
    fingerprint: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")


class LatestRunResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")
    public_id: UUID
    status: str
    trigger_type: str
    attempt_number: int
    started_at: datetime
    finished_at: datetime | None


class SourceResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")
    public_id: UUID
    slug: str
    name: str
    source_type: str
    content_type: str
    access_class: str
    policy_state: str
    operator_state: OperatorState
    effective_state: EffectiveState
    credential_required: bool
    credential_configured: bool
    execution_available: bool
    freshness: Literal["fresh", "stale", "never", "not_applicable"]
    progress: SourceProgressResponse
    latest_run: LatestRunResponse | None
    quota_state: str | None
    backoff_until: datetime | None
    next_scheduled_at: datetime | None
    available_actions: list[
        Literal["manual_run", "retry", "pause", "resume", "disable", "enable"]
    ]


class SourceListResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")
    items: list[SourceResponse]
    total: int = Field(ge=0)
    limit: int = Field(ge=1, le=100)
    offset: int = Field(ge=0, le=100000)


class OperationsSummaryResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")
    generated_at: datetime
    deployment_state: Literal["inactive", "available"]
    configured_handler_count: int = Field(ge=0)
    active_cycle_count: int = Field(ge=0)
    active_run_count: int = Field(ge=0)
    source_attention_count: int = Field(ge=0)
    run_counts_by_status: dict[str, int]
    latest_cycle: CycleResponse | None


class OperationAcceptanceResponse(BaseModel):
    model_config = ConfigDict(extra="forbid", from_attributes=True)
    cycle_public_id: UUID
    run_public_id: UUID
    source_slug: str
    trigger_type: Literal["manual", "retry"]
    status: str
    accepted_at: datetime
    replayed: bool


class SourceTransitionResponse(BaseModel):
    model_config = ConfigDict(extra="forbid", from_attributes=True)
    source_public_id: UUID
    source_slug: str
    prior_state: OperatorState
    operator_state: OperatorState
    changed: bool
