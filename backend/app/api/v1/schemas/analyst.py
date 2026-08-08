"""Strict allow-listed schemas for C08 analyst and UAE read models."""

from __future__ import annotations

from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field


class StrictReadModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class EvidenceTagResponse(StrictReadModel):
    kind: Literal["authority", "emirate", "language", "sector"]
    slug: str = Field(min_length=1, max_length=100)
    label: str = Field(min_length=1, max_length=120)
    confidence: float = Field(ge=0, le=1)
    evidence: str = Field(min_length=1, max_length=500)


class ImportRunEvidenceResponse(StrictReadModel):
    public_id: UUID
    action: Literal["created", "updated", "unchanged", "skipped", "failed"]
    status: str = Field(min_length=1, max_length=30)
    started_at: datetime
    completed_at: datetime | None
    processed_at: datetime


class SourceEvidenceResponse(StrictReadModel):
    source_slug: str = Field(min_length=1, max_length=80)
    source_name: str = Field(min_length=1, max_length=160)
    source_url: str = Field(min_length=1, max_length=2048)
    content_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    published_at: datetime | None
    modified_at: datetime | None
    collected_at: datetime
    first_seen_at: datetime
    last_seen_at: datetime
    import_runs: list[ImportRunEvidenceResponse]


class ItemIndicatorEvidenceResponse(StrictReadModel):
    public_id: UUID
    observable_type: str = Field(min_length=1, max_length=20)
    normalized_value: str = Field(min_length=1, max_length=2048)
    hash_algorithm: str | None = Field(default=None, max_length=20)
    status: str = Field(min_length=1, max_length=40)
    confidence: float | None = Field(default=None, ge=0, le=1)
    context_summary: str | None = Field(default=None, max_length=500)
    first_observed_at: datetime
    last_observed_at: datetime


class ItemProvenanceResponse(StrictReadModel):
    item_public_id: UUID
    sources: list[SourceEvidenceResponse]
    classification_tags: list[EvidenceTagResponse]
    indicators: list[ItemIndicatorEvidenceResponse]


class UaeIntelligenceItemResponse(StrictReadModel):
    public_id: UUID
    title: str = Field(min_length=1, max_length=500)
    summary: str | None
    item_type: str = Field(min_length=1, max_length=40)
    cve_id: str | None = Field(default=None, max_length=40)
    severity: str | None = Field(default=None, max_length=20)
    source_slug: str | None = Field(default=None, max_length=80)
    source_name: str | None = Field(default=None, max_length=160)
    source_url: str | None = Field(default=None, max_length=2048)
    published_at: datetime | None
    modified_at: datetime | None
    collected_at: datetime
    last_seen_at: datetime
    geographic_scope: str = Field(min_length=1, max_length=40)
    relevance_status: str = Field(min_length=1, max_length=40)
    relevance_label: Literal[
        "Direct UAE evidence",
        "Potential UAE relevance",
        "Global relevance",
        "No demonstrated UAE relevance",
    ]
    relevance_confidence: float | None = Field(default=None, ge=0, le=1)
    relevance_reason: str | None = Field(default=None, max_length=1000)
    relevance_method: str = Field(min_length=1, max_length=40)
    classification_tags: list[EvidenceTagResponse]


class UaeIntelligenceListResponse(StrictReadModel):
    items: list[UaeIntelligenceItemResponse]
    total: int = Field(ge=0)
    limit: int = Field(ge=1, le=100)
    offset: int = Field(ge=0, le=10_000)


class ThreatEntitySummaryResponse(StrictReadModel):
    public_id: UUID
    entity_type: Literal[
        "threat_actor", "campaign", "malware_family", "attack_technique"
    ]
    name: str = Field(min_length=1, max_length=500)
    attack_id: str | None = Field(default=None, max_length=20)
    aliases: list[str]
    confidence: float | None = Field(default=None, ge=0, le=1)
    source_slug: str = Field(min_length=1, max_length=80)
    source_name: str = Field(min_length=1, max_length=160)
    source_url: str = Field(min_length=1, max_length=2048)
    content_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    stix_created_at: datetime
    stix_modified_at: datetime
    revoked: bool


class ThreatRelationshipResponse(StrictReadModel):
    public_id: UUID
    direction: Literal["incoming", "outgoing"]
    relationship_type: Literal["uses", "attributed-to"]
    other_entity_public_id: UUID
    other_entity_type: Literal[
        "threat_actor", "campaign", "malware_family", "attack_technique"
    ]
    other_entity_name: str = Field(min_length=1, max_length=500)
    confidence: float | None = Field(default=None, ge=0, le=1)
    stix_modified_at: datetime
    revoked: bool


class ThreatEntityDetailResponse(ThreatEntitySummaryResponse):
    relationships: list[ThreatRelationshipResponse]


class ThreatEntityListResponse(StrictReadModel):
    items: list[ThreatEntitySummaryResponse]
    total: int = Field(ge=0)
    limit: int = Field(ge=1, le=100)
    offset: int = Field(ge=0, le=10_000)


class IndicatorSummaryResponse(StrictReadModel):
    public_id: UUID
    observable_type: Literal["ipv4", "ipv6", "domain", "url", "file_hash"]
    normalized_value: str = Field(min_length=1, max_length=2048)
    hash_algorithm: str | None = Field(default=None, max_length=20)
    status: Literal["active", "inactive", "revoked", "false_positive", "archived"]
    confidence: float | None = Field(default=None, ge=0, le=1)
    context_summary: str | None = Field(default=None, max_length=1000)
    first_seen_at: datetime | None
    last_seen_at: datetime | None
    expires_at: datetime | None
    provenance_count: int = Field(ge=0)
    publication_count: int = Field(ge=0)


class IndicatorProvenanceResponse(StrictReadModel):
    public_id: UUID
    source_slug: str = Field(min_length=1, max_length=80)
    source_name: str = Field(min_length=1, max_length=160)
    source_url: str | None = Field(default=None, max_length=2048)
    confidence: float | None = Field(default=None, ge=0, le=1)
    context_summary: str | None = Field(default=None, max_length=1000)
    first_observed_at: datetime | None
    last_observed_at: datetime | None


class IndicatorPublicationResponse(StrictReadModel):
    item_public_id: UUID
    title: str = Field(min_length=1, max_length=500)
    item_type: str = Field(min_length=1, max_length=40)
    relationship_type: Literal["mentioned"]
    confidence: float = Field(ge=0, le=1)
    context_summary: str | None = Field(default=None, max_length=500)
    first_observed_at: datetime
    last_observed_at: datetime


class IndicatorDetailResponse(IndicatorSummaryResponse):
    provenances: list[IndicatorProvenanceResponse]
    publications: list[IndicatorPublicationResponse]


class IndicatorListResponse(StrictReadModel):
    items: list[IndicatorSummaryResponse]
    total: int = Field(ge=0)
    limit: int = Field(ge=1, le=100)
    offset: int = Field(ge=0, le=10_000)
