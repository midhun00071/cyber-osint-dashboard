"""Caller-transactional persistence facade for normalized CERT-EU RSS advisories."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.ingestion.collectors.rss_client import CERT_EU_FEED_URL
from app.ingestion.normalizers.rss import NormalizedRssEntry
from app.ingestion.publication_pipeline import (
    PublicationCandidate,
    PublicationCandidateError,
    PublicationPersistenceError,
    PublicationPipeline,
    PublicationSourceError,
    VALID_PUBLICATION_OUTCOMES,
    safe_publication_external_id_for_error,
)
from app.ingestion.source_registry import get_source_definition
from app.models import IntelligenceSource, SourceRecord


_RSS_SOURCE = get_source_definition("cert-eu-security-advisories")
RSS_SOURCE_SLUG = _RSS_SOURCE.slug
RSS_SOURCE_NAME = _RSS_SOURCE.display_name
RSS_SOURCE_TYPE = _RSS_SOURCE.source_type
RSS_SOURCE_BASE_URL = CERT_EU_FEED_URL
RSS_RATE_LIMIT_NOTES = _RSS_SOURCE.rate_limit_notes
VALID_OUTCOMES = VALID_PUBLICATION_OUTCOMES


class RssPersistenceError(RuntimeError):
    """A database operation failed without exposing database details."""


@dataclass(frozen=True)
class RssPersistenceResult:
    """Sanitized outcome for one normalized RSS advisory."""

    source_external_id: str
    outcome: str
    message: str | None = None
    source_record: SourceRecord | None = None
    intelligence_item_id: int | None = None

    def __post_init__(self) -> None:
        if self.outcome not in VALID_OUTCOMES:
            raise ValueError("Invalid RSS persistence outcome.")


class RssIngestionService:
    """Persist normalized CERT-EU advisories without committing or rolling back."""

    def __init__(self, session: Session) -> None:
        self._pipeline = PublicationPipeline(session)

    def ensure_source(self) -> IntelligenceSource:
        """Create or validate the fixed CERT-EU RSS source without committing."""

        try:
            return self._pipeline.ensure_source(RSS_SOURCE_SLUG)
        except (PublicationPersistenceError, PublicationSourceError, SQLAlchemyError) as exc:
            message = _rss_message(str(exc))
            if message and "conflicts" in message:
                raise RssPersistenceError(message) from exc
            raise RssPersistenceError(
                "Database error while preparing the approved CERT-EU RSS source."
            ) from exc

    def persist(
        self,
        normalized: NormalizedRssEntry,
        *,
        observed_at: datetime | None = None,
    ) -> RssPersistenceResult:
        try:
            candidate = _candidate_from_rss_entry(normalized)
        except PublicationCandidateError:
            return RssPersistenceResult(
                source_external_id=safe_publication_external_id_for_error(
                    normalized.source_external_id
                ),
                outcome="failed",
                message="The CERT-EU RSS advisory could not be validated safely.",
            )
        try:
            result = self._pipeline.persist(
                candidate,
                observed_at=observed_at,
            )
        except PublicationPersistenceError as exc:
            raise RssPersistenceError(
                "Database error while persisting normalized RSS data."
            ) from exc
        return RssPersistenceResult(
            source_external_id=result.source_external_id,
            outcome=result.outcome,
            message=_rss_message(result.message),
            source_record=result.source_record,
            intelligence_item_id=result.intelligence_item_id,
        )


def _candidate_from_rss_entry(normalized: NormalizedRssEntry) -> PublicationCandidate:
    return PublicationCandidate(
        source_slug=RSS_SOURCE_SLUG,
        source_external_id=normalized.source_external_id,
        canonical_title=normalized.canonical_title,
        summary=normalized.summary,
        canonical_url=normalized.canonical_url,
        source_published_at=normalized.source_published_at,
        source_modified_at=normalized.source_modified_at,
        safe_source_payload=normalized.raw_payload,
    )


def _rss_message(message: str | None) -> str | None:
    if message is None:
        return None
    return message.replace("publication", "RSS").replace("Publication", "RSS")
