"""Transactional persistence service for synthetic development seed data."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TypeVar

from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.dev_data.dataset import SEED_DATASET, SEED_IDENTIFIER_NAMESPACE, SeedDataset
from app.models import (
    IntelligenceItem,
    IntelligenceItemIdentifier,
    IntelligenceItemTag,
    IntelligenceSource,
    SourceRecord,
    Tag,
    Vulnerability,
)


class SeedConflictError(RuntimeError):
    """Raised when existing seed-keyed records conflict with expected data."""


class SeedDatabaseError(RuntimeError):
    """Raised for sanitized database errors during seed persistence."""


@dataclass(frozen=True)
class SeedCounts:
    sources: int = 0
    tags: int = 0
    intelligence_items: int = 0
    identifiers: int = 0
    vulnerabilities: int = 0
    source_records: int = 0
    item_tag_associations: int = 0


@dataclass(frozen=True)
class SeedResult:
    created: SeedCounts
    existing: SeedCounts


_ModelT = TypeVar("_ModelT")


def seed_development_data(
    session: Session,
    dataset: SeedDataset = SEED_DATASET,
) -> SeedResult:
    """Insert deterministic synthetic records once and commit atomically."""

    service = SeedService(session=session, dataset=dataset)
    try:
        result = service.seed()
        session.commit()
        return result
    except SQLAlchemyError as exc:
        session.rollback()
        raise SeedDatabaseError(
            "Database error while seeding synthetic development data."
        ) from exc


class SeedService:
    """Idempotent writer for the static development dataset."""

    def __init__(self, session: Session, dataset: SeedDataset = SEED_DATASET) -> None:
        self._session = session
        self._dataset = dataset

    def seed(self) -> SeedResult:
        created = _MutableCounts()
        existing = _MutableCounts()

        sources = self._seed_sources(created, existing)
        tags = self._seed_tags(created, existing)
        self._seed_items(sources, tags, created, existing)

        return SeedResult(created=created.freeze(), existing=existing.freeze())

    def _seed_sources(
        self,
        created: "_MutableCounts",
        existing: "_MutableCounts",
    ) -> dict[str, IntelligenceSource]:
        sources: dict[str, IntelligenceSource] = {}
        for seed_source in self._dataset.sources:
            source = self._scalar_one_or_none(
                select(IntelligenceSource).where(
                    IntelligenceSource.slug == seed_source.slug
                )
            )
            if source is None:
                source = IntelligenceSource(
                    name=seed_source.name,
                    slug=seed_source.slug,
                    public_id=seed_source.public_id,
                    source_type=seed_source.source_type,
                    base_url=seed_source.base_url,
                    is_enabled=True,
                    rate_limit_notes=seed_source.rate_limit_notes,
                    checkpoint_value="synthetic-seed-static",
                )
                self._session.add(source)
                created.sources += 1
            else:
                self._assert_existing(
                    "source",
                    seed_source.slug,
                    source,
                    {
                        "name": seed_source.name,
                        "public_id": seed_source.public_id,
                        "source_type": seed_source.source_type,
                        "base_url": seed_source.base_url,
                    },
                )
                existing.sources += 1
            sources[seed_source.slug] = source
        return sources

    def _seed_tags(
        self,
        created: "_MutableCounts",
        existing: "_MutableCounts",
    ) -> dict[str, Tag]:
        tags: dict[str, Tag] = {}
        for seed_tag in self._dataset.tags:
            tag = self._scalar_one_or_none(
                select(Tag).where(Tag.slug == seed_tag.slug)
            )
            if tag is None:
                tag = Tag(
                    slug=seed_tag.slug,
                    display_name=seed_tag.display_name,
                    tag_type=seed_tag.tag_type,
                )
                self._session.add(tag)
                created.tags += 1
            else:
                self._assert_existing(
                    "tag",
                    seed_tag.slug,
                    tag,
                    {
                        "display_name": seed_tag.display_name,
                        "tag_type": seed_tag.tag_type,
                    },
                )
                existing.tags += 1
            tags[seed_tag.slug] = tag
        return tags

    def _seed_items(
        self,
        sources: dict[str, IntelligenceSource],
        tags: dict[str, Tag],
        created: "_MutableCounts",
        existing: "_MutableCounts",
    ) -> None:
        for seed_item in self._dataset.items:
            item = self._find_item_by_seed_key(seed_item.seed_key)
            if item is None:
                item = IntelligenceItem(
                    public_id=seed_item.public_id,
                    item_type=seed_item.item_type,
                    canonical_title=seed_item.canonical_title,
                    summary=seed_item.summary,
                    canonical_url=seed_item.canonical_url,
                    source_published_at=seed_item.source_published_at,
                    source_modified_at=seed_item.source_modified_at,
                    collected_at=seed_item.collected_at,
                    last_seen_at=seed_item.last_seen_at,
                    status=seed_item.status,
                    data_confidence=seed_item.data_confidence,
                    geographic_scope=seed_item.geographic_scope,
                    uae_relevance_status=seed_item.uae_relevance_status,
                    uae_relevance_confidence=seed_item.uae_relevance_confidence,
                    uae_relevance_reason=seed_item.uae_relevance_reason,
                    uae_relevance_method=seed_item.uae_relevance_method,
                    analyst_review_status=seed_item.analyst_review_status,
                )
                self._session.add(item)
                created.intelligence_items += 1
            else:
                self._assert_existing(
                    "intelligence item",
                    seed_item.seed_key,
                    item,
                    {
                        "public_id": seed_item.public_id,
                        "item_type": seed_item.item_type,
                        "canonical_title": seed_item.canonical_title,
                    },
                )
                existing.intelligence_items += 1

            source_record = self._seed_source_record(
                seed_item,
                item,
                sources[seed_item.source_record.source_slug],
                created,
                existing,
            )
            self._seed_identifiers(seed_item, item, source_record, created, existing)
            self._seed_vulnerability(seed_item, item, created, existing)
            self._seed_tag_assignments(seed_item, item, tags, created, existing)

    def _seed_source_record(
        self,
        seed_item,
        item: IntelligenceItem,
        source: IntelligenceSource,
        created: "_MutableCounts",
        existing: "_MutableCounts",
    ) -> SourceRecord:
        seed_record = seed_item.source_record
        record = self._scalar_one_or_none(
            select(SourceRecord)
            .join(IntelligenceSource)
            .where(IntelligenceSource.slug == seed_record.source_slug)
            .where(SourceRecord.source_external_id == seed_record.source_external_id)
        )
        if record is None:
            record = SourceRecord(
                source=source,
                intelligence_item=item,
                source_external_id=seed_record.source_external_id,
                source_url=seed_record.source_url,
                canonical_url_hash=None,
                content_hash=seed_record.content_hash,
                is_primary_reference=True,
                raw_payload={
                    "synthetic": True,
                    "seed_key": seed_item.seed_key,
                    "safe_summary": seed_item.summary,
                },
                payload_collected_at=seed_item.collected_at,
                first_seen_at=seed_item.collected_at,
                last_seen_at=seed_item.last_seen_at,
                source_published_at=seed_record.source_published_at,
                source_modified_at=seed_record.source_modified_at,
                processing_status="processed",
                last_processed_at=seed_item.collected_at,
                safe_error_summary=None,
                upstream_status="present",
            )
            self._session.add(record)
            created.source_records += 1
        else:
            self._assert_existing(
                "source record",
                seed_record.source_external_id,
                record,
                {
                    "source_url": seed_record.source_url,
                    "content_hash": seed_record.content_hash,
                    "processing_status": "processed",
                    "upstream_status": "present",
                    "source": source,
                    "intelligence_item": item,
                },
            )
            existing.source_records += 1
        return record

    def _seed_identifiers(
        self,
        seed_item,
        item: IntelligenceItem,
        source_record: SourceRecord,
        created: "_MutableCounts",
        existing: "_MutableCounts",
    ) -> None:
        for seed_identifier in seed_item.identifiers:
            identifier = self._scalar_one_or_none(
                select(IntelligenceItemIdentifier)
                .where(IntelligenceItemIdentifier.source_id.is_(None))
                .where(IntelligenceItemIdentifier.namespace == seed_identifier.namespace)
                .where(
                    IntelligenceItemIdentifier.normalized_value
                    == seed_identifier.normalized_value
                )
            )
            if identifier is None:
                identifier = IntelligenceItemIdentifier(
                    intelligence_item=item,
                    source=None,
                    source_record=source_record,
                    namespace=seed_identifier.namespace,
                    identifier_value=seed_identifier.value,
                    normalized_value=seed_identifier.normalized_value,
                    is_primary=seed_identifier.is_primary,
                )
                self._session.add(identifier)
                created.identifiers += 1
            else:
                self._assert_existing(
                    "identifier",
                    seed_identifier.normalized_value,
                    identifier,
                    {
                        "identifier_value": seed_identifier.value,
                        "is_primary": seed_identifier.is_primary,
                        "intelligence_item": item,
                        "source_record": source_record,
                    },
                )
                existing.identifiers += 1

    def _seed_vulnerability(
        self,
        seed_item,
        item: IntelligenceItem,
        created: "_MutableCounts",
        existing: "_MutableCounts",
    ) -> None:
        if seed_item.vulnerability is None:
            return

        vulnerability = item.vulnerability
        seed_vulnerability = seed_item.vulnerability
        if vulnerability is None:
            vulnerability = Vulnerability(
                intelligence_item=item,
                severity=seed_vulnerability.severity,
                cvss_score=seed_vulnerability.cvss_score,
                cvss_vector=seed_vulnerability.cvss_vector,
                cvss_version=seed_vulnerability.cvss_version,
                epss_score=seed_vulnerability.epss_score,
                epss_percentile=seed_vulnerability.epss_percentile,
                kev_status=seed_vulnerability.kev_status,
                kev_last_checked_at=seed_vulnerability.kev_last_checked_at,
                kev_date_added=seed_vulnerability.kev_date_added,
                kev_due_date=seed_vulnerability.kev_due_date,
                kev_required_action=seed_vulnerability.kev_required_action,
                known_ransomware_campaign_use=(
                    seed_vulnerability.known_ransomware_campaign_use
                ),
                affected_summary=seed_vulnerability.affected_summary,
                affected_products_json=seed_vulnerability.affected_products_json,
            )
            self._session.add(vulnerability)
            created.vulnerabilities += 1
        else:
            self._assert_existing(
                "vulnerability",
                seed_item.seed_key,
                vulnerability,
                {
                    "severity": seed_vulnerability.severity,
                    "kev_status": seed_vulnerability.kev_status,
                    "cvss_score": seed_vulnerability.cvss_score,
                },
            )
            existing.vulnerabilities += 1

    def _seed_tag_assignments(
        self,
        seed_item,
        item: IntelligenceItem,
        tags: dict[str, Tag],
        created: "_MutableCounts",
        existing: "_MutableCounts",
    ) -> None:
        for tag_slug in seed_item.tag_slugs:
            tag = tags[tag_slug]
            assignment = next(
                (
                    existing_assignment
                    for existing_assignment in item.tag_assignments
                    if existing_assignment.tag is tag
                ),
                None,
            )
            if assignment is None:
                assignment = IntelligenceItemTag(
                    intelligence_item=item,
                    tag=tag,
                    assigned_by=seed_item.tag_assignment_source,
                    confidence=seed_item.tag_confidence,
                )
                self._session.add(assignment)
                created.item_tag_associations += 1
            else:
                self._assert_existing(
                    "item tag association",
                    f"{seed_item.seed_key}:{tag_slug}",
                    assignment,
                    {
                        "assigned_by": seed_item.tag_assignment_source,
                        "confidence": seed_item.tag_confidence,
                    },
                )
                existing.item_tag_associations += 1

    def _find_item_by_seed_key(self, seed_key: str) -> IntelligenceItem | None:
        identifier = self._scalar_one_or_none(
            select(IntelligenceItemIdentifier)
            .where(IntelligenceItemIdentifier.source_id.is_(None))
            .where(IntelligenceItemIdentifier.namespace == SEED_IDENTIFIER_NAMESPACE)
            .where(IntelligenceItemIdentifier.normalized_value == seed_key.upper())
        )
        if identifier is None:
            return None
        return identifier.intelligence_item

    def _scalar_one_or_none(self, statement) -> _ModelT | None:
        return self._session.execute(statement).scalar_one_or_none()

    @staticmethod
    def _assert_existing(
        record_type: str,
        key: str,
        record: object,
        expected_values: dict[str, object],
    ) -> None:
        conflicts = [
            field_name
            for field_name, expected_value in expected_values.items()
            if getattr(record, field_name) != expected_value
        ]
        if conflicts:
            conflict_list = ", ".join(sorted(conflicts))
            raise SeedConflictError(
                f"Existing {record_type} '{key}' conflicts on: {conflict_list}."
            )


@dataclass
class _MutableCounts:
    sources: int = 0
    tags: int = 0
    intelligence_items: int = 0
    identifiers: int = 0
    vulnerabilities: int = 0
    source_records: int = 0
    item_tag_associations: int = 0

    def freeze(self) -> SeedCounts:
        return SeedCounts(
            sources=self.sources,
            tags=self.tags,
            intelligence_items=self.intelligence_items,
            identifiers=self.identifiers,
            vulnerabilities=self.vulnerabilities,
            source_records=self.source_records,
            item_tag_associations=self.item_tag_associations,
        )
