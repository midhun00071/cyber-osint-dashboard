"""Bounded read services for C08 analyst, provenance, and UAE views."""

from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal
from uuid import UUID

from sqlalchemy import Select, func, or_, select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session, aliased, load_only, raiseload, selectinload

from app.api.v1.schemas.analyst import (
    EvidenceTagResponse,
    ImportRunEvidenceResponse,
    IndicatorDetailResponse,
    IndicatorListResponse,
    IndicatorProvenanceResponse,
    IndicatorPublicationResponse,
    IndicatorSummaryResponse,
    ItemIndicatorEvidenceResponse,
    ItemProvenanceResponse,
    SourceEvidenceResponse,
    ThreatEntityDetailResponse,
    ThreatEntityListResponse,
    ThreatEntitySummaryResponse,
    ThreatRelationshipResponse,
    UaeIntelligenceItemResponse,
    UaeIntelligenceListResponse,
)
from app.models import (
    Indicator,
    IndicatorProvenance,
    IngestionRun,
    IngestionRunRecord,
    IntelligenceItem,
    IntelligenceItemIdentifier,
    IntelligenceItemIndicator,
    IntelligenceItemTag,
    IntelligenceSource,
    SourceRecord,
    Tag,
    ThreatEntity,
    ThreatEntityAlias,
    ThreatRelationship,
    Vulnerability,
)


ACTIVE_ITEM_STATUS = "active"
SEARCH_ESCAPE = "\\"
MAX_THREAT_ALIASES = 20
MAX_THREAT_RELATIONSHIPS = 100
MAX_INDICATOR_PROVENANCES = 50
MAX_INDICATOR_PUBLICATIONS = 100
MAX_ITEM_SOURCE_RECORDS = 25
MAX_SOURCE_IMPORT_RUNS = 20
MAX_ITEM_INDICATOR_RELATIONSHIPS = 100
MAX_CLASSIFICATION_TAGS = 16
_CONTROLLED_TAG_KINDS = {
    "language-": "language",
    "uae-authority-": "authority",
    "uae-emirate-": "emirate",
    "uae-sector-": "sector",
}


class AnalystQueryError(RuntimeError):
    """A read failed without exposing storage details."""


class AnalystNotFoundError(LookupError):
    """The requested public analyst resource does not exist."""


@dataclass(frozen=True)
class PageOptions:
    limit: int = 25
    offset: int = 0


@dataclass(frozen=True)
class ThreatEntityFilters(PageOptions):
    q: str | None = None
    entity_type: str | None = None
    source_slug: str | None = None
    revoked: bool | None = False


@dataclass(frozen=True)
class IndicatorFilters(PageOptions):
    q: str | None = None
    observable_type: str | None = None
    status: str | None = "active"


@dataclass(frozen=True)
class UaeIntelligenceFilters(PageOptions):
    q: str | None = None
    relevance: str | None = None
    item_type: str | None = None
    source_slug: str | None = None


class AnalystQueryService:
    """Load only safe, bounded analyst-facing metadata."""

    def __init__(self, session: Session) -> None:
        self._session = session

    def list_threat_entities(
        self,
        filters: ThreatEntityFilters,
    ) -> ThreatEntityListResponse:
        statement = self._threat_statement(filters)
        try:
            total = int(
                self._session.execute(
                    select(func.count()).select_from(statement.order_by(None).subquery())
                ).scalar_one()
                or 0
            )
            rows = self._session.execute(
                statement
                .options(
                    load_only(
                        ThreatEntity.id,
                        ThreatEntity.public_id,
                        ThreatEntity.entity_type,
                        ThreatEntity.name,
                        ThreatEntity.attack_id,
                        ThreatEntity.confidence,
                        ThreatEntity.stix_created_at,
                        ThreatEntity.stix_modified_at,
                        ThreatEntity.revoked,
                        raiseload=True,
                    ),
                    load_only(
                        SourceRecord.source_url,
                        SourceRecord.content_hash,
                        raiseload=True,
                    ),
                    load_only(
                        IntelligenceSource.slug,
                        IntelligenceSource.name,
                        raiseload=True,
                    ),
                )
                .order_by(
                    ThreatEntity.stix_modified_at.desc(),
                    ThreatEntity.id.desc(),
                )
                .limit(filters.limit)
                .offset(filters.offset)
            ).all()
            aliases = self._threat_aliases([row[0].id for row in rows])
        except SQLAlchemyError as exc:
            raise AnalystQueryError("Unable to load threat metadata.") from exc

        return ThreatEntityListResponse(
            items=[
                self._serialize_threat_row(*row, aliases=aliases.get(row[0].id, []))
                for row in rows
            ],
            total=total,
            limit=filters.limit,
            offset=filters.offset,
        )

    def get_threat_entity(self, public_id: UUID) -> ThreatEntityDetailResponse:
        filters = ThreatEntityFilters(revoked=None)
        statement = self._threat_statement(filters).where(
            ThreatEntity.public_id == public_id
        )
        try:
            row = self._session.execute(
                statement.options(
                    load_only(
                        ThreatEntity.id,
                        ThreatEntity.public_id,
                        ThreatEntity.entity_type,
                        ThreatEntity.name,
                        ThreatEntity.attack_id,
                        ThreatEntity.confidence,
                        ThreatEntity.stix_created_at,
                        ThreatEntity.stix_modified_at,
                        ThreatEntity.revoked,
                        ThreatEntity.source_id,
                        raiseload=True,
                    ),
                    load_only(
                        SourceRecord.source_url,
                        SourceRecord.content_hash,
                        raiseload=True,
                    ),
                    load_only(
                        IntelligenceSource.slug,
                        IntelligenceSource.name,
                        raiseload=True,
                    ),
                )
            ).one_or_none()
            if row is None:
                raise AnalystNotFoundError("Threat entity not found.")
            aliases = self._threat_aliases([row[0].id]).get(row[0].id, [])
            relationships = self._threat_relationships(row[0])
        except AnalystNotFoundError:
            raise
        except SQLAlchemyError as exc:
            raise AnalystQueryError("Unable to load threat metadata.") from exc

        summary = self._serialize_threat_row(*row, aliases=aliases)
        return ThreatEntityDetailResponse(
            **summary.model_dump(),
            relationships=relationships,
        )

    def list_indicators(self, filters: IndicatorFilters) -> IndicatorListResponse:
        statement = select(Indicator)
        if filters.q is not None:
            statement = statement.where(
                Indicator.normalized_value.ilike(
                    f"%{self._escape_like(filters.q)}%",
                    escape=SEARCH_ESCAPE,
                )
            )
        if filters.observable_type is not None:
            statement = statement.where(
                Indicator.observable_type == filters.observable_type
            )
        if filters.status is not None:
            statement = statement.where(Indicator.status == filters.status)

        provenance_count = (
            select(func.count(IndicatorProvenance.id))
            .where(IndicatorProvenance.indicator_id == Indicator.id)
            .correlate(Indicator)
            .scalar_subquery()
        )
        publication_count = (
            select(func.count())
            .select_from(IntelligenceItemIndicator)
            .join(
                IntelligenceItem,
                IntelligenceItem.id
                == IntelligenceItemIndicator.intelligence_item_id,
            )
            .where(IntelligenceItemIndicator.indicator_id == Indicator.id)
            .where(IntelligenceItem.status == ACTIVE_ITEM_STATUS)
            .correlate(Indicator)
            .scalar_subquery()
        )

        try:
            total = int(
                self._session.execute(
                    select(func.count()).select_from(statement.order_by(None).subquery())
                ).scalar_one()
                or 0
            )
            rows = self._session.execute(
                statement
                .add_columns(
                    provenance_count.label("provenance_count"),
                    publication_count.label("publication_count"),
                )
                .options(*self._indicator_base_load_options())
                .order_by(
                    Indicator.last_seen_at.desc().nulls_last(),
                    Indicator.id.desc(),
                )
                .limit(filters.limit)
                .offset(filters.offset)
            ).all()
        except SQLAlchemyError as exc:
            raise AnalystQueryError("Unable to load indicators.") from exc

        return IndicatorListResponse(
            items=[
                self._serialize_indicator(
                    indicator,
                    provenance_count=int(provenance_count_value or 0),
                    publication_count=int(publication_count_value or 0),
                )
                for indicator, provenance_count_value, publication_count_value in rows
            ],
            total=total,
            limit=filters.limit,
            offset=filters.offset,
        )

    def get_indicator(self, public_id: UUID) -> IndicatorDetailResponse:
        statement = (
            select(Indicator)
            .where(Indicator.public_id == public_id)
            .options(*self._indicator_base_load_options())
        )
        try:
            indicator = self._session.execute(statement).scalars().one_or_none()
            if indicator is None:
                raise AnalystNotFoundError("Indicator not found.")
            provenance_count, publication_count = self._indicator_counts(indicator.id)
            provenances = self._indicator_provenances(indicator.id)
            publications = self._indicator_publications(indicator.id)
        except AnalystNotFoundError:
            raise
        except SQLAlchemyError as exc:
            raise AnalystQueryError("Unable to load indicator.") from exc
        summary = self._serialize_indicator(
            indicator,
            provenance_count=provenance_count,
            publication_count=publication_count,
        )
        return IndicatorDetailResponse(
            **summary.model_dump(),
            provenances=provenances,
            publications=publications,
        )

    def get_item_provenance(self, public_id: UUID) -> ItemProvenanceResponse:
        statement = (
            select(IntelligenceItem)
            .where(
                IntelligenceItem.public_id == public_id,
                IntelligenceItem.status == ACTIVE_ITEM_STATUS,
            )
            .options(
                load_only(
                    IntelligenceItem.id,
                    IntelligenceItem.public_id,
                    raiseload=True,
                ),
                raiseload("*"),
            )
        )
        try:
            item = self._session.execute(statement).scalars().one_or_none()
            if item is None:
                raise AnalystNotFoundError("Intelligence item not found.")
            source_rows = self._item_sources(item.id)
            import_run_rows = {
                source_record.id: self._source_import_runs(source_record.id)
                for source_record, _source in source_rows
            }
            tag_rows = self._item_classification_tag_rows(item.id)
            indicator_rows = self._item_indicators(item.id)
        except AnalystNotFoundError:
            raise
        except SQLAlchemyError as exc:
            raise AnalystQueryError("Unable to load item provenance.") from exc

        return ItemProvenanceResponse(
            item_public_id=item.public_id,
            sources=[
                self._serialize_source_evidence(
                    source_record,
                    source,
                    import_run_rows[source_record.id],
                )
                for source_record, source in source_rows
            ],
            classification_tags=self._classification_tags_from_rows(tag_rows),
            indicators=[
                ItemIndicatorEvidenceResponse(
                    public_id=indicator.public_id,
                    observable_type=indicator.observable_type,
                    normalized_value=indicator.normalized_value,
                    hash_algorithm=indicator.hash_algorithm,
                    status=indicator.status,
                    confidence=self._decimal_to_float(relationship.confidence),
                    context_summary=relationship.context_summary,
                    first_observed_at=relationship.first_observed_at,
                    last_observed_at=relationship.last_observed_at,
                )
                for relationship, indicator in indicator_rows
            ],
        )

    def list_uae_intelligence(
        self,
        filters: UaeIntelligenceFilters,
    ) -> UaeIntelligenceListResponse:
        statement = select(IntelligenceItem).where(
            IntelligenceItem.status == ACTIVE_ITEM_STATUS
        )
        if filters.q is not None:
            pattern = f"%{self._escape_like(filters.q)}%"
            statement = statement.where(
                or_(
                    IntelligenceItem.canonical_title.ilike(
                        pattern, escape=SEARCH_ESCAPE
                    ),
                    IntelligenceItem.summary.ilike(pattern, escape=SEARCH_ESCAPE),
                )
            )
        if filters.item_type is not None:
            statement = statement.where(IntelligenceItem.item_type == filters.item_type)
        if filters.source_slug is not None:
            statement = statement.where(
                select(SourceRecord.id)
                .join(
                    IntelligenceSource,
                    SourceRecord.source_id == IntelligenceSource.id,
                )
                .where(SourceRecord.intelligence_item_id == IntelligenceItem.id)
                .where(IntelligenceSource.slug == filters.source_slug)
                .exists()
            )
        if filters.relevance is not None:
            statement = statement.where(self._relevance_expression(filters.relevance))

        try:
            total = int(
                self._session.execute(
                    select(func.count()).select_from(statement.order_by(None).subquery())
                ).scalar_one()
                or 0
            )
            items = list(
                self._session.execute(
                    statement
                    .options(*self._uae_load_options())
                    .order_by(
                        IntelligenceItem.source_published_at.desc().nulls_last(),
                        IntelligenceItem.last_seen_at.desc(),
                        IntelligenceItem.id.desc(),
                    )
                    .limit(filters.limit)
                    .offset(filters.offset)
                )
                .scalars()
                    .all()
            )
            source_rows = {
                item.id: self._uae_primary_source(item.id)
                for item in items
            }
            tag_rows = {
                item.id: self._item_classification_tag_rows(item.id)
                for item in items
            }
        except SQLAlchemyError as exc:
            raise AnalystQueryError("Unable to load UAE intelligence.") from exc

        return UaeIntelligenceListResponse(
            items=[
                self._serialize_uae_item(
                    item,
                    source_row=source_rows[item.id],
                    classification_tags=self._classification_tags_from_rows(
                        tag_rows[item.id]
                    ),
                )
                for item in items
            ],
            total=total,
            limit=filters.limit,
            offset=filters.offset,
        )

    @staticmethod
    def _threat_statement(
        filters: ThreatEntityFilters,
    ) -> Select:
        statement = (
            select(ThreatEntity, SourceRecord, IntelligenceSource)
            .join(
                SourceRecord,
                (SourceRecord.id == ThreatEntity.source_record_id)
                & (SourceRecord.source_id == ThreatEntity.source_id),
            )
            .join(
                IntelligenceSource,
                IntelligenceSource.id == ThreatEntity.source_id,
            )
        )
        if filters.q is not None:
            pattern = f"%{AnalystQueryService._escape_like(filters.q)}%"
            statement = statement.where(
                or_(
                    ThreatEntity.name.ilike(pattern, escape=SEARCH_ESCAPE),
                    ThreatEntity.attack_id.ilike(pattern, escape=SEARCH_ESCAPE),
                    select(ThreatEntityAlias.id)
                    .where(ThreatEntityAlias.threat_entity_id == ThreatEntity.id)
                    .where(
                        ThreatEntityAlias.display_value.ilike(
                            pattern, escape=SEARCH_ESCAPE
                        )
                    )
                    .exists(),
                )
            )
        if filters.entity_type is not None:
            statement = statement.where(ThreatEntity.entity_type == filters.entity_type)
        if filters.source_slug is not None:
            statement = statement.where(IntelligenceSource.slug == filters.source_slug)
        if filters.revoked is not None:
            statement = statement.where(ThreatEntity.revoked.is_(filters.revoked))
        return statement

    def _serialize_threat_row(
        self,
        entity: ThreatEntity,
        source_record: SourceRecord,
        source: IntelligenceSource,
        *,
        aliases: list[str],
    ) -> ThreatEntitySummaryResponse:
        return ThreatEntitySummaryResponse(
            public_id=entity.public_id,
            entity_type=entity.entity_type,
            name=entity.name,
            attack_id=entity.attack_id,
            aliases=aliases,
            confidence=self._decimal_to_float(entity.confidence),
            source_slug=source.slug,
            source_name=source.name,
            source_url=source_record.source_url,
            content_sha256=source_record.content_hash,
            stix_created_at=entity.stix_created_at,
            stix_modified_at=entity.stix_modified_at,
            revoked=entity.revoked,
        )

    def _threat_aliases(self, entity_ids: list[int]) -> dict[int, list[str]]:
        if not entity_ids:
            return {}
        ranked = (
            select(
                ThreatEntityAlias.threat_entity_id.label("entity_id"),
                ThreatEntityAlias.display_value.label("display_value"),
                func.row_number()
                .over(
                    partition_by=ThreatEntityAlias.threat_entity_id,
                    order_by=(
                        ThreatEntityAlias.normalized_value.asc(),
                        ThreatEntityAlias.id.asc(),
                    ),
                )
                .label("position"),
            )
            .where(ThreatEntityAlias.threat_entity_id.in_(entity_ids))
            .subquery()
        )
        rows = self._session.execute(
            select(ranked.c.entity_id, ranked.c.display_value)
            .where(ranked.c.position <= MAX_THREAT_ALIASES)
            .order_by(ranked.c.entity_id.asc(), ranked.c.position.asc())
        ).all()
        results = {entity_id: [] for entity_id in entity_ids}
        for entity_id, display_value in rows:
            results.setdefault(int(entity_id), []).append(display_value)
        return results

    def _threat_relationships(
        self,
        entity: ThreatEntity,
    ) -> list[ThreatRelationshipResponse]:
        other = aliased(ThreatEntity)
        statement = (
            select(ThreatRelationship, other)
            .join(
                other,
                or_(
                    (
                        (ThreatRelationship.source_entity_id == entity.id)
                        & (other.id == ThreatRelationship.target_entity_id)
                    ),
                    (
                        (ThreatRelationship.target_entity_id == entity.id)
                        & (other.id == ThreatRelationship.source_entity_id)
                    ),
                ),
            )
            .where(ThreatRelationship.source_id == entity.source_id)
            .where(
                or_(
                    ThreatRelationship.source_entity_id == entity.id,
                    ThreatRelationship.target_entity_id == entity.id,
                )
            )
            .order_by(
                ThreatRelationship.stix_modified_at.desc(),
                ThreatRelationship.public_id.desc(),
            )
            .limit(MAX_THREAT_RELATIONSHIPS)
        )
        rows = self._session.execute(statement).all()
        return [
            ThreatRelationshipResponse(
                public_id=relationship.public_id,
                direction=(
                    "outgoing"
                    if relationship.source_entity_id == entity.id
                    else "incoming"
                ),
                relationship_type=relationship.relationship_type,
                other_entity_public_id=other_entity.public_id,
                other_entity_type=other_entity.entity_type,
                other_entity_name=other_entity.name,
                confidence=self._decimal_to_float(relationship.confidence),
                stix_modified_at=relationship.stix_modified_at,
                revoked=relationship.revoked,
            )
            for relationship, other_entity in rows
        ]

    @staticmethod
    def _indicator_base_load_options() -> tuple:
        return (
            load_only(
                Indicator.id,
                Indicator.public_id,
                Indicator.observable_type,
                Indicator.normalized_value,
                Indicator.hash_algorithm,
                Indicator.status,
                Indicator.confidence,
                Indicator.context_summary,
                Indicator.first_seen_at,
                Indicator.last_seen_at,
                Indicator.expires_at,
                raiseload=True,
            ),
            raiseload("*"),
        )

    def _indicator_counts(self, indicator_id: int) -> tuple[int, int]:
        provenance_count = (
            select(func.count(IndicatorProvenance.id))
            .where(IndicatorProvenance.indicator_id == indicator_id)
            .scalar_subquery()
        )
        publication_count = (
            select(func.count())
            .select_from(IntelligenceItemIndicator)
            .join(
                IntelligenceItem,
                IntelligenceItem.id
                == IntelligenceItemIndicator.intelligence_item_id,
            )
            .where(IntelligenceItemIndicator.indicator_id == indicator_id)
            .where(IntelligenceItem.status == ACTIVE_ITEM_STATUS)
            .scalar_subquery()
        )
        row = self._session.execute(
            select(
                provenance_count.label("provenance_count"),
                publication_count.label("publication_count"),
            )
        ).one()
        return int(row[0] or 0), int(row[1] or 0)

    def _indicator_provenances(
        self,
        indicator_id: int,
    ) -> list[IndicatorProvenanceResponse]:
        rows = self._session.execute(
            select(IndicatorProvenance, IntelligenceSource, SourceRecord)
            .join(
                IntelligenceSource,
                IntelligenceSource.id == IndicatorProvenance.source_id,
            )
            .outerjoin(
                SourceRecord,
                (SourceRecord.id == IndicatorProvenance.source_record_id)
                & (SourceRecord.source_id == IndicatorProvenance.source_id),
            )
            .where(IndicatorProvenance.indicator_id == indicator_id)
            .options(
                load_only(
                    IndicatorProvenance.public_id,
                    IndicatorProvenance.confidence,
                    IndicatorProvenance.context_summary,
                    IndicatorProvenance.first_observed_at,
                    IndicatorProvenance.last_observed_at,
                    raiseload=True,
                ),
                load_only(
                    IntelligenceSource.slug,
                    IntelligenceSource.name,
                    raiseload=True,
                ),
                load_only(SourceRecord.source_url, raiseload=True),
            )
            .order_by(
                IntelligenceSource.slug.asc(),
                IndicatorProvenance.public_id.asc(),
            )
            .limit(MAX_INDICATOR_PROVENANCES)
        ).all()
        return [
            IndicatorProvenanceResponse(
                public_id=provenance.public_id,
                source_slug=source.slug,
                source_name=source.name,
                source_url=(source_record.source_url if source_record else None),
                confidence=self._decimal_to_float(provenance.confidence),
                context_summary=provenance.context_summary,
                first_observed_at=provenance.first_observed_at,
                last_observed_at=provenance.last_observed_at,
            )
            for provenance, source, source_record in rows
        ]

    def _indicator_publications(
        self,
        indicator_id: int,
    ) -> list[IndicatorPublicationResponse]:
        rows = self._session.execute(
            select(IntelligenceItemIndicator, IntelligenceItem)
            .join(
                IntelligenceItem,
                IntelligenceItem.id
                == IntelligenceItemIndicator.intelligence_item_id,
            )
            .where(IntelligenceItemIndicator.indicator_id == indicator_id)
            .where(IntelligenceItem.status == ACTIVE_ITEM_STATUS)
            .options(
                load_only(
                    IntelligenceItemIndicator.relationship_type,
                    IntelligenceItemIndicator.confidence,
                    IntelligenceItemIndicator.context_summary,
                    IntelligenceItemIndicator.first_observed_at,
                    IntelligenceItemIndicator.last_observed_at,
                    raiseload=True,
                ),
                load_only(
                    IntelligenceItem.public_id,
                    IntelligenceItem.canonical_title,
                    IntelligenceItem.item_type,
                    raiseload=True,
                ),
            )
            .order_by(
                IntelligenceItem.canonical_title.asc(),
                IntelligenceItem.public_id.asc(),
            )
            .limit(MAX_INDICATOR_PUBLICATIONS)
        ).all()
        return [
            IndicatorPublicationResponse(
                item_public_id=item.public_id,
                title=item.canonical_title,
                item_type=item.item_type,
                relationship_type=relationship.relationship_type,
                confidence=float(relationship.confidence),
                context_summary=relationship.context_summary,
                first_observed_at=relationship.first_observed_at,
                last_observed_at=relationship.last_observed_at,
            )
            for relationship, item in rows
        ]

    def _serialize_indicator(
        self,
        indicator: Indicator,
        *,
        provenance_count: int,
        publication_count: int,
    ) -> IndicatorSummaryResponse:
        return IndicatorSummaryResponse(
            public_id=indicator.public_id,
            observable_type=indicator.observable_type,
            normalized_value=indicator.normalized_value,
            hash_algorithm=indicator.hash_algorithm,
            status=indicator.status,
            confidence=self._decimal_to_float(indicator.confidence),
            context_summary=indicator.context_summary,
            first_seen_at=indicator.first_seen_at,
            last_seen_at=indicator.last_seen_at,
            expires_at=indicator.expires_at,
            provenance_count=provenance_count,
            publication_count=publication_count,
        )

    def _serialize_source_evidence(
        self,
        source_record: SourceRecord,
        source: IntelligenceSource,
        import_run_rows: list[tuple[IngestionRunRecord, IngestionRun]],
    ) -> SourceEvidenceResponse:
        import_runs = [
                ImportRunEvidenceResponse(
                    public_id=run.public_id,
                    action=record.action,
                    status=run.status,
                    started_at=run.started_at,
                    completed_at=run.completed_at,
                    processed_at=record.processed_at,
                )
                for record, run in import_run_rows
        ]
        return SourceEvidenceResponse(
            source_slug=source.slug,
            source_name=source.name,
            source_url=source_record.source_url,
            content_sha256=source_record.content_hash,
            published_at=source_record.source_published_at,
            modified_at=source_record.source_modified_at,
            collected_at=source_record.payload_collected_at,
            first_seen_at=source_record.first_seen_at,
            last_seen_at=source_record.last_seen_at,
            import_runs=import_runs,
        )

    def _item_sources(
        self,
        item_id: int,
    ) -> list[tuple[SourceRecord, IntelligenceSource]]:
        return self._session.execute(
            select(SourceRecord, IntelligenceSource)
            .join(
                IntelligenceSource,
                IntelligenceSource.id == SourceRecord.source_id,
            )
            .where(SourceRecord.intelligence_item_id == item_id)
            .options(
                load_only(
                    SourceRecord.id,
                    SourceRecord.source_external_id,
                    SourceRecord.source_url,
                    SourceRecord.content_hash,
                    SourceRecord.payload_collected_at,
                    SourceRecord.first_seen_at,
                    SourceRecord.last_seen_at,
                    SourceRecord.source_published_at,
                    SourceRecord.source_modified_at,
                    SourceRecord.is_primary_reference,
                    SourceRecord.created_at,
                    raiseload=True,
                ),
                load_only(
                    IntelligenceSource.slug,
                    IntelligenceSource.name,
                    raiseload=True,
                ),
            )
            .order_by(
                SourceRecord.is_primary_reference.desc(),
                IntelligenceSource.slug.asc(),
                SourceRecord.source_external_id.asc().nulls_last(),
                SourceRecord.id.asc(),
            )
            .limit(MAX_ITEM_SOURCE_RECORDS)
        ).all()

    def _source_import_runs(
        self,
        source_record_id: int,
    ) -> list[tuple[IngestionRunRecord, IngestionRun]]:
        return self._session.execute(
            select(IngestionRunRecord, IngestionRun)
            .join(
                IngestionRun,
                IngestionRun.id == IngestionRunRecord.ingestion_run_id,
            )
            .where(IngestionRunRecord.source_record_id == source_record_id)
            .options(
                load_only(
                    IngestionRunRecord.action,
                    IngestionRunRecord.processed_at,
                    raiseload=True,
                ),
                load_only(
                    IngestionRun.public_id,
                    IngestionRun.status,
                    IngestionRun.started_at,
                    IngestionRun.completed_at,
                    raiseload=True,
                ),
            )
            .order_by(
                IngestionRun.started_at.desc(),
                IngestionRun.public_id.desc(),
            )
            .limit(MAX_SOURCE_IMPORT_RUNS)
        ).all()

    def _item_classification_tag_rows(
        self,
        item_id: int,
    ) -> list[tuple[IntelligenceItemTag, Tag]]:
        controlled = or_(
            *(Tag.slug.startswith(prefix) for prefix in _CONTROLLED_TAG_KINDS)
        )
        return self._session.execute(
            select(IntelligenceItemTag, Tag)
            .join(Tag, Tag.id == IntelligenceItemTag.tag_id)
            .where(IntelligenceItemTag.intelligence_item_id == item_id)
            .where(IntelligenceItemTag.confidence.is_not(None))
            .where(controlled)
            .options(
                load_only(
                    IntelligenceItemTag.assigned_by,
                    IntelligenceItemTag.confidence,
                    raiseload=True,
                ),
                load_only(
                    Tag.slug,
                    Tag.display_name,
                    Tag.tag_type,
                    raiseload=True,
                ),
            )
            .order_by(Tag.tag_type.asc(), Tag.slug.asc())
            .limit(MAX_CLASSIFICATION_TAGS)
        ).all()

    def _item_indicators(
        self,
        item_id: int,
    ) -> list[tuple[IntelligenceItemIndicator, Indicator]]:
        return self._session.execute(
            select(IntelligenceItemIndicator, Indicator)
            .join(Indicator, Indicator.id == IntelligenceItemIndicator.indicator_id)
            .where(IntelligenceItemIndicator.intelligence_item_id == item_id)
            .options(
                load_only(
                    IntelligenceItemIndicator.confidence,
                    IntelligenceItemIndicator.context_summary,
                    IntelligenceItemIndicator.first_observed_at,
                    IntelligenceItemIndicator.last_observed_at,
                    raiseload=True,
                ),
                load_only(
                    Indicator.public_id,
                    Indicator.observable_type,
                    Indicator.normalized_value,
                    Indicator.hash_algorithm,
                    Indicator.status,
                    raiseload=True,
                ),
            )
            .order_by(
                Indicator.observable_type.asc(),
                Indicator.normalized_value.asc(),
                Indicator.public_id.asc(),
            )
            .limit(MAX_ITEM_INDICATOR_RELATIONSHIPS)
        ).all()

    def _uae_primary_source(
        self,
        item_id: int,
    ) -> tuple[SourceRecord, IntelligenceSource] | None:
        return self._session.execute(
            select(SourceRecord, IntelligenceSource)
            .join(
                IntelligenceSource,
                IntelligenceSource.id == SourceRecord.source_id,
            )
            .where(SourceRecord.intelligence_item_id == item_id)
            .options(
                load_only(
                    SourceRecord.source_url,
                    SourceRecord.source_published_at,
                    SourceRecord.source_modified_at,
                    SourceRecord.is_primary_reference,
                    SourceRecord.created_at,
                    raiseload=True,
                ),
                load_only(
                    IntelligenceSource.slug,
                    IntelligenceSource.name,
                    raiseload=True,
                ),
            )
            .order_by(
                SourceRecord.is_primary_reference.desc(),
                IntelligenceSource.slug.asc(),
                SourceRecord.created_at.asc(),
                SourceRecord.id.asc(),
            )
            .limit(1)
        ).one_or_none()

    @staticmethod
    def _uae_load_options() -> tuple:
        return (
            load_only(
                IntelligenceItem.id,
                IntelligenceItem.public_id,
                IntelligenceItem.canonical_title,
                IntelligenceItem.summary,
                IntelligenceItem.item_type,
                IntelligenceItem.source_published_at,
                IntelligenceItem.source_modified_at,
                IntelligenceItem.collected_at,
                IntelligenceItem.last_seen_at,
                IntelligenceItem.geographic_scope,
                IntelligenceItem.uae_relevance_status,
                IntelligenceItem.uae_relevance_confidence,
                IntelligenceItem.uae_relevance_reason,
                IntelligenceItem.uae_relevance_method,
                raiseload=True,
            ),
            raiseload("*"),
            selectinload(IntelligenceItem.identifiers).options(
                load_only(
                    IntelligenceItemIdentifier.namespace,
                    IntelligenceItemIdentifier.normalized_value,
                    IntelligenceItemIdentifier.is_primary,
                    raiseload=True,
                ),
                raiseload("*"),
            ),
            selectinload(IntelligenceItem.vulnerability).options(
                load_only(Vulnerability.severity, raiseload=True),
                raiseload("*"),
            ),
        )

    def _serialize_uae_item(
        self,
        item: IntelligenceItem,
        *,
        source_row: tuple[SourceRecord, IntelligenceSource] | None,
        classification_tags: list[EvidenceTagResponse],
    ) -> UaeIntelligenceItemResponse:
        source_record = source_row[0] if source_row is not None else None
        source = source_row[1] if source_row is not None else None
        primary_identifier = next(
            (identifier for identifier in item.identifiers if identifier.is_primary),
            next(
                (
                    identifier
                    for identifier in item.identifiers
                    if identifier.namespace == "cve"
                ),
                None,
            ),
        )
        return UaeIntelligenceItemResponse(
            public_id=item.public_id,
            title=item.canonical_title,
            summary=item.summary,
            item_type=item.item_type,
            cve_id=(
                primary_identifier.normalized_value
                if primary_identifier is not None
                and primary_identifier.namespace == "cve"
                else None
            ),
            severity=item.vulnerability.severity if item.vulnerability else None,
            source_slug=(source.slug if source is not None else None),
            source_name=(source.name if source is not None else None),
            source_url=(source_record.source_url if source_record is not None else None),
            published_at=(
                source_record.source_published_at
                if source_record is not None
                and source_record.source_published_at is not None
                else item.source_published_at
            ),
            modified_at=(
                source_record.source_modified_at
                if source_record is not None
                and source_record.source_modified_at is not None
                else item.source_modified_at
            ),
            collected_at=item.collected_at,
            last_seen_at=item.last_seen_at,
            geographic_scope=item.geographic_scope,
            relevance_status=item.uae_relevance_status,
            relevance_label=self._relevance_label(item),
            relevance_confidence=self._decimal_to_float(
                item.uae_relevance_confidence
            ),
            relevance_reason=item.uae_relevance_reason,
            relevance_method=item.uae_relevance_method,
            classification_tags=classification_tags,
        )

    @staticmethod
    def _relevance_expression(relevance: str):
        if relevance == "direct":
            return IntelligenceItem.uae_relevance_status == "confirmed"
        if relevance == "potential":
            return IntelligenceItem.uae_relevance_status.in_(("probable", "possible"))
        if relevance == "global":
            return (
                (IntelligenceItem.uae_relevance_status == "not_relevant")
                & (IntelligenceItem.geographic_scope == "global")
            )
        if relevance == "no_evidence":
            return IntelligenceItem.uae_relevance_status == "unknown"
        raise ValueError("Unsupported relevance filter.")

    @staticmethod
    def _relevance_label(item: IntelligenceItem) -> str:
        if item.uae_relevance_status == "confirmed":
            return "Direct UAE evidence"
        if item.uae_relevance_status in {"probable", "possible"}:
            return "Potential UAE relevance"
        if (
            item.uae_relevance_status == "not_relevant"
            and item.geographic_scope == "global"
        ):
            return "Global relevance"
        return "No demonstrated UAE relevance"

    def _classification_tags_from_rows(
        self,
        rows: list[tuple[IntelligenceItemTag, Tag]],
    ) -> list[EvidenceTagResponse]:
        results: list[EvidenceTagResponse] = []
        for assignment, tag in rows:
            confidence = self._decimal_to_float(assignment.confidence)
            if confidence is None:
                continue
            kind = next(
                (
                    value
                    for prefix, value in _CONTROLLED_TAG_KINDS.items()
                    if tag.slug.startswith(prefix)
                ),
                None,
            )
            if kind is None:
                continue
            evidence = {
                "authority": "Controlled authority tag assigned from source provenance.",
                "emirate": "Controlled emirate tag assigned from normalized metadata.",
                "language": "Controlled language tag assigned from normalized metadata.",
                "sector": "Controlled sector tag assigned from normalized metadata.",
            }[kind]
            results.append(
                EvidenceTagResponse(
                    kind=kind,
                    slug=tag.slug,
                    label=tag.display_name,
                    confidence=confidence,
                    evidence=evidence,
                )
            )
        return results

    @staticmethod
    def _escape_like(value: str) -> str:
        return (
            value.replace(SEARCH_ESCAPE, SEARCH_ESCAPE * 2)
            .replace("%", SEARCH_ESCAPE + "%")
            .replace("_", SEARCH_ESCAPE + "_")
        )

    @staticmethod
    def _decimal_to_float(value: Decimal | None) -> float | None:
        return float(value) if value is not None else None
