from __future__ import annotations

from datetime import UTC, datetime
from decimal import Decimal
from uuid import UUID

from app.models import (
    Indicator,
    IndicatorProvenance,
    IntelligenceItem,
    IntelligenceItemIndicator,
    IntelligenceSource,
    SourceRecord,
)
from app.services.analyst_query_service import (
    MAX_INDICATOR_PROVENANCES,
    MAX_INDICATOR_PUBLICATIONS,
    MAX_ITEM_INDICATOR_RELATIONSHIPS,
    MAX_ITEM_SOURCE_RECORDS,
    MAX_THREAT_ALIASES,
    AnalystQueryService,
    IndicatorFilters,
)


NOW = datetime(2026, 8, 8, tzinfo=UTC)


class Rows:
    def __init__(self, values: list[tuple]):
        self._values = values

    def all(self) -> list[tuple]:
        return list(self._values)


class Scalar:
    def __init__(self, value: int):
        self.value = value

    def scalar_one(self) -> int:
        return self.value


class LimitEmulatingSession:
    def __init__(self, fixtures: dict[str, list[tuple]]):
        self.fixtures = fixtures
        self.statements = []

    def execute(self, statement) -> Rows:
        self.statements.append(statement)
        entities = {
            description.get("entity") for description in statement.column_descriptions
        }
        sql = str(statement)
        if "threat_entity_aliases" in sql:
            key = "aliases"
            limit = MAX_THREAT_ALIASES
        elif IndicatorProvenance in entities:
            key = "provenances"
            limit = getattr(statement._limit_clause, "value", None)
        elif IntelligenceItemIndicator in entities and IntelligenceItem in entities:
            key = "publications"
            limit = getattr(statement._limit_clause, "value", None)
        elif IntelligenceItemIndicator in entities and Indicator in entities:
            key = "item_indicators"
            limit = getattr(statement._limit_clause, "value", None)
        elif SourceRecord in entities and IntelligenceSource in entities:
            key = "sources"
            limit = getattr(statement._limit_clause, "value", None)
        else:
            raise AssertionError(f"Unexpected bounded statement: {sql}")
        values = self.fixtures[key]
        return Rows(values[:limit] if limit is not None else values)


def make_source(index: int) -> IntelligenceSource:
    return IntelligenceSource(
        id=index,
        slug=f"source-{index:03d}",
        name=f"Source {index:03d}",
        source_type="api",
        base_url="https://example.test",
        is_enabled=True,
    )


def test_nested_analyst_collections_apply_deterministic_sql_limits() -> None:
    provenances = []
    publications = []
    item_indicators = []
    sources = []
    for index in range(1, MAX_ITEM_INDICATOR_RELATIONSHIPS + 2):
        source = make_source(index)
        if index <= MAX_INDICATOR_PROVENANCES + 1:
            provenances.append(
                (
                    IndicatorProvenance(
                        id=index,
                        public_id=UUID(int=index),
                        indicator_id=1,
                        source_id=index,
                        source_record_id=None,
                        confidence=Decimal("0.700"),
                        context_summary="Synthetic provenance.",
                        first_observed_at=NOW,
                        last_observed_at=NOW,
                    ),
                    source,
                    None,
                )
            )
        item = IntelligenceItem(
            id=index,
            public_id=UUID(int=10_000 + index),
            item_type="security_advisory",
            canonical_title=f"Publication {index:03d}",
            collected_at=NOW,
            last_seen_at=NOW,
            status="active",
            geographic_scope="global",
            uae_relevance_status="unknown",
            uae_relevance_method="unassigned",
            analyst_review_status="pending",
        )
        relationship = IntelligenceItemIndicator(
            intelligence_item_id=index,
            indicator_id=1,
            relationship_type="mentioned",
            extraction_method="deterministic_text",
            confidence=Decimal("0.800"),
            context_summary="Synthetic mention.",
            first_observed_at=NOW,
            last_observed_at=NOW,
        )
        publications.append((relationship, item))
        indicator = Indicator(
            id=index,
            public_id=UUID(int=20_000 + index),
            observable_type="domain",
            normalized_value=f"indicator-{index:03d}.example",
            status="active",
        )
        item_indicators.append((relationship, indicator))
        if index <= MAX_ITEM_SOURCE_RECORDS + 1:
            sources.append(
                (
                    SourceRecord(
                        id=index,
                        source_id=index,
                        intelligence_item_id=1,
                        source_url=f"https://example.test/{index}",
                        is_primary_reference=index == 1,
                        payload_collected_at=NOW,
                        first_seen_at=NOW,
                        last_seen_at=NOW,
                        processing_status="processed",
                        upstream_status="present",
                    ),
                    source,
                )
            )

    session = LimitEmulatingSession(
        {
            "aliases": [(1, f"Alias {index:03d}") for index in range(MAX_THREAT_ALIASES + 1)],
            "provenances": provenances,
            "publications": publications,
            "item_indicators": item_indicators,
            "sources": sources,
        }
    )
    service = AnalystQueryService(session)  # type: ignore[arg-type]

    aliases = service._threat_aliases([1])
    bounded_provenances = service._indicator_provenances(1)
    bounded_publications = service._indicator_publications(1)
    bounded_sources = service._item_sources(1)
    bounded_item_indicators = service._item_indicators(1)

    assert len(aliases[1]) == MAX_THREAT_ALIASES
    assert len(bounded_provenances) == MAX_INDICATOR_PROVENANCES
    assert len(bounded_publications) == MAX_INDICATOR_PUBLICATIONS
    assert len(bounded_sources) == MAX_ITEM_SOURCE_RECORDS
    assert len(bounded_item_indicators) == MAX_ITEM_INDICATOR_RELATIONSHIPS
    assert aliases[1][0] == "Alias 000"
    assert bounded_provenances[0].source_slug == "source-001"
    assert bounded_publications[0].title == "Publication 001"
    assert all("ORDER BY" in str(statement) for statement in session.statements)


def test_indicator_list_uses_sql_aggregate_counts_without_relationship_loads() -> None:
    class Session:
        def __init__(self):
            self.statements = []

        def execute(self, statement):
            self.statements.append(statement)
            if len(self.statements) == 1:
                return Scalar(0)
            return Rows([])

    session = Session()

    response = AnalystQueryService(session).list_indicators(  # type: ignore[arg-type]
        IndicatorFilters(q="example", limit=5, offset=10)
    )

    assert response.total == 0
    assert response.items == []
    assert len(session.statements) == 2
    page_sql = str(session.statements[1]).lower()
    assert "select count(indicator_provenances.id)" in page_sql
    assert "select count(*)" in page_sql
    assert "intelligence_item_indicators" in page_sql
    assert "limit" in page_sql
    assert "offset" in page_sql
