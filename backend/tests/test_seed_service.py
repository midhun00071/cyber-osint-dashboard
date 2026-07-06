from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import pytest
from sqlalchemy.exc import SQLAlchemyError

from app.dev_data.dataset import SEED_DATASET
from app.dev_data.seed_service import (
    SeedDatabaseError,
    seed_development_data,
)
from app.models import (
    IntelligenceItem,
    IntelligenceItemIdentifier,
    IntelligenceItemTag,
    IntelligenceSource,
    SourceRecord,
    Tag,
    Vulnerability,
)


@dataclass
class _ScalarResult:
    value: object | None

    def scalar_one_or_none(self) -> object | None:
        return self.value


class InMemorySeedSession:
    def __init__(self, *, fail_commit: bool = False) -> None:
        self.fail_commit = fail_commit
        self.commits = 0
        self.rollbacks = 0
        self.added: list[object] = []
        self.sources: list[IntelligenceSource] = []
        self.tags: list[Tag] = []
        self.items: list[IntelligenceItem] = []
        self.identifiers: list[IntelligenceItemIdentifier] = []
        self.source_records: list[SourceRecord] = []
        self.vulnerabilities: list[Vulnerability] = []
        self.item_tags: list[IntelligenceItemTag] = []

    def add(self, record: object) -> None:
        self.added.append(record)
        if isinstance(record, IntelligenceSource):
            self.sources.append(record)
        elif isinstance(record, Tag):
            self.tags.append(record)
        elif isinstance(record, IntelligenceItem):
            self.items.append(record)
        elif isinstance(record, IntelligenceItemIdentifier):
            self.identifiers.append(record)
        elif isinstance(record, SourceRecord):
            self.source_records.append(record)
        elif isinstance(record, Vulnerability):
            self.vulnerabilities.append(record)
        elif isinstance(record, IntelligenceItemTag):
            self.item_tags.append(record)
        else:
            raise AssertionError(f"unexpected record type: {type(record)}")

    def execute(self, statement: Any) -> _ScalarResult:
        entity = statement.column_descriptions[0]["entity"]
        criteria = list(statement._where_criteria)

        if entity is IntelligenceSource:
            return _ScalarResult(self._find_by_attr(self.sources, "slug", criteria))
        if entity is Tag:
            return _ScalarResult(self._find_by_attr(self.tags, "slug", criteria))
        if entity is IntelligenceItemIdentifier:
            namespace = _criterion_value(criteria, "namespace")
            normalized_value = _criterion_value(criteria, "normalized_value")
            return _ScalarResult(
                next(
                    (
                        identifier
                        for identifier in self.identifiers
                        if identifier.namespace == namespace
                        and identifier.normalized_value == normalized_value
                    ),
                    None,
                )
            )
        if entity is SourceRecord:
            source_slug = _criterion_value(criteria, "slug")
            external_id = _criterion_value(criteria, "source_external_id")
            return _ScalarResult(
                next(
                    (
                        record
                        for record in self.source_records
                        if record.source.slug == source_slug
                        and record.source_external_id == external_id
                    ),
                    None,
                )
            )
        if entity is Vulnerability:
            item = _criterion_value(criteria, "intelligence_item")
            return _ScalarResult(
                next(
                    (
                        vulnerability
                        for vulnerability in self.vulnerabilities
                        if vulnerability.intelligence_item is item
                    ),
                    None,
                )
            )
        if entity is IntelligenceItemTag:
            item = _criterion_value(criteria, "intelligence_item")
            tag = _criterion_value(criteria, "tag")
            return _ScalarResult(
                next(
                    (
                        assignment
                        for assignment in self.item_tags
                        if assignment.intelligence_item is item and assignment.tag is tag
                    ),
                    None,
                )
            )
        raise AssertionError(f"unexpected select entity: {entity}")

    def commit(self) -> None:
        if self.fail_commit:
            raise SQLAlchemyError("synthetic failure with password=hidden")
        self.commits += 1

    def rollback(self) -> None:
        self.rollbacks += 1

    @staticmethod
    def _find_by_attr(records: list[object], attr_name: str, criteria: list[object]):
        expected = _criterion_value(criteria, attr_name)
        return next(
            (record for record in records if getattr(record, attr_name) == expected),
            None,
        )


def _criterion_value(criteria: list[object], column_name: str) -> object:
    for criterion in criteria:
        left = getattr(criterion, "left", None)
        if left is None or getattr(left, "name", None) != column_name:
            continue
        right = getattr(criterion, "right", None)
        if hasattr(right, "value"):
            return right.value
    return None


def test_seed_service_first_run_creates_expected_records():
    session = InMemorySeedSession()

    result = seed_development_data(session)  # type: ignore[arg-type]

    assert result.created.sources == len(SEED_DATASET.sources)
    assert result.created.tags == len(SEED_DATASET.tags)
    assert result.created.intelligence_items == len(SEED_DATASET.items)
    assert result.created.identifiers == SEED_DATASET.identifier_count
    assert result.created.vulnerabilities == SEED_DATASET.vulnerability_count
    assert result.created.source_records == SEED_DATASET.source_record_count
    assert (
        result.created.item_tag_associations
        == SEED_DATASET.item_tag_association_count
    )
    assert result.existing.sources == 0
    assert session.commits == 1
    assert session.rollbacks == 0


def test_seed_service_second_run_is_idempotent_and_preserves_unrelated_records():
    session = InMemorySeedSession()
    unrelated = Tag(
        slug="unrelated",
        display_name="Unrelated",
        tag_type="general",
    )
    session.add(unrelated)

    first = seed_development_data(session)  # type: ignore[arg-type]
    second = seed_development_data(session)  # type: ignore[arg-type]

    assert first.created.tags == len(SEED_DATASET.tags)
    assert second.created.sources == 0
    assert second.created.tags == 0
    assert second.created.intelligence_items == 0
    assert second.created.identifiers == 0
    assert second.created.vulnerabilities == 0
    assert second.created.source_records == 0
    assert second.created.item_tag_associations == 0
    assert second.existing.sources == len(SEED_DATASET.sources)
    assert second.existing.tags == len(SEED_DATASET.tags)
    assert second.existing.intelligence_items == len(SEED_DATASET.items)
    assert second.existing.identifiers == SEED_DATASET.identifier_count
    assert second.existing.vulnerabilities == SEED_DATASET.vulnerability_count
    assert second.existing.source_records == SEED_DATASET.source_record_count
    assert (
        second.existing.item_tag_associations
        == SEED_DATASET.item_tag_association_count
    )
    assert unrelated in session.tags
    assert len([tag for tag in session.tags if tag.slug == "unrelated"]) == 1


def test_seed_service_relationships_are_created_without_duplicate_assignments():
    session = InMemorySeedSession()

    seed_development_data(session)  # type: ignore[arg-type]
    seed_development_data(session)  # type: ignore[arg-type]

    assert all(record.source is not None for record in session.source_records)
    assert all(record.intelligence_item is not None for record in session.source_records)
    assert all(
        identifier.intelligence_item is not None for identifier in session.identifiers
    )
    assert all(assignment.tag is not None for assignment in session.item_tags)
    assert len(session.item_tags) == SEED_DATASET.item_tag_association_count
    assert len(session.identifiers) == SEED_DATASET.identifier_count
    assert len(session.source_records) == SEED_DATASET.source_record_count


def test_seed_service_rolls_back_database_errors_without_sanitizing_in_service_message():
    session = InMemorySeedSession(fail_commit=True)

    with pytest.raises(SeedDatabaseError) as exc_info:
        seed_development_data(session)  # type: ignore[arg-type]

    assert session.rollbacks == 1
    assert "Database error while seeding synthetic development data" in str(
        exc_info.value
    )
    assert "password=hidden" not in str(exc_info.value)
