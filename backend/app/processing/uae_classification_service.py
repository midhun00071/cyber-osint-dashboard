"""Bounded database service for deterministic UAE relevance classification."""

from __future__ import annotations

from dataclasses import dataclass, field
from decimal import Decimal

from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session, selectinload

from app.models import IntelligenceItem, SourceRecord
from app.processing.uae_relevance_classifier import (
    UaeClassificationInput,
    UaeClassificationResult,
    classify_uae_relevance,
)


MAX_CLASSIFICATION_ITEMS = 500
ELIGIBLE_METHODS = {"unassigned", "automatic"}


class UaeClassificationServiceError(RuntimeError):
    """The classification service failed without exposing database details."""


@dataclass(frozen=True)
class UaeClassificationCounts:
    """Structured classification run counts."""

    processed: int = 0
    updated: int = 0
    would_update: int = 0
    unchanged: int = 0
    skipped_protected: int = 0
    failed: int = 0
    rule_counts: dict[str, int] = field(default_factory=dict)


@dataclass
class _MutableCounts:
    processed: int = 0
    updated: int = 0
    would_update: int = 0
    unchanged: int = 0
    skipped_protected: int = 0
    failed: int = 0
    rule_counts: dict[str, int] = field(default_factory=dict)

    def freeze(self) -> UaeClassificationCounts:
        return UaeClassificationCounts(
            processed=self.processed,
            updated=self.updated,
            would_update=self.would_update,
            unchanged=self.unchanged,
            skipped_protected=self.skipped_protected,
            failed=self.failed,
            rule_counts=dict(sorted(self.rule_counts.items())),
        )


class UaeClassificationService:
    """Classify existing intelligence items in a bounded transaction."""

    def __init__(self, session: Session) -> None:
        self._session = session

    def classify_existing(
        self,
        *,
        max_items: int,
        apply: bool = False,
    ) -> UaeClassificationCounts:
        if not self._valid_limit(max_items):
            raise ValueError(
                f"max_items must be between 1 and {MAX_CLASSIFICATION_ITEMS}."
            )

        counts = _MutableCounts()
        try:
            items = self._load_items(max_items)
            for item in items:
                counts.processed += 1
                if self._is_protected(item):
                    counts.skipped_protected += 1
                    continue

                result = self.classify_item(item)
                counts.rule_counts[result.matched_rule_id] = (
                    counts.rule_counts.get(result.matched_rule_id, 0) + 1
                )
                if not self._would_change(item, result):
                    counts.unchanged += 1
                    continue

                if apply:
                    self.apply_result(item, result)
                    counts.updated += 1
                else:
                    counts.would_update += 1

            if apply:
                self._session.commit()
            else:
                self._session.rollback()
            return counts.freeze()
        except SQLAlchemyError as exc:
            self._session.rollback()
            raise UaeClassificationServiceError(
                "Database error while classifying UAE relevance."
            ) from exc

    def classify_item(self, item: IntelligenceItem) -> UaeClassificationResult:
        return classify_uae_relevance(
            UaeClassificationInput(
                title=item.canonical_title,
                summary=item.summary,
                source_slugs=self._source_slugs(item),
                geographic_scope=item.geographic_scope,
            )
        )

    @staticmethod
    def apply_result(
        item: IntelligenceItem,
        result: UaeClassificationResult,
    ) -> None:
        item.geographic_scope = result.geographic_scope
        item.uae_relevance_status = result.uae_relevance_status
        item.uae_relevance_confidence = result.uae_relevance_confidence
        item.uae_relevance_reason = result.uae_relevance_reason
        item.uae_relevance_method = result.uae_relevance_method

    @staticmethod
    def item_allows_automatic_update(item: IntelligenceItem) -> bool:
        return item.uae_relevance_method in ELIGIBLE_METHODS

    def classify_and_apply_if_allowed(self, item: IntelligenceItem) -> None:
        if not self.item_allows_automatic_update(item):
            return
        result = self.classify_item(item)
        if self._would_change(item, result):
            self.apply_result(item, result)

    def _load_items(self, max_items: int) -> list[IntelligenceItem]:
        selected: list[IntelligenceItem] = []
        for method in ("unassigned", "automatic"):
            remaining = max_items - len(selected)
            if remaining <= 0:
                break
            selected.extend(self._load_items_by_method(method, remaining))

        if selected:
            return selected

        return self._load_protected_items(max_items)

    def _load_items_by_method(
        self,
        method: str,
        limit: int,
    ) -> list[IntelligenceItem]:
        statement = (
            select(IntelligenceItem)
            .options(
                selectinload(IntelligenceItem.source_records).selectinload(
                    SourceRecord.source
                )
            )
            .where(IntelligenceItem.uae_relevance_method == method)
            .order_by(
                IntelligenceItem.source_published_at.asc().nulls_last(),
                IntelligenceItem.last_seen_at.asc(),
                IntelligenceItem.id.asc(),
            )
            .limit(limit)
        )
        return list(self._session.execute(statement).scalars().all())

    def _load_protected_items(self, max_items: int) -> list[IntelligenceItem]:
        statement = (
            select(IntelligenceItem)
            .options(
                selectinload(IntelligenceItem.source_records).selectinload(
                    SourceRecord.source
                )
            )
            .order_by(
                IntelligenceItem.source_published_at.asc().nulls_last(),
                IntelligenceItem.last_seen_at.asc(),
                IntelligenceItem.id.asc(),
            )
            .limit(max_items)
        )
        return [
            item
            for item in self._session.execute(statement).scalars().all()
            if self._is_protected(item)
        ]

    @staticmethod
    def _valid_limit(value: int) -> bool:
        return (
            isinstance(value, int)
            and not isinstance(value, bool)
            and 1 <= value <= MAX_CLASSIFICATION_ITEMS
        )

    @staticmethod
    def _is_protected(item: IntelligenceItem) -> bool:
        return item.uae_relevance_method not in ELIGIBLE_METHODS

    @staticmethod
    def _source_slugs(item: IntelligenceItem) -> tuple[str, ...]:
        return tuple(
            record.source.slug
            for record in item.source_records
            if record.source is not None and record.source.slug
        )

    @staticmethod
    def _would_change(
        item: IntelligenceItem,
        result: UaeClassificationResult,
    ) -> bool:
        return any(
            (
                item.geographic_scope != result.geographic_scope,
                item.uae_relevance_status != result.uae_relevance_status,
                _decimal_or_none(item.uae_relevance_confidence)
                != result.uae_relevance_confidence,
                item.uae_relevance_reason != result.uae_relevance_reason,
                item.uae_relevance_method != result.uae_relevance_method,
            )
        )


def _decimal_or_none(value: Decimal | None) -> Decimal | None:
    return value if value is not None else None
