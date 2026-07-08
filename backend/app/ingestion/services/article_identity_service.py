"""Reusable identity helpers for article and advisory duplicate prevention."""

from __future__ import annotations

from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import IntelligenceItem, IntelligenceItemIdentifier


ARTICLE_URL_IDENTIFIER_NAMESPACE = "canonical_url_sha256"
ARTICLE_TITLE_IDENTIFIER_NAMESPACE = "normalized_title_sha256"
ARTICLE_IDENTITY_CONFLICT_MESSAGE = (
    "The advisory identity signals conflict with existing records."
)
ARTICLE_TITLE_ONLY_CONFLICT_MESSAGE = (
    "A possible duplicate advisory title requires analyst review."
)
SECURITY_ADVISORY_ITEM_TYPE = "security_advisory"


@dataclass(frozen=True)
class ArticleIdentityResolution:
    """Result of resolving global article fingerprints."""

    item: IntelligenceItem | None = None
    failure_message: str | None = None

    @property
    def failed(self) -> bool:
        return self.failure_message is not None


class ArticleIdentityConflictError(RuntimeError):
    """Article identity rows are ambiguous or unsafe to mutate."""


@dataclass(frozen=True)
class ArticleIdentifierUpdatePlan:
    """Prepared fingerprint update that has already passed identity validation."""

    item: IntelligenceItem
    url_identifier: IntelligenceItemIdentifier | None
    title_identifier: IntelligenceItemIdentifier | None
    canonical_url_hash: str
    normalized_title_hash: str


class ArticleIdentityService:
    """Resolve and maintain global article fingerprints without owning transactions."""

    def __init__(self, session: Session) -> None:
        self._session = session

    def resolve_new_article(
        self,
        *,
        canonical_url_hash: str,
        normalized_title_hash: str,
    ) -> ArticleIdentityResolution:
        url_identifier = self._find_global_identifier(
            ARTICLE_URL_IDENTIFIER_NAMESPACE,
            canonical_url_hash,
        )
        title_identifier = self._find_global_identifier(
            ARTICLE_TITLE_IDENTIFIER_NAMESPACE,
            normalized_title_hash,
        )
        url_item = self._safe_advisory_item(url_identifier)
        title_item = self._safe_advisory_item(title_identifier)
        if url_identifier is not None and url_item is None:
            return ArticleIdentityResolution(
                failure_message=ARTICLE_IDENTITY_CONFLICT_MESSAGE
            )
        if title_identifier is not None and title_item is None:
            return ArticleIdentityResolution(
                failure_message=ARTICLE_IDENTITY_CONFLICT_MESSAGE
            )
        if url_item is not None and title_item is not None and url_item is not title_item:
            return ArticleIdentityResolution(
                failure_message=ARTICLE_IDENTITY_CONFLICT_MESSAGE
            )
        if url_item is not None:
            try:
                self.prepare_identifier_update(
                    url_item,
                    canonical_url_hash=canonical_url_hash,
                    normalized_title_hash=normalized_title_hash,
                    allow_missing_title_owner=True,
                )
            except ArticleIdentityConflictError as exc:
                return ArticleIdentityResolution(failure_message=str(exc))
            return ArticleIdentityResolution(item=url_item)
        if title_item is not None:
            return ArticleIdentityResolution(
                failure_message=ARTICLE_TITLE_ONLY_CONFLICT_MESSAGE
            )
        return ArticleIdentityResolution()

    def prepare_identifier_update(
        self,
        item: IntelligenceItem,
        *,
        canonical_url_hash: str,
        normalized_title_hash: str,
        allow_missing_title_owner: bool = False,
    ) -> ArticleIdentifierUpdatePlan:
        if (
            item is None
            or item.item_type != SECURITY_ADVISORY_ITEM_TYPE
            or item.status != "active"
        ):
            raise ArticleIdentityConflictError(
                "The existing RSS source record is not linked to an active security advisory."
            )
        item_url_identifier = self._item_identifier(
            item,
            ARTICLE_URL_IDENTIFIER_NAMESPACE,
        )
        item_title_identifier = self._item_identifier(
            item,
            ARTICLE_TITLE_IDENTIFIER_NAMESPACE,
        )
        url_identifier = self._find_global_identifier(
            ARTICLE_URL_IDENTIFIER_NAMESPACE,
            canonical_url_hash,
        )
        title_identifier = self._find_global_identifier(
            ARTICLE_TITLE_IDENTIFIER_NAMESPACE,
            normalized_title_hash,
        )
        url_item = self._safe_advisory_item(url_identifier)
        title_item = self._safe_advisory_item(title_identifier)
        if url_identifier is not None and url_item is None:
            raise ArticleIdentityConflictError(ARTICLE_IDENTITY_CONFLICT_MESSAGE)
        if title_identifier is not None and title_item is None:
            raise ArticleIdentityConflictError(ARTICLE_IDENTITY_CONFLICT_MESSAGE)
        if url_item is not None and url_item is not item:
            raise ArticleIdentityConflictError(ARTICLE_IDENTITY_CONFLICT_MESSAGE)
        if title_item is not None and title_item is not item:
            raise ArticleIdentityConflictError(ARTICLE_IDENTITY_CONFLICT_MESSAGE)
        if url_item is not None and title_item is not None and url_item is not title_item:
            raise ArticleIdentityConflictError(ARTICLE_IDENTITY_CONFLICT_MESSAGE)
        return ArticleIdentifierUpdatePlan(
            item=item,
            url_identifier=item_url_identifier,
            title_identifier=item_title_identifier,
            canonical_url_hash=canonical_url_hash,
            normalized_title_hash=normalized_title_hash,
        )

    def validate_source_record_identity(
        self,
        item: IntelligenceItem | None,
        *,
        canonical_url_hash: str,
        normalized_title_hash: str,
    ) -> str | None:
        if item is None:
            return "The existing RSS source record is not linked to an active security advisory."
        try:
            self.prepare_identifier_update(
                item,
                canonical_url_hash=canonical_url_hash,
                normalized_title_hash=normalized_title_hash,
            )
        except ArticleIdentityConflictError as exc:
            return str(exc)
        return None

    def add_fingerprint_identifiers(
        self,
        item: IntelligenceItem,
        *,
        canonical_url_hash: str,
        normalized_title_hash: str,
    ) -> None:
        self._ensure_item_identifier(
            item,
            ARTICLE_URL_IDENTIFIER_NAMESPACE,
            canonical_url_hash,
        )
        self._ensure_item_identifier(
            item,
            ARTICLE_TITLE_IDENTIFIER_NAMESPACE,
            normalized_title_hash,
        )

    def update_fingerprint_identifiers(
        self,
        plan: ArticleIdentifierUpdatePlan,
    ) -> None:
        self._apply_identifier(
            plan.item,
            plan.url_identifier,
            ARTICLE_URL_IDENTIFIER_NAMESPACE,
            plan.canonical_url_hash,
        )
        self._apply_identifier(
            plan.item,
            plan.title_identifier,
            ARTICLE_TITLE_IDENTIFIER_NAMESPACE,
            plan.normalized_title_hash,
        )

    def _apply_identifier(
        self,
        item: IntelligenceItem,
        existing: IntelligenceItemIdentifier | None,
        namespace: str,
        normalized_value: str,
    ) -> IntelligenceItemIdentifier:
        if existing is not None:
            existing.identifier_value = normalized_value
            existing.normalized_value = normalized_value
            existing.is_primary = False
            return existing
        identifier = IntelligenceItemIdentifier(
            intelligence_item=item,
            source=None,
            source_record=None,
            namespace=namespace,
            identifier_value=normalized_value,
            normalized_value=normalized_value,
            is_primary=False,
        )
        self._session.add(identifier)
        return identifier

    def apply_identifier_update(
        self,
        plan: ArticleIdentifierUpdatePlan,
    ) -> None:
        self.update_fingerprint_identifiers(plan)

    def _find_global_identifier(
        self,
        namespace: str,
        normalized_value: str,
    ) -> IntelligenceItemIdentifier | None:
        return self._session.execute(
            select(IntelligenceItemIdentifier)
            .where(IntelligenceItemIdentifier.source_id.is_(None))
            .where(IntelligenceItemIdentifier.namespace == namespace)
            .where(IntelligenceItemIdentifier.normalized_value == normalized_value)
        ).scalar_one_or_none()

    @staticmethod
    def _safe_advisory_item(
        identifier: IntelligenceItemIdentifier | None,
    ) -> IntelligenceItem | None:
        if identifier is None:
            return None
        item = identifier.intelligence_item
        if (
            item is None
            or item.item_type != SECURITY_ADVISORY_ITEM_TYPE
            or item.status != "active"
        ):
            return None
        return item

    def _ensure_item_identifier(
        self,
        item: IntelligenceItem,
        namespace: str,
        normalized_value: str,
    ) -> IntelligenceItemIdentifier:
        existing = self._item_identifier(item, namespace)
        if existing is not None:
            existing.identifier_value = normalized_value
            existing.normalized_value = normalized_value
            existing.is_primary = False
            return existing
        identifier = IntelligenceItemIdentifier(
            intelligence_item=item,
            source=None,
            source_record=None,
            namespace=namespace,
            identifier_value=normalized_value,
            normalized_value=normalized_value,
            is_primary=False,
        )
        self._session.add(identifier)
        return identifier

    @staticmethod
    def _item_identifier(
        item: IntelligenceItem,
        namespace: str,
    ) -> IntelligenceItemIdentifier | None:
        matches = [
            identifier
            for identifier in item.identifiers
            if identifier.source_id is None and identifier.namespace == namespace
        ]
        if len(matches) > 1:
            raise ArticleIdentityConflictError(ARTICLE_IDENTITY_CONFLICT_MESSAGE)
        return matches[0] if matches else None
