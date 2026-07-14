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
THREAT_REPORT_ITEM_TYPE = "threat_report"
SUPPORTED_PUBLICATION_ITEM_TYPES = (
    SECURITY_ADVISORY_ITEM_TYPE,
    THREAT_REPORT_ITEM_TYPE,
)


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
        expected_item_type: str = SECURITY_ADVISORY_ITEM_TYPE,
    ) -> ArticleIdentityResolution:
        _validate_expected_item_type(expected_item_type)
        url_identifier = self._find_global_identifier(
            ARTICLE_URL_IDENTIFIER_NAMESPACE,
            canonical_url_hash,
        )
        title_identifier = self._find_global_identifier(
            ARTICLE_TITLE_IDENTIFIER_NAMESPACE,
            normalized_title_hash,
        )
        url_item = self._safe_item(url_identifier, expected_item_type)
        title_item = self._safe_item(title_identifier, expected_item_type)
        if url_identifier is not None and url_item is None:
            return ArticleIdentityResolution(
                failure_message=_identity_conflict_message(expected_item_type)
            )
        if title_identifier is not None and title_item is None:
            return ArticleIdentityResolution(
                failure_message=_identity_conflict_message(expected_item_type)
            )
        if url_item is not None and title_item is not None and url_item is not title_item:
            return ArticleIdentityResolution(
                failure_message=_identity_conflict_message(expected_item_type)
            )
        if url_item is not None:
            try:
                self.prepare_identifier_update(
                    url_item,
                    canonical_url_hash=canonical_url_hash,
                    normalized_title_hash=normalized_title_hash,
                    allow_missing_title_owner=True,
                    expected_item_type=expected_item_type,
                )
            except ArticleIdentityConflictError as exc:
                return ArticleIdentityResolution(failure_message=str(exc))
            return ArticleIdentityResolution(item=url_item)
        if title_item is not None:
            return ArticleIdentityResolution(
                failure_message=_title_only_conflict_message(expected_item_type)
            )
        return ArticleIdentityResolution()

    def prepare_identifier_update(
        self,
        item: IntelligenceItem,
        *,
        canonical_url_hash: str,
        normalized_title_hash: str,
        allow_missing_title_owner: bool = False,
        expected_item_type: str = SECURITY_ADVISORY_ITEM_TYPE,
    ) -> ArticleIdentifierUpdatePlan:
        _validate_expected_item_type(expected_item_type)
        if (
            item is None
            or item.item_type != expected_item_type
            or item.status != "active"
        ):
            raise ArticleIdentityConflictError(
                _inactive_item_message(expected_item_type)
            )
        item_url_identifier = self._item_identifier(
            item,
            ARTICLE_URL_IDENTIFIER_NAMESPACE,
            expected_item_type,
        )
        item_title_identifier = self._item_identifier(
            item,
            ARTICLE_TITLE_IDENTIFIER_NAMESPACE,
            expected_item_type,
        )
        url_identifier = self._find_global_identifier(
            ARTICLE_URL_IDENTIFIER_NAMESPACE,
            canonical_url_hash,
        )
        title_identifier = self._find_global_identifier(
            ARTICLE_TITLE_IDENTIFIER_NAMESPACE,
            normalized_title_hash,
        )
        url_item = self._safe_item(url_identifier, expected_item_type)
        title_item = self._safe_item(title_identifier, expected_item_type)
        if url_identifier is not None and url_item is None:
            raise ArticleIdentityConflictError(
                _identity_conflict_message(expected_item_type)
            )
        if title_identifier is not None and title_item is None:
            raise ArticleIdentityConflictError(
                _identity_conflict_message(expected_item_type)
            )
        if url_item is not None and url_item is not item:
            raise ArticleIdentityConflictError(
                _identity_conflict_message(expected_item_type)
            )
        if title_item is not None and title_item is not item:
            raise ArticleIdentityConflictError(
                _identity_conflict_message(expected_item_type)
            )
        if url_item is not None and title_item is not None and url_item is not title_item:
            raise ArticleIdentityConflictError(
                _identity_conflict_message(expected_item_type)
            )
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
        expected_item_type: str = SECURITY_ADVISORY_ITEM_TYPE,
    ) -> str | None:
        _validate_expected_item_type(expected_item_type)
        if item is None:
            return _inactive_item_message(expected_item_type)
        try:
            self.prepare_identifier_update(
                item,
                canonical_url_hash=canonical_url_hash,
                normalized_title_hash=normalized_title_hash,
                expected_item_type=expected_item_type,
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
    def _safe_item(
        identifier: IntelligenceItemIdentifier | None,
        expected_item_type: str,
    ) -> IntelligenceItem | None:
        if identifier is None:
            return None
        item = identifier.intelligence_item
        if (
            item is None
            or item.item_type != expected_item_type
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
        expected_item_type: str = SECURITY_ADVISORY_ITEM_TYPE,
    ) -> IntelligenceItemIdentifier | None:
        matches = [
            identifier
            for identifier in item.identifiers
            if identifier.source_id is None and identifier.namespace == namespace
        ]
        if len(matches) > 1:
            raise ArticleIdentityConflictError(
                _identity_conflict_message(expected_item_type)
            )
        return matches[0] if matches else None


def _validate_expected_item_type(expected_item_type: str) -> None:
    if expected_item_type not in SUPPORTED_PUBLICATION_ITEM_TYPES:
        raise ArticleIdentityConflictError(
            "The publication item type is not supported for identity resolution."
        )


def _identity_conflict_message(expected_item_type: str) -> str:
    if expected_item_type == SECURITY_ADVISORY_ITEM_TYPE:
        return ARTICLE_IDENTITY_CONFLICT_MESSAGE
    return "The publication identity signals conflict with existing records."


def _title_only_conflict_message(expected_item_type: str) -> str:
    if expected_item_type == SECURITY_ADVISORY_ITEM_TYPE:
        return ARTICLE_TITLE_ONLY_CONFLICT_MESSAGE
    return "A possible duplicate publication title requires analyst review."


def _inactive_item_message(expected_item_type: str) -> str:
    if expected_item_type == SECURITY_ADVISORY_ITEM_TYPE:
        return "The existing RSS source record is not linked to an active security advisory."
    if expected_item_type == THREAT_REPORT_ITEM_TYPE:
        return "The existing publication source record is not linked to an active threat report."
    return "The existing publication source record is not linked to an active publication."
