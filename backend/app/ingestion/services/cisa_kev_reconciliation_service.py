"""Complete-catalog validation and caller-transactional local CISA KEV reconciliation."""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Callable, Collection
from dataclasses import dataclass
from datetime import UTC, datetime
import re
from typing import Any

from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.ingestion.normalizers.cisa_kev import (
    CVE_ID_PATTERN,
    CisaKevNormalizationError,
    NormalizedCisaKevEntry,
    deduplicate_cisa_kev_entries,
    extract_cisa_kev_entries,
    normalize_cisa_kev_entry,
)
from app.models import IntelligenceItemIdentifier, Vulnerability


MAX_CATALOG_METADATA_LENGTH = 100
CATALOG_VERSION_PATTERN = re.compile(r"[A-Za-z0-9._-]+", re.ASCII)


class CisaKevCatalogValidationError(ValueError):
    """The catalog was not complete enough to support absence decisions."""


class CisaKevReconciliationPersistenceError(RuntimeError):
    """A local reconciliation database operation failed safely."""


@dataclass(frozen=True)
class ValidatedCisaKevCatalog:
    """Minimal complete-catalog evidence needed by local reconciliation."""

    catalog_version: str
    date_released: datetime
    raw_record_count: int
    cve_ids: frozenset[str]

    def __post_init__(self) -> None:
        _required_catalog_version(self.catalog_version)

    @property
    def cve_count(self) -> int:
        return len(self.cve_ids)


@dataclass(frozen=True)
class CisaKevReconciliationRecord:
    """One sanitized local reconciliation outcome."""

    vulnerability_id: int
    intelligence_item_id: int
    cve_id: str | None
    target_status: str | None
    outcome: str
    safe_detail: str


@dataclass(frozen=True)
class CisaKevReconciliationResult:
    """Counters and safe per-row audit data for one selected local set."""

    inspected: int
    listed: int
    not_listed: int
    updated: int
    unchanged: int
    skipped: int
    failed: int
    unknown_remaining: int
    records: tuple[CisaKevReconciliationRecord, ...]

    def __post_init__(self) -> None:
        counters = (
            self.inspected,
            self.listed,
            self.not_listed,
            self.updated,
            self.unchanged,
            self.skipped,
            self.failed,
            self.unknown_remaining,
        )
        if any(type(counter) is not int or counter < 0 for counter in counters):
            raise ValueError(
                "CISA KEV reconciliation counters must be non-negative integers."
            )
        if self.inspected != self.updated + self.unchanged + self.skipped + self.failed:
            raise ValueError("CISA KEV reconciliation counters do not reconcile.")
        if self.listed + self.not_listed != self.updated + self.unchanged:
            raise ValueError("CISA KEV status counters do not reconcile.")
        if self.unknown_remaining > self.skipped:
            raise ValueError(
                "CISA KEV unknown remaining cannot exceed skipped local rows."
            )
        if len(self.records) != self.inspected:
            raise ValueError(
                "CISA KEV reconciliation audit records do not reconcile."
            )


def validate_complete_cisa_kev_catalog(
    catalog: dict[str, Any],
    *,
    entry_extractor: Callable[[dict[str, Any]], list[dict[str, Any]]] = (
        extract_cisa_kev_entries
    ),
    entry_normalizer: Callable[
        [dict[str, Any]], NormalizedCisaKevEntry
    ] = normalize_cisa_kev_entry,
) -> ValidatedCisaKevCatalog:
    """Validate every declared catalog row before absence can be inferred."""

    if not isinstance(catalog, dict):
        raise CisaKevCatalogValidationError(
            "The CISA KEV catalog failed complete validation."
        )

    catalog_version = _required_catalog_version(catalog.get("catalogVersion"))
    date_released = _required_release_time(catalog.get("dateReleased"))
    declared_count = catalog.get("count")
    if (
        not isinstance(declared_count, int)
        or isinstance(declared_count, bool)
        or declared_count <= 0
    ):
        raise CisaKevCatalogValidationError(
            "The CISA KEV catalog failed complete validation."
        )

    try:
        entries = entry_extractor(catalog)
    except CisaKevNormalizationError as exc:
        raise CisaKevCatalogValidationError(
            "The CISA KEV catalog failed complete validation."
        ) from exc
    if not entries or len(entries) != declared_count:
        raise CisaKevCatalogValidationError(
            "The CISA KEV catalog failed complete validation."
        )

    try:
        normalized = [entry_normalizer(entry) for entry in entries]
        unique_entries = deduplicate_cisa_kev_entries(normalized)
    except CisaKevNormalizationError as exc:
        raise CisaKevCatalogValidationError(
            "The CISA KEV catalog failed complete validation."
        ) from exc

    if not unique_entries:
        raise CisaKevCatalogValidationError(
            "The CISA KEV catalog failed complete validation."
        )
    return ValidatedCisaKevCatalog(
        catalog_version=catalog_version,
        date_released=date_released,
        raw_record_count=declared_count,
        cve_ids=frozenset(entry.cve_id for entry in unique_entries),
    )


class CisaKevReconciliationService:
    """Reconcile bounded local vulnerability rows without owning the transaction."""

    def __init__(self, session: Session) -> None:
        self._session = session

    def reconcile(
        self,
        catalog_cve_ids: Collection[str],
        *,
        max_cves: int,
        batch_size: int,
        checked_at: datetime,
    ) -> CisaKevReconciliationResult:
        """Apply listed/not-listed status to a bounded deterministic local set."""

        if checked_at.tzinfo is None or checked_at.utcoffset() is None:
            raise ValueError("The CISA KEV checked time must be timezone-aware.")
        checked_at = checked_at.astimezone(UTC)
        normalized_catalog = _validated_cve_set(catalog_cve_ids)

        inspected = listed = not_listed = updated = unchanged = skipped = 0
        unknown_remaining = 0
        records: list[CisaKevReconciliationRecord] = []
        after_id = 0

        try:
            while inspected < max_cves:
                limit = min(batch_size, max_cves - inspected)
                vulnerabilities = self._load_vulnerability_batch(
                    after_id=after_id,
                    limit=limit,
                )
                if not vulnerabilities:
                    break

                item_ids = [
                    self._validated_row_ids(vulnerability)[1]
                    for vulnerability in vulnerabilities
                ]
                identifiers_by_item = self._load_global_cve_identifiers(item_ids)

                for vulnerability in vulnerabilities:
                    vulnerability_id, item_id = self._validated_row_ids(vulnerability)
                    after_id = vulnerability_id
                    inspected += 1
                    usable_cve_ids = {
                        cve_id
                        for value in identifiers_by_item.get(item_id, ())
                        if (cve_id := _usable_local_cve(value)) is not None
                    }
                    if len(usable_cve_ids) != 1:
                        skipped += 1
                        if vulnerability.kev_status == "unknown":
                            unknown_remaining += 1
                        safe_reason = (
                            "no usable global CVE identifier"
                            if not usable_cve_ids
                            else "ambiguous global CVE identity"
                        )
                        records.append(
                            CisaKevReconciliationRecord(
                                vulnerability_id=vulnerability_id,
                                intelligence_item_id=item_id,
                                cve_id=None,
                                target_status=None,
                                outcome="skipped",
                                safe_detail=(
                                    "Local vulnerability skipped because it has "
                                    f"{safe_reason}."
                                ),
                            )
                        )
                        continue

                    cve_id = next(iter(usable_cve_ids))
                    target_status = (
                        "listed" if cve_id in normalized_catalog else "not_listed"
                    )
                    if target_status == "listed":
                        listed += 1
                    else:
                        not_listed += 1

                    outcome = (
                        "unchanged"
                        if vulnerability.kev_status == target_status
                        else "updated"
                    )
                    if outcome == "updated":
                        updated += 1
                        vulnerability.kev_status = target_status
                    else:
                        unchanged += 1
                    vulnerability.kev_last_checked_at = checked_at
                    records.append(
                        CisaKevReconciliationRecord(
                            vulnerability_id=vulnerability_id,
                            intelligence_item_id=item_id,
                            cve_id=cve_id,
                            target_status=target_status,
                            outcome=outcome,
                            safe_detail=(
                                f"Local CVE reconciliation {outcome}; "
                                f"KEV status is {target_status}."
                            ),
                        )
                    )

                self._session.flush()
                if len(vulnerabilities) < limit:
                    break
        except CisaKevReconciliationPersistenceError:
            raise
        except SQLAlchemyError as exc:
            raise CisaKevReconciliationPersistenceError(
                "A database error interrupted CISA KEV local reconciliation."
            ) from exc

        return CisaKevReconciliationResult(
            inspected=inspected,
            listed=listed,
            not_listed=not_listed,
            updated=updated,
            unchanged=unchanged,
            skipped=skipped,
            failed=0,
            unknown_remaining=unknown_remaining,
            records=tuple(records),
        )

    def _load_vulnerability_batch(
        self,
        *,
        after_id: int,
        limit: int,
    ) -> list[Vulnerability]:
        statement = (
            select(Vulnerability)
            .where(Vulnerability.id > after_id)
            .order_by(Vulnerability.id.asc())
            .limit(limit)
        )
        return list(self._session.execute(statement).scalars().all())

    def _load_global_cve_identifiers(
        self,
        intelligence_item_ids: Collection[int],
    ) -> dict[int, tuple[object, ...]]:
        statement = select(
            IntelligenceItemIdentifier.intelligence_item_id,
            IntelligenceItemIdentifier.normalized_value,
        ).where(
            IntelligenceItemIdentifier.intelligence_item_id.in_(
                intelligence_item_ids
            ),
            IntelligenceItemIdentifier.source_id.is_(None),
            IntelligenceItemIdentifier.namespace == "cve",
        )
        grouped: defaultdict[int, list[object]] = defaultdict(list)
        for item_id, normalized_value in self._session.execute(statement).all():
            grouped[item_id].append(normalized_value)
        return {item_id: tuple(values) for item_id, values in grouped.items()}

    @staticmethod
    def _validated_row_ids(vulnerability: Vulnerability) -> tuple[int, int]:
        vulnerability_id = getattr(vulnerability, "id", None)
        item_id = getattr(vulnerability, "intelligence_item_id", None)
        if (
            not isinstance(vulnerability_id, int)
            or isinstance(vulnerability_id, bool)
            or not isinstance(item_id, int)
            or isinstance(item_id, bool)
        ):
            raise CisaKevReconciliationPersistenceError(
                "A local vulnerability row could not be reconciled safely."
            )
        return vulnerability_id, item_id


def _required_catalog_version(value: object) -> str:
    if (
        not isinstance(value, str)
        or len(value) > MAX_CATALOG_METADATA_LENGTH
        or CATALOG_VERSION_PATTERN.fullmatch(value) is None
    ):
        raise CisaKevCatalogValidationError(
            "The CISA KEV catalog failed complete validation."
        )
    return value


def _required_metadata_text(value: object) -> str:
    if not isinstance(value, str):
        raise CisaKevCatalogValidationError(
            "The CISA KEV catalog failed complete validation."
        )
    normalized = value.strip()
    if not normalized or len(normalized) > MAX_CATALOG_METADATA_LENGTH:
        raise CisaKevCatalogValidationError(
            "The CISA KEV catalog failed complete validation."
        )
    return normalized


def _required_release_time(value: object) -> datetime:
    text = _required_metadata_text(value)
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise CisaKevCatalogValidationError(
            "The CISA KEV catalog failed complete validation."
        ) from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise CisaKevCatalogValidationError(
            "The CISA KEV catalog failed complete validation."
        )
    return parsed.astimezone(UTC)


def _validated_cve_set(values: Collection[str]) -> frozenset[str]:
    normalized: set[str] = set()
    for value in values:
        if not isinstance(value, str) or CVE_ID_PATTERN.fullmatch(value) is None:
            raise ValueError("The validated CISA KEV CVE set is invalid.")
        normalized.add(value.upper())
    if not normalized:
        raise ValueError("The validated CISA KEV CVE set must not be empty.")
    return frozenset(normalized)


def _usable_local_cve(value: object) -> str | None:
    if not isinstance(value, str) or CVE_ID_PATTERN.fullmatch(value) is None:
        return None
    return value.upper()
