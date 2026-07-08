"""Shared validation helpers for read-only API query filters."""

from __future__ import annotations

import re
from datetime import UTC, date, datetime, time, timedelta
from typing import Iterable

from fastapi import HTTPException, status

from app.models.intelligence_item import (
    GEOGRAPHIC_SCOPE_VALUES,
    ITEM_TYPE_VALUES,
    UAE_RELEVANCE_STATUS_VALUES,
)


ARTICLE_ITEM_TYPE_VALUES = tuple(
    value for value in ITEM_TYPE_VALUES if value != "vulnerability"
)
SEVERITY_VALUES = ("unknown", "none", "low", "medium", "high", "critical")
CANONICAL_SLUG_PATTERN = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
CVE_ID_PATTERN = re.compile(r"^CVE-[0-9]{4}-[0-9]{4,}$")
MAX_ARTICLE_DATE_RANGE_YEARS = 5


def normalize_search_text(value: str | None, *, field_name: str = "q") -> str | None:
    """Trim a supplied search parameter and reject whitespace-only values."""

    if value is None:
        return None
    normalized = value.strip()
    if not normalized:
        _raise_validation_error(f"{field_name} must contain non-whitespace text.")
    return normalized


def normalize_enum_filter(
    value: str | None,
    *,
    allowed_values: Iterable[str],
    field_name: str,
) -> str | None:
    """Trim, lowercase, and validate a single-value enum query filter."""

    if value is None:
        return None
    normalized = value.strip().lower()
    if not normalized:
        _raise_validation_error(f"{field_name} must not be empty.")
    allowed = tuple(allowed_values)
    if normalized not in allowed:
        _raise_validation_error(f"{field_name} has an unsupported value.")
    return normalized


def normalize_slug_filter(value: str | None, *, field_name: str) -> str | None:
    """Trim, lowercase, and validate an exact-match canonical slug filter."""

    if value is None:
        return None
    normalized = value.strip().lower()
    if not normalized:
        _raise_validation_error(f"{field_name} must not be empty.")
    if CANONICAL_SLUG_PATTERN.fullmatch(normalized) is None:
        _raise_validation_error(f"{field_name} has an invalid slug format.")
    return normalized


def normalize_cve_id_filter(value: str | None) -> str | None:
    """Trim, uppercase, and validate a strict CVE identifier filter."""

    if value is None:
        return None
    normalized = value.strip().upper()
    if not normalized:
        _raise_validation_error("cve_id must not be empty.")
    if CVE_ID_PATTERN.fullmatch(normalized) is None:
        _raise_validation_error("cve_id has an invalid CVE format.")
    return normalized


def validate_article_date_range(
    published_from: date | None,
    published_to: date | None,
) -> tuple[datetime | None, datetime | None]:
    """Validate article publication date filters and return UTC boundaries."""

    if published_to == date.max:
        _raise_invalid_article_date_range()

    if published_from is not None and published_to is not None:
        if published_from > published_to or _range_exceeds_five_calendar_years(
            published_from,
            published_to,
        ):
            _raise_invalid_article_date_range()

    lower = (
        datetime.combine(published_from, time.min, tzinfo=UTC)
        if published_from is not None
        else None
    )
    upper = (
        datetime.combine(published_to + timedelta(days=1), time.min, tzinfo=UTC)
        if published_to is not None
        else None
    )
    return lower, upper


def validate_vulnerability_filter_combination(
    *,
    item_type: str | None,
    severity: str | None,
    cve_id: str | None,
) -> None:
    """Reject vulnerability-only filters with explicit non-vulnerability type."""

    if item_type is None or item_type == "vulnerability":
        return
    if severity is not None or cve_id is not None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Vulnerability filters require item_type=vulnerability.",
        )


def _range_exceeds_five_calendar_years(start: date, end: date) -> bool:
    if start.year + MAX_ARTICLE_DATE_RANGE_YEARS > date.max.year:
        return False
    return end > _add_calendar_years(start, MAX_ARTICLE_DATE_RANGE_YEARS)


def _add_calendar_years(value: date, years: int) -> date:
    target_year = value.year + years
    try:
        return value.replace(year=target_year)
    except ValueError:
        return value.replace(year=target_year, day=28)


def _raise_invalid_article_date_range() -> None:
    raise HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST,
        detail="Invalid article date range.",
    )


def _raise_validation_error(message: str) -> None:
    raise HTTPException(
        status_code=422,
        detail=message,
    )
