"""Shared validation helpers for read-only API query filters."""

from __future__ import annotations

import re
from collections.abc import Callable
from datetime import UTC, date, datetime, time, timedelta
from typing import Annotated, Iterable
from uuid import UUID

from fastapi import HTTPException, Request, status
from pydantic import BeforeValidator

from app.models.intelligence_item import (
    GEOGRAPHIC_SCOPE_VALUES,
    ITEM_TYPE_VALUES,
    UAE_RELEVANCE_STATUS_VALUES,
)


ARTICLE_ITEM_TYPE_VALUES = tuple(
    value for value in ITEM_TYPE_VALUES if value != "vulnerability"
)
SEVERITY_VALUES = ("unknown", "none", "low", "medium", "high", "critical")
LIST_SORT_VALUES = (
    "recently_ingested",
    "newest_published",
    "oldest_published",
)
DEFAULT_LIST_SORT = LIST_SORT_VALUES[0]
CANONICAL_SLUG_PATTERN = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
CVE_ID_PATTERN = re.compile(r"^CVE-[0-9]{4}-[0-9]{4,}$")
CANONICAL_PUBLIC_UUID_PATTERN = re.compile(
    r"^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-"
    r"[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$"
)
MAX_ARTICLE_DATE_RANGE_YEARS = 5
MAX_PAGINATION_OFFSET = 10_000
MAX_SEARCH_LENGTH = 120
MIN_PUBLISHED_YEAR = 2020
VALIDATION_ERROR_DETAIL = "Request validation failed."


def _validate_canonical_public_uuid(value: object) -> object:
    if (
        not isinstance(value, str)
        or CANONICAL_PUBLIC_UUID_PATTERN.fullmatch(value) is None
    ):
        raise ValueError(VALIDATION_ERROR_DETAIL)
    return value


CanonicalPublicUUID = Annotated[
    UUID,
    BeforeValidator(_validate_canonical_public_uuid),
]


def _validate_published_year(value: object) -> int:
    if type(value) is int:
        year = value
    elif isinstance(value, str) and re.fullmatch(r"[0-9]{4}", value) is not None:
        year = int(value)
    else:
        raise ValueError(VALIDATION_ERROR_DETAIL)

    if year < MIN_PUBLISHED_YEAR or year > datetime.now(UTC).year:
        raise ValueError(VALIDATION_ERROR_DETAIL)
    return year


PublishedYear = Annotated[
    int,
    BeforeValidator(_validate_published_year),
]


def validate_query_parameters(
    allowed_names: Iterable[str],
) -> Callable[[Request], None]:
    """Return a dependency that rejects unknown or repeated scalar queries."""

    allowed = frozenset(allowed_names)

    def validate(request: Request) -> None:
        decoded_names = [name for name, _ in request.query_params.multi_items()]
        if any(name not in allowed for name in decoded_names):
            _raise_validation_error()
        if len(decoded_names) != len(set(decoded_names)):
            _raise_validation_error()

    return validate


def normalize_search_text(value: str | None, *, field_name: str = "q") -> str | None:
    """Trim and validate a bounded, printable plain-text search value."""

    if value is None:
        return None
    if len(value) > MAX_SEARCH_LENGTH:
        _raise_validation_error()
    if any(character in "<>" or not character.isprintable() for character in value):
        _raise_validation_error()
    normalized = value.strip()
    if not normalized:
        _raise_validation_error()
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
        _raise_validation_error()
    allowed = tuple(allowed_values)
    if normalized not in allowed:
        _raise_validation_error()
    return normalized


def normalize_slug_filter(value: str | None, *, field_name: str) -> str | None:
    """Trim, lowercase, and validate an exact-match canonical slug filter."""

    if value is None:
        return None
    normalized = value.strip().lower()
    if not normalized:
        _raise_validation_error()
    if CANONICAL_SLUG_PATTERN.fullmatch(normalized) is None:
        _raise_validation_error()
    return normalized


def normalize_cve_id_filter(value: str | None) -> str | None:
    """Trim, uppercase, and validate a strict CVE identifier filter."""

    if value is None:
        return None
    normalized = value.strip().upper()
    if not normalized:
        _raise_validation_error()
    if CVE_ID_PATTERN.fullmatch(normalized) is None:
        _raise_validation_error()
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
    published_year: int | None,
) -> None:
    """Reject vulnerability-only filters with explicit non-vulnerability type."""

    if item_type is None or item_type == "vulnerability":
        return
    if severity is not None or cve_id is not None or published_year is not None:
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


def _raise_validation_error() -> None:
    raise HTTPException(
        status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
        detail=VALIDATION_ERROR_DETAIL,
    )
