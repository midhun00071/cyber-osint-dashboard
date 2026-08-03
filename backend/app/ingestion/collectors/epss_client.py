"""Small synchronous client for the official FIRST EPSS API."""

from __future__ import annotations

from dataclasses import dataclass
import json
import re
from typing import Any

import httpx

from app.ingestion.source_registry import get_required_source_base_url


FIRST_EPSS_SOURCE_SLUG = "first-epss"
FIRST_EPSS_API_URL = get_required_source_base_url(FIRST_EPSS_SOURCE_SLUG)
DEFAULT_TIMEOUT = httpx.Timeout(20.0, connect=5.0)
MAX_CVE_QUERY_CHARS = 2000
DEFAULT_MAX_BATCH_SIZE = 100
MAX_RESPONSE_BYTES = 2 * 1024 * 1024
CVE_ID_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)


class EpssClientError(Exception):
    """Base class for sanitized EPSS client failures."""


class EpssRequestError(EpssClientError):
    """The EPSS request could not be completed."""


class EpssHttpError(EpssClientError):
    """The EPSS API returned an unsuccessful HTTP status."""


class EpssRateLimitError(EpssHttpError):
    """The EPSS API rejected a request because of rate limiting."""


class EpssResponseError(EpssClientError):
    """The EPSS response or request parameters were invalid."""


@dataclass(frozen=True)
class EpssBatch:
    """Validated EPSS records from one bounded API response."""

    requested_cves: tuple[str, ...]
    records: list[dict[str, Any]]


class EpssClient:
    """Fetch bounded CVE-specific score records from the official EPSS API."""

    def __init__(self, *, http_client: httpx.Client | None = None) -> None:
        self._owns_http_client = http_client is None
        self._http_client = http_client or httpx.Client(timeout=DEFAULT_TIMEOUT)

    def fetch_scores(
        self,
        cve_ids: list[str] | tuple[str, ...],
        *,
        max_batch_size: int = DEFAULT_MAX_BATCH_SIZE,
    ) -> list[EpssBatch]:
        """Fetch all requested CVEs in deterministic bounded batches."""

        return [
            self.fetch_batch(batch)
            for batch in self.build_batches(cve_ids, max_batch_size=max_batch_size)
        ]

    def fetch_batch(self, cve_ids: tuple[str, ...] | list[str]) -> EpssBatch:
        """Fetch one validated batch whose `cve` query fits FIRST limits."""

        normalized = self._normalize_cve_ids(cve_ids)
        if not normalized:
            raise EpssResponseError("At least one CVE ID is required.")
        cve_query = ",".join(normalized)
        if len(cve_query) > MAX_CVE_QUERY_CHARS:
            raise EpssResponseError("The EPSS CVE query exceeds the approved limit.")

        try:
            with self._http_client.stream(
                "GET",
                FIRST_EPSS_API_URL,
                params={"cve": cve_query, "limit": len(normalized)},
            ) as response:
                if response.status_code == 429:
                    raise EpssRateLimitError(
                        "The EPSS API rate limit was reached (HTTP 429)."
                    )
                if not response.is_success:
                    raise EpssHttpError(
                        f"The EPSS API returned HTTP {response.status_code}."
                    )
                declared_length = self._valid_content_length(
                    response.headers.get("Content-Length")
                )
                if declared_length is not None and declared_length > MAX_RESPONSE_BYTES:
                    raise EpssResponseError(
                        "The EPSS response exceeded the approved size limit."
                    )
                body = bytearray()
                for chunk in response.iter_bytes():
                    if len(body) + len(chunk) > MAX_RESPONSE_BYTES:
                        body.clear()
                        raise EpssResponseError(
                            "The EPSS response exceeded the approved size limit."
                        )
                    body.extend(chunk)
        except httpx.TimeoutException as exc:
            raise EpssRequestError("The EPSS request timed out.") from exc
        except httpx.TransportError as exc:
            raise EpssRequestError("The EPSS request failed during transport.") from exc

        try:
            payload = json.loads(body)
        except (UnicodeDecodeError, ValueError) as exc:
            raise EpssResponseError("The EPSS API returned invalid JSON.") from exc

        return EpssBatch(
            requested_cves=tuple(normalized),
            records=self._parse_records(payload),
        )

    def build_batches(
        self,
        cve_ids: list[str] | tuple[str, ...],
        *,
        max_batch_size: int = DEFAULT_MAX_BATCH_SIZE,
    ) -> list[tuple[str, ...]]:
        """Normalize, deduplicate, and split CVEs within count and query limits."""

        if (
            not isinstance(max_batch_size, int)
            or isinstance(max_batch_size, bool)
            or max_batch_size < 1
        ):
            raise EpssResponseError("The EPSS batch size must be a positive integer.")

        normalized = self._normalize_cve_ids(cve_ids)
        batches: list[list[str]] = []
        current: list[str] = []
        current_length = 0
        for cve_id in normalized:
            added_length = len(cve_id) if not current else len(cve_id) + 1
            if current and (
                len(current) >= max_batch_size
                or current_length + added_length > MAX_CVE_QUERY_CHARS
            ):
                batches.append(current)
                current = []
                current_length = 0
                added_length = len(cve_id)
            current.append(cve_id)
            current_length += added_length
        if current:
            batches.append(current)
        return [tuple(batch) for batch in batches]

    def close(self) -> None:
        """Close the HTTP client only when this instance created it."""

        if self._owns_http_client:
            self._http_client.close()

    def __enter__(self) -> EpssClient:
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()

    @staticmethod
    def _normalize_cve_ids(cve_ids: list[str] | tuple[str, ...]) -> list[str]:
        if not isinstance(cve_ids, (list, tuple)):
            raise EpssResponseError("EPSS CVE IDs must be supplied as a list.")
        normalized: list[str] = []
        seen: set[str] = set()
        for value in cve_ids:
            if not isinstance(value, str) or CVE_ID_PATTERN.fullmatch(value) is None:
                raise EpssResponseError("The EPSS request contains an invalid CVE ID.")
            cve_id = value.upper()
            if cve_id not in seen:
                normalized.append(cve_id)
                seen.add(cve_id)
        return normalized

    @staticmethod
    def _parse_records(payload: object) -> list[dict[str, Any]]:
        if not isinstance(payload, dict):
            raise EpssResponseError("The EPSS response must be a JSON object.")
        records = payload.get("data")
        if not isinstance(records, list) or any(
            not isinstance(record, dict) for record in records
        ):
            raise EpssResponseError("The EPSS data field must be a list of objects.")
        return records

    @staticmethod
    def _valid_content_length(value: str | None) -> int | None:
        if value is None:
            return None
        normalized = value.strip()
        if not normalized.isascii() or not normalized.isdecimal():
            return None
        return int(normalized)
