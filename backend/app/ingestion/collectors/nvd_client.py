"""Small synchronous client for the official NVD CVE API."""

from __future__ import annotations

from collections.abc import Callable, Iterator
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
import time
from typing import Any

import httpx
from pydantic import SecretStr

from app.ingestion.source_registry import get_required_source_base_url


NVD_SOURCE_SLUG = "nvd"
NVD_CVE_API_URL = get_required_source_base_url(NVD_SOURCE_SLUG)
MAX_RESULTS_PER_PAGE = 2000
MAX_DATE_WINDOW = timedelta(days=120)
DEFAULT_TIMEOUT = httpx.Timeout(30.0, connect=10.0)
UNAUTHENTICATED_DELAY_SECONDS = 6.0
AUTHENTICATED_DELAY_SECONDS = 0.6


class NvdClientError(Exception):
    """Base class for sanitized NVD client failures."""


class NvdRequestError(NvdClientError):
    """The NVD request could not be completed."""


class NvdHttpError(NvdClientError):
    """The NVD API returned an unsuccessful HTTP status."""


class NvdRateLimitError(NvdHttpError):
    """The NVD API rejected a request because of rate limiting."""


class NvdResponseError(NvdClientError):
    """The NVD response or request parameters were invalid."""


@dataclass(frozen=True)
class NvdPage:
    """Validated pagination metadata and CVE records from one NVD response."""

    vulnerabilities: list[dict[str, Any]]
    start_index: int
    results_per_page: int
    total_results: int


class NvdClient:
    """Fetch bounded, date-filtered pages from the official NVD CVE API."""

    def __init__(
        self,
        api_key: SecretStr | None = None,
        *,
        http_client: httpx.Client | None = None,
        sleeper: Callable[[float], None] = time.sleep,
    ) -> None:
        secret_value = api_key.get_secret_value() if api_key is not None else ""
        self._headers = {"apiKey": secret_value} if secret_value else {}
        self._request_delay = (
            AUTHENTICATED_DELAY_SECONDS
            if secret_value
            else UNAUTHENTICATED_DELAY_SECONDS
        )
        self._sleeper = sleeper
        self._owns_http_client = http_client is None
        self._http_client = http_client or httpx.Client(timeout=DEFAULT_TIMEOUT)

    def fetch_page(
        self,
        last_modified_start: datetime,
        last_modified_end: datetime,
        start_index: int = 0,
        results_per_page: int = MAX_RESULTS_PER_PAGE,
    ) -> NvdPage:
        """Fetch and validate one page for an explicit modification window."""

        self._validate_request(
            last_modified_start,
            last_modified_end,
            start_index,
            results_per_page,
        )
        params = {
            "lastModStartDate": self._format_datetime(last_modified_start),
            "lastModEndDate": self._format_datetime(last_modified_end),
            "startIndex": start_index,
            "resultsPerPage": results_per_page,
        }

        try:
            response = self._http_client.get(
                NVD_CVE_API_URL,
                params=params,
                headers=self._headers,
            )
        except httpx.TimeoutException as exc:
            raise NvdRequestError("The NVD request timed out.") from exc
        except httpx.TransportError as exc:
            raise NvdRequestError("The NVD request failed during transport.") from exc

        if response.status_code == 429:
            raise NvdRateLimitError("The NVD API rate limit was reached (HTTP 429).")
        if not response.is_success:
            raise NvdHttpError(
                f"The NVD API returned HTTP {response.status_code}."
            )

        try:
            payload = response.json()
        except ValueError as exc:
            raise NvdResponseError("The NVD API returned invalid JSON.") from exc

        return self._parse_page(payload)

    def iter_vulnerabilities(
        self,
        last_modified_start: datetime,
        last_modified_end: datetime,
        results_per_page: int = MAX_RESULTS_PER_PAGE,
    ) -> Iterator[dict[str, Any]]:
        """Yield all CVE records in the date window, pacing between pages."""

        start_index = 0
        while True:
            page = self.fetch_page(
                last_modified_start,
                last_modified_end,
                start_index=start_index,
                results_per_page=results_per_page,
            )
            if page.start_index != start_index:
                raise NvdResponseError(
                    "The NVD response start index did not match the requested page."
                )
            yield from page.vulnerabilities

            next_start_index = page.start_index + len(page.vulnerabilities)
            if next_start_index >= page.total_results:
                return
            if not page.vulnerabilities or next_start_index <= start_index:
                raise NvdResponseError(
                    "NVD pagination stopped making progress before all results were returned."
                )

            start_index = next_start_index
            self._sleeper(self._request_delay)

    def close(self) -> None:
        """Close the HTTP client only when this instance created it."""

        if self._owns_http_client:
            self._http_client.close()

    def __enter__(self) -> NvdClient:
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()

    @staticmethod
    def _validate_request(
        last_modified_start: datetime,
        last_modified_end: datetime,
        start_index: int,
        results_per_page: int,
    ) -> None:
        if (
            last_modified_start.tzinfo is None
            or last_modified_end.tzinfo is None
            or last_modified_start.utcoffset() is None
            or last_modified_end.utcoffset() is None
        ):
            raise NvdResponseError("NVD date filters must be timezone-aware.")
        if last_modified_start > last_modified_end:
            raise NvdResponseError(
                "The NVD modification start date must not be after the end date."
            )
        if last_modified_end - last_modified_start > MAX_DATE_WINDOW:
            raise NvdResponseError("The NVD modification window cannot exceed 120 days.")
        if not isinstance(start_index, int) or isinstance(start_index, bool):
            raise NvdResponseError("The NVD start index must be an integer.")
        if start_index < 0:
            raise NvdResponseError("The NVD start index must be zero or greater.")
        if not isinstance(results_per_page, int) or isinstance(
            results_per_page, bool
        ):
            raise NvdResponseError("NVD results per page must be an integer.")
        if not 1 <= results_per_page <= MAX_RESULTS_PER_PAGE:
            raise NvdResponseError(
                "NVD results per page must be between 1 and 2000."
            )

    @staticmethod
    def _format_datetime(value: datetime) -> str:
        return value.astimezone(UTC).isoformat(timespec="milliseconds").replace(
            "+00:00", "Z"
        )

    @staticmethod
    def _parse_page(payload: object) -> NvdPage:
        if not isinstance(payload, dict):
            raise NvdResponseError("The NVD response must be a JSON object.")

        vulnerabilities = payload.get("vulnerabilities", [])
        if not isinstance(vulnerabilities, list) or any(
            not isinstance(item, dict) for item in vulnerabilities
        ):
            raise NvdResponseError(
                "The NVD vulnerabilities field must be a list of objects."
            )

        pagination_values = {
            "startIndex": payload.get("startIndex"),
            "resultsPerPage": payload.get("resultsPerPage"),
            "totalResults": payload.get("totalResults"),
        }
        if any(
            not isinstance(value, int) or isinstance(value, bool)
            for value in pagination_values.values()
        ):
            raise NvdResponseError(
                "The NVD response contains invalid pagination metadata."
            )
        if any(value < 0 for value in pagination_values.values()):
            raise NvdResponseError(
                "The NVD response contains negative pagination metadata."
            )

        return NvdPage(
            vulnerabilities=vulnerabilities,
            start_index=pagination_values["startIndex"],
            results_per_page=pagination_values["resultsPerPage"],
            total_results=pagination_values["totalResults"],
        )
