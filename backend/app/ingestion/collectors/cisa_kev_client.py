"""Synchronous locked-down collector for the official CISA KEV JSON catalog."""

from __future__ import annotations

from dataclasses import dataclass
import json

import httpx

from app.ingestion.source_registry import (
    get_required_source_base_url,
    get_source_definition,
)


CISA_KEV_SOURCE_SLUG = "cisa-kev"
CISA_KEV_CATALOG_URL = get_required_source_base_url(CISA_KEV_SOURCE_SLUG)
CISA_KEV_ALLOWED_HOST = get_source_definition(CISA_KEV_SOURCE_SLUG).allowed_hosts[0]
DEFAULT_TIMEOUT = httpx.Timeout(20.0, connect=5.0, read=10.0, write=5.0, pool=5.0)
MAX_RESPONSE_BYTES = 2 * 1024 * 1024
USER_AGENT = "CyberSentinelOSINT/1.0 (+defensive-cisa-kev-ingestion)"
ACCEPT_HEADER = "application/json, */*;q=0.1"
ALLOWED_CONTENT_TYPES = {
    "application/json",
    "application/octet-stream",
    "text/plain",
}


class CisaKevClientError(Exception):
    """Base class for sanitized CISA KEV client failures."""


class CisaKevRequestError(CisaKevClientError):
    """The CISA KEV request could not be completed."""


class CisaKevHttpError(CisaKevClientError):
    """The CISA KEV catalog returned an unsuccessful HTTP status."""


class CisaKevRateLimitError(CisaKevHttpError):
    """The CISA KEV catalog rejected a request because of rate limiting."""


class CisaKevRedirectError(CisaKevClientError):
    """The CISA KEV request encountered an unsafe redirect."""


class CisaKevResponseTooLargeError(CisaKevClientError):
    """The CISA KEV response exceeded the approved size limit."""


class CisaKevContentTypeError(CisaKevClientError):
    """The CISA KEV response content type was not acceptable."""


class CisaKevResponseError(CisaKevClientError):
    """The CISA KEV response could not be parsed safely."""


@dataclass(frozen=True)
class CisaKevFetchResult:
    """Bounded parsed catalog and safe collection metadata."""

    catalog: dict
    source_url: str
    final_url: str
    content_type: str | None
    byte_count: int


class CisaKevClient:
    """Fetch the approved CISA KEV catalog with strict URL and response bounds."""

    def __init__(self, *, http_client: httpx.Client | None = None) -> None:
        self._owns_http_client = http_client is None
        self._http_client = http_client or httpx.Client(
            timeout=DEFAULT_TIMEOUT,
            follow_redirects=False,
            trust_env=False,
        )

    def fetch_catalog(self) -> CisaKevFetchResult:
        """Fetch and parse the approved CISA KEV JSON catalog."""

        try:
            with self._http_client.stream(
                "GET",
                CISA_KEV_CATALOG_URL,
                headers={"User-Agent": USER_AGENT, "Accept": ACCEPT_HEADER},
                follow_redirects=False,
            ) as response:
                if response.status_code in {301, 302, 303, 307, 308}:
                    raise CisaKevRedirectError(
                        "The CISA KEV catalog does not permit redirects."
                    )
                if response.status_code == 429:
                    raise CisaKevRateLimitError(
                        "The CISA KEV catalog rate limit was reached (HTTP 429)."
                    )
                if not response.is_success:
                    raise CisaKevHttpError(
                        f"The CISA KEV catalog returned HTTP {response.status_code}."
                    )

                content_type = _content_type(response.headers.get("content-type"))
                if not _acceptable_content_type(content_type):
                    raise CisaKevContentTypeError(
                        "The CISA KEV catalog returned an unsupported content type."
                    )
                body = _read_bounded(response)
                try:
                    payload = json.loads(body)
                except ValueError as exc:
                    raise CisaKevResponseError(
                        "The CISA KEV catalog returned invalid JSON."
                    ) from exc
                if not isinstance(payload, dict):
                    raise CisaKevResponseError(
                        "The CISA KEV catalog must be a JSON object."
                    )
                return CisaKevFetchResult(
                    catalog=payload,
                    source_url=CISA_KEV_CATALOG_URL,
                    final_url=CISA_KEV_CATALOG_URL,
                    content_type=content_type,
                    byte_count=len(body),
                )
        except CisaKevClientError:
            raise
        except httpx.TimeoutException as exc:
            raise CisaKevRequestError("The CISA KEV request timed out.") from exc
        except httpx.TransportError as exc:
            raise CisaKevRequestError(
                "The CISA KEV request failed during transport."
            ) from exc

    def close(self) -> None:
        """Close the HTTP client only when this instance created it."""

        if self._owns_http_client:
            self._http_client.close()

    def __enter__(self) -> CisaKevClient:
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()


def _read_bounded(response: httpx.Response) -> bytes:
    chunks: list[bytes] = []
    total = 0
    for chunk in response.iter_bytes():
        total += len(chunk)
        if total > MAX_RESPONSE_BYTES:
            raise CisaKevResponseTooLargeError(
                "The CISA KEV response exceeded the approved size limit."
            )
        chunks.append(chunk)
    return b"".join(chunks)


def _content_type(value: str | None) -> str | None:
    if value is None:
        return None
    return value.split(";", 1)[0].strip().lower() or None


def _acceptable_content_type(value: str | None) -> bool:
    if value is None:
        return True
    return value in ALLOWED_CONTENT_TYPES or value.endswith("+json")
