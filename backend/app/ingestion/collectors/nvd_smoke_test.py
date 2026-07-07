"""Manual, summary-only smoke test for the public NVD CVE API."""

from __future__ import annotations

import argparse
from collections.abc import Callable, Sequence
from datetime import UTC, datetime, timedelta
import re
import sys
from typing import TextIO

from pydantic import SecretStr

from app.core.config import get_settings
from app.ingestion.collectors.nvd_client import NvdClient, NvdClientError, NvdPage


DEFAULT_WINDOW_MINUTES = 5
DEFAULT_RESULTS_PER_PAGE = 3
MIN_WINDOW_MINUTES = 1
MAX_WINDOW_MINUTES = 60
MIN_RESULTS_PER_PAGE = 1
MAX_SMOKE_RESULTS_PER_PAGE = 5
CVE_ID_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,}$")


class SmokeTestArgumentError(ValueError):
    """The manual smoke-test arguments were invalid."""


class SmokeTestArgumentParser(argparse.ArgumentParser):
    """Argument parser that returns controlled errors to the CLI entry point."""

    def error(self, message: str) -> None:
        del message
        raise SmokeTestArgumentError("Invalid manual NVD smoke-test arguments.")


def _bounded_integer(name: str, minimum: int, maximum: int) -> Callable[[str], int]:
    def parse(value: str) -> int:
        try:
            parsed_value = int(value)
        except ValueError as exc:
            raise argparse.ArgumentTypeError(f"{name} must be an integer.") from exc

        if not minimum <= parsed_value <= maximum:
            raise argparse.ArgumentTypeError(
                f"{name} must be between {minimum} and {maximum}."
            )
        return parsed_value

    return parse


def _build_parser() -> SmokeTestArgumentParser:
    parser = SmokeTestArgumentParser(
        description="Run one small, manual request against the public NVD CVE API.",
    )
    parser.add_argument(
        "--window-minutes",
        type=_bounded_integer(
            "window minutes",
            MIN_WINDOW_MINUTES,
            MAX_WINDOW_MINUTES,
        ),
        default=DEFAULT_WINDOW_MINUTES,
    )
    parser.add_argument(
        "--results-per-page",
        type=_bounded_integer(
            "results per page",
            MIN_RESULTS_PER_PAGE,
            MAX_SMOKE_RESULTS_PER_PAGE,
        ),
        default=DEFAULT_RESULTS_PER_PAGE,
    )
    return parser


def _format_utc(value: datetime) -> str:
    return value.astimezone(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")


def _safe_cve_ids(page: NvdPage, limit: int) -> list[str]:
    identifiers: list[str] = []
    for record in page.vulnerabilities[:limit]:
        cve = record.get("cve")
        identifier = cve.get("id") if isinstance(cve, dict) else None
        if isinstance(identifier, str) and CVE_ID_PATTERN.fullmatch(identifier):
            identifiers.append(identifier)
    return identifiers


def _print_summary(
    page: NvdPage,
    start: datetime,
    end: datetime,
    results_per_page: int,
    stdout: TextIO,
) -> None:
    identifiers = _safe_cve_ids(page, results_per_page)
    print("Manual NVD smoke test completed.", file=stdout)
    print(f"UTC window start: {_format_utc(start)}", file=stdout)
    print(f"UTC window end: {_format_utc(end)}", file=stdout)
    print(f"totalResults: {page.total_results}", file=stdout)
    print(f"Returned item count: {len(page.vulnerabilities)}", file=stdout)
    print(
        f"CVE IDs: {', '.join(identifiers) if identifiers else 'none'}",
        file=stdout,
    )


def run_smoke_test(
    *,
    window_minutes: int,
    results_per_page: int,
    api_key: SecretStr | None,
    clock: Callable[[], datetime] = lambda: datetime.now(UTC),
    client_factory: Callable[..., NvdClient] = NvdClient,
    stdout: TextIO = sys.stdout,
    stderr: TextIO = sys.stderr,
) -> int:
    """Run one bounded request and print only safe summary fields."""

    if (
        not isinstance(window_minutes, int)
        or isinstance(window_minutes, bool)
        or not MIN_WINDOW_MINUTES <= window_minutes <= MAX_WINDOW_MINUTES
        or not isinstance(results_per_page, int)
        or isinstance(results_per_page, bool)
        or not MIN_RESULTS_PER_PAGE
        <= results_per_page
        <= MAX_SMOKE_RESULTS_PER_PAGE
    ):
        print("Invalid manual NVD smoke-test parameters.", file=stderr)
        return 2

    end = clock()
    if end.tzinfo is None or end.utcoffset() is None:
        print("NVD smoke test failed because the clock was not timezone-aware.", file=stderr)
        return 1
    end = end.astimezone(UTC)
    start = end - timedelta(minutes=window_minutes)

    try:
        with client_factory(api_key=api_key) as client:
            page = client.fetch_page(
                last_modified_start=start,
                last_modified_end=end,
                start_index=0,
                results_per_page=results_per_page,
            )
    except NvdClientError as exc:
        print(f"Manual NVD smoke test failed: {exc}", file=stderr)
        return 1

    _print_summary(page, start, end, results_per_page, stdout)
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    """Parse manual CLI arguments and return a stable process exit code."""

    try:
        arguments = _build_parser().parse_args(argv)
    except SmokeTestArgumentError as exc:
        print(str(exc), file=sys.stderr)
        return 2

    settings = get_settings()
    return run_smoke_test(
        window_minutes=arguments.window_minutes,
        results_per_page=arguments.results_per_page,
        api_key=settings.nvd_api_key,
    )


if __name__ == "__main__":
    raise SystemExit(main())
