from __future__ import annotations

from contextlib import AbstractContextManager
from datetime import UTC, datetime, timedelta
from io import StringIO
from typing import Any

import pytest
from pydantic import SecretStr

from app.ingestion.collectors import nvd_smoke_test
from app.ingestion.collectors.nvd_client import NvdPage, NvdRequestError


NOW = datetime(2026, 7, 8, 12, 30, tzinfo=UTC)


class FakeNvdClient(AbstractContextManager["FakeNvdClient"]):
    def __init__(self, page: NvdPage | None = None, error: Exception | None = None):
        self.page = page or make_page()
        self.error = error
        self.calls: list[dict[str, Any]] = []
        self.closed = False

    def __enter__(self) -> FakeNvdClient:
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.closed = True

    def fetch_page(self, **kwargs: Any) -> NvdPage:
        self.calls.append(kwargs)
        if self.error is not None:
            raise self.error
        return self.page


class CapturingFactory:
    def __init__(self, client: FakeNvdClient):
        self.client = client
        self.api_keys: list[SecretStr | None] = []

    def __call__(self, *, api_key: SecretStr | None) -> FakeNvdClient:
        self.api_keys.append(api_key)
        return self.client


def make_page(vulnerabilities: list[dict[str, Any]] | None = None) -> NvdPage:
    records = vulnerabilities or [{"cve": {"id": "CVE-2026-12345"}}]
    return NvdPage(
        vulnerabilities=records,
        start_index=0,
        results_per_page=len(records),
        total_results=17,
    )


def run_helper(
    *,
    window_minutes: int = 5,
    results_per_page: int = 3,
    client: FakeNvdClient | None = None,
    api_key: SecretStr | None = None,
) -> tuple[int, str, str, FakeNvdClient, CapturingFactory]:
    fake_client = client or FakeNvdClient()
    factory = CapturingFactory(fake_client)
    stdout = StringIO()
    stderr = StringIO()
    exit_code = nvd_smoke_test.run_smoke_test(
        window_minutes=window_minutes,
        results_per_page=results_per_page,
        api_key=api_key,
        clock=lambda: NOW,
        client_factory=factory,  # type: ignore[arg-type]
        stdout=stdout,
        stderr=stderr,
    )
    return exit_code, stdout.getvalue(), stderr.getvalue(), fake_client, factory


def test_default_arguments_use_small_utc_window(monkeypatch) -> None:
    captured: dict[str, int] = {}

    def fake_run_smoke_test(**kwargs: Any) -> int:
        captured.update(
            window_minutes=kwargs["window_minutes"],
            results_per_page=kwargs["results_per_page"],
        )
        return 0

    monkeypatch.setattr(nvd_smoke_test, "run_smoke_test", fake_run_smoke_test)
    monkeypatch.setattr(
        nvd_smoke_test,
        "get_settings",
        lambda: type("Settings", (), {"nvd_api_key": None})(),
    )

    assert nvd_smoke_test.main([]) == 0
    assert captured == {"window_minutes": 5, "results_per_page": 3}


@pytest.mark.parametrize("window_minutes", [1, 60])
def test_window_minutes_accepts_boundaries(monkeypatch, window_minutes: int) -> None:
    monkeypatch.setattr(nvd_smoke_test, "run_smoke_test", lambda **kwargs: 0)
    monkeypatch.setattr(
        nvd_smoke_test,
        "get_settings",
        lambda: type("Settings", (), {"nvd_api_key": None})(),
    )

    assert nvd_smoke_test.main(["--window-minutes", str(window_minutes)]) == 0


@pytest.mark.parametrize("value", ["0", "-1", "invalid", "61"])
def test_window_minutes_rejects_invalid_values(value: str, capsys) -> None:
    assert nvd_smoke_test.main(["--window-minutes", value]) == 2
    assert "Invalid manual NVD smoke-test arguments." in capsys.readouterr().err


@pytest.mark.parametrize("results_per_page", [1, 5])
def test_results_per_page_accepts_boundaries(
    monkeypatch,
    results_per_page: int,
) -> None:
    monkeypatch.setattr(nvd_smoke_test, "run_smoke_test", lambda **kwargs: 0)
    monkeypatch.setattr(
        nvd_smoke_test,
        "get_settings",
        lambda: type("Settings", (), {"nvd_api_key": None})(),
    )

    assert (
        nvd_smoke_test.main(["--results-per-page", str(results_per_page)]) == 0
    )


@pytest.mark.parametrize("value", ["0", "-1", "invalid", "6"])
def test_results_per_page_rejects_invalid_values(value: str, capsys) -> None:
    assert nvd_smoke_test.main(["--results-per-page", value]) == 2
    assert "Invalid manual NVD smoke-test arguments." in capsys.readouterr().err


def test_fetches_exactly_one_bounded_page() -> None:
    exit_code, _, _, client, _ = run_helper(window_minutes=12, results_per_page=5)

    assert exit_code == 0
    assert client.closed
    assert len(client.calls) == 1
    call = client.calls[0]
    assert call["last_modified_end"] == NOW
    assert call["last_modified_start"] == NOW - timedelta(minutes=12)
    assert call["start_index"] == 0
    assert call["results_per_page"] == 5


def test_safe_summary_includes_counts_window_and_valid_ids() -> None:
    page = make_page(
        [
            {"cve": {"id": "CVE-2026-12345", "descriptions": ["private"]}},
            {"cve": {"id": "CVE-2025-9999"}, "references": ["private-url"]},
        ]
    )

    exit_code, stdout, stderr, _, _ = run_helper(client=FakeNvdClient(page))

    assert exit_code == 0
    assert stderr == ""
    assert "Manual NVD smoke test completed." in stdout
    assert "UTC window start: 2026-07-08T12:25:00Z" in stdout
    assert "UTC window end: 2026-07-08T12:30:00Z" in stdout
    assert "totalResults: 17" in stdout
    assert "Returned item count: 2" in stdout
    assert "CVE-2026-12345" in stdout
    assert "CVE-2025-9999" in stdout
    assert "descriptions" not in stdout
    assert "references" not in stdout
    assert "private" not in stdout


def test_malformed_and_unsafe_ids_are_omitted() -> None:
    page = make_page(
        [
            {"cve": {"id": "not-a-cve"}},
            {"cve": {"id": "CVE-2026-1234\nunsafe"}},
            {"cve": {}},
            {"unexpected": "value"},
            {"cve": {"id": "CVE-2026-54321"}},
        ]
    )

    _, stdout, _, _, _ = run_helper(results_per_page=5, client=FakeNvdClient(page))

    assert "CVE IDs: CVE-2026-54321" in stdout
    assert "not-a-cve" not in stdout
    assert "unsafe" not in stdout


def test_api_key_is_passed_but_never_printed() -> None:
    secret_value = "synthetic-nvd-key-do-not-use"
    api_key = SecretStr(secret_value)

    _, stdout, stderr, _, factory = run_helper(api_key=api_key)

    assert factory.api_keys == [api_key]
    assert secret_value not in stdout
    assert secret_value not in stderr


def test_nvd_client_error_returns_one_with_sanitized_stderr() -> None:
    client = FakeNvdClient(error=NvdRequestError("The NVD request timed out."))

    exit_code, stdout, stderr, _, _ = run_helper(client=client)

    assert exit_code == 1
    assert stdout == ""
    assert stderr == "Manual NVD smoke test failed: The NVD request timed out.\n"


def test_timezone_aware_clock_is_required() -> None:
    stdout = StringIO()
    stderr = StringIO()

    exit_code = nvd_smoke_test.run_smoke_test(
        window_minutes=5,
        results_per_page=3,
        api_key=None,
        clock=lambda: NOW.replace(tzinfo=None),
        client_factory=lambda **kwargs: pytest.fail("client must not be created"),
        stdout=stdout,
        stderr=stderr,
    )

    assert exit_code == 1
    assert stdout.getvalue() == ""
    assert "clock was not timezone-aware" in stderr.getvalue()


@pytest.mark.parametrize("window_minutes", [0, -1, 61, "5", 1.5, True, False])
def test_run_smoke_test_rejects_invalid_window_minutes_directly(
    window_minutes: object,
) -> None:
    stdout = StringIO()
    stderr = StringIO()

    exit_code = nvd_smoke_test.run_smoke_test(
        window_minutes=window_minutes,  # type: ignore[arg-type]
        results_per_page=3,
        api_key=None,
        clock=lambda: pytest.fail("clock must not be called"),
        client_factory=lambda **kwargs: pytest.fail("client must not be created"),
        stdout=stdout,
        stderr=stderr,
    )

    assert exit_code == 2
    assert stdout.getvalue() == ""
    assert stderr.getvalue() == "Invalid manual NVD smoke-test parameters.\n"


@pytest.mark.parametrize("results_per_page", [0, -1, 6, "3", 1.5, True, False])
def test_run_smoke_test_rejects_invalid_results_per_page_directly(
    results_per_page: object,
) -> None:
    stdout = StringIO()
    stderr = StringIO()

    exit_code = nvd_smoke_test.run_smoke_test(
        window_minutes=5,
        results_per_page=results_per_page,  # type: ignore[arg-type]
        api_key=None,
        clock=lambda: pytest.fail("clock must not be called"),
        client_factory=lambda **kwargs: pytest.fail("client must not be created"),
        stdout=stdout,
        stderr=stderr,
    )

    assert exit_code == 2
    assert stdout.getvalue() == ""
    assert stderr.getvalue() == "Invalid manual NVD smoke-test parameters.\n"
