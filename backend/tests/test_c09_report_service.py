from datetime import UTC, datetime

import pytest

from app.api.v1.schemas.reports import ReportFormat, ReportType
from app.services import report_service as module
from app.services.report_service import (
    MAX_REPORT_BYTES,
    MAX_REPORT_CELL_CHARACTERS,
    ReportService,
    ReportSizeLimitError,
    neutralize_csv_cell,
    pdf_record_lines,
)


@pytest.mark.parametrize(
    "value",
    ["=SUM(1,1)", "+cmd", "-1+2", "@SUM(A1:A2)", "  =SUM(1,1)", "\tvalue", "\rvalue", "\nvalue"],
)
def test_csv_formula_and_control_prefixes_are_neutralized(value: str) -> None:
    assert neutralize_csv_cell(value) == "'" + value


def test_csv_preserves_utf8_and_bounds_cells() -> None:
    assert neutralize_csv_cell("أمن الإمارات") == "أمن الإمارات"
    assert len(neutralize_csv_cell("x" * 700)) == MAX_REPORT_CELL_CHARACTERS


def test_pdf_is_generated_in_memory_without_remote_resources(monkeypatch) -> None:
    service = ReportService(object(), now=lambda: datetime(2026, 8, 9, tzinfo=UTC))
    monkeypatch.setattr(
        service,
        "_load_rows",
        lambda *_args: (("title",), [{"title": "<b>plain text only</b> https://example.invalid/image"}]),
    )
    generated = service.generate(
        report_type=ReportType.UAE_INTELLIGENCE,
        report_format=ReportFormat.PDF,
        limit=1,
        permissions=frozenset(),
    )
    assert generated.content.startswith(b"%PDF-")
    assert generated.filename == "cyber-sentinel-uae-intelligence-20260809T000000Z.pdf"
    assert generated.content_type == "application/pdf"


def test_generated_output_over_limit_is_rejected_not_truncated(monkeypatch) -> None:
    service = ReportService(object())
    monkeypatch.setattr(service, "_load_rows", lambda *_args: (("title",), []))
    monkeypatch.setattr(service, "_csv", lambda *_args: b"x" * (MAX_REPORT_BYTES + 1))
    with pytest.raises(ReportSizeLimitError):
        service.generate(
            report_type=ReportType.UAE_INTELLIGENCE,
            report_format=ReportFormat.CSV,
            limit=1,
            permissions=frozenset(),
        )


def test_uae_query_receives_the_requested_bound(monkeypatch) -> None:
    captured = []

    class Result:
        items = []

    monkeypatch.setattr(
        module.AnalystQueryService,
        "list_uae_intelligence",
        lambda _self, filters: captured.append(filters) or Result(),
    )
    ReportService(object()).generate(
        report_type=ReportType.UAE_INTELLIGENCE,
        report_format=ReportFormat.CSV,
        limit=100,
        permissions=frozenset(),
    )
    assert captured[0].limit == 100 and captured[0].offset == 0


@pytest.mark.parametrize(
    "headers",
    [
        module._UAE_FIELDS,
        module._SOURCE_FIELDS,
    ],
)
def test_pdf_record_layout_contains_every_allow_listed_field(headers) -> None:
    values = {field: f"value-for-{field}" for field in headers}
    rendered = "\n".join(line for line, _bold in pdf_record_lines(headers, [values]))
    for field in headers:
        assert f"- {field}" in rendered
        assert f"{field}: value-for-{field}" in rendered


def test_pdf_tail_fields_are_never_silently_omitted() -> None:
    required = {
        module._UAE_FIELDS: ("relevance_confidence", "relevance_method"),
        module._SOURCE_FIELDS: (
            "latest_run_started_at", "progress_kind", "progress_committed_at"
        ),
    }
    for headers, tail_fields in required.items():
        rows = [{field: f"evidence-{field}" for field in headers}]
        rendered = "\n".join(line for line, _bold in pdf_record_lines(headers, rows))
        for field in tail_fields:
            assert f"{field}: evidence-{field}" in rendered


def test_pdf_wraps_full_bounded_content_and_neutralizes_layout_controls() -> None:
    value = "x" * MAX_REPORT_CELL_CHARACTERS
    lines = [line for line, _bold in pdf_record_lines(("title",), [{"title": value}])]
    record_lines = lines[lines.index("Record 1") + 1 :]
    assert len(record_lines) > 1
    assert "".join(line.removeprefix("title: ").strip() for line in record_lines) == value
    controlled = "\n".join(
        line for line, _bold in pdf_record_lines(("title",), [{"title": "a\nb\tc"}])
    )
    assert "title: a b c" in controlled
