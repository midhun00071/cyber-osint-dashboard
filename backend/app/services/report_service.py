"""Bounded in-memory CSV and PDF report generation."""

from __future__ import annotations

import csv
from dataclasses import dataclass
from datetime import UTC, datetime
from io import BytesIO, StringIO
import textwrap
from typing import Callable, Iterable, Mapping

from reportlab.lib.pagesizes import landscape, letter
from reportlab.pdfgen import canvas

from app.api.v1.schemas.reports import ReportFormat, ReportType
from app.security.contracts import Permission
from app.services.analyst_query_service import AnalystQueryService, UaeIntelligenceFilters
from app.services.operations_query_service import OperationsQueryService


MAX_REPORT_ROWS = 100
MAX_REPORT_BYTES = 2 * 1024 * 1024
MAX_REPORT_CELL_CHARACTERS = 500

_UAE_FIELDS = (
    "public_id", "title", "item_type", "cve_id", "severity", "source_slug",
    "source_name", "published_at", "collected_at", "last_seen_at",
    "geographic_scope", "relevance_status", "relevance_label",
    "relevance_confidence", "relevance_method",
)
_SOURCE_FIELDS = (
    "slug", "name", "source_type", "access_class", "policy_state",
    "operator_state", "effective_state", "credential_required",
    "credential_configured", "execution_available", "freshness",
    "latest_run_status", "latest_run_started_at", "progress_kind",
    "progress_committed_at",
)


class ReportGenerationError(RuntimeError):
    """A report could not be generated without exposing underlying data."""


class ReportSizeLimitError(ReportGenerationError):
    """The fully generated report exceeded the fixed byte ceiling."""


@dataclass(frozen=True, slots=True)
class GeneratedReport:
    content: bytes
    content_type: str
    filename: str


class ReportService:
    def __init__(self, session, *, now: Callable[[], datetime] | None = None) -> None:
        self._session = session
        self._now = now or (lambda: datetime.now(UTC))

    def generate(
        self,
        *,
        report_type: ReportType,
        report_format: ReportFormat,
        limit: int,
        permissions: frozenset[Permission],
    ) -> GeneratedReport:
        if type(limit) is not int or not 1 <= limit <= MAX_REPORT_ROWS:
            raise ValueError("The report row limit is invalid.")
        headers, rows = self._load_rows(report_type, limit, permissions)
        content = (
            self._csv(headers, rows)
            if report_format is ReportFormat.CSV
            else self._pdf(report_type, headers, rows)
        )
        if not content or len(content) > MAX_REPORT_BYTES:
            raise ReportSizeLimitError("The report exceeds the configured limit.")
        stamp = self._now().astimezone(UTC).strftime("%Y%m%dT%H%M%SZ")
        slug = report_type.value.replace("_", "-")
        return GeneratedReport(
            content=content,
            content_type=(
                "text/csv; charset=utf-8"
                if report_format is ReportFormat.CSV
                else "application/pdf"
            ),
            filename=f"alpha-data-{slug}-{stamp}.{report_format.value}",
        )

    def _load_rows(
        self,
        report_type: ReportType,
        limit: int,
        permissions: frozenset[Permission],
    ) -> tuple[tuple[str, ...], list[dict[str, object]]]:
        if report_type is ReportType.UAE_INTELLIGENCE:
            response = AnalystQueryService(self._session).list_uae_intelligence(
                UaeIntelligenceFilters(limit=limit, offset=0)
            )
            return _UAE_FIELDS, [
                {field: item.model_dump(mode="json").get(field) for field in _UAE_FIELDS}
                for item in response.items
            ]
        if report_type is ReportType.SOURCE_OPERATIONS:
            items, _ = OperationsQueryService(self._session).list_sources(
                permissions=permissions, limit=limit, offset=0
            )
            rows: list[dict[str, object]] = []
            for item in items:
                latest = item.get("latest_run") or {}
                progress = item.get("progress") or {}
                rows.append(
                    {
                        "slug": item.get("slug"),
                        "name": item.get("name"),
                        "source_type": item.get("source_type"),
                        "access_class": item.get("access_class"),
                        "policy_state": item.get("policy_state"),
                        "operator_state": item.get("operator_state"),
                        "effective_state": item.get("effective_state"),
                        "credential_required": item.get("credential_required"),
                        "credential_configured": item.get("credential_configured"),
                        "execution_available": item.get("execution_available"),
                        "freshness": item.get("freshness"),
                        "latest_run_status": latest.get("status"),
                        "latest_run_started_at": latest.get("started_at"),
                        "progress_kind": progress.get("kind"),
                        "progress_committed_at": progress.get("committed_at"),
                    }
                )
            return _SOURCE_FIELDS, rows
        raise ValueError("The report type is not supported.")

    @staticmethod
    def _csv(headers: tuple[str, ...], rows: Iterable[Mapping[str, object]]) -> bytes:
        output = StringIO(newline="")
        writer = csv.writer(output, lineterminator="\r\n")
        writer.writerow(headers)
        for row in rows:
            writer.writerow([neutralize_csv_cell(row.get(field)) for field in headers])
        return output.getvalue().encode("utf-8")

    @staticmethod
    def _pdf(
        report_type: ReportType,
        headers: tuple[str, ...],
        rows: Iterable[Mapping[str, object]],
    ) -> bytes:
        output = BytesIO()
        page_width, page_height = landscape(letter)
        document = canvas.Canvas(output, pagesize=(page_width, page_height), pageCompression=1)
        document.setTitle(f"Alpha Data {report_type.value.replace('_', ' ')}")
        document.setAuthor("Alpha Data")
        margin = 28
        line_height = 11
        y = page_height - margin

        def line(value: str, *, bold: bool = False) -> None:
            nonlocal y
            if y < margin:
                document.showPage()
                y = page_height - margin
            document.setFont("Helvetica-Bold" if bold else "Helvetica", 7)
            document.drawString(margin, y, value)
            y -= line_height

        line(f"Alpha Data - {report_type.value.replace('_', ' ').title()}", bold=True)
        for value, bold in pdf_record_lines(headers, rows):
            line(value, bold=bold)
        document.save()
        return output.getvalue()


def safe_cell_text(value: object) -> str:
    if value is None:
        return ""
    if isinstance(value, bool):
        text = "true" if value else "false"
    elif isinstance(value, datetime):
        text = value.astimezone(UTC).isoformat().replace("+00:00", "Z")
    else:
        text = str(value)
    return text[:MAX_REPORT_CELL_CHARACTERS]


def pdf_cell_text(value: object) -> str:
    """Return bounded plain text whose controls cannot alter the canvas layout."""

    return "".join(
        character if ord(character) >= 32 and character != "\x7f" else " "
        for character in safe_cell_text(value)
    )


def pdf_record_lines(
    headers: tuple[str, ...],
    rows: Iterable[Mapping[str, object]],
    *,
    width: int = 105,
) -> tuple[tuple[str, bool], ...]:
    """Build deterministic wrapped record blocks with every allow-listed field."""

    if type(width) is not int or width < 40 or width > 160:
        raise ValueError("The PDF line width is invalid.")
    output: list[tuple[str, bool]] = [("Allow-listed fields", True)]
    output.extend((f"- {field}", False) for field in headers)
    materialized = list(rows)
    if not materialized:
        output.append(("No records matched the report request.", False))
        return tuple(output)
    for index, row in enumerate(materialized, start=1):
        output.append((f"Record {index}", True))
        for field in headers:
            value = pdf_cell_text(row.get(field))
            wrapped = textwrap.wrap(
                f"{field}: {value}",
                width=width,
                subsequent_indent="  ",
                replace_whitespace=True,
                drop_whitespace=False,
                break_long_words=True,
                break_on_hyphens=False,
            )
            output.extend((line, False) for line in (wrapped or [f"{field}: "]))
    return tuple(output)


def neutralize_csv_cell(value: object) -> str:
    text = safe_cell_text(value)
    if not text:
        return text
    leading = text.lstrip(" \t\r\n\v\f" + "".join(chr(i) for i in range(32)))
    if text[0] in "\t\r\n" or (leading and leading[0] in "=+-@"):
        return "'" + text
    return text
