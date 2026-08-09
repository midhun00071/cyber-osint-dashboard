"""Strict report catalog and export contracts."""

from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field


class ReportType(StrEnum):
    UAE_INTELLIGENCE = "uae_intelligence"
    SOURCE_OPERATIONS = "source_operations"


class ReportFormat(StrEnum):
    CSV = "csv"
    PDF = "pdf"


class ReportExportRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", hide_input_in_errors=True)

    report_type: ReportType
    format: ReportFormat
    limit: int = Field(default=50, strict=True, ge=1, le=100)


class ReportCatalogItem(BaseModel):
    model_config = ConfigDict(extra="forbid")

    report_type: ReportType
    label: str
    formats: list[ReportFormat]


class ReportCatalogResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    reports: list[ReportCatalogItem]
    maximum_rows: int = Field(ge=1, le=100)
    maximum_bytes: int = Field(ge=1)
    maximum_cell_characters: int = Field(ge=1)
