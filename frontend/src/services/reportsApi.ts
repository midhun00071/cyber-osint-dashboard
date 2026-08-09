import { apiFetch } from "@/services/apiClient";
import type { ReportCatalog, ReportFormat, ReportRequest, ReportResult, ReportType } from "@/types/report";

const REPORT_TYPES = new Set<ReportType>(["uae_intelligence", "source_operations"]);
const FORMATS = new Set<ReportFormat>(["csv", "pdf"]);

function object(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function catalog(value: unknown): ReportCatalog | null {
  if (!object(value) || !Array.isArray(value.reports)) return null;
  if (!Number.isInteger(value.maximum_rows) || (value.maximum_rows as number) < 1 || (value.maximum_rows as number) > 100) return null;
  if (!Number.isInteger(value.maximum_bytes) || !Number.isInteger(value.maximum_cell_characters)) return null;
  const reports = value.reports.map((item) => {
    if (!object(item) || typeof item.label !== "string" || !REPORT_TYPES.has(item.report_type as ReportType) || !Array.isArray(item.formats)) return null;
    const formats = item.formats.filter((format): format is ReportFormat => FORMATS.has(format as ReportFormat));
    if (formats.length !== item.formats.length || formats.length === 0) return null;
    return { report_type: item.report_type as ReportType, label: item.label, formats };
  });
  if (reports.some((item) => item === null)) return null;
  return { reports: reports as ReportCatalog["reports"], maximum_rows: value.maximum_rows as number, maximum_bytes: value.maximum_bytes as number, maximum_cell_characters: value.maximum_cell_characters as number };
}

export async function fetchReportCatalog(signal?: AbortSignal): Promise<ReportResult<ReportCatalog>> {
  try {
    const response = await apiFetch("/api/v1/reports/catalog", { signal });
    if (!response.ok) return { status: "error" };
    const validated = catalog(await response.json());
    return validated ? { status: "success", data: validated } : { status: "error" };
  } catch (error) {
    if (error instanceof DOMException && error.name === "AbortError") throw error;
    return { status: "error" };
  }
}

export async function exportReport(request: ReportRequest): Promise<ReportResult<{ blob: Blob; filename: string }>> {
  if (!REPORT_TYPES.has(request.report_type) || !FORMATS.has(request.format) || !Number.isInteger(request.limit) || request.limit < 1 || request.limit > 100) return { status: "error" };
  try {
    const response = await apiFetch("/api/v1/reports/export", {
      method: "POST",
      headers: { Accept: request.format === "pdf" ? "application/pdf" : "text/csv" },
      body: JSON.stringify(request),
    });
    if (!response.ok) return { status: "error" };
    const disposition = response.headers.get("Content-Disposition") ?? "";
    const match = /^attachment; filename="(alpha-data-[a-z-]+-[0-9]{8}T[0-9]{6}Z\.(?:csv|pdf))"$/.exec(disposition);
    const contentType = response.headers.get("Content-Type") ?? "";
    if (!match || (request.format === "pdf" ? !contentType.startsWith("application/pdf") : !contentType.startsWith("text/csv"))) return { status: "error" };
    const blob = await response.blob();
    return blob.size > 0 && blob.size <= 2 * 1024 * 1024 ? { status: "success", data: { blob, filename: match[1] } } : { status: "error" };
  } catch {
    return { status: "error" };
  }
}
