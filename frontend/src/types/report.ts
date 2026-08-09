export type ReportType = "uae_intelligence" | "source_operations";
export type ReportFormat = "csv" | "pdf";

export type ReportCatalog = {
  reports: Array<{ report_type: ReportType; label: string; formats: ReportFormat[] }>;
  maximum_rows: number;
  maximum_bytes: number;
  maximum_cell_characters: number;
};

export type ReportRequest = { report_type: ReportType; format: ReportFormat; limit: number };
export type ReportResult<T> = { status: "success"; data: T } | { status: "error" };
