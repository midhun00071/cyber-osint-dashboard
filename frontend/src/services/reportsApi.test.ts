import { beforeEach, describe, expect, test, vi } from "vitest";

import { apiFetch } from "@/services/apiClient";
import { exportReport, fetchReportCatalog } from "@/services/reportsApi";

vi.mock("@/services/apiClient", () => ({ apiFetch: vi.fn() }));
const apiFetchMock = vi.mocked(apiFetch);

describe("reportsApi", () => {
  beforeEach(() => apiFetchMock.mockReset());

  test("validates the bounded catalog", async () => {
    apiFetchMock.mockResolvedValue(new Response(JSON.stringify({ reports: [{ report_type: "uae_intelligence", label: "UAE Intelligence", formats: ["csv", "pdf"] }], maximum_rows: 100, maximum_bytes: 2097152, maximum_cell_characters: 500 }), { status: 200 }));
    const result = await fetchReportCatalog();
    expect(result.status).toBe("success");
  });

  test("rejects malformed catalog data", async () => {
    apiFetchMock.mockResolvedValue(new Response(JSON.stringify({ reports: [{ report_type: "raw_dump", label: "Raw", formats: ["html"] }], maximum_rows: 1000 }), { status: 200 }));
    expect((await fetchReportCatalog()).status).toBe("error");
  });

  test("requests an allow-listed server export and preserves its filename", async () => {
    apiFetchMock.mockResolvedValue(new Response(new Blob(["safe"]), { status: 200, headers: { "Content-Type": "text/csv; charset=utf-8", "Content-Disposition": 'attachment; filename="alpha-data-uae-intelligence-20260809T000000Z.csv"' } }));
    const result = await exportReport({ report_type: "uae_intelligence", format: "csv", limit: 25 });
    expect(result.status).toBe("success");
    expect(apiFetchMock).toHaveBeenCalledWith("/api/v1/reports/export", expect.objectContaining({ method: "POST", headers: { Accept: "text/csv" } }));
  });

  test("rejects client-side out-of-range requests without a network call", async () => {
    expect((await exportReport({ report_type: "uae_intelligence", format: "csv", limit: 101 })).status).toBe("error");
    expect(apiFetchMock).not.toHaveBeenCalled();
  });
});
