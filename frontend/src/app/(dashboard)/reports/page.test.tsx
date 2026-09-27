import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { expect, test, vi } from "vitest";

import ReportsPage from "@/app/(dashboard)/reports/page";
import { exportReport, fetchReportCatalog } from "@/services/reportsApi";

vi.mock("@/components/auth/ProtectedRoute", () => ({ ProtectedRoute: ({ children }: { children: React.ReactNode }) => children }));
vi.mock("@/components/auth/AuthProvider", () => ({ useAuth: () => ({ hasPermission: (permission: string) => permission === "report.export" }) }));
vi.mock("@/services/reportsApi", () => ({ fetchReportCatalog: vi.fn(), exportReport: vi.fn() }));

test("loads selectors and performs a bounded download with Blob cleanup", async () => {
  vi.mocked(fetchReportCatalog).mockResolvedValue({ status: "success", data: { reports: [{ report_type: "uae_intelligence", label: "UAE Intelligence", formats: ["csv", "pdf"] }], maximum_rows: 100, maximum_bytes: 2097152, maximum_cell_characters: 500 } });
  vi.mocked(exportReport).mockResolvedValue({ status: "success", data: { blob: new Blob(["safe"]), filename: "cyber-sentinel-uae-intelligence-20260809T000000Z.csv" } });
  const create = vi.spyOn(URL, "createObjectURL").mockReturnValue("blob:report");
  const revoke = vi.spyOn(URL, "revokeObjectURL").mockImplementation(() => undefined);
  vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(() => undefined);
  render(<ReportsPage />);
  expect(await screen.findByLabelText("Report type")).toBeVisible();
  fireEvent.click(screen.getByRole("button", { name: "Export report" }));
  await waitFor(() => expect(exportReport).toHaveBeenCalledWith({ report_type: "uae_intelligence", format: "csv", limit: 50 }));
  expect(create).toHaveBeenCalled();
  await waitFor(() => expect(revoke).toHaveBeenCalledWith("blob:report"));
});

test("shows a sanitized API failure without fake preview data", async () => {
  vi.mocked(fetchReportCatalog).mockResolvedValue({ status: "error" });
  render(<ReportsPage />);
  expect(await screen.findByRole("alert")).toHaveTextContent("could not complete");
  expect(screen.queryByText(/preview/i)).not.toBeInTheDocument();
});
