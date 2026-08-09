import { fireEvent, render, screen } from "@testing-library/react";
import { expect, test, vi } from "vitest";

import AuditLogPage from "@/app/(dashboard)/audit-log/page";
import { fetchAuditEvents } from "@/services/auditApi";

vi.mock("@/components/auth/ProtectedRoute", () => ({ ProtectedRoute: ({ children }: { children: React.ReactNode }) => children }));
vi.mock("@/services/auditApi", () => ({ fetchAuditEvents: vi.fn() }));

test("renders bounded safe audit events and filters", async () => {
  vi.mocked(fetchAuditEvents).mockResolvedValue({ status: "success", data: { items: [{ public_id: "11111111-1111-4111-8111-111111111111", actor_type: "user", actor_ref: "safe-actor", action: "report.export.requested", target_type: "system", target_ref: "report:uae_intelligence", outcome: "success", correlation_id: null, safe_detail: { operation: "csv" }, occurred_at: "2026-08-09T00:00:00Z" }], total: 1, limit: 25, offset: 0 } });
  render(<AuditLogPage />);
  expect(await screen.findByText("report.export.requested")).toBeVisible();
  expect(screen.getByLabelText("Correlation ID")).toBeVisible();
  fireEvent.change(screen.getByLabelText("Outcome"), { target: { value: "success" } });
  fireEvent.click(screen.getByRole("button", { name: "Search" }));
  expect(fetchAuditEvents).toHaveBeenCalled();
  expect(screen.queryByText(/bearer synthetic-secret|raw request body/i)).not.toBeInTheDocument();
});

test("renders empty and failure states", async () => {
  vi.mocked(fetchAuditEvents).mockResolvedValueOnce({ status: "success", data: { items: [], total: 0, limit: 25, offset: 0 } });
  const rendered = render(<AuditLogPage />);
  expect(await screen.findByText("No audit events match these filters.")).toBeVisible();
  vi.mocked(fetchAuditEvents).mockResolvedValueOnce({ status: "error" });
  rendered.unmount();
  render(<AuditLogPage />);
  expect(await screen.findByRole("alert")).toHaveTextContent("could not be loaded safely");
});
