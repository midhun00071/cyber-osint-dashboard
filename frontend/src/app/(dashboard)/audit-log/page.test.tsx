import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { beforeEach, expect, test, vi } from "vitest";

import AuditLogPage from "@/app/(dashboard)/audit-log/page";
import { fetchAuditEvents } from "@/services/auditApi";

vi.mock("@/components/auth/ProtectedRoute", () => ({ ProtectedRoute: ({ children }: { children: React.ReactNode }) => children }));
vi.mock("@/services/auditApi", () => ({ fetchAuditEvents: vi.fn() }));
const auditMock = vi.mocked(fetchAuditEvents);

beforeEach(() => auditMock.mockReset());

test("renders bounded safe audit events and filters", async () => {
  auditMock.mockResolvedValue({ status: "success", data: { items: [{ public_id: "11111111-1111-4111-8111-111111111111", actor_type: "user", actor_ref: "safe-actor", action: "report.export.requested", target_type: "system", target_ref: "report:uae_intelligence", outcome: "success", correlation_id: null, safe_detail: { operation: "csv" }, occurred_at: "2026-08-09T00:00:00Z" }], total: 1, limit: 25, offset: 0 } });
  render(<AuditLogPage />);
  expect(await screen.findByText("report.export.requested")).toBeVisible();
  expect(screen.getByLabelText("Correlation ID")).toBeVisible();
  fireEvent.change(screen.getByLabelText("Outcome"), { target: { value: "success" } });
  fireEvent.click(screen.getByRole("button", { name: "Search" }));
  expect(fetchAuditEvents).toHaveBeenCalled();
  fireEvent.change(screen.getByLabelText("Correlation ID"), { target: { value: "11111111-1111-4111-8111-111111111111" } });
  fireEvent.change(screen.getByLabelText("From UTC date"), { target: { value: "2026-08-01" } });
  fireEvent.change(screen.getByLabelText("From UTC time"), { target: { value: "06:15" } });
  fireEvent.change(screen.getByLabelText("To UTC date"), { target: { value: "2026-08-02" } });
  fireEvent.change(screen.getByLabelText("To UTC time"), { target: { value: "18:45" } });
  fireEvent.click(screen.getByRole("button", { name: "Reset filters" }));
  expect(screen.getByLabelText("Outcome")).toHaveValue("");
  expect(screen.getByLabelText("Correlation ID")).toHaveValue("");
  expect(screen.getByLabelText("From UTC date")).toHaveValue("");
  expect(screen.getByLabelText("From UTC time")).toHaveValue("");
  expect(screen.getByLabelText("To UTC date")).toHaveValue("");
  expect(screen.getByLabelText("To UTC time")).toHaveValue("");
  await waitFor(() => expect(fetchAuditEvents).toHaveBeenLastCalledWith({ limit: 25, offset: 0 }, expect.any(AbortSignal)));
  expect(screen.getByText("safe-actor")).toHaveAttribute("title", "safe-actor");
  expect(screen.queryByText(/bearer synthetic-secret|raw request body/i)).not.toBeInTheDocument();
});

test("combines From/To pairs into the pre-existing UTC filter values", async () => {
  auditMock.mockResolvedValue({ status: "success", data: { items: [], total: 0, limit: 25, offset: 0 } });
  render(<AuditLogPage />);
  await screen.findByText("No audit events match these filters.");
  fireEvent.change(screen.getByLabelText("From UTC date"), { target: { value: "2026-08-01" } });
  fireEvent.change(screen.getByLabelText("From UTC time"), { target: { value: "06:15" } });
  fireEvent.change(screen.getByLabelText("To UTC date"), { target: { value: "2026-08-02" } });
  fireEvent.change(screen.getByLabelText("To UTC time"), { target: { value: "18:45" } });
  fireEvent.click(screen.getByRole("button", { name: "Search" }));
  await waitFor(() => expect(auditMock).toHaveBeenCalledTimes(2));
  expect(auditMock).toHaveBeenLastCalledWith({
    action: undefined,
    outcome: undefined,
    correlationId: undefined,
    from: new Date("2026-08-01T06:15").toISOString(),
    to: new Date("2026-08-02T18:45").toISOString(),
    limit: 25,
    offset: 0,
  }, expect.any(AbortSignal));
});

test("does not submit a partial audit datetime pair", async () => {
  auditMock.mockResolvedValue({ status: "success", data: { items: [], total: 0, limit: 25, offset: 0 } });
  render(<AuditLogPage />);
  await screen.findByText("No audit events match these filters.");
  fireEvent.change(screen.getByLabelText("To UTC time"), { target: { value: "18:45" } });
  expect(screen.getByRole("alert")).toHaveTextContent("Enter both a date and time for to utc.");
  fireEvent.click(screen.getByRole("button", { name: "Search" }));
  expect(auditMock).toHaveBeenCalledTimes(1);
});

test("renders empty and failure states", async () => {
  auditMock.mockResolvedValueOnce({ status: "success", data: { items: [], total: 0, limit: 25, offset: 0 } });
  const rendered = render(<AuditLogPage />);
  expect(await screen.findByText("No audit events match these filters.")).toBeVisible();
  auditMock.mockResolvedValueOnce({ status: "error" });
  rendered.unmount();
  render(<AuditLogPage />);
  expect(await screen.findByRole("alert")).toHaveTextContent("could not be loaded safely");
});
