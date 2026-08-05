import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import type { ReactNode } from "react";
import { beforeEach, describe, expect, test, vi } from "vitest";

import RunHistoryPage from "@/app/(dashboard)/run-history/page";
import { fetchRun, fetchRunEvents, fetchRuns, requestRetry } from "@/services/operationsApi";
import type { RunEvent } from "@/types/operations";

vi.mock("@/components/auth/ProtectedRoute", () => ({ ProtectedRoute: ({ children }: { children: ReactNode }) => children }));
vi.mock("@/services/operationsApi", () => ({ fetchRuns: vi.fn(), fetchRun: vi.fn(), fetchRunEvents: vi.fn(), requestRetry: vi.fn() }));
const runsMock = vi.mocked(fetchRuns);
const runMock = vi.mocked(fetchRun);
const eventsMock = vi.mocked(fetchRunEvents);
const retryMock = vi.mocked(requestRetry);

const RUN = { public_id: "11111111-1111-4111-8111-111111111111", cycle_public_id: "22222222-2222-4222-8222-222222222222", source_public_id: "33333333-3333-4333-8333-333333333333", source_slug: "cisa-kev", source_name: "CISA KEV", trigger_type: "manual", status: "failed", attempt_number: 2, retry_of_public_id: "44444444-4444-4444-8444-444444444444", accepted_at: "2026-08-05T12:00:00Z", started_at: "2026-08-05T12:00:01Z", finished_at: "2026-08-05T12:01:00Z", duration_seconds: 59, retryable: true, summary_message: "Temporary source failure.", counters: { fetched: 3, created: 1, updated: 1, unchanged: 1, skipped: 0, failed: 1, error_count: 1 } };
const LIST = { status: "success" as const, data: { total: 1, limit: 25, offset: 0, items: [RUN] } };

describe("RunHistoryPage", () => {
  beforeEach(() => {
    runsMock.mockReset(); runMock.mockReset(); eventsMock.mockReset(); retryMock.mockReset();
    runsMock.mockResolvedValue(LIST);
    runMock.mockResolvedValue({ status: "success", data: RUN });
    eventsMock.mockResolvedValue({ status: "success", data: { total: 2, limit: 500, offset: 0, items: [
      { sequence: 2, event_type: "finished", from_status: "running", to_status: "failed", message: "event-two", occurred_at: "2026-08-05T12:01:00Z", provider_payload: "unsafe" } as unknown as RunEvent,
      { sequence: 1, event_type: "started", from_status: "accepted", to_status: "running", message: "event-one", occurred_at: "2026-08-05T12:00:01Z" },
    ] } });
    retryMock.mockResolvedValue({ status: "success", data: {} });
  });

  test("renders lineage, complete safe timing/counters, detail, and ordered events", async () => {
    render(<RunHistoryPage />);
    expect(await screen.findByText("Temporary source failure.")).toBeVisible();
    expect(screen.getByText(/Retry parent: 44444444/)).toBeVisible();
    expect(screen.getByText(/Fetched 3; created 1; updated 1; unchanged 1; skipped 0; failed 1; errors 1/)).toBeVisible();
    fireEvent.click(screen.getByRole("button", { name: "View details" }));
    expect(await screen.findByText(/1\. started/)).toBeVisible();
    const eventItems = screen.getAllByRole("listitem");
    expect(eventItems[0]).toHaveTextContent("event-one");
    expect(eventItems[1]).toHaveTextContent("event-two");
    expect(screen.queryByText("unsafe")).not.toBeInTheDocument();
    expect(runMock).toHaveBeenCalledWith(RUN.public_id, expect.any(AbortSignal));
    expect(eventsMock).toHaveBeenCalledWith(RUN.public_id, expect.any(AbortSignal));
  });

  test("applies only the fixed run-history filters with aware timestamps", async () => {
    render(<RunHistoryPage />);
    await screen.findByText("Temporary source failure.");
    fireEvent.change(screen.getByLabelText("Source slug"), { target: { value: "cisa-kev" } });
    fireEvent.change(screen.getByLabelText("Status"), { target: { value: "failed" } });
    fireEvent.change(screen.getByLabelText("Trigger type"), { target: { value: "manual" } });
    fireEvent.change(screen.getByLabelText("Retryable"), { target: { value: "true" } });
    fireEvent.change(screen.getByLabelText("From"), { target: { value: "2026-08-01T00:00" } });
    fireEvent.change(screen.getByLabelText("To"), { target: { value: "2026-08-02T00:00" } });
    fireEvent.click(screen.getByRole("button", { name: "Apply filters" }));
    await waitFor(() => expect(runsMock).toHaveBeenCalledTimes(2));
    const submitted = runsMock.mock.calls[1]?.[0];
    expect(submitted).toBeDefined();
    if (!submitted) throw new Error("Expected the filtered request.");
    expect(submitted).toMatchObject({ sourceSlug: "cisa-kev", status: "failed", triggerType: "manual", retryable: true, limit: 25, offset: 0 });
    expect(submitted.from).toMatch(/Z$/);
    expect(submitted.to).toMatch(/Z$/);
  });

  test("exposes retry only when the backend marks the run retryable", async () => {
    runsMock.mockResolvedValue({ ...LIST, data: { ...LIST.data, items: [{ ...RUN, retryable: false }] } });
    render(<RunHistoryPage />);
    await screen.findByText("Temporary source failure.");
    expect(screen.queryByRole("button", { name: "Retry" })).not.toBeInTheDocument();
  });

  test("successful retry triggers one immediate history refresh", async () => {
    vi.spyOn(window, "confirm").mockReturnValue(true);
    render(<RunHistoryPage />);
    fireEvent.click(await screen.findByRole("button", { name: "Retry" }));
    await waitFor(() => expect(retryMock).toHaveBeenCalledWith(RUN.public_id));
    await waitFor(() => expect(runsMock).toHaveBeenCalledTimes(2));
  });
});
