import { act, render, screen, waitFor } from "@testing-library/react";
import type { ReactNode } from "react";
import { beforeEach, describe, expect, test, vi } from "vitest";

import OperationsPage from "@/app/(dashboard)/operations/page";
import { fetchCycles, fetchOperationsSummary, fetchRuns } from "@/services/operationsApi";

vi.mock("@/components/auth/ProtectedRoute", () => ({ ProtectedRoute: ({ children }: { children: ReactNode }) => children }));
vi.mock("@/services/operationsApi", () => ({ fetchOperationsSummary: vi.fn(), fetchCycles: vi.fn(), fetchRuns: vi.fn() }));
const summaryMock = vi.mocked(fetchOperationsSummary);
const cyclesMock = vi.mocked(fetchCycles);
const runsMock = vi.mocked(fetchRuns);

const SUMMARY = { status: "success" as const, data: { generated_at: "2026-08-05T12:00:00Z", deployment_state: "available" as const, configured_handler_count: 2, active_cycle_count: 1, active_run_count: 2, source_attention_count: 4, run_counts_by_status: { running: 1, checkpoint_pending: 1, failed: 3 }, latest_cycle: null } };
const CYCLES = { status: "success" as const, data: { total: 1, limit: 25, offset: 0, items: [{ public_id: "cycle", trigger_type: "scheduled", status: "running", started_at: "2026-08-05T12:00:00Z", finished_at: null, duration_seconds: null, sources_expected: 4, sources_started: 2, sources_completed: 1, sources_successful: 1, sources_non_successful: 0, summary_message: "Safe cycle." }] } };
const RUNS = { status: "success" as const, data: { total: 1, limit: 25, offset: 0, items: [{ public_id: "run", cycle_public_id: "cycle", source_public_id: "source", source_slug: "cisa-kev", source_name: "CISA KEV", trigger_type: "scheduled", status: "running", attempt_number: 0, retry_of_public_id: null, accepted_at: "2026-08-05T12:00:00Z", started_at: "2026-08-05T12:00:00Z", finished_at: null, duration_seconds: null, retryable: false, summary_message: null, counters: { fetched: 0, created: 0, updated: 0, unchanged: 0, skipped: 0, failed: 0, error_count: 0 } }] } };

describe("OperationsPage", () => {
  beforeEach(() => {
    summaryMock.mockReset(); cyclesMock.mockReset(); runsMock.mockReset();
    summaryMock.mockResolvedValue(SUMMARY); cyclesMock.mockResolvedValue(CYCLES); runsMock.mockResolvedValue(RUNS);
  });

  test("shows execution, refresh, active cycle, active run, and status evidence", async () => {
    render(<OperationsPage />);
    expect(screen.getByText("Loading operations…")).toBeVisible();
    expect(await screen.findByText("Available")).toBeVisible();
    expect(screen.getByText("Configured handlers").nextSibling).toHaveTextContent("2");
    expect(screen.getByText("Running runs").nextSibling).toHaveTextContent("1");
    expect(screen.getByText("Checkpoint pending runs").nextSibling).toHaveTextContent("1");
    expect(screen.getAllByText(/Running · Scheduled/)).toHaveLength(2);
    expect(screen.getByText(/CISA KEV · Running · Scheduled/)).toBeVisible();
    expect(screen.getByText(/Last refreshed:/)).toBeVisible();
  });

  test("performs the three page-level requests sequentially", async () => {
    let resolveSummary!: (value: typeof SUMMARY) => void;
    summaryMock.mockReturnValueOnce(new Promise((resolve) => { resolveSummary = resolve; }));
    render(<OperationsPage />);
    expect(summaryMock).toHaveBeenCalledTimes(1);
    expect(cyclesMock).not.toHaveBeenCalled();
    await act(async () => resolveSummary(SUMMARY));
    await waitFor(() => expect(cyclesMock).toHaveBeenCalledTimes(1));
    await waitFor(() => expect(runsMock).toHaveBeenCalledTimes(1));
  });

  test("shows explicit empty evidence without fabricating activity", async () => {
    summaryMock.mockResolvedValue({ ...SUMMARY, data: { ...SUMMARY.data, deployment_state: "inactive", configured_handler_count: 0, active_cycle_count: 0, active_run_count: 0, run_counts_by_status: {} } });
    cyclesMock.mockResolvedValue({ status: "success", data: { total: 0, limit: 25, offset: 0, items: [] } });
    runsMock.mockResolvedValue({ status: "success", data: { total: 0, limit: 25, offset: 0, items: [] } });
    render(<OperationsPage />);
    expect(await screen.findByText("Unavailable")).toBeVisible();
    expect(screen.getByText("No cycle activity has been recorded.")).toBeVisible();
    expect(screen.getByText("No run activity has been recorded.")).toBeVisible();
  });

  test("aggregates equivalent presentation labels without changing raw status counts", async () => {
    const rawCounts = { success: 4, failed: 5, succeeded: 15, partial: 17 };
    summaryMock.mockResolvedValue({ ...SUMMARY, data: { ...SUMMARY.data, run_counts_by_status: rawCounts } });

    render(<OperationsPage />);

    const statusSection = (await screen.findByRole("heading", { name: "Status counts" })).closest("section");
    expect(statusSection).not.toBeNull();
    if (!statusSection) throw new Error("Expected the status-count section.");
    const rows = Array.from(statusSection.querySelectorAll("li"));
    expect(rows.map((row) => row.querySelector("span")?.textContent)).toEqual(["Failed", "Partial", "Succeeded"]);
    expect(rows.map((row) => Number(row.querySelector("strong")?.textContent))).toEqual([5, 17, 19]);
    expect(rows.reduce((total, row) => total + Number(row.querySelector("strong")?.textContent), 0)).toBe(41);
    expect(rawCounts).toEqual({ success: 4, failed: 5, succeeded: 15, partial: 17 });
  });

  test("renders normal and cycle-less runs in the same operations list", async () => {
    const linkedRun = RUNS.data.items[0];
    runsMock.mockResolvedValue({
      status: "success",
      data: {
        total: 2,
        limit: 25,
        offset: 0,
        items: [
          linkedRun,
          {
            ...linkedRun,
            public_id: "cycle-less-run",
            cycle_public_id: null,
            source_slug: "legacy-feed",
            source_name: "Legacy Feed",
          },
        ],
      },
    });

    render(<OperationsPage />);

    expect(await screen.findByText(/CISA KEV/)).toBeVisible();
    expect(screen.getByText(/Legacy Feed/)).toBeVisible();
  });
});
