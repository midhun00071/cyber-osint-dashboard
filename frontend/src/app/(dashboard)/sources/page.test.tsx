import { act, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, test, vi } from "vitest";

import SourcesPage from "@/app/(dashboard)/sources/page";
import { controlSource, fetchSources } from "@/services/operationsApi";

vi.mock("@/services/operationsApi", () => ({ fetchSources: vi.fn(), controlSource: vi.fn(), requestManualRun: vi.fn() }));
const fetchSourcesMock = vi.mocked(fetchSources);
const controlSourceMock = vi.mocked(controlSource);

const SOURCE = {
  public_id: "source", slug: "cisa-kev", name: "CISA KEV", source_type: "json", content_type: "vulnerability", access_class: "public_feed",
  policy_state: "implemented_enabled", operator_state: "enabled" as const, effective_state: "eligible",
  credential_required: false, credential_configured: true, execution_available: false, freshness: "stale" as const,
  progress: { kind: "checkpoint" as const, version: 2, committed_at: "2026-08-05T11:00:00Z", fingerprint: "a".repeat(64) },
  latest_run: { public_id: "run", status: "success", trigger_type: "scheduled", attempt_number: 1, started_at: "2026-08-05T10:00:00Z", finished_at: "2026-08-05T10:01:00Z" },
  quota_state: "available", backoff_until: "2026-08-05T13:00:00Z", next_scheduled_at: "2026-08-05T14:00:00Z", available_actions: ["pause" as const],
};
const RESPONSE = { status: "success" as const, data: { total: 1, limit: 100, offset: 0, items: [SOURCE] } };

describe("SourcesPage", () => {
  let visibility = "visible";
  beforeEach(() => {
    visibility = "visible";
    vi.spyOn(document, "visibilityState", "get").mockImplementation(() => visibility as DocumentVisibilityState);
    fetchSourcesMock.mockReset();
    controlSourceMock.mockReset();
    fetchSourcesMock.mockResolvedValue(RESPONSE);
  });
  afterEach(() => vi.useRealTimers());

  test("shows every safe readiness, progress, quota, schedule, and latest-run field", async () => {
    fetchSourcesMock.mockResolvedValue({ ...RESPONSE, data: { ...RESPONSE.data, items: [{ ...SOURCE, checkpoint_value: "must-not-render", credential_reference_id: "must-not-render" } as typeof SOURCE] } });
    render(<SourcesPage />);
    expect(await screen.findByText("CISA KEV")).toBeVisible();
    for (const phrase of ["Policy: implemented_enabled", "Operator: enabled", "Effective: eligible", "Freshness: stale", "Credentials required: No", "Credentials configured: Yes", "Kind: checkpoint", "Version: 2", `Fingerprint: ${"a".repeat(64)}`, "Quota: available", "Status: success", "Trigger: scheduled", "Attempt: 1"]) {
      expect(screen.getByText(phrase)).toBeVisible();
    }
    expect(screen.queryByText("must-not-render")).not.toBeInTheDocument();
  });

  test("queues exactly one visible refresh while hidden-request cancellation settles", async () => {
    fetchSourcesMock
      .mockImplementationOnce((signal) => new Promise((_, reject) => signal?.addEventListener("abort", () => reject(new DOMException("aborted", "AbortError")), { once: true })))
      .mockResolvedValueOnce(RESPONSE);
    render(<SourcesPage />);
    await waitFor(() => expect(fetchSourcesMock).toHaveBeenCalledTimes(1));
    visibility = "hidden";
    document.dispatchEvent(new Event("visibilitychange"));
    visibility = "visible";
    document.dispatchEvent(new Event("visibilitychange"));
    document.dispatchEvent(new Event("visibilitychange"));
    await waitFor(() => expect(fetchSourcesMock).toHaveBeenCalledTimes(2));
    expect(await screen.findByText("CISA KEV")).toBeVisible();
  });

  test("skips overlapping interval ticks instead of starting another request", async () => {
    vi.useFakeTimers();
    fetchSourcesMock.mockImplementationOnce(() => new Promise(() => undefined));
    const rendered = render(<SourcesPage />);
    expect(fetchSourcesMock).toHaveBeenCalledTimes(1);
    await act(async () => vi.advanceTimersByTimeAsync(45_000));
    expect(fetchSourcesMock).toHaveBeenCalledTimes(1);
    rendered.unmount();
  });

  test("aborts outstanding work on unmount", async () => {
    let signal: AbortSignal | undefined;
    fetchSourcesMock.mockImplementationOnce((submitted) => {
      signal = submitted;
      return new Promise(() => undefined);
    });
    const rendered = render(<SourcesPage />);
    await waitFor(() => expect(signal).toBeDefined());
    rendered.unmount();
    expect(signal?.aborted).toBe(true);
  });

  test("successful mutation requests exactly one immediate refresh", async () => {
    controlSourceMock.mockResolvedValue({ status: "success", data: {} });
    vi.spyOn(window, "confirm").mockReturnValue(true);
    render(<SourcesPage />);
    fireEvent.click(await screen.findByRole("button", { name: "pause" }));
    await waitFor(() => expect(controlSourceMock).toHaveBeenCalledWith("cisa-kev", "pause"));
    await waitFor(() => expect(fetchSourcesMock).toHaveBeenCalledTimes(2));
  });
});
