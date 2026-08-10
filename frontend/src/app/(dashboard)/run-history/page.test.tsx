import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
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
    fireEvent.click(screen.getByRole("button", { name: "View details" }));
    const dialog = await screen.findByRole("dialog", { name: "Run details" });
    expect(within(dialog).getByText("44444444-4444-4444-8444-444444444444")).toBeVisible();
    expect(within(dialog).getByText(/Fetched 3; created 1; updated 1; unchanged 1; skipped 0; failed 1; errors 1/)).toBeVisible();
    expect(within(dialog).getByText(/1\. Started/)).toBeVisible();
    const eventItems = within(dialog).getAllByRole("listitem");
    expect(eventItems[0]).toHaveTextContent("event-one");
    expect(eventItems[1]).toHaveTextContent("event-two");
    expect(screen.queryByText("unsafe")).not.toBeInTheDocument();
    expect(runMock).toHaveBeenCalledWith(RUN.public_id, expect.any(AbortSignal));
    expect(eventsMock).toHaveBeenCalledWith(RUN.public_id, expect.any(AbortSignal));
    fireEvent.click(within(dialog).getByRole("button", { name: "Close" }));
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    await waitFor(() => expect(screen.getByRole("button", { name: "View details" })).toHaveFocus());
  });

  test("contains modal focus, closes on Escape, and restores the exact trigger", async () => {
    const secondRun = { ...RUN, public_id: "55555555-5555-4555-8555-555555555555", source_name: "Second Source", source_slug: "second-source" };
    runsMock.mockResolvedValue({ ...LIST, data: { ...LIST.data, total: 2, items: [RUN, secondRun] } });
    runMock.mockImplementation(async (publicId) => ({ status: "success", data: publicId === secondRun.public_id ? secondRun : RUN }));
    const confirm = vi.spyOn(window, "confirm");
    render(<RunHistoryPage />);
    const triggers = await screen.findAllByRole("button", { name: "View details" });
    fireEvent.click(triggers[1]);
    const dialog = await screen.findByRole("dialog", { name: "Run details" });
    const close = within(dialog).getByRole("button", { name: "Close" });
    await waitFor(() => expect(close).toHaveFocus());

    const backdrop = document.querySelector(".runDetailBackdrop");
    expect(backdrop?.tagName).toBe("DIV");
    expect(backdrop).not.toHaveAttribute("tabindex");
    expect(fireEvent.keyDown(close, { key: "Tab" })).toBe(false);
    expect(close).toHaveFocus();
    expect(fireEvent.keyDown(close, { key: "Tab", shiftKey: true })).toBe(false);
    expect(close).toHaveFocus();

    screen.getAllByRole("button", { name: "Retry run" })[0].focus();
    expect(close).toHaveFocus();
    expect(retryMock).not.toHaveBeenCalled();
    expect(confirm).not.toHaveBeenCalled();

    fireEvent.keyDown(close, { key: "Escape" });
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    await waitFor(() => expect(triggers[1]).toHaveFocus());
  });

  test("applies only the fixed run-history filters with aware timestamps", async () => {
    render(<RunHistoryPage />);
    await screen.findByText("Temporary source failure.");
    fireEvent.change(screen.getByLabelText("Source slug"), { target: { value: "cisa-kev" } });
    fireEvent.change(screen.getByLabelText("Status"), { target: { value: "failed" } });
    fireEvent.change(screen.getByLabelText("Trigger type"), { target: { value: "manual" } });
    fireEvent.change(screen.getByLabelText("Retryable"), { target: { value: "true" } });
    fireEvent.change(screen.getByLabelText("From date"), { target: { value: "2026-08-01" } });
    fireEvent.change(screen.getByLabelText("From time"), { target: { value: "00:00" } });
    fireEvent.change(screen.getByLabelText("To date"), { target: { value: "2026-08-02" } });
    fireEvent.change(screen.getByLabelText("To time"), { target: { value: "00:00" } });
    fireEvent.click(screen.getByRole("button", { name: "Apply filters" }));
    await waitFor(() => expect(runsMock).toHaveBeenCalledTimes(2));
    const submitted = runsMock.mock.calls[1]?.[0];
    expect(submitted).toBeDefined();
    if (!submitted) throw new Error("Expected the filtered request.");
    expect(submitted).toMatchObject({ sourceSlug: "cisa-kev", status: "failed", triggerType: "manual", retryable: true, limit: 25, offset: 0 });
    expect(submitted.from).toBe(new Date("2026-08-01T00:00").toISOString());
    expect(submitted.to).toBe(new Date("2026-08-02T00:00").toISOString());
  });

  test("blocks partial run-history datetime pairs and Reset clears both parts", async () => {
    render(<RunHistoryPage />);
    await screen.findByText("Temporary source failure.");
    fireEvent.change(screen.getByLabelText("From date"), { target: { value: "2026-08-01" } });
    expect(screen.getByRole("alert")).toHaveTextContent("Enter both a date and time for from.");
    fireEvent.click(screen.getByRole("button", { name: "Apply filters" }));
    expect(runsMock).toHaveBeenCalledTimes(1);

    fireEvent.change(screen.getByLabelText("From time"), { target: { value: "12:30" } });
    fireEvent.change(screen.getByLabelText("To date"), { target: { value: "2026-08-02" } });
    fireEvent.change(screen.getByLabelText("To time"), { target: { value: "13:45" } });
    fireEvent.click(screen.getByRole("button", { name: "Reset" }));
    expect(screen.getByLabelText("From date")).toHaveValue("");
    expect(screen.getByLabelText("From time")).toHaveValue("");
    expect(screen.getByLabelText("To date")).toHaveValue("");
    expect(screen.getByLabelText("To time")).toHaveValue("");
    await waitFor(() => expect(runsMock).toHaveBeenLastCalledWith({ limit: 25, offset: 0 }, expect.any(AbortSignal)));
  });

  test("exposes retry only when the backend marks the run retryable", async () => {
    runsMock.mockResolvedValue({ ...LIST, data: { ...LIST.data, items: [{ ...RUN, retryable: false }] } });
    render(<RunHistoryPage />);
    await screen.findByText("Temporary source failure.");
    expect(screen.queryByRole("button", { name: "Retry run" })).not.toBeInTheDocument();
  });

  test("successful retry triggers one immediate history refresh", async () => {
    vi.spyOn(window, "confirm").mockReturnValue(true);
    render(<RunHistoryPage />);
    fireEvent.click(await screen.findByRole("button", { name: "Retry run" }));
    await waitFor(() => expect(retryMock).toHaveBeenCalledWith(RUN.public_id));
    await waitFor(() => expect(runsMock).toHaveBeenCalledTimes(2));
  });

  test("Retry remains confirmation-gated", async () => {
    const confirm = vi.spyOn(window, "confirm").mockReturnValue(false);
    render(<RunHistoryPage />);
    fireEvent.click(await screen.findByRole("button", { name: "Retry run" }));
    expect(confirm).toHaveBeenCalledWith("Create the next bounded retry attempt?");
    expect(retryMock).not.toHaveBeenCalled();
  });
});
