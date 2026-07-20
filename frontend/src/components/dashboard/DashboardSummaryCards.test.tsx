import { render, screen } from "@testing-library/react";
import { beforeEach, describe, expect, test, vi } from "vitest";

import { DashboardSummaryCards } from "@/components/dashboard/DashboardSummaryCards";
import { fetchDashboardSummary } from "@/services/dashboardSummaryApi";
import { makeDashboardSummary } from "@/test/fixtures";

vi.mock("@/services/dashboardSummaryApi", () => ({
  fetchDashboardSummary: vi.fn(),
}));

const fetchSummaryMock = vi.mocked(fetchDashboardSummary);

describe("DashboardSummaryCards", () => {
  beforeEach(() => {
    fetchSummaryMock.mockReturnValue(new Promise(() => undefined));
  });

  test("renders four accessible loading placeholders", () => {
    render(<DashboardSummaryCards />);

    expect(
      screen.getByRole("region", { name: "Dashboard summary KPI cards" }),
    ).toHaveAttribute("aria-busy", "true");
    expect(screen.getAllByText("Loading backend summary")).toHaveLength(4);
  });

  test("renders formatted backend metrics", async () => {
    fetchSummaryMock.mockResolvedValue({
      status: "success",
      data: makeDashboardSummary(),
    });

    render(<DashboardSummaryCards />);

    expect(await screen.findByText("2,345")).toBeVisible();
    expect(screen.getByText("12")).toBeVisible();
    expect(screen.getByText("34")).toBeVisible();
    expect(screen.getByText("56")).toBeVisible();
    expect(screen.getAllByText("Backend summary")).toHaveLength(4);
  });

  test.each([
    ["controlled service error", async () => ({ status: "error" as const })],
    [
      "rejected promise",
      async () => {
        throw new Error("private summary failure");
      },
    ],
  ])("shows a sanitized state for a %s", async (_label, implementation) => {
    fetchSummaryMock.mockImplementation(implementation);

    render(<DashboardSummaryCards />);

    expect(await screen.findByText("Summary unavailable")).toBeVisible();
    expect(screen.queryByText("private summary failure")).not.toBeInTheDocument();
  });

  test("aborts the summary request when unmounted", () => {
    let signal: AbortSignal | undefined;
    fetchSummaryMock.mockImplementation((requestSignal) => {
      signal = requestSignal;
      return new Promise(() => undefined);
    });

    const { unmount } = render(<DashboardSummaryCards />);

    expect(signal?.aborted).toBe(false);
    unmount();
    expect(signal?.aborted).toBe(true);
  });
});
