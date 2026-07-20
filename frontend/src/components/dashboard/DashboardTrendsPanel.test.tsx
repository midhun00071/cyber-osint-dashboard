import { render, screen } from "@testing-library/react";
import { beforeEach, describe, expect, test, vi } from "vitest";

import { DashboardTrendsPanel } from "@/components/dashboard/DashboardTrendsPanel";
import { fetchDashboardTrends } from "@/services/dashboardTrendsApi";
import { makeArticle, makeDashboardTrends, makeVulnerability } from "@/test/fixtures";

vi.mock("@/services/dashboardTrendsApi", () => ({
  fetchDashboardTrends: vi.fn(),
}));

const fetchTrendsMock = vi.mocked(fetchDashboardTrends);

describe("DashboardTrendsPanel", () => {
  beforeEach(() => {
    fetchTrendsMock.mockReturnValue(new Promise(() => undefined));
  });

  test("shows an accessible loading state", () => {
    render(<DashboardTrendsPanel />);

    expect(screen.getByRole("status")).toHaveAttribute("aria-busy", "true");
    expect(screen.getByText("Loading stored trend data")).toBeVisible();
  });

  test("renders representative severity, category, and timeline data", async () => {
    fetchTrendsMock.mockResolvedValue({
      status: "success",
      data: makeDashboardTrends({
        vulnerabilities: [
          makeVulnerability(),
          makeVulnerability({
            public_id: "bbbbbbbb-cccc-4ddd-8eee-ffffffffffff",
            severity: "high",
          }),
        ],
        articles: [
          makeArticle(),
          makeArticle({
            public_id: "22222222-3333-4444-8555-666666666666",
            category: "threat_report",
          }),
        ],
      }),
    });

    render(<DashboardTrendsPanel />);

    expect(
      await screen.findByRole("heading", {
        name: "Latest vulnerability severity distribution",
      }),
    ).toBeVisible();
    expect(
      screen.getByRole("heading", { name: "Latest article category distribution" }),
    ).toBeVisible();
    expect(screen.getByRole("heading", { name: "Recent stored activity timeline" })).toBeVisible();
    expect(screen.getByRole("img", { name: "Critical: 1 records" })).toBeVisible();
    expect(screen.getByRole("img", { name: "High: 1 records" })).toBeVisible();
    expect(screen.getByRole("img", { name: "Threat report: 1 records" })).toBeVisible();
    expect(
      screen.getAllByText("2", { selector: ".trendSummaryStrip span" }),
    ).toHaveLength(2);
  });

  test("shows an explicit empty state for a successful empty response", async () => {
    fetchTrendsMock.mockResolvedValue({
      status: "success",
      data: makeDashboardTrends({ articles: [], vulnerabilities: [] }),
    });

    render(<DashboardTrendsPanel />);

    expect(await screen.findByText("No trend data available")).toBeVisible();
  });

  test("shows a dated-data empty state when records have no usable dates", async () => {
    fetchTrendsMock.mockResolvedValue({
      status: "success",
      data: makeDashboardTrends({
        articles: [makeArticle({ published_at: null, last_seen_at: "invalid" })],
        vulnerabilities: [
          makeVulnerability({ source_published_at: null, last_seen_at: "invalid" }),
        ],
      }),
    });

    render(<DashboardTrendsPanel />);

    expect(await screen.findByText("No dated activity available")).toBeVisible();
  });

  test.each([
    ["controlled error", async () => ({ status: "error" as const })],
    [
      "rejection",
      async () => {
        throw new Error("private trends failure");
      },
    ],
  ])("sanitizes a service %s", async (_label, implementation) => {
    fetchTrendsMock.mockImplementation(implementation);

    render(<DashboardTrendsPanel />);

    expect(await screen.findByText("Trends unavailable")).toBeVisible();
    expect(screen.queryByText("private trends failure")).not.toBeInTheDocument();
  });
});
