import { render, screen } from "@testing-library/react";
import { describe, expect, test, vi } from "vitest";

import DashboardOverviewPage from "@/app/(dashboard)/page";

vi.mock("@/components/HealthStatusCard", () => ({
  HealthStatusCard: () => <div>Mock backend health state</div>,
}));
vi.mock("@/components/dashboard/DashboardSummaryCards", () => ({
  DashboardSummaryCards: () => <section aria-label="Mock dashboard summary" />,
}));
vi.mock("@/components/dashboard/DashboardTrendsPanel", () => ({
  DashboardTrendsPanel: () => <div>Mock recent trends</div>,
}));
vi.mock("@/components/dashboard/LatestArticlesFeed", () => ({
  LatestArticlesFeed: ({ originPath }: { originPath?: string }) => <div data-origin-path={originPath}>Mock latest articles feed</div>,
}));
vi.mock("@/components/dashboard/VulnerabilitiesTable", () => ({
  VulnerabilitiesTable: ({ originPath }: { originPath?: string }) => <div data-origin-path={originPath}>Mock vulnerabilities table</div>,
}));

describe("DashboardOverviewPage", () => {
  test("composes the primary dashboard sections without a full-page snapshot", () => {
    render(<DashboardOverviewPage />);

    expect(
      screen.getByRole("heading", { name: "Cyber OSINT Dashboard", level: 1 }),
    ).toBeVisible();
    expect(screen.getByRole("region", { name: "Mock dashboard summary" })).toBeVisible();
    expect(screen.getByText("Mock recent trends")).toBeVisible();
    expect(screen.getByText("Mock vulnerabilities table")).toBeVisible();
    expect(screen.getByText("Mock latest articles feed")).toBeVisible();
    expect(screen.getByText("Mock vulnerabilities table")).toHaveAttribute("data-origin-path", "/");
    expect(screen.getByText("Mock latest articles feed")).toHaveAttribute("data-origin-path", "/");
    expect(screen.getByText("Mock backend health state")).toBeVisible();
    expect(screen.getByLabelText("Dashboard data scope")).toHaveTextContent(
      "Stored backend data · no live collection",
    );
    expect(screen.queryByText(/preview sections/i)).not.toBeInTheDocument();
  });
});
