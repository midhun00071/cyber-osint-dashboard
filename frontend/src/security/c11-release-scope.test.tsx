import { existsSync, readFileSync } from "node:fs";
import path from "node:path";

import { render, screen } from "@testing-library/react";
import { beforeEach, describe, expect, test, vi } from "vitest";

import { Sidebar } from "@/components/dashboard/Sidebar";


const hasPermission = vi.fn<(permission: string) => boolean>();

vi.mock("next/navigation", () => ({
  usePathname: () => "/",
  useRouter: () => ({ push: vi.fn(), replace: vi.fn() }),
}));
vi.mock("@/components/auth/AuthProvider", () => ({
  useAuth: () => ({
    hasPermission,
    principal: {
      display_name: "Synthetic Release Reviewer",
      role: "administrator",
    },
    state: "authenticated",
  }),
}));

const releaseRoutes = [
  ["Overview", "/", "src/app/(dashboard)/page.tsx"],
  ["Threat Feed", "/threat-feed", "src/app/(dashboard)/threat-feed/page.tsx"],
  ["Vulnerabilities", "/vulnerabilities", "src/app/(dashboard)/vulnerabilities/page.tsx"],
  ["UAE Intelligence", "/uae-intelligence", "src/app/(dashboard)/uae-intelligence/page.tsx"],
  ["IOC Search", "/ioc-search", "src/app/(dashboard)/ioc-search/page.tsx"],
  ["Ingestion Operations", "/ingestion-operations", "src/app/(dashboard)/ingestion-operations/page.tsx"],
  ["Sources", "/sources", "src/app/(dashboard)/sources/page.tsx"],
  ["Run History", "/run-history", "src/app/(dashboard)/run-history/page.tsx"],
  ["Reports", "/reports", "src/app/(dashboard)/reports/page.tsx"],
  ["System Health", "/system-health", "src/app/(dashboard)/system-health/page.tsx"],
  ["Audit Log", "/audit-log", "src/app/(dashboard)/audit-log/page.tsx"],
  ["Methodology", "/methodology", "src/app/(dashboard)/methodology/page.tsx"],
] as const;

const releaseImplementationFiles = [
  ...releaseRoutes.map(([, , file]) => file),
  "src/components/HealthStatusCard.tsx",
  "src/components/analyst/IndicatorSearch.tsx",
  "src/components/analyst/ThreatMetadataList.tsx",
  "src/components/analyst/UaeIntelligenceList.tsx",
  "src/components/dashboard/DashboardSummaryCards.tsx",
  "src/components/dashboard/DashboardTrendsPanel.tsx",
  "src/components/dashboard/LatestArticlesFeed.tsx",
  "src/components/dashboard/VulnerabilitiesTable.tsx",
] as const;

const removedRouteSegments = [
  "threat-entities",
  "threat-graph",
  "predictions",
  "soar",
  "malware-samples",
  "chatbot",
  "alerts",
  "mobile",
  "dashboard-builder",
  "tenants",
  "kubernetes",
  "sso",
] as const;

function source(relativePath: string): string {
  return readFileSync(path.resolve(relativePath), "utf8");
}

describe("C11 release scope", () => {
  beforeEach(() => {
    hasPermission.mockReset();
    hasPermission.mockReturnValue(true);
  });

  test("renders all twelve release links with real route files", () => {
    render(<Sidebar />);

    for (const [label, href, routeFile] of releaseRoutes) {
      expect(screen.getByRole("link", { name: label })).toHaveAttribute("href", href);
      expect(existsSync(path.resolve(routeFile))).toBe(true);
    }
  });

  test("keeps removed features and Coming Soon surfaces absent", () => {
    const dashboardRoot = path.resolve("src/app/(dashboard)");
    for (const segment of removedRouteSegments) {
      expect(existsSync(path.join(dashboardRoot, segment))).toBe(false);
    }

    const visibleSource = [
      source("src/components/dashboard/Sidebar.tsx"),
      ...releaseImplementationFiles.map(source),
    ].join("\n");
    expect(visibleSource).not.toMatch(/coming soon|todo ui|disabled fake button/i);
    expect(visibleSource).not.toMatch(/href=["']\/(?:threat-entities|threat-graph|predictions|soar|chatbot|alerts|mobile|dashboard-builder|tenants|kubernetes|sso)/i);
  });

  test("keeps release buttons connected to handlers or form submission", () => {
    for (const file of releaseImplementationFiles) {
      const buttons = source(file).match(/<button\b[\s\S]*?<\/button>/g) ?? [];
      for (const button of buttons) {
        expect(button, `${file}: ${button}`).toMatch(/onClick=|type="submit"/);
      }
    }
  });

  test("retains accessible page identity and truthful state vocabulary", () => {
    for (const [label, , file] of releaseRoutes) {
      const pageSource = source(file);
      if (label === "Ingestion Operations") {
        expect(pageSource).toContain('export { default } from "../operations/page"');
      } else {
        expect(pageSource).toMatch(/<h1(?:\s|>)/);
      }
    }

    const visibleSource = releaseImplementationFiles.map(source).join("\n");
    expect(visibleSource).toMatch(/role="status"/);
    expect(visibleSource).toMatch(/role="alert"/);
    expect(visibleSource).toMatch(/No approved sources are available/);
    expect(visibleSource).toMatch(/No runs match the selected filters/);
    expect(visibleSource).toMatch(/No audit events match these filters/);
  });
});
