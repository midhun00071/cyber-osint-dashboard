import { render, screen } from "@testing-library/react";
import { expect, test, vi } from "vitest";

import SystemHealthPage from "@/app/(dashboard)/system-health/page";
import { fetchSystemHealth } from "@/services/systemHealthApi";

vi.mock("@/components/auth/ProtectedRoute", () => ({ ProtectedRoute: ({ children }: { children: React.ReactNode }) => children }));
vi.mock("@/services/systemHealthApi", () => ({ fetchSystemHealth: vi.fn() }));

test("renders truthful component states and deployment identity", async () => {
  const names = ["backend", "database", "prefect_server", "prefect_worker", "ingestion_operations", "source_freshness", "storage", "deployment_identity"] as const;
  vi.mocked(fetchSystemHealth).mockResolvedValue({ status: "success", data: { status: "degraded", generated_at: "2026-08-09T00:00:00Z", version: "1.2.3", commit_sha: "a".repeat(40), components: names.map((name, index) => ({ name, status: index === 4 ? "disabled" : index === 5 ? "stale" : index === 6 ? "unknown" : "healthy", summary: "Safe state.", observations: {} })) } });
  render(<SystemHealthPage />);
  expect(await screen.findByText("Overall: degraded")).toBeVisible();
  expect(screen.getByText(`Commit ${"a".repeat(40)}`)).toBeVisible();
  expect(screen.getByText("disabled")).toBeVisible();
  expect(screen.getByText("stale")).toBeVisible();
  expect(screen.getByText("unknown")).toBeVisible();
});

test("renders a sanitized failure", async () => {
  vi.mocked(fetchSystemHealth).mockResolvedValue({ status: "error" });
  render(<SystemHealthPage />);
  expect(await screen.findByRole("alert")).toHaveTextContent("could not be refreshed safely");
});
