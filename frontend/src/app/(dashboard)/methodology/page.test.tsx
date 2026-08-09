import { render, screen } from "@testing-library/react";
import { expect, test, vi } from "vitest";

import MethodologyPage from "@/app/(dashboard)/methodology/page";

vi.mock("@/components/auth/ProtectedRoute", () => ({ ProtectedRoute: ({ children }: { children: React.ReactNode }) => children }));

test("documents evidence, UAE relevance, freshness, and limitations", () => {
  render(<MethodologyPage />);
  for (const heading of ["Defensive OSINT and approved sources", "Normalization, provenance, evidence, and inference", "UAE relevance", "Freshness and operational state", "Known limitations"]) expect(screen.getByRole("heading", { name: heading })).toBeVisible();
  expect(screen.getByText(/Direct UAE evidence:/)).toBeVisible();
  expect(screen.getByText(/No demonstrated UAE relevance:/)).toBeVisible();
  expect(screen.getByText(/keyword matches alone/i)).toBeVisible();
  expect(screen.queryByText(/coming soon/i)).not.toBeInTheDocument();
});
