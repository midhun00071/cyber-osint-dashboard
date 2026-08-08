import { createRef } from "react";
import { render, screen } from "@testing-library/react";
import { beforeEach, describe, expect, test, vi } from "vitest";

import { Sidebar } from "@/components/dashboard/Sidebar";
import { TopHeader } from "@/components/dashboard/TopHeader";

const hasPermission = vi.fn<(permission: string) => boolean>();
vi.mock("next/navigation", () => ({ usePathname: () => "/", useRouter: () => ({ push: vi.fn(), replace: vi.fn() }) }));
vi.mock("@/components/auth/AuthProvider", () => ({
  useAuth: () => ({ hasPermission, logout: vi.fn(), principal: { display_name: "Synthetic Analyst", role: "analyst" }, state: "authenticated" }),
}));

describe("C08 navigation", () => {
  beforeEach(() => hasPermission.mockReset());

  test("shows functional release links and projects IOC permission visibility", () => {
    hasPermission.mockImplementation((permission) => permission === "analysis.use" || permission === "ingestion.read");
    render(<Sidebar />);
    for (const name of ["Threat Feed", "Vulnerabilities", "UAE Intelligence", "IOC Search", "Sources", "Ingestion Operations", "Run History"]) {
      expect(screen.getByRole("link", { name })).toHaveAttribute("href");
    }
    expect(screen.queryByText(/coming soon/i)).not.toBeInTheDocument();
  });

  test("hides permission-restricted links and has no dead header search", () => {
    hasPermission.mockReturnValue(false);
    const { rerender } = render(<Sidebar />);
    expect(screen.queryByRole("link", { name: "IOC Search" })).not.toBeInTheDocument();
    expect(screen.queryByRole("link", { name: "Ingestion Operations" })).not.toBeInTheDocument();
    rerender(<TopHeader drawerId="navigation" isDrawerOpen={false} onOpenDrawer={vi.fn()} openButtonRef={createRef<HTMLButtonElement>()} />);
    expect(screen.queryByRole("searchbox")).not.toBeInTheDocument();
    expect(screen.queryByText(/visual placeholder|coming soon/i)).not.toBeInTheDocument();
  });
});
