import { render, screen } from "@testing-library/react";
import { beforeEach, describe, expect, test, vi } from "vitest";

import { Sidebar } from "@/components/dashboard/Sidebar";
import { getSafeReturnPath } from "@/components/auth/AuthProvider";

const hasPermission = vi.fn<(permission: string) => boolean>();
vi.mock("next/navigation", () => ({ usePathname: () => "/", useRouter: () => ({ replace: vi.fn() }) }));
vi.mock("@/components/auth/AuthProvider", async (original) => {
  const actual = await original<typeof import("@/components/auth/AuthProvider")>();
  return { ...actual, useAuth: () => ({ hasPermission, principal: { display_name: "Synthetic", role: "analyst" }, state: "authenticated" }) };
});

describe("C09 navigation", () => {
  beforeEach(() => hasPermission.mockReset());
  test("projects permissions while keeping methodology authenticated", () => {
    hasPermission.mockImplementation((permission) => ["report.read", "source.read"].includes(permission));
    render(<Sidebar />);
    expect(screen.getByRole("link", { name: "Reports" })).toHaveAttribute("href", "/reports");
    expect(screen.getByRole("link", { name: "System Health" })).toHaveAttribute("href", "/system-health");
    expect(screen.getByRole("link", { name: "Methodology" })).toHaveAttribute("href", "/methodology");
    expect(screen.queryByRole("link", { name: "Audit Log" })).not.toBeInTheDocument();
  });
  test("allows new local returns and rejects unsafe redirects", () => {
    for (const path of ["/reports", "/system-health", "/audit-log", "/methodology"]) expect(getSafeReturnPath(path)).toBe(path);
    expect(getSafeReturnPath("%2f%2fattacker.invalid")).toBe("/");
  });
});
