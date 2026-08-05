import { render, screen } from "@testing-library/react";
import { beforeEach, describe, expect, test, vi } from "vitest";

import { ProtectedRoute, allowReturnPath } from "@/components/auth/ProtectedRoute";
import { useAuth } from "@/components/auth/AuthProvider";

const { replaceMock } = vi.hoisted(() => ({ replaceMock: vi.fn() }));
vi.mock("next/navigation", () => ({ usePathname: () => "/sources", useRouter: () => ({ replace: replaceMock }) }));
vi.mock("@/components/auth/AuthProvider", async (importOriginal) => ({
  ...(await importOriginal<typeof import("@/components/auth/AuthProvider")>()),
  useAuth: vi.fn(),
}));
const useAuthMock = vi.mocked(useAuth);

describe("ProtectedRoute", () => {
  beforeEach(() => { replaceMock.mockReset(); });
  test("blocks children during bootstrap", () => {
    useAuthMock.mockReturnValue({ state: "bootstrapping", principal: null, bootstrap: vi.fn(), login: vi.fn(), logout: vi.fn(), hasPermission: vi.fn() });
    render(<ProtectedRoute><div>private</div></ProtectedRoute>);
    expect(screen.queryByText("private")).not.toBeInTheDocument();
    expect(screen.getByRole("status")).toHaveAttribute("aria-busy", "true");
  });
  test("renders authenticated permitted content", () => {
    useAuthMock.mockReturnValue({ state: "authenticated", principal: null, bootstrap: vi.fn(), login: vi.fn(), logout: vi.fn(), hasPermission: () => true });
    render(<ProtectedRoute permission="ingestion.read"><div>private</div></ProtectedRoute>);
    expect(screen.getByText("private")).toBeVisible();
  });
  test("allow-lists only local protected return paths", () => {
    expect(allowReturnPath("/sources")).toBe(true);
    expect(allowReturnPath("/articles/11111111-1111-4111-8111-111111111111")).toBe(true);
    expect(allowReturnPath("/articles/not-a-uuid")).toBe(false);
    expect(allowReturnPath("//attacker.invalid")).toBe(false);
  });
});
