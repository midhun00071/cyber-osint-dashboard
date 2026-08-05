import { fireEvent, render, screen } from "@testing-library/react";
import { beforeEach, describe, expect, test, vi } from "vitest";

import LoginPage from "@/app/login/page";
import { useAuth } from "@/components/auth/AuthProvider";

vi.mock("next/navigation", () => ({ useRouter: () => ({ replace: vi.fn() }) }));
vi.mock("@/components/auth/AuthProvider", async (importOriginal) => ({
  ...(await importOriginal<typeof import("@/components/auth/AuthProvider")>()),
  useAuth: vi.fn(),
}));
const useAuthMock = vi.mocked(useAuth);

describe("LoginPage", () => {
  beforeEach(() => window.history.replaceState({}, "", "/login"));

  test("submits bounded credentials with a validated local return path and no token field", async () => {
    window.history.replaceState({}, "", "/login?next=%2Fsources");
    const login = vi.fn().mockResolvedValue(true);
    useAuthMock.mockReturnValue({ state: "anonymous", principal: null, bootstrap: vi.fn(), login, logout: vi.fn(), hasPermission: vi.fn() });
    render(<LoginPage />);
    fireEvent.change(screen.getByLabelText("Username"), { target: { value: "operator" } });
    fireEvent.change(screen.getByLabelText("Password"), { target: { value: "long-test-password" } });
    fireEvent.submit(screen.getByRole("button", { name: "Sign in" }).closest("form")!);
    expect(login).toHaveBeenCalledWith("operator", "long-test-password", "/sources");
    expect(screen.queryByLabelText(/token/i)).not.toBeInTheDocument();
  });

  test("falls back to the overview for an external return path", () => {
    window.history.replaceState({}, "", "/login?next=https%3A%2F%2Fattacker.invalid");
    const login = vi.fn().mockResolvedValue(true);
    useAuthMock.mockReturnValue({ state: "anonymous", principal: null, bootstrap: vi.fn(), login, logout: vi.fn(), hasPermission: vi.fn() });
    render(<LoginPage />);
    fireEvent.change(screen.getByLabelText("Username"), { target: { value: "operator" } });
    fireEvent.change(screen.getByLabelText("Password"), { target: { value: "long-test-password" } });
    fireEvent.submit(screen.getByRole("button", { name: "Sign in" }).closest("form")!);
    expect(login).toHaveBeenCalledWith("operator", "long-test-password", "/");
  });
});
