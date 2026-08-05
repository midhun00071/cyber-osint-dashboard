import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import type { ReactNode } from "react";
import { beforeEach, describe, expect, test, vi } from "vitest";

import AdminUsersPage from "@/app/(dashboard)/admin/users/page";
import {
  changeUserExpiry,
  changeUserRole,
  changeUserStatus,
  createAdminUser,
  fetchAdminUsers,
  revokeUserSessions,
} from "@/services/adminUsersApi";

vi.mock("@/components/auth/ProtectedRoute", () => ({ ProtectedRoute: ({ children }: { children: ReactNode }) => children }));
vi.mock("@/services/adminUsersApi", () => ({ fetchAdminUsers: vi.fn(), createAdminUser: vi.fn(), changeUserStatus: vi.fn(), changeUserRole: vi.fn(), changeUserExpiry: vi.fn(), revokeUserSessions: vi.fn() }));
const fetchMock = vi.mocked(fetchAdminUsers);
const createMock = vi.mocked(createAdminUser);
const statusMock = vi.mocked(changeUserStatus);
const roleMock = vi.mocked(changeUserRole);
const expiryMock = vi.mocked(changeUserExpiry);
const revokeMock = vi.mocked(revokeUserSessions);

const USER = { public_id: "11111111-1111-4111-8111-111111111111", username: "operator", display_name: "Synthetic Operator", status: "active" as const, role: "ingestion_operator" as const, permissions: ["ingestion.read"], account_expires_at: null, last_authenticated_at: null, created_at: "2026-08-05T12:00:00Z", updated_at: "2026-08-05T12:00:00Z" };

describe("AdminUsersPage", () => {
  beforeEach(() => {
    for (const mock of [fetchMock, createMock, statusMock, roleMock, expiryMock, revokeMock]) mock.mockReset();
    fetchMock.mockResolvedValue({ status: "success", data: { total: 1, limit: 100, offset: 0, items: [USER] } });
    createMock.mockResolvedValue({ status: "success", data: USER });
    statusMock.mockResolvedValue({ status: "success", data: USER });
    roleMock.mockResolvedValue({ status: "success", data: USER });
    expiryMock.mockResolvedValue({ status: "success", data: USER });
    revokeMock.mockResolvedValue(true);
  });

  test("creates a user from fixed fields and clears password state after completion", async () => {
    render(<AdminUsersPage />);
    await screen.findByText("Synthetic Operator");
    fireEvent.change(screen.getByLabelText("Username"), { target: { value: "new.operator" } });
    fireEvent.change(screen.getByLabelText("Display name"), { target: { value: "New Operator" } });
    fireEvent.change(screen.getByLabelText("Temporary password"), { target: { value: "long-test-password" } });
    fireEvent.change(screen.getByLabelText("Role", { selector: "select" }), { target: { value: "analyst" } });
    fireEvent.click(screen.getByRole("button", { name: "Create user" }));
    await waitFor(() => expect(createMock).toHaveBeenCalledWith({ username: "new.operator", displayName: "New Operator", password: "long-test-password", role: "analyst", accountExpiresAt: null }));
    await waitFor(() => expect(screen.getByLabelText("Temporary password")).toHaveValue(""));
  });

  test("requires confirmation for disable, role, expiry, and session operations", async () => {
    const confirm = vi.spyOn(window, "confirm").mockReturnValue(false);
    render(<AdminUsersPage />);
    await screen.findByText("Synthetic Operator");
    fireEvent.change(screen.getByLabelText("New role for operator"), { target: { value: "analyst" } });
    fireEvent.change(screen.getByLabelText("New expiry for operator"), { target: { value: "2026-09-01T00:00" } });
    fireEvent.click(screen.getByRole("button", { name: "Disable" }));
    fireEvent.click(screen.getByRole("button", { name: "Change role" }));
    fireEvent.click(screen.getByRole("button", { name: "Change expiry" }));
    fireEvent.click(screen.getByRole("button", { name: "Revoke sessions" }));
    expect(confirm).toHaveBeenCalledTimes(4);
    expect(statusMock).not.toHaveBeenCalled();
    expect(roleMock).not.toHaveBeenCalled();
    expect(expiryMock).not.toHaveBeenCalled();
    expect(revokeMock).not.toHaveBeenCalled();
  });

  test("uses the public identifier for confirmed lifecycle changes", async () => {
    vi.spyOn(window, "confirm").mockReturnValue(true);
    render(<AdminUsersPage />);
    await screen.findByText("Synthetic Operator");
    fireEvent.change(screen.getByLabelText("New role for operator"), { target: { value: "analyst" } });
    fireEvent.click(screen.getByRole("button", { name: "Change role" }));
    await waitFor(() => expect(roleMock).toHaveBeenCalledWith(USER.public_id, "analyst"));
    fireEvent.click(screen.getByRole("button", { name: "Revoke sessions" }));
    await waitFor(() => expect(revokeMock).toHaveBeenCalledWith(USER.public_id));
  });

  test("does not render unsafe server fields", async () => {
    const unsafeUser = { ...USER, password_hash: "must-not-render" } as unknown as typeof USER;
    fetchMock.mockResolvedValue({ status: "success", data: { total: 1, limit: 100, offset: 0, items: [unsafeUser] } });
    render(<AdminUsersPage />);
    await screen.findByText("Synthetic Operator");
    expect(screen.queryByText("must-not-render")).not.toBeInTheDocument();
  });
});
