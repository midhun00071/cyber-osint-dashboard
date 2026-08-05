import { beforeEach, describe, expect, test, vi } from "vitest";

import {
  changeUserExpiry,
  changeUserRole,
  changeUserStatus,
  createAdminUser,
  fetchAdminUsers,
  revokeUserSessions,
} from "@/services/adminUsersApi";
import { apiFetch } from "@/services/apiClient";

vi.mock("@/services/apiClient", () => ({ apiFetch: vi.fn() }));
const apiFetchMock = vi.mocked(apiFetch);

const USER = {
  public_id: "11111111-1111-4111-8111-111111111111", username: "operator", display_name: "Operator",
  status: "active", role: "viewer", permissions: ["content.read"], account_expires_at: null,
  last_authenticated_at: null, created_at: "2026-08-05T12:00:00Z", updated_at: "2026-08-05T12:00:00Z",
};

describe("adminUsersApi", () => {
  beforeEach(() => apiFetchMock.mockReset());

  test("sends strict create, status, role, and expiry payloads", async () => {
    apiFetchMock.mockImplementation(async () => new Response(JSON.stringify(USER), { status: 200 }));
    await createAdminUser({ username: "operator", displayName: "Operator", password: "long-test-password", role: "viewer", accountExpiresAt: null });
    await changeUserStatus(USER.public_id, "disabled");
    await changeUserRole(USER.public_id, "analyst");
    await changeUserExpiry(USER.public_id, "2026-09-01T00:00:00Z");
    expect(JSON.parse(String(apiFetchMock.mock.calls[0][1]?.body))).toEqual({ username: "operator", display_name: "Operator", password: "long-test-password", role: "viewer", account_expires_at: null });
    expect(JSON.parse(String(apiFetchMock.mock.calls[1][1]?.body))).toEqual({ status: "disabled" });
    expect(JSON.parse(String(apiFetchMock.mock.calls[2][1]?.body))).toEqual({ role: "analyst" });
    expect(JSON.parse(String(apiFetchMock.mock.calls[3][1]?.body))).toEqual({ account_expires_at: "2026-09-01T00:00:00Z" });
  });

  test("uses the public user identifier for session revocation", async () => {
    apiFetchMock.mockResolvedValue(new Response(null, { status: 204 }));
    await expect(revokeUserSessions(USER.public_id)).resolves.toBe(true);
    expect(apiFetchMock).toHaveBeenCalledWith(`/api/v1/admin/users/${USER.public_id}/sessions/revoke`, { method: "POST" });
  });

  test("removes unsafe server fields from allow-listed user data", async () => {
    apiFetchMock.mockResolvedValue(new Response(JSON.stringify({ items: [{ ...USER, password_hash: "unsafe" }], total: 1, limit: 100, offset: 0 }), { status: 200 }));
    const result = await fetchAdminUsers();
    expect(result.status).toBe("success");
    if (result.status === "success") expect(result.data.items[0]).not.toHaveProperty("password_hash");
  });

  test("rejects a response containing no allow-listed user shape", async () => {
    apiFetchMock.mockResolvedValue(new Response(JSON.stringify({ items: [{ password_hash: "unsafe" }], total: 1, limit: 100, offset: 0 }), { status: 200 }));
    await expect(fetchAdminUsers()).resolves.toEqual({ status: "error" });
  });
});
