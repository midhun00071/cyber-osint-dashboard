import { apiFetch } from "@/services/apiClient";
import type { AdminUser, AdminUserList, CreateAdminUser } from "@/types/adminUser";
import type { RoleKey } from "@/types/auth";
import type { OperationResult } from "@/types/operations";

const roles = new Set<RoleKey>(["viewer", "analyst", "ingestion_operator", "administrator"]);

function object(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}

function parsedAdminUser(value: unknown): AdminUser | null {
  if (!(object(value) && typeof value.public_id === "string" && typeof value.username === "string" &&
    typeof value.display_name === "string" && ["active", "disabled"].includes(String(value.status)) &&
    typeof value.role === "string" && roles.has(value.role as RoleKey) &&
    Array.isArray(value.permissions) && value.permissions.every((entry) => typeof entry === "string") &&
    (value.account_expires_at === null || typeof value.account_expires_at === "string") &&
    (value.last_authenticated_at === null || typeof value.last_authenticated_at === "string") &&
    typeof value.created_at === "string" && typeof value.updated_at === "string")) return null;
  return {
    public_id: value.public_id,
    username: value.username,
    display_name: value.display_name,
    status: value.status as AdminUser["status"],
    role: value.role as RoleKey,
    permissions: [...value.permissions] as string[],
    account_expires_at: value.account_expires_at,
    last_authenticated_at: value.last_authenticated_at,
    created_at: value.created_at,
    updated_at: value.updated_at,
  };
}

function parsedAdminUserList(value: unknown): AdminUserList | null {
  if (!object(value) || !Array.isArray(value.items) || typeof value.total !== "number" ||
    typeof value.limit !== "number" || typeof value.offset !== "number") return null;
  const items = value.items.map(parsedAdminUser);
  if (items.some((item) => item === null)) return null;
  return { items: items as AdminUser[], total: value.total, limit: value.limit, offset: value.offset };
}

async function parsedUser(response: Response): Promise<OperationResult<AdminUser>> {
  if (!response.ok) return { status: "error" };
  const value: unknown = await response.json();
  const parsed = parsedAdminUser(value);
  return parsed ? { status: "success", data: parsed } : { status: "error" };
}

export async function fetchAdminUsers(signal?: AbortSignal): Promise<OperationResult<AdminUserList>> {
  try {
    const response = await apiFetch("/api/v1/admin/users?limit=100&offset=0", { signal });
    if (!response.ok) return { status: "error" };
    const value: unknown = await response.json();
    const parsed = parsedAdminUserList(value);
    return parsed ? { status: "success", data: parsed } : { status: "error" };
  } catch (error) {
    if (error instanceof DOMException && error.name === "AbortError") throw error;
    return { status: "error" };
  }
}

export async function createAdminUser(input: CreateAdminUser): Promise<OperationResult<AdminUser>> {
  const payload = {
    username: input.username,
    display_name: input.displayName,
    password: input.password,
    role: input.role,
    account_expires_at: input.accountExpiresAt,
  };
  try {
    return parsedUser(await apiFetch("/api/v1/admin/users", {
      method: "POST",
      body: JSON.stringify(payload),
    }));
  } catch { return { status: "error" }; }
}

export async function changeUserStatus(publicId: string, status: "active" | "disabled"): Promise<OperationResult<AdminUser>> {
  const payload = { status };
  try {
    return parsedUser(await apiFetch(`/api/v1/admin/users/${encodeURIComponent(publicId)}/status`, {
      method: "PATCH", body: JSON.stringify(payload),
    }));
  } catch { return { status: "error" }; }
}

export async function changeUserRole(publicId: string, role: RoleKey): Promise<OperationResult<AdminUser>> {
  const payload = { role };
  try {
    return parsedUser(await apiFetch(`/api/v1/admin/users/${encodeURIComponent(publicId)}/role`, {
      method: "PATCH", body: JSON.stringify(payload),
    }));
  } catch { return { status: "error" }; }
}

export async function changeUserExpiry(publicId: string, accountExpiresAt: string | null): Promise<OperationResult<AdminUser>> {
  const payload = { account_expires_at: accountExpiresAt };
  try {
    return parsedUser(await apiFetch(`/api/v1/admin/users/${encodeURIComponent(publicId)}/expiry`, {
      method: "PATCH", body: JSON.stringify(payload),
    }));
  } catch { return { status: "error" }; }
}

export async function revokeUserSessions(publicId: string): Promise<boolean> {
  try {
    return (await apiFetch(`/api/v1/admin/users/${encodeURIComponent(publicId)}/sessions/revoke`, {
      method: "POST",
    })).status === 204;
  } catch { return false; }
}
