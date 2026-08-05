import { apiFetch } from "@/services/apiClient";
import type { Principal, RoleKey } from "@/types/auth";

const roles = new Set<RoleKey>([
  "viewer", "analyst", "ingestion_operator", "administrator",
]);

function isPrincipal(value: unknown): value is Principal {
  if (typeof value !== "object" || value === null) return false;
  const item = value as Record<string, unknown>;
  return typeof item.public_id === "string" &&
    typeof item.display_name === "string" &&
    typeof item.role === "string" && roles.has(item.role as RoleKey) &&
    Array.isArray(item.permissions) && item.permissions.every((entry) => typeof entry === "string") &&
    (item.account_expires_at === null || typeof item.account_expires_at === "string");
}

async function principalResponse(response: Response): Promise<Principal | null> {
  if (!response.ok) return null;
  const value: unknown = await response.json();
  return isPrincipal(value) ? value : null;
}

export async function fetchPrincipal(signal?: AbortSignal): Promise<
  { status: "authenticated"; principal: Principal } |
  { status: "anonymous" } |
  { status: "error" }
> {
  try {
    const response = await apiFetch("/api/v1/auth/me", { signal, notifyAuthentication: false });
    if (response.status === 401) return { status: "anonymous" };
    const principal = await principalResponse(response);
    return principal ? { status: "authenticated", principal } : { status: "error" };
  } catch (error) {
    if (error instanceof DOMException && error.name === "AbortError") throw error;
    return { status: "error" };
  }
}

export async function login(username: string, password: string): Promise<
  { status: "authenticated"; principal: Principal } |
  { status: "invalid" } |
  { status: "error" }
> {
  try {
    const response = await apiFetch("/api/v1/auth/login", {
      method: "POST",
      body: JSON.stringify({ username, password }),
      notifyAuthentication: false,
    });
    if (response.status === 401) return { status: "invalid" };
    const principal = await principalResponse(response);
    return principal ? { status: "authenticated", principal } : { status: "error" };
  } catch {
    return { status: "error" };
  }
}

export async function logout(): Promise<boolean> {
  try {
    return (await apiFetch("/api/v1/auth/logout", { method: "POST", notifyAuthentication: false })).status === 204;
  } catch {
    return false;
  }
}
