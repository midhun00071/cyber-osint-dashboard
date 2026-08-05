import { validatePublicEnvironment } from "@/config/publicEnvironment";

export const API_BASE_URL = validatePublicEnvironment(
  {
    NEXT_PUBLIC_APP_ENV:
      process.env.NEXT_PUBLIC_APP_ENV ??
      (process.env.NODE_ENV === "test" ? "test" : undefined),
    NEXT_PUBLIC_API_BASE_URL: process.env.NEXT_PUBLIC_API_BASE_URL,
  },
).apiBaseUrl;

export const AUTH_EXPIRED_EVENT = "alpha-data:auth-expired";
export const ACCESS_DENIED_EVENT = "alpha-data:access-denied";

type ApiRequestOptions = RequestInit & Readonly<{
  notifyAuthentication?: boolean;
}>;

function csrfToken(): string | null {
  if (typeof document === "undefined") {
    return null;
  }
  const match = document.cookie
    .split(";")
    .map((part) => part.trim())
    .find((part) => part.startsWith("alpha_csrf="));
  if (!match) {
    return null;
  }
  try {
    return decodeURIComponent(match.slice("alpha_csrf=".length));
  } catch {
    return null;
  }
}

function notify(name: string): void {
  if (typeof window !== "undefined") {
    window.dispatchEvent(new Event(name));
  }
}

export async function apiFetch(
  path: string,
  options: ApiRequestOptions = {},
): Promise<Response> {
  if (!path.startsWith("/api/")) {
    throw new Error("Only local API paths are permitted.");
  }
  const { notifyAuthentication = true, ...requestOptions } = options;
  const method = (requestOptions.method ?? "GET").toUpperCase();
  const headers = new Headers(requestOptions.headers);
  headers.set("Accept", "application/json");
  if (!["GET", "HEAD", "OPTIONS"].includes(method)) {
    headers.set("Content-Type", "application/json");
    const csrf = csrfToken();
    if (csrf) {
      headers.set("X-CSRF-Token", csrf);
    }
  }
  const response = await fetch(API_BASE_URL + path, {
    ...requestOptions,
    cache: "no-store",
    credentials: "include",
    headers,
    method,
  });
  if (notifyAuthentication && response.status === 401) {
    notify(AUTH_EXPIRED_EVENT);
  } else if (notifyAuthentication && response.status === 403) {
    notify(ACCESS_DENIED_EVENT);
  }
  return response;
}
