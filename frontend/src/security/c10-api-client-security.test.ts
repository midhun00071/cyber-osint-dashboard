import { beforeEach, describe, expect, test, vi } from "vitest";

import { API_BASE_URL, apiFetch } from "../services/apiClient";

const fetchMock = vi.fn<typeof fetch>();

beforeEach(() => {
  fetchMock.mockReset();
  vi.stubGlobal("fetch", fetchMock);
  document.cookie = "alpha_csrf=synthetic-csrf-token";
});

describe("C10 API client security", () => {
  test("uses same-origin relative paths with credentials and CSRF protection", async () => {
    fetchMock.mockResolvedValue(new Response(null, { status: 204 }));

    await apiFetch("/api/v1/auth/logout", { method: "POST" });

    const [target, options] = fetchMock.mock.calls[0];
    expect(target).toBe(`${API_BASE_URL}/api/v1/auth/logout`);
    expect(options?.credentials).toBe("include");
    expect(new Headers(options?.headers).get("X-CSRF-Token")).toBe(
      "synthetic-csrf-token",
    );
  });

  test.each([
    "https://attacker.invalid/api",
    "//attacker.invalid/api",
    "javascript:alert(1)",
    "/api/v1/items\r\nX-Test: injected",
  ])("rejects non-relative or control-bearing request target %s", async (target) => {
    await expect(apiFetch(target)).rejects.toThrow();
    expect(fetchMock).not.toHaveBeenCalled();
  });
});
