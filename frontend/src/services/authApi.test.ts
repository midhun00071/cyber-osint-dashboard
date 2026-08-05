import { describe, expect, test, vi } from "vitest";

import { fetchPrincipal } from "@/services/authApi";
import { apiFetch } from "@/services/apiClient";

vi.mock("@/services/apiClient", () => ({ apiFetch: vi.fn() }));
const apiFetchMock = vi.mocked(apiFetch);

describe("authApi", () => {
  test("treats me 401 as anonymous without fabricating a principal", async () => {
    apiFetchMock.mockResolvedValue(new Response(null, { status: 401 }));
    await expect(fetchPrincipal()).resolves.toEqual({ status: "anonymous" });
    expect(apiFetchMock).toHaveBeenCalledWith("/api/v1/auth/me", expect.objectContaining({ notifyAuthentication: false }));
  });
});
