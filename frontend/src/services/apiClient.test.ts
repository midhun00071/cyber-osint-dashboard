import { afterEach, describe, expect, test, vi } from "vitest";


afterEach(() => {
  vi.resetModules();
  vi.unstubAllEnvs();
});


describe("API client public configuration", () => {
  test("uses the test loopback fallback when no value is configured", async () => {
    vi.stubEnv("NODE_ENV", "test");
    vi.stubEnv("NEXT_PUBLIC_APP_ENV", "test");
    vi.stubEnv("NEXT_PUBLIC_API_BASE_URL", "");

    const { API_BASE_URL } = await import("@/services/apiClient");

    expect(API_BASE_URL).toBe("http://localhost:8000");
  });

  test("normalizes configured trailing slashes", async () => {
    vi.stubEnv("NODE_ENV", "test");
    vi.stubEnv("NEXT_PUBLIC_APP_ENV", "test");
    vi.stubEnv(
      "NEXT_PUBLIC_API_BASE_URL",
      "https://api.example.invalid///",
    );

    const { API_BASE_URL } = await import("@/services/apiClient");

    expect(API_BASE_URL).toBe("https://api.example.invalid");
  });

  test("does not export backend-only configuration", async () => {
    vi.stubEnv("NODE_ENV", "test");
    vi.stubEnv("NEXT_PUBLIC_APP_ENV", "test");
    vi.stubEnv("NEXT_PUBLIC_API_BASE_URL", "http://localhost:8000");
    vi.stubEnv("DATABASE_URL", "synthetic-test-secret");

    const apiClient = await import("@/services/apiClient");

    expect(Object.keys(apiClient).sort()).toEqual([
      "ACCESS_DENIED_EVENT", "API_BASE_URL", "AUTH_EXPIRED_EVENT", "apiFetch",
    ].sort());
    expect(JSON.stringify(apiClient)).not.toContain("synthetic-test-secret");
  });

  test("uses explicit local identity even when NODE_ENV is production", async () => {
    vi.stubEnv("NODE_ENV", "production");
    vi.stubEnv("NEXT_PUBLIC_APP_ENV", "local");
    vi.stubEnv("NEXT_PUBLIC_API_BASE_URL", "");

    const { API_BASE_URL } = await import("@/services/apiClient");

    expect(API_BASE_URL).toBe("http://localhost:8000");
  });
});
