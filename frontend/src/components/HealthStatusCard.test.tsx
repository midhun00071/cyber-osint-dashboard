import { render, screen } from "@testing-library/react";
import { describe, expect, test, vi } from "vitest";

import { HealthStatusCard } from "@/components/HealthStatusCard";

function response({
  body,
  ok = true,
}: Readonly<{ body?: unknown; ok?: boolean }>): Response {
  return {
    ok,
    json: vi.fn().mockResolvedValue(body),
  } as unknown as Response;
}

describe("HealthStatusCard", () => {
  test("shows an accessible loading state while the request is pending", () => {
    vi.stubGlobal("fetch", vi.fn(() => new Promise(() => undefined)));

    render(<HealthStatusCard />);

    expect(screen.getByText("Checking service availability…")).toBeVisible();
    expect(screen.getByText("Backend API").closest("div[aria-busy='true']")).toBeInTheDocument();
  });

  test("renders a valid health response and environment", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(
        response({
          body: {
            status: "ok",
            service: "Synthetic API",
            environment: "test",
            timestamp: "2026-01-12T08:00:00Z",
          },
        }),
      ),
    );

    render(<HealthStatusCard />);

    expect(await screen.findByText("Synthetic API is operational")).toBeVisible();
    expect(screen.getByText("test")).toBeVisible();
    expect(screen.getByRole("status")).toHaveTextContent(
      "Health check completed successfully.",
    );
  });

  test.each([
    ["malformed response", response({ body: { status: "ok" } })],
    ["non-success response", response({ ok: false })],
  ])("shows a controlled unavailable state for a %s", async (_label, result) => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(result));

    render(<HealthStatusCard />);

    expect(await screen.findByText("Service unavailable")).toBeVisible();
    expect(screen.queryByText("Health request failed")).not.toBeInTheDocument();
    expect(screen.queryByText("Unexpected health response")).not.toBeInTheDocument();
  });

  test("sanitizes a rejected request", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockRejectedValue(new Error("secret upstream details")),
    );

    render(<HealthStatusCard />);

    expect(await screen.findByText("Service unavailable")).toBeVisible();
    expect(screen.queryByText("secret upstream details")).not.toBeInTheDocument();
  });

  test("aborts the pending request when unmounted", () => {
    let signal: AbortSignal | undefined;
    vi.stubGlobal(
      "fetch",
      vi.fn((_url: RequestInfo | URL, init?: RequestInit) => {
        signal = init?.signal ?? undefined;
        return new Promise(() => undefined);
      }),
    );

    const { unmount } = render(<HealthStatusCard />);

    expect(signal?.aborted).toBe(false);
    unmount();
    expect(signal?.aborted).toBe(true);
  });
});
