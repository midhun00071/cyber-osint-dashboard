import { render, screen } from "@testing-library/react";
import type { ReactNode } from "react";
import { beforeEach, describe, expect, test, vi } from "vitest";

import VulnerabilityDetailPage from "@/app/vulnerabilities/[publicId]/page";
import { fetchVulnerabilityDetail } from "@/services/vulnerabilityApi";
import { makeVulnerability } from "@/test/fixtures";
import type { VulnerabilityDetailResult } from "@/types/vulnerability";

const { useParamsMock, useSearchParamsMock } = vi.hoisted(() => ({ useParamsMock: vi.fn(), useSearchParamsMock: vi.fn() }));

vi.mock("next/navigation", () => ({ useParams: useParamsMock, useSearchParams: useSearchParamsMock }));
vi.mock("@/components/auth/ProtectedRoute", () => ({ ProtectedRoute: ({ children }: { children: ReactNode }) => children }));
vi.mock("@/services/vulnerabilityApi", () => ({
  fetchVulnerabilityDetail: vi.fn(),
}));

const fetchVulnerabilityDetailMock = vi.mocked(fetchVulnerabilityDetail);
const publicId = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee";

function pendingUntilAbort(
  signal?: AbortSignal,
): Promise<VulnerabilityDetailResult> {
  return new Promise((_resolve, reject) => {
    signal?.addEventListener(
      "abort",
      () => reject(new DOMException("Aborted", "AbortError")),
      { once: true },
    );
  });
}

describe("VulnerabilityDetailPage", () => {
  beforeEach(() => {
    window.history.replaceState({}, "", `/vulnerabilities/${publicId}`);
    useParamsMock.mockReturnValue({ publicId });
    useSearchParamsMock.mockImplementation(() => new URLSearchParams(window.location.search));
    fetchVulnerabilityDetailMock.mockImplementation((_id, signal) =>
      pendingUntilAbort(signal),
    );
  });

  test("shows loading and passes the exact route ID and AbortSignal", () => {
    render(<VulnerabilityDetailPage />);

    expect(screen.getByRole("status")).toHaveAttribute("aria-busy", "true");
    expect(fetchVulnerabilityDetailMock).toHaveBeenCalledWith(
      publicId,
      expect.any(AbortSignal),
    );
  });

  test("renders representative vulnerability metadata and navigation", async () => {
    fetchVulnerabilityDetailMock.mockResolvedValue({
      status: "success",
      data: makeVulnerability(),
    });
    render(<VulnerabilityDetailPage />);

    expect(await screen.findByRole("heading", { name: "CVE-2026-12345" })).toBeVisible();
    expect(screen.getByText("Synthetic vulnerability title")).toBeVisible();
    expect(screen.getByText("Synthetic vulnerability summary for offline testing.")).toBeVisible();
    expect(screen.getByText("Critical")).toBeVisible();
    expect(screen.getByText("9.8 / 3.1")).toBeVisible();
    expect(screen.getByText("42.00%")).toBeVisible();
    expect(screen.getByText("P91.0")).toBeVisible();
    expect(screen.getByText("KEV listed")).toBeVisible();
    expect(screen.getByText("Known campaign use")).toBeVisible();
    expect(screen.getByText("Synthetic edge appliances")).toBeVisible();
    expect(screen.getByText("Synthetic CVE Source")).toBeVisible();
    expect(screen.getByText("Global")).toBeVisible();
    expect(screen.getAllByText("Probable · Medium confidence (85%)")).toHaveLength(2);
    expect(screen.getByRole("link", { name: "Back to Vulnerabilities" })).toHaveAttribute(
      "href",
      "/vulnerabilities",
    );
    expect(screen.getByRole("link", { name: "Open source" })).toHaveAttribute(
      "href",
      "https://example.test/cve",
    );
  });

  test("keeps unsafe URLs and markup-like fields non-executable", async () => {
    const title = "<svg onload=alert(1)>";
    fetchVulnerabilityDetailMock.mockResolvedValue({
      status: "success",
      data: makeVulnerability({
        title,
        summary: "<script>secret()</script>",
        affected_summary: "<iframe src=bad>",
        source_url: "javascript:alert(1)",
      }),
    });
    render(<VulnerabilityDetailPage />);

    expect(await screen.findByText(title)).toBeVisible();
    expect(screen.getByText("<script>secret()</script>")).toBeVisible();
    expect(screen.getByText("<iframe src=bad>")).toBeVisible();
    expect(document.querySelector("script, svg, iframe")).toBeNull();
    expect(screen.queryByRole("link", { name: "Open source" })).not.toBeInTheDocument();
    expect(screen.getByText("Open source")).toHaveAttribute("aria-disabled", "true");
  });

  test("renders the not-found state", async () => {
    fetchVulnerabilityDetailMock.mockResolvedValue({ status: "not_found" });
    render(<VulnerabilityDetailPage />);

    expect(
      await screen.findByRole("heading", { name: "Vulnerability not found" }),
    ).toBeVisible();
  });

  test.each([
    ["controlled error", async () => ({ status: "error" as const })],
    [
      "rejected promise",
      async () => {
        throw new Error("private vulnerability detail failure");
      },
    ],
  ])("renders a sanitized unavailable state for a %s", async (_label, implementation) => {
    fetchVulnerabilityDetailMock.mockImplementation(implementation);
    render(<VulnerabilityDetailPage />);

    expect(
      await screen.findByRole("heading", { name: "Vulnerability unavailable" }),
    ).toBeVisible();
    expect(screen.queryByText("private vulnerability detail failure")).not.toBeInTheDocument();
  });

  test.each([
    ["missing", undefined],
    ["blank", "   "],
    ["array", [publicId]],
  ])("does not request the service for a %s route parameter", (_label, value) => {
    useParamsMock.mockReturnValue({ publicId: value });
    render(<VulnerabilityDetailPage />);

    expect(screen.getByRole("heading", { name: "Vulnerability not found" })).toBeVisible();
    expect(fetchVulnerabilityDetailMock).not.toHaveBeenCalled();
  });

  test("aborts the pending detail request on unmount", () => {
    let signal: AbortSignal | undefined;
    fetchVulnerabilityDetailMock.mockImplementation((_id, requestSignal) => {
      signal = requestSignal;
      return pendingUntilAbort(requestSignal);
    });
    const { unmount } = render(<VulnerabilityDetailPage />);

    expect(signal?.aborted).toBe(false);
    unmount();
    expect(signal?.aborted).toBe(true);
  });

  test("uses a safe originating UAE list return when supplied", async () => {
    fetchVulnerabilityDetailMock.mockResolvedValue({ status: "success", data: makeVulnerability() });
    window.history.replaceState({}, "", `/vulnerabilities/${publicId}?returnTo=${encodeURIComponent("/uae-intelligence?relevance=direct")}`);
    render(<VulnerabilityDetailPage />);
    expect(await screen.findByRole("link", { name: "Back to UAE Intelligence" })).toHaveAttribute("href", "/uae-intelligence?relevance=direct");
  });

  test("returns to the exact vulnerability list state supplied by the route", async () => {
    fetchVulnerabilityDetailMock.mockResolvedValue({ status: "success", data: makeVulnerability() });
    const returnTo = "/vulnerabilities?q=CVE-2026&severity=high&scope=uae&limit=25&offset=25";
    window.history.replaceState({}, "", `/vulnerabilities/${publicId}?returnTo=${encodeURIComponent(returnTo)}`);
    render(<VulnerabilityDetailPage />);
    expect(await screen.findByRole("link", { name: "Back to Vulnerabilities" })).toHaveAttribute("href", returnTo);
  });
});
