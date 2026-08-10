import { render, screen } from "@testing-library/react";
import type { ReactNode } from "react";
import { beforeEach, describe, expect, test, vi } from "vitest";

import ArticleDetailPage from "@/app/articles/[publicId]/page";
import { fetchArticleDetail } from "@/services/articleApi";
import { makeArticle } from "@/test/fixtures";
import type { ArticleDetailResult } from "@/types/article";

const { useParamsMock, useSearchParamsMock } = vi.hoisted(() => ({ useParamsMock: vi.fn(), useSearchParamsMock: vi.fn() }));

vi.mock("next/navigation", () => ({ useParams: useParamsMock, useSearchParams: useSearchParamsMock }));
vi.mock("@/components/auth/ProtectedRoute", () => ({ ProtectedRoute: ({ children }: { children: ReactNode }) => children }));
vi.mock("@/services/articleApi", () => ({
  fetchArticleDetail: vi.fn(),
}));

const fetchArticleDetailMock = vi.mocked(fetchArticleDetail);
const publicId = "11111111-2222-4333-8444-555555555555";

function pendingUntilAbort(signal?: AbortSignal): Promise<ArticleDetailResult> {
  return new Promise((_resolve, reject) => {
    signal?.addEventListener(
      "abort",
      () => reject(new DOMException("Aborted", "AbortError")),
      { once: true },
    );
  });
}

describe("ArticleDetailPage", () => {
  beforeEach(() => {
    window.history.replaceState({}, "", `/articles/${publicId}`);
    useParamsMock.mockReturnValue({ publicId });
    useSearchParamsMock.mockImplementation(() => new URLSearchParams(window.location.search));
    fetchArticleDetailMock.mockImplementation((_id, signal) =>
      pendingUntilAbort(signal),
    );
  });

  test("shows an accessible loading state and passes the exact route ID and signal", () => {
    render(<ArticleDetailPage />);

    expect(screen.getByRole("status")).toHaveAttribute("aria-busy", "true");
    expect(fetchArticleDetailMock).toHaveBeenCalledWith(
      publicId,
      expect.any(AbortSignal),
    );
  });

  test("renders article fields, dashboard navigation, and a safe source link", async () => {
    fetchArticleDetailMock.mockResolvedValue({
      status: "success",
      data: makeArticle(),
    });
    render(<ArticleDetailPage />);

    expect(
      await screen.findByRole("heading", { name: "Synthetic defensive advisory" }),
    ).toBeVisible();
    expect(screen.getByText("Synthetic summary for an offline frontend test.")).toBeVisible();
    expect(screen.getByText("Security Advisory")).toBeVisible();
    expect(screen.getByText("Synthetic Source")).toBeVisible();
    expect(screen.getByText("UAE")).toBeVisible();
    expect(screen.getAllByText("Confirmed · High confidence (95%)")).toHaveLength(2);
    expect(screen.getByRole("link", { name: "Back to Threat Feed" })).toHaveAttribute(
      "href",
      "/threat-feed",
    );
    expect(screen.getByRole("link", { name: "Open source" })).toHaveAttribute(
      "href",
      "https://example.test/advisory",
    );
  });

  test("renders unsafe source URLs and markup-like article content as plain text", async () => {
    const title = "<img src=x onerror=alert(1)>";
    fetchArticleDetailMock.mockResolvedValue({
      status: "success",
      data: makeArticle({
        title,
        summary: "<script>secret()</script>",
        source_url: "data:text/html,unsafe",
      }),
    });
    render(<ArticleDetailPage />);

    expect(await screen.findByRole("heading", { name: title })).toBeVisible();
    expect(screen.getByText("<script>secret()</script>")).toBeVisible();
    expect(screen.queryByRole("img")).not.toBeInTheDocument();
    expect(document.querySelector("script")).toBeNull();
    expect(screen.queryByRole("link", { name: "Open source" })).not.toBeInTheDocument();
    expect(screen.getByText("Open source")).toHaveAttribute("aria-disabled", "true");
  });

  test("renders the not-found state", async () => {
    fetchArticleDetailMock.mockResolvedValue({ status: "not_found" });
    render(<ArticleDetailPage />);

    expect(await screen.findByRole("heading", { name: "Article not found" })).toBeVisible();
    expect(screen.getByRole("link", { name: "Back to Threat Feed" })).toHaveAttribute(
      "href",
      "/threat-feed",
    );
  });

  test.each([
    ["controlled error", async () => ({ status: "error" as const })],
    [
      "rejected promise",
      async () => {
        throw new Error("private article detail failure");
      },
    ],
  ])("renders a safe unavailable state for a %s", async (_label, implementation) => {
    fetchArticleDetailMock.mockImplementation(implementation);
    render(<ArticleDetailPage />);

    expect(await screen.findByRole("heading", { name: "Article unavailable" })).toBeVisible();
    expect(screen.queryByText("private article detail failure")).not.toBeInTheDocument();
  });

  test.each([
    ["missing", undefined],
    ["blank", "   "],
    ["array", [publicId]],
  ])("does not request the service for a %s route parameter", (_label, value) => {
    useParamsMock.mockReturnValue({ publicId: value });
    render(<ArticleDetailPage />);

    expect(screen.getByRole("heading", { name: "Article not found" })).toBeVisible();
    expect(fetchArticleDetailMock).not.toHaveBeenCalled();
  });

  test("aborts a pending detail request when unmounted", () => {
    let signal: AbortSignal | undefined;
    fetchArticleDetailMock.mockImplementation((_id, requestSignal) => {
      signal = requestSignal;
      return pendingUntilAbort(requestSignal);
    });
    const { unmount } = render(<ArticleDetailPage />);

    expect(signal?.aborted).toBe(false);
    unmount();
    expect(signal?.aborted).toBe(true);
  });

  test("returns to the originating filtered list and rejects external return targets", async () => {
    fetchArticleDetailMock.mockResolvedValue({ status: "success", data: makeArticle() });
    window.history.replaceState({}, "", `/articles/${publicId}?returnTo=${encodeURIComponent("/uae-intelligence?q=dubai&offset=25")}`);
    const rendered = render(<ArticleDetailPage />);
    expect(await screen.findByRole("link", { name: "Back to UAE Intelligence" })).toHaveAttribute("href", "/uae-intelligence?q=dubai&offset=25");
    rendered.unmount();

    window.history.replaceState({}, "", `/articles/${publicId}?returnTo=${encodeURIComponent("/threat-feed?q=cloud&category=threat_report&scope=global&offset=6")}`);
    const threatFeed = render(<ArticleDetailPage />);
    expect(await screen.findByRole("link", { name: "Back to Threat Feed" })).toHaveAttribute("href", "/threat-feed?q=cloud&category=threat_report&scope=global&offset=6");
    threatFeed.unmount();

    window.history.replaceState({}, "", `/articles/${publicId}?returnTo=${encodeURIComponent("/")}`);
    const overview = render(<ArticleDetailPage />);
    expect(await screen.findByRole("link", { name: "Back to Overview" })).toHaveAttribute("href", "/");
    overview.unmount();

    window.history.replaceState({}, "", `/articles/${publicId}?returnTo=${encodeURIComponent("//attacker.invalid/")}`);
    render(<ArticleDetailPage />);
    expect(await screen.findByRole("link", { name: "Back to Threat Feed" })).toHaveAttribute("href", "/threat-feed");
  });

  test.each([
    ["external", "https://attacker.invalid/threat-feed"],
    ["protocol-relative", "//attacker.invalid/threat-feed"],
    ["backslash", "/threat-feed\\attacker"],
    ["fragment-only", "#threat-feed"],
    ["javascript", "javascript:alert(1)"],
    ["data", "data:text/html,unsafe"],
  ])("rejects a %s return target", async (_label, returnTo) => {
    fetchArticleDetailMock.mockResolvedValue({ status: "success", data: makeArticle() });
    window.history.replaceState({}, "", `/articles/${publicId}?returnTo=${encodeURIComponent(returnTo)}`);
    render(<ArticleDetailPage />);
    expect(await screen.findByRole("link", { name: "Back to Threat Feed" })).toHaveAttribute("href", "/threat-feed");
  });
});
