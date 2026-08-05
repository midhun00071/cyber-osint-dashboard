import { render, screen } from "@testing-library/react";
import type { ReactNode } from "react";
import { beforeEach, describe, expect, test, vi } from "vitest";

import ArticleDetailPage from "@/app/articles/[publicId]/page";
import { fetchArticleDetail } from "@/services/articleApi";
import { makeArticle } from "@/test/fixtures";
import type { ArticleDetailResult } from "@/types/article";

const { useParamsMock } = vi.hoisted(() => ({ useParamsMock: vi.fn() }));

vi.mock("next/navigation", () => ({ useParams: useParamsMock }));
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
    useParamsMock.mockReturnValue({ publicId });
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
    expect(screen.getByRole("link", { name: "Back to dashboard" })).toHaveAttribute(
      "href",
      "/",
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
    expect(screen.getByRole("link", { name: "Back to dashboard" })).toHaveAttribute(
      "href",
      "/",
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
});
