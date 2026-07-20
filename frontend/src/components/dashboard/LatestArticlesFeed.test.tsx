import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, test, vi } from "vitest";

import { LatestArticlesFeed } from "@/components/dashboard/LatestArticlesFeed";
import { fetchArticles } from "@/services/articleApi";
import { makeArticle, makeArticleList } from "@/test/fixtures";
import type { ArticleListResult } from "@/types/article";

vi.mock("@/services/articleApi", () => ({
  fetchArticles: vi.fn(),
}));

const fetchArticlesMock = vi.mocked(fetchArticles);

function deferred<T>() {
  let resolve!: (value: T) => void;
  let reject!: (reason?: unknown) => void;
  const promise = new Promise<T>((resolvePromise, rejectPromise) => {
    resolve = resolvePromise;
    reject = rejectPromise;
  });
  return { promise, reject, resolve };
}

function pendingUntilAbort(signal?: AbortSignal): Promise<ArticleListResult> {
  return new Promise((_resolve, reject) => {
    signal?.addEventListener(
      "abort",
      () => reject(new DOMException("Aborted", "AbortError")),
      { once: true },
    );
  });
}

describe("LatestArticlesFeed", () => {
  beforeEach(() => {
    fetchArticlesMock.mockResolvedValue({
      status: "success",
      data: makeArticleList(),
    });
  });

  test("shows an accessible loading state and disabled pagination", () => {
    fetchArticlesMock.mockImplementation((_filters, signal) =>
      pendingUntilAbort(signal),
    );

    render(<LatestArticlesFeed />);

    expect(screen.getByRole("status")).toHaveAttribute("aria-busy", "true");
    expect(screen.getByRole("button", { name: "Previous" })).toBeDisabled();
    expect(screen.getByRole("button", { name: "Next" })).toBeDisabled();
  });

  test("renders article metadata, navigation, safe links, and markup as text", async () => {
    const unsafeTitle = "<img src=x onerror=alert(1)>";
    fetchArticlesMock.mockResolvedValue({
      status: "success",
      data: makeArticleList({
        total: 2,
        items: [
          makeArticle({ title: unsafeTitle }),
          makeArticle({
            public_id: "22222222-3333-4444-8555-666666666666",
            title: "Unsafe source article",
            summary: "<script>window.location='bad'</script>",
            source_url: "javascript:alert(1)",
            category: "threat_report",
            geographic_scope: "global",
            uae_relevance_status: "possible",
          }),
        ],
      }),
    });

    render(<LatestArticlesFeed />);

    const titleLink = await screen.findByRole("link", { name: unsafeTitle });
    expect(titleLink).toHaveAttribute(
      "href",
      "/articles/11111111-2222-4333-8444-555555555555",
    );
    const firstArticle = titleLink.closest("article");
    expect(firstArticle).not.toBeNull();
    expect(screen.getByText("Synthetic summary for an offline frontend test.")).toBeVisible();
    expect(screen.getByText("Security Advisory")).toBeVisible();
    expect(within(firstArticle!).getByText("Synthetic Source")).toBeVisible();
    expect(within(firstArticle!).getByText("UAE")).toBeVisible();
    expect(
      within(firstArticle!).getByText("Confirmed · High confidence (95%)"),
    ).toBeVisible();
    expect(screen.getByRole("link", { name: "Open source" })).toHaveAttribute(
      "href",
      "https://example.test/advisory",
    );
    expect(screen.getAllByText("Open source")[1]).toHaveAttribute(
      "aria-disabled",
      "true",
    );
    expect(screen.getByText("<script>window.location='bad'</script>")).toBeVisible();
    expect(document.querySelector("script")).toBeNull();
    expect(screen.queryByRole("img")).not.toBeInTheDocument();
  });

  test("keeps typed search local until Apply and submits trimmed combined filters", async () => {
    const user = userEvent.setup();
    render(<LatestArticlesFeed />);
    await screen.findByText("Synthetic defensive advisory");

    await user.type(screen.getByLabelText("Search articles"), "  cloud alert  ");
    expect(fetchArticlesMock).toHaveBeenCalledTimes(1);

    await user.selectOptions(screen.getByLabelText("Category"), "threat_report");
    await user.selectOptions(screen.getByLabelText("Geographic scope"), "regional");
    await user.selectOptions(screen.getByLabelText("UAE relevance"), "probable");
    await user.click(screen.getByRole("button", { name: "Apply" }));

    await waitFor(() =>
      expect(fetchArticlesMock).toHaveBeenLastCalledWith(
        {
          category: "threat_report",
          geographic_scope: "regional",
          limit: 6,
          offset: 0,
          q: "cloud alert",
          uae_relevance_status: "probable",
        },
        expect.any(AbortSignal),
      ),
    );
  });

  test("Clear removes active filters and resets the request to offset zero", async () => {
    const user = userEvent.setup();
    render(<LatestArticlesFeed />);
    await screen.findByText("Synthetic defensive advisory");

    await user.selectOptions(screen.getByLabelText("Category"), "cyber_news");
    await user.type(screen.getByLabelText("Search articles"), "alert");
    await user.click(screen.getByRole("button", { name: "Apply" }));
    await user.click(screen.getByRole("button", { name: "Clear" }));

    await waitFor(() =>
      expect(fetchArticlesMock).toHaveBeenLastCalledWith(
        {
          category: undefined,
          geographic_scope: undefined,
          limit: 6,
          offset: 0,
          q: "",
          uae_relevance_status: undefined,
        },
        expect.any(AbortSignal),
      ),
    );
  });

  test("distinguishes no stored articles from a filtered empty response", async () => {
    const user = userEvent.setup();
    fetchArticlesMock.mockResolvedValue({
      status: "success",
      data: makeArticleList({ items: [], total: 0 }),
    });
    render(<LatestArticlesFeed />);

    expect(await screen.findByText("No articles found")).toBeVisible();
    await user.selectOptions(screen.getByLabelText("Category"), "cyber_news");
    expect(
      await screen.findByText("No articles match the selected filters"),
    ).toBeVisible();
  });

  test("paginates by six, disables controls while loading, and returns back", async () => {
    const user = userEvent.setup();
    const nextPage = deferred<ArticleListResult>();
    fetchArticlesMock
      .mockResolvedValueOnce({
        status: "success",
        data: makeArticleList({ total: 13 }),
      })
      .mockReturnValueOnce(nextPage.promise)
      .mockResolvedValueOnce({
        status: "success",
        data: makeArticleList({ total: 13 }),
      });

    render(<LatestArticlesFeed />);
    expect(await screen.findByText("Showing 1-6 of 13 stored articles")).toBeVisible();
    expect(screen.getByRole("button", { name: "Previous" })).toBeDisabled();

    await user.click(screen.getByRole("button", { name: "Next" }));
    expect(await screen.findByText("Loading stored articles")).toBeVisible();
    expect(screen.getByRole("button", { name: "Next" })).toBeDisabled();
    expect(fetchArticlesMock).toHaveBeenLastCalledWith(
      expect.objectContaining({ offset: 6 }),
      expect.any(AbortSignal),
    );

    nextPage.resolve({
      status: "success",
      data: makeArticleList({ total: 13, offset: 6 }),
    });
    expect(await screen.findByText("Showing 7-12 of 13 stored articles")).toBeVisible();
    await user.click(screen.getByRole("button", { name: "Previous" }));
    expect(await screen.findByText("Showing 1-6 of 13 stored articles")).toBeVisible();
    expect(fetchArticlesMock).toHaveBeenLastCalledWith(
      expect.objectContaining({ offset: 0 }),
      expect.any(AbortSignal),
    );
  });

  test.each([
    ["controlled error", async () => ({ status: "error" as const })],
    [
      "rejected promise",
      async () => {
        throw new Error("private article failure");
      },
    ],
  ])("renders a safe message for a %s", async (_label, implementation) => {
    fetchArticlesMock.mockImplementation(implementation);
    render(<LatestArticlesFeed />);

    expect(await screen.findByText("Articles unavailable")).toBeVisible();
    expect(screen.queryByText("private article failure")).not.toBeInTheDocument();
  });

  test("aborts an older filter request before displaying the newer result", async () => {
    const user = userEvent.setup();
    let firstSignal: AbortSignal | undefined;
    fetchArticlesMock
      .mockImplementationOnce((_filters, signal) => {
        firstSignal = signal;
        return pendingUntilAbort(signal);
      })
      .mockResolvedValueOnce({
        status: "success",
        data: makeArticleList({
          items: [makeArticle({ title: "Newest filtered article" })],
        }),
      });

    const { unmount } = render(<LatestArticlesFeed />);
    await user.selectOptions(screen.getByLabelText("Category"), "cyber_news");

    expect(await screen.findByText("Newest filtered article")).toBeVisible();
    expect(firstSignal?.aborted).toBe(true);
    expect(screen.queryByText("Articles unavailable")).not.toBeInTheDocument();
    unmount();
  });

  test("exposes an accessible pagination region", async () => {
    render(<LatestArticlesFeed />);
    await screen.findByText("Synthetic defensive advisory");

    const pagination = screen.getByLabelText("Latest articles pagination");
    expect(within(pagination).getByRole("button", { name: "Previous" })).toBeDisabled();
    expect(within(pagination).getByRole("button", { name: "Next" })).toBeDisabled();
  });
});
