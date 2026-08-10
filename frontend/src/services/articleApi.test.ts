import { beforeEach, describe, expect, test, vi } from "vitest";

import { apiFetch } from "@/services/apiClient";
import { fetchArticles } from "@/services/articleApi";
import { makeArticleList } from "@/test/fixtures";

vi.mock("@/services/apiClient", () => ({ apiFetch: vi.fn() }));
const apiFetchMock = vi.mocked(apiFetch);

describe("articleApi", () => {
  beforeEach(() => apiFetchMock.mockReset());

  test("sends the allow-listed server sort with pagination and filters", async () => {
    apiFetchMock.mockResolvedValue(
      new Response(JSON.stringify(makeArticleList()), { status: 200 }),
    );

    const result = await fetchArticles({
      category: "threat_report",
      limit: 6,
      offset: 12,
      q: "cloud",
      sort: "newest_published",
    });

    expect(result.status).toBe("success");
    expect(apiFetchMock.mock.calls[0][0]).toBe(
      "/api/v1/articles?limit=6&offset=12&sort=newest_published&q=cloud&category=threat_report",
    );
  });
});
