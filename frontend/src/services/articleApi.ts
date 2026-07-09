import { API_BASE_URL } from "@/services/apiClient";
import type {
  ArticleCategory,
  ArticleDetailResult,
  ArticleFilters,
  ArticleListItem,
  ArticleListResponse,
  ArticleListResult,
  GeographicScope,
  UaeRelevanceStatus,
} from "@/types/article";

const articleCategoryValues = new Set<ArticleCategory>([
  "security_advisory",
  "cyber_news",
  "threat_report",
  "uae_official_alert",
  "other_defensive_intel",
]);

const geographicScopeValues = new Set<GeographicScope>([
  "global",
  "regional",
  "uae",
  "unknown",
]);

const uaeRelevanceStatusValues = new Set<UaeRelevanceStatus>([
  "confirmed",
  "probable",
  "possible",
  "not_relevant",
  "unknown",
]);

function isNullableString(value: unknown): value is string | null {
  return typeof value === "string" || value === null;
}

function isNonNegativeInteger(value: unknown): value is number {
  return typeof value === "number" && Number.isInteger(value) && value >= 0;
}

function isPositiveInteger(value: unknown): value is number {
  return typeof value === "number" && Number.isInteger(value) && value > 0;
}

function isArticleCategory(value: unknown): value is ArticleCategory {
  return (
    typeof value === "string" &&
    articleCategoryValues.has(value as ArticleCategory)
  );
}

function isGeographicScope(value: unknown): value is GeographicScope {
  return (
    typeof value === "string" &&
    geographicScopeValues.has(value as GeographicScope)
  );
}

function isUaeRelevanceStatus(value: unknown): value is UaeRelevanceStatus {
  return (
    typeof value === "string" &&
    uaeRelevanceStatusValues.has(value as UaeRelevanceStatus)
  );
}

function isNullableConfidence(value: unknown): value is number | null {
  return (
    value === null ||
    (typeof value === "number" && Number.isFinite(value) && value >= 0 && value <= 1)
  );
}

function isArticleListItem(value: unknown): value is ArticleListItem {
  if (typeof value !== "object" || value === null) {
    return false;
  }

  const item = value as Record<string, unknown>;

  return (
    typeof item.public_id === "string" &&
    typeof item.title === "string" &&
    isNullableString(item.summary) &&
    isArticleCategory(item.category) &&
    isNullableString(item.source_slug) &&
    isNullableString(item.source_name) &&
    isNullableString(item.source_url) &&
    isNullableString(item.published_at) &&
    isNullableString(item.modified_at) &&
    isGeographicScope(item.geographic_scope) &&
    isUaeRelevanceStatus(item.uae_relevance_status) &&
    isNullableConfidence(item.uae_relevance_confidence) &&
    typeof item.last_seen_at === "string"
  );
}

function isArticleListResponse(value: unknown): value is ArticleListResponse {
  if (typeof value !== "object" || value === null) {
    return false;
  }

  const response = value as Record<string, unknown>;

  return (
    Array.isArray(response.items) &&
    response.items.every(isArticleListItem) &&
    isNonNegativeInteger(response.total) &&
    isPositiveInteger(response.limit) &&
    response.limit <= 100 &&
    isNonNegativeInteger(response.offset)
  );
}

function setTrimmedParam(params: URLSearchParams, key: string, value?: string): void {
  const trimmed = value?.trim();

  if (trimmed) {
    params.set(key, trimmed);
  }
}

function buildArticleUrl(filters: ArticleFilters): string {
  const params = new URLSearchParams({
    limit: String(filters.limit),
    offset: String(filters.offset),
  });

  setTrimmedParam(params, "q", filters.q);
  setTrimmedParam(params, "category", filters.category);
  setTrimmedParam(params, "source_slug", filters.source_slug);
  setTrimmedParam(params, "geographic_scope", filters.geographic_scope);
  setTrimmedParam(params, "uae_relevance_status", filters.uae_relevance_status);

  return `${API_BASE_URL}/api/v1/articles?${params.toString()}`;
}

export async function fetchArticles(
  filters: ArticleFilters,
  signal?: AbortSignal,
): Promise<ArticleListResult> {
  try {
    const response = await fetch(buildArticleUrl(filters), {
      cache: "no-store",
      headers: { Accept: "application/json" },
      signal,
    });

    if (!response.ok) {
      return { status: "error" };
    }

    const data: unknown = await response.json();

    if (!isArticleListResponse(data)) {
      return { status: "error" };
    }

    return { status: "success", data };
  } catch (error: unknown) {
    if (error instanceof DOMException && error.name === "AbortError") {
      throw error;
    }

    return { status: "error" };
  }
}

export async function fetchArticleDetail(
  publicId: string,
  signal?: AbortSignal,
): Promise<ArticleDetailResult> {
  try {
    const response = await fetch(
      `${API_BASE_URL}/api/v1/articles/${encodeURIComponent(publicId)}`,
      {
        cache: "no-store",
        headers: { Accept: "application/json" },
        signal,
      },
    );

    if (response.status === 404) {
      return { status: "not_found" };
    }

    if (!response.ok) {
      return { status: "error" };
    }

    const data: unknown = await response.json();

    if (!isArticleListItem(data)) {
      return { status: "error" };
    }

    return { status: "success", data };
  } catch (error: unknown) {
    if (error instanceof DOMException && error.name === "AbortError") {
      throw error;
    }

    return { status: "error" };
  }
}
