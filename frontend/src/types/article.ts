export type ArticleCategory =
  | "security_advisory"
  | "cyber_news"
  | "threat_report"
  | "uae_official_alert"
  | "other_defensive_intel";

export type GeographicScope = "global" | "regional" | "uae" | "unknown";

export type UaeRelevanceStatus =
  | "confirmed"
  | "probable"
  | "possible"
  | "not_relevant"
  | "unknown";

export type ListSort =
  | "recently_ingested"
  | "newest_published"
  | "oldest_published";

export type ArticleFilters = {
  category?: ArticleCategory;
  geographic_scope?: GeographicScope;
  limit: number;
  offset: number;
  q?: string;
  source_slug?: string;
  sort: ListSort;
  uae_relevance_status?: UaeRelevanceStatus;
};

export type ArticleListItem = {
  public_id: string;
  title: string;
  summary: string | null;
  category: ArticleCategory;
  source_slug: string | null;
  source_name: string | null;
  source_url: string | null;
  published_at: string | null;
  modified_at: string | null;
  geographic_scope: GeographicScope;
  uae_relevance_status: UaeRelevanceStatus;
  uae_relevance_confidence: number | null;
  last_seen_at: string;
};

export type ArticleListResponse = {
  items: ArticleListItem[];
  total: number;
  limit: number;
  offset: number;
};

export type ArticleListResult =
  | { status: "success"; data: ArticleListResponse }
  | { status: "error" };

export type ArticleDetailResult =
  | { status: "success"; data: ArticleListItem }
  | { status: "not_found" }
  | { status: "error" };
