import type { ArticleListItem, ArticleListResponse } from "@/types/article";
import type { DashboardSummary } from "@/types/dashboardSummary";
import type { DashboardTrendsData } from "@/types/dashboardTrends";
import type {
  VulnerabilityListItem,
  VulnerabilityListResponse,
} from "@/types/vulnerability";

export function makeArticle(
  overrides: Partial<ArticleListItem> = {},
): ArticleListItem {
  return {
    public_id: "11111111-2222-4333-8444-555555555555",
    title: "Synthetic defensive advisory",
    summary: "Synthetic summary for an offline frontend test.",
    category: "security_advisory",
    source_slug: "synthetic-source",
    source_name: "Synthetic Source",
    source_url: "https://example.test/advisory",
    published_at: "2026-01-10T08:00:00Z",
    modified_at: "2026-01-11T08:00:00Z",
    geographic_scope: "uae",
    uae_relevance_status: "confirmed",
    uae_relevance_confidence: 0.95,
    last_seen_at: "2026-01-12T08:00:00Z",
    ...overrides,
  };
}

export function makeArticleList(
  overrides: Partial<ArticleListResponse> = {},
): ArticleListResponse {
  return {
    items: [makeArticle()],
    total: 1,
    limit: 6,
    offset: 0,
    ...overrides,
  };
}

export function makeVulnerability(
  overrides: Partial<VulnerabilityListItem> = {},
): VulnerabilityListItem {
  return {
    public_id: "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
    title: "Synthetic vulnerability title",
    summary: "Synthetic vulnerability summary for offline testing.",
    cve_id: "CVE-2026-12345",
    severity: "critical",
    cvss_score: 9.8,
    cvss_version: "3.1",
    epss_score: 0.42,
    epss_percentile: 0.91,
    epss_score_date: "2026-01-12",
    kev_status: "listed",
    kev_date_added: "2026-01-11",
    kev_due_date: "2026-02-01",
    known_ransomware_campaign_use: true,
    affected_summary: "Synthetic edge appliances",
    source_slug: "synthetic-cve-source",
    source_name: "Synthetic CVE Source",
    source_url: "https://example.test/cve",
    source_published_at: "2026-01-10T08:00:00Z",
    source_modified_at: "2026-01-11T08:00:00Z",
    first_seen_at: "2026-01-10T08:00:00Z",
    last_seen_at: "2026-01-12T08:00:00Z",
    item_type: "vulnerability",
    status: "active",
    geographic_scope: "global",
    uae_relevance_status: "probable",
    uae_relevance_confidence: 0.85,
    ...overrides,
  };
}

export function makeVulnerabilityList(
  overrides: Partial<VulnerabilityListResponse> = {},
): VulnerabilityListResponse {
  return {
    items: [makeVulnerability()],
    total: 1,
    limit: 10,
    offset: 0,
    ...overrides,
  };
}

export function makeDashboardSummary(
  overrides: Partial<DashboardSummary> = {},
): DashboardSummary {
  return {
    generated_at: "2026-01-12T08:00:00Z",
    metrics: {
      active_article_count: 2345,
      critical_vulnerability_count: 12,
      kev_vulnerability_count: 34,
      uae_related_item_count: 56,
    },
    ...overrides,
  };
}

export function makeDashboardTrends(
  overrides: Partial<DashboardTrendsData> = {},
): DashboardTrendsData {
  return {
    activeArticleCount: 120,
    criticalVulnerabilityCount: 8,
    generatedAt: "2026-01-12T08:00:00Z",
    articles: [makeArticle()],
    vulnerabilities: [makeVulnerability()],
    ...overrides,
  };
}
