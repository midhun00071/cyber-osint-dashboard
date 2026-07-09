export type DashboardSummaryMetrics = {
  active_article_count: number;
  critical_vulnerability_count: number;
  kev_vulnerability_count: number;
  uae_related_item_count: number;
};

export type DashboardSummary = {
  generated_at: string;
  metrics: DashboardSummaryMetrics;
};

export type DashboardSummaryResult =
  | { status: "success"; data: DashboardSummary }
  | { status: "error" };
