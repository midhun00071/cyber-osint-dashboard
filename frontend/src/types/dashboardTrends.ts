import type { ArticleListItem } from "@/types/article";
import type { VulnerabilityListItem } from "@/types/vulnerability";

export type DashboardTrendsData = {
  activeArticleCount: number;
  criticalVulnerabilityCount: number;
  generatedAt: string;
  articles: ArticleListItem[];
  vulnerabilities: VulnerabilityListItem[];
};

export type DashboardTrendsResult =
  | { status: "success"; data: DashboardTrendsData }
  | { status: "error" };
