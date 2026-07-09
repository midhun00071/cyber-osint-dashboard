import { fetchArticles } from "@/services/articleApi";
import { fetchDashboardSummary } from "@/services/dashboardSummaryApi";
import { fetchVulnerabilities } from "@/services/vulnerabilityApi";
import type {
  DashboardTrendsData,
  DashboardTrendsResult,
} from "@/types/dashboardTrends";

const trendSampleLimit = 50;

export async function fetchDashboardTrends(
  signal?: AbortSignal,
): Promise<DashboardTrendsResult> {
  try {
    const [summaryResult, vulnerabilityResult, articleResult] = await Promise.all([
      fetchDashboardSummary(signal),
      fetchVulnerabilities(
        {
          limit: trendSampleLimit,
          offset: 0,
        },
        signal,
      ),
      fetchArticles(
        {
          limit: trendSampleLimit,
          offset: 0,
        },
        signal,
      ),
    ]);

    if (
      summaryResult.status !== "success" ||
      vulnerabilityResult.status !== "success" ||
      articleResult.status !== "success"
    ) {
      return { status: "error" };
    }

    const data: DashboardTrendsData = {
      activeArticleCount: summaryResult.data.metrics.active_article_count,
      criticalVulnerabilityCount:
        summaryResult.data.metrics.critical_vulnerability_count,
      generatedAt: summaryResult.data.generated_at,
      articles: articleResult.data.items,
      vulnerabilities: vulnerabilityResult.data.items,
    };

    return { status: "success", data };
  } catch (error: unknown) {
    if (error instanceof DOMException && error.name === "AbortError") {
      throw error;
    }

    return { status: "error" };
  }
}
