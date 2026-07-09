import { API_BASE_URL } from "@/services/apiClient";
import type {
  DashboardSummary,
  DashboardSummaryMetrics,
  DashboardSummaryResult,
} from "@/types/dashboardSummary";

function isNonNegativeFiniteNumber(value: unknown): value is number {
  return typeof value === "number" && Number.isFinite(value) && value >= 0;
}

function isDashboardSummaryMetrics(value: unknown): value is DashboardSummaryMetrics {
  if (typeof value !== "object" || value === null) {
    return false;
  }

  const metrics = value as Record<string, unknown>;

  return (
    isNonNegativeFiniteNumber(metrics.critical_vulnerability_count) &&
    isNonNegativeFiniteNumber(metrics.kev_vulnerability_count) &&
    isNonNegativeFiniteNumber(metrics.active_article_count) &&
    isNonNegativeFiniteNumber(metrics.uae_related_item_count)
  );
}

function isDashboardSummary(value: unknown): value is DashboardSummary {
  if (typeof value !== "object" || value === null) {
    return false;
  }

  const summary = value as Record<string, unknown>;

  return (
    typeof summary.generated_at === "string" &&
    isDashboardSummaryMetrics(summary.metrics)
  );
}

export async function fetchDashboardSummary(
  signal?: AbortSignal,
): Promise<DashboardSummaryResult> {
  try {
    const response = await fetch(`${API_BASE_URL}/api/v1/dashboard/summary`, {
      cache: "no-store",
      headers: { Accept: "application/json" },
      signal,
    });

    if (!response.ok) {
      return { status: "error" };
    }

    const data: unknown = await response.json();

    if (!isDashboardSummary(data)) {
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
