"use client";

import { useEffect, useMemo, useState } from "react";

import { StatusBadge } from "@/components/dashboard/StatusBadge";
import { fetchDashboardTrends } from "@/services/dashboardTrendsApi";
import type { ArticleCategory, ArticleListItem } from "@/types/article";
import type { BadgeTone } from "@/types/dashboard";
import type { DashboardTrendsData } from "@/types/dashboardTrends";
import type {
  VulnerabilityListItem,
  VulnerabilitySeverity,
} from "@/types/vulnerability";

type TrendsState =
  | { status: "loading" }
  | { status: "success"; data: DashboardTrendsData }
  | { status: "error" };

type DistributionRow<T extends string> = {
  count: number;
  key: T;
  label: string;
  tone: BadgeTone;
};

type TimelineBucket = {
  articleCount: number;
  dateKey: string;
  label: string;
  vulnerabilityCount: number;
};

const severityRows: readonly Omit<
  DistributionRow<VulnerabilitySeverity>,
  "count"
>[] = [
  { key: "critical", label: "Critical", tone: "critical" },
  { key: "high", label: "High", tone: "warning" },
  { key: "medium", label: "Medium", tone: "info" },
  { key: "low", label: "Low", tone: "success" },
  { key: "none", label: "None", tone: "neutral" },
  { key: "unknown", label: "Unknown", tone: "neutral" },
] as const;

const categoryRows: readonly Omit<DistributionRow<ArticleCategory>, "count">[] = [
  { key: "security_advisory", label: "Security advisory", tone: "info" },
  { key: "cyber_news", label: "Cyber news", tone: "neutral" },
  { key: "threat_report", label: "Threat report", tone: "warning" },
  { key: "uae_official_alert", label: "UAE official alert", tone: "uae" },
  { key: "other_defensive_intel", label: "Other defensive intel", tone: "success" },
] as const;

function formatDate(value: string | null): string {
  if (!value) {
    return "Unknown";
  }

  const date = new Date(value);

  if (Number.isNaN(date.getTime())) {
    return "Unknown";
  }

  return new Intl.DateTimeFormat("en-CA", {
    day: "2-digit",
    month: "short",
    timeZone: "UTC",
    year: "numeric",
  }).format(date);
}

function toDateKey(value: string | null): string | null {
  if (!value) {
    return null;
  }

  const date = new Date(value);

  if (Number.isNaN(date.getTime())) {
    return null;
  }

  return date.toISOString().slice(0, 10);
}

function buildSeverityDistribution(
  vulnerabilities: readonly VulnerabilityListItem[],
): readonly DistributionRow<VulnerabilitySeverity>[] {
  return severityRows.map((row) => ({
    ...row,
    count: vulnerabilities.filter(
      (item) => (item.severity ?? "unknown") === row.key,
    ).length,
  }));
}

function buildCategoryDistribution(
  articles: readonly ArticleListItem[],
): readonly DistributionRow<ArticleCategory>[] {
  return categoryRows.map((row) => ({
    ...row,
    count: articles.filter((item) => item.category === row.key).length,
  }));
}

function buildTimelineBuckets(
  vulnerabilities: readonly VulnerabilityListItem[],
  articles: readonly ArticleListItem[],
): readonly TimelineBucket[] {
  const bucketMap = new Map<
    string,
    Pick<TimelineBucket, "articleCount" | "vulnerabilityCount">
  >();

  vulnerabilities.forEach((item) => {
    const key = toDateKey(item.source_published_at ?? item.last_seen_at);
    if (!key) {
      return;
    }

    const bucket = bucketMap.get(key) ?? { articleCount: 0, vulnerabilityCount: 0 };
    bucket.vulnerabilityCount += 1;
    bucketMap.set(key, bucket);
  });

  articles.forEach((item) => {
    const key = toDateKey(item.published_at ?? item.last_seen_at);
    if (!key) {
      return;
    }

    const bucket = bucketMap.get(key) ?? { articleCount: 0, vulnerabilityCount: 0 };
    bucket.articleCount += 1;
    bucketMap.set(key, bucket);
  });

  return Array.from(bucketMap.entries())
    .sort(([left], [right]) => right.localeCompare(left))
    .slice(0, 7)
    .reverse()
    .map(([dateKey, counts]) => ({
      ...counts,
      dateKey,
      label: formatDate(dateKey),
    }));
}

function maxCount(rows: readonly { count: number }[]): number {
  return Math.max(1, ...rows.map((row) => row.count));
}

function DistributionChart<T extends string>({
  rows,
  title,
}: Readonly<{
  rows: readonly DistributionRow<T>[];
  title: string;
}>) {
  const max = maxCount(rows);

  return (
    <div className="trendChartBlock">
      <h3>{title}</h3>
      <div className="trendBars">
        {rows.map((row) => {
          const percentage = row.count === 0 ? 0 : Math.max(8, (row.count / max) * 100);

          return (
            <div className="trendBarRow" key={row.key}>
              <div className="trendBarLabel">
                <StatusBadge label={row.label} tone={row.tone} />
                <span>{row.count.toLocaleString()}</span>
              </div>
              <div
                aria-label={`${row.label}: ${row.count.toLocaleString()} records`}
                className={`trendBarTrack trendBarTrack-${row.tone}`}
                role="img"
              >
                <span style={{ width: `${percentage}%` }} />
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}

function ActivityTimeline({
  buckets,
}: Readonly<{ buckets: readonly TimelineBucket[] }>) {
  const max = Math.max(
    1,
    ...buckets.map((bucket) => bucket.articleCount + bucket.vulnerabilityCount),
  );

  return (
    <div className="trendChartBlock">
      <h3>Recent stored activity timeline</h3>
      <div className="timelineList">
        {buckets.map((bucket) => {
          const total = bucket.articleCount + bucket.vulnerabilityCount;
          const percentage = total === 0 ? 0 : Math.max(8, (total / max) * 100);

          return (
            <div className="timelineRow" key={bucket.dateKey}>
              <div className="timelineDate">
                <strong>{bucket.label}</strong>
                <span>{total.toLocaleString()} records</span>
              </div>
              <div
                aria-label={`${bucket.label}: ${bucket.vulnerabilityCount.toLocaleString()} vulnerabilities and ${bucket.articleCount.toLocaleString()} articles`}
                className="timelineTrack"
                role="img"
              >
                <span style={{ width: `${percentage}%` }} />
              </div>
              <div className="timelineCounts">
                <span>{bucket.vulnerabilityCount.toLocaleString()} CVEs</span>
                <span>{bucket.articleCount.toLocaleString()} articles</span>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}

export function DashboardTrendsPanel() {
  const [state, setState] = useState<TrendsState>({ status: "loading" });

  useEffect(() => {
    const controller = new AbortController();

    async function loadTrends() {
      try {
        const result = await fetchDashboardTrends(controller.signal);

        if (result.status === "success") {
          setState({ status: "success", data: result.data });
          return;
        }

        setState({ status: "error" });
      } catch (error: unknown) {
        if (error instanceof DOMException && error.name === "AbortError") {
          return;
        }

        setState({ status: "error" });
      }
    }

    void loadTrends();

    return () => controller.abort();
  }, []);

  const trendData = useMemo(() => {
    if (state.status !== "success") {
      return null;
    }

    return {
      categoryDistribution: buildCategoryDistribution(state.data.articles),
      severityDistribution: buildSeverityDistribution(state.data.vulnerabilities),
      timelineBuckets: buildTimelineBuckets(
        state.data.vulnerabilities,
        state.data.articles,
      ),
    };
  }, [state]);

  if (state.status === "loading") {
    return (
      <div className="tableLoadingState" aria-busy="true" role="status">
        Loading stored trend data
      </div>
    );
  }

  if (state.status === "error") {
    return (
      <div className="emptyState" role="status">
        <p className="panelEyebrow">Backend data</p>
        <h3>Trends unavailable</h3>
        <p>
          Stored trend data could not be loaded right now. The dashboard remains
          usable while the backend or database is offline.
        </p>
      </div>
    );
  }

  if (
    state.data.vulnerabilities.length === 0 &&
    state.data.articles.length === 0
  ) {
    return (
      <div className="emptyState" role="status">
        <p className="panelEyebrow">No stored records</p>
        <h3>No trend data available</h3>
        <p>
          The chart will populate after stored vulnerabilities or articles are
          available from the read-only backend APIs.
        </p>
      </div>
    );
  }

  if (!trendData) {
    return null;
  }

  return (
    <div className="dashboardTrendsShell">
      <div className="trendSummaryStrip">
        <div>
          <span>{state.data.vulnerabilities.length.toLocaleString()}</span>
          <p>Latest CVEs sampled</p>
        </div>
        <div>
          <span>{state.data.articles.length.toLocaleString()}</span>
          <p>Latest articles sampled</p>
        </div>
        <div>
          <span>{state.data.criticalVulnerabilityCount.toLocaleString()}</span>
          <p>Critical CVEs in summary</p>
        </div>
        <div>
          <span>{state.data.activeArticleCount.toLocaleString()}</span>
          <p>Active articles in summary</p>
        </div>
      </div>

      <p className="trendScopeNote">
        Recent stored-data view using bounded latest API records. It is not a
        complete historical analytics module.
      </p>

      <div className="trendChartsGrid">
        <DistributionChart
          rows={trendData.severityDistribution}
          title="Latest vulnerability severity distribution"
        />
        <DistributionChart
          rows={trendData.categoryDistribution}
          title="Latest article category distribution"
        />
      </div>

      {trendData.timelineBuckets.length > 0 ? (
        <ActivityTimeline buckets={trendData.timelineBuckets} />
      ) : (
        <div className="emptyState" role="status">
          <p className="panelEyebrow">Timeline</p>
          <h3>No dated activity available</h3>
          <p>
            Recent records loaded, but none included a valid publication or
            last-seen date for timeline grouping.
          </p>
        </div>
      )}

      <p className="panelNote">Summary generated {formatDate(state.data.generatedAt)}.</p>
    </div>
  );
}
