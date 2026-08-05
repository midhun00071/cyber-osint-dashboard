"use client";

import { useEffect, useMemo, useState } from "react";
import Link from "next/link";
import { useParams } from "next/navigation";

import { SafeExternalLink } from "@/components/SafeExternalLink";
import { ProtectedRoute } from "@/components/auth/ProtectedRoute";
import { StatusBadge } from "@/components/dashboard/StatusBadge";
import { fetchVulnerabilityDetail } from "@/services/vulnerabilityApi";
import type {
  GeographicScope,
  KevStatus,
  UaeRelevanceStatus,
  VulnerabilityListItem,
  VulnerabilitySeverity,
} from "@/types/vulnerability";
import type { BadgeTone } from "@/types/dashboard";
import { formatUaeRelevanceWithConfidence } from "@/utils/uaeConfidence";

type DetailState =
  | { status: "loading" }
  | { status: "success"; data: VulnerabilityListItem }
  | { status: "not_found" }
  | { status: "error" };

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

function formatSeverity(severity: VulnerabilitySeverity | null): string {
  return severity ? severity.charAt(0).toUpperCase() + severity.slice(1) : "Unknown";
}

function severityTone(severity: VulnerabilitySeverity | null): BadgeTone {
  if (severity === "critical") {
    return "critical";
  }

  if (severity === "high") {
    return "warning";
  }

  if (severity === "medium") {
    return "info";
  }

  if (severity === "low" || severity === "none") {
    return "success";
  }

  return "neutral";
}

function kevLabel(status: KevStatus | null): string {
  if (status === "listed") {
    return "KEV listed";
  }

  if (status === "not_listed") {
    return "Not listed";
  }

  return "Unknown KEV status";
}

function kevTone(status: KevStatus | null): BadgeTone {
  if (status === "listed") {
    return "critical";
  }

  if (status === "not_listed") {
    return "success";
  }

  return "neutral";
}

function formatCvss(score: number | null, version: string | null): string {
  if (score === null) {
    return "Unknown";
  }

  return version ? `${score.toFixed(1)} / ${version}` : score.toFixed(1);
}

function formatEpss(score: number | null): string {
  return score === null ? "Unknown" : `${(score * 100).toFixed(2)}%`;
}

function formatPercentile(percentile: number | null): string {
  return percentile === null ? "Unknown" : `P${(percentile * 100).toFixed(1)}`;
}

function formatScope(scope: GeographicScope): string {
  return scope === "uae" ? "UAE" : scope.charAt(0).toUpperCase() + scope.slice(1);
}

function uaeRelevanceTone(status: UaeRelevanceStatus): BadgeTone {
  if (status === "confirmed" || status === "probable") {
    return "uae";
  }

  if (status === "possible") {
    return "info";
  }

  if (status === "not_relevant") {
    return "success";
  }

  return "neutral";
}

function formatRansomwareUse(value: boolean | null): string {
  if (value === true) {
    return "Known campaign use";
  }

  if (value === false) {
    return "No known campaign use";
  }

  return "Unknown";
}

function getPublicIdParam(value: string | string[] | undefined): string | null {
  if (typeof value !== "string") {
    return null;
  }

  const trimmed = value.trim();

  return trimmed || null;
}

function VulnerabilityDetailContent() {
  const params = useParams<{ publicId?: string | string[] }>();
  const publicId = useMemo(() => getPublicIdParam(params.publicId), [params]);
  const [state, setState] = useState<DetailState>({ status: "loading" });

  useEffect(() => {
    if (!publicId) {
      return;
    }

    const requestedPublicId = publicId;
    const controller = new AbortController();

    async function loadVulnerability() {
      setState({ status: "loading" });

      try {
        const result = await fetchVulnerabilityDetail(
          requestedPublicId,
          controller.signal,
        );

        if (result.status === "success") {
          setState({ status: "success", data: result.data });
          return;
        }

        if (result.status === "not_found") {
          setState({ status: "not_found" });
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

    void loadVulnerability();

    return () => controller.abort();
  }, [publicId]);

  if (!publicId || state.status === "not_found") {
    return (
      <main className="articleDetailPage">
        <div className="emptyState" role="status">
          <p className="panelEyebrow">Vulnerability detail</p>
          <h1>Vulnerability not found</h1>
          <p>
            The requested record is unavailable, inactive, or outside the safe
            vulnerability feed.
          </p>
          <Link className="safeSourceLink" href="/">
            Back to dashboard
          </Link>
        </div>
      </main>
    );
  }

  if (state.status === "loading") {
    return (
      <main className="articleDetailPage">
        <div className="tableLoadingState" aria-busy="true" role="status">
          Loading vulnerability details
        </div>
      </main>
    );
  }

  if (state.status === "error") {
    return (
      <main className="articleDetailPage">
        <div className="emptyState" role="status">
          <p className="panelEyebrow">Backend data</p>
          <h1>Vulnerability unavailable</h1>
          <p>
            Stored vulnerability details could not be loaded right now. Try
            again after the backend or database is available.
          </p>
          <Link className="safeSourceLink" href="/">
            Back to dashboard
          </Link>
        </div>
      </main>
    );
  }

  const item = state.data;
  const sourceLabel = item.source_name ?? item.source_slug ?? "Unknown source";

  return (
    <main className="articleDetailPage">
      <article className="articleDetailShell">
        <div className="articleDetailNav">
          <Link className="safeSourceLink" href="/">
            Back to dashboard
          </Link>
          <SafeExternalLink className="safeSourceLink" url={item.source_url}>
            Open source
          </SafeExternalLink>
        </div>

        <header className="articleDetailHero">
          <div className="articleFeedMeta">
            <StatusBadge label={formatSeverity(item.severity)} tone={severityTone(item.severity)} />
            <StatusBadge label={kevLabel(item.kev_status)} tone={kevTone(item.kev_status)} />
            <StatusBadge
              label={formatUaeRelevanceWithConfidence(
                item.uae_relevance_status,
                item.uae_relevance_confidence,
              ).label}
              tone={uaeRelevanceTone(item.uae_relevance_status)}
            />
          </div>
          <p className="pageKicker">Vulnerability detail</p>
          <h1>{item.cve_id ?? "Unassigned CVE"}</h1>
          <p className="pageSubtitle">{item.title}</p>
        </header>

        <section className="vulnerabilityDetailSummary" aria-label="Summary">
          <h2>Summary</h2>
          <p>{item.summary?.trim() || "No summary is available for this stored CVE."}</p>
        </section>

        <section className="articleDetailGrid" aria-label="Vulnerability metadata">
          <div>
            <span>CVSS</span>
            <strong>{formatCvss(item.cvss_score, item.cvss_version)}</strong>
          </div>
          <div>
            <span>EPSS score</span>
            <strong>{formatEpss(item.epss_score)}</strong>
          </div>
          <div>
            <span>EPSS percentile</span>
            <strong>{formatPercentile(item.epss_percentile)}</strong>
          </div>
          <div>
            <span>EPSS date</span>
            <strong>{formatDate(item.epss_score_date)}</strong>
          </div>
          <div>
            <span>KEV date added</span>
            <strong>{formatDate(item.kev_date_added)}</strong>
          </div>
          <div>
            <span>KEV due date</span>
            <strong>{formatDate(item.kev_due_date)}</strong>
          </div>
          <div>
            <span>Ransomware use</span>
            <strong>{formatRansomwareUse(item.known_ransomware_campaign_use)}</strong>
          </div>
          <div>
            <span>Affected systems</span>
            <strong>{item.affected_summary?.trim() || "Unknown"}</strong>
          </div>
          <div>
            <span>Source</span>
            <strong>{sourceLabel}</strong>
          </div>
          <div>
            <span>Published</span>
            <strong>{formatDate(item.source_published_at)}</strong>
          </div>
          <div>
            <span>Modified</span>
            <strong>{formatDate(item.source_modified_at)}</strong>
          </div>
          <div>
            <span>Last seen</span>
            <strong>{formatDate(item.last_seen_at)}</strong>
          </div>
          <div>
            <span>Geographic scope</span>
            <strong>{formatScope(item.geographic_scope)}</strong>
          </div>
          <div>
            <span>UAE relevance</span>
            <strong>
              {formatUaeRelevanceWithConfidence(
                item.uae_relevance_status,
                item.uae_relevance_confidence,
              ).label}
            </strong>
          </div>
        </section>
      </article>
    </main>
  );
}

export default function VulnerabilityDetailPage() {
  return <ProtectedRoute><VulnerabilityDetailContent /></ProtectedRoute>;
}
