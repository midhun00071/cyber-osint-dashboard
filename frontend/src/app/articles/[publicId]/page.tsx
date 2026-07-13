"use client";

import { useEffect, useMemo, useState } from "react";
import Link from "next/link";
import { useParams } from "next/navigation";

import { StatusBadge } from "@/components/dashboard/StatusBadge";
import { fetchArticleDetail } from "@/services/articleApi";
import type {
  ArticleCategory,
  ArticleListItem,
  GeographicScope,
  UaeRelevanceStatus,
} from "@/types/article";
import type { BadgeTone } from "@/types/dashboard";
import { formatUaeRelevanceWithConfidence } from "@/utils/uaeConfidence";

type DetailState =
  | { status: "loading" }
  | { status: "success"; data: ArticleListItem }
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

function formatCategory(category: ArticleCategory): string {
  return category
    .split("_")
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
    .join(" ");
}

function formatScope(scope: GeographicScope): string {
  if (scope === "uae") {
    return "UAE";
  }

  return scope.charAt(0).toUpperCase() + scope.slice(1);
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

function isSafeExternalSourceUrl(value: string | null): value is string {
  if (!value) {
    return false;
  }

  try {
    return new URL(value).protocol === "https:";
  } catch {
    return false;
  }
}

function getPublicIdParam(value: string | string[] | undefined): string | null {
  if (typeof value !== "string") {
    return null;
  }

  const trimmed = value.trim();

  return trimmed || null;
}

export default function ArticleDetailPage() {
  const params = useParams<{ publicId?: string | string[] }>();
  const publicId = useMemo(() => getPublicIdParam(params.publicId), [params]);
  const [state, setState] = useState<DetailState>({ status: "loading" });

  useEffect(() => {
    if (!publicId) {
      return;
    }

    const requestedPublicId = publicId;
    const controller = new AbortController();

    async function loadArticle() {
      setState({ status: "loading" });

      try {
        const result = await fetchArticleDetail(requestedPublicId, controller.signal);

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

    void loadArticle();

    return () => controller.abort();
  }, [publicId]);

  if (!publicId || state.status === "not_found") {
    return (
      <main className="articleDetailPage">
        <div className="emptyState" role="status">
          <p className="panelEyebrow">Article detail</p>
          <h1>Article not found</h1>
          <p>
            The requested article is unavailable, inactive, or outside the safe
            article feed.
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
          Loading article details
        </div>
      </main>
    );
  }

  if (state.status === "error") {
    return (
      <main className="articleDetailPage">
        <div className="emptyState" role="status">
          <p className="panelEyebrow">Backend data</p>
          <h1>Article unavailable</h1>
          <p>
            Stored article details could not be loaded right now. Try again
            after the backend or database is available.
          </p>
          <Link className="safeSourceLink" href="/">
            Back to dashboard
          </Link>
        </div>
      </main>
    );
  }

  const article = state.data;
  const sourceLabel = article.source_name ?? article.source_slug ?? "Unknown source";

  return (
    <main className="articleDetailPage">
      <article className="articleDetailShell">
        <div className="articleDetailNav">
          <Link className="safeSourceLink" href="/">
            Back to dashboard
          </Link>
          {isSafeExternalSourceUrl(article.source_url) ? (
            <a
              className="safeSourceLink"
              href={article.source_url}
              rel="noreferrer noopener"
              target="_blank"
            >
              Open source
            </a>
          ) : null}
        </div>

        <header className="articleDetailHero">
          <div className="articleFeedMeta">
            <StatusBadge label={formatCategory(article.category)} tone="info" />
            <StatusBadge
              label={formatUaeRelevanceWithConfidence(
                article.uae_relevance_status,
                article.uae_relevance_confidence,
              ).label}
              tone={uaeRelevanceTone(article.uae_relevance_status)}
            />
          </div>
          <p className="pageKicker">Article detail</p>
          <h1>{article.title}</h1>
          <p className="pageSubtitle">
            {article.summary?.trim() || "No summary is available for this stored article."}
          </p>
        </header>

        <section className="articleDetailGrid" aria-label="Article metadata">
          <div>
            <span>Source</span>
            <strong>{sourceLabel}</strong>
          </div>
          <div>
            <span>Published</span>
            <strong>{formatDate(article.published_at)}</strong>
          </div>
          <div>
            <span>Modified</span>
            <strong>{formatDate(article.modified_at)}</strong>
          </div>
          <div>
            <span>Last seen</span>
            <strong>{formatDate(article.last_seen_at)}</strong>
          </div>
          <div>
            <span>Geographic scope</span>
            <strong>{formatScope(article.geographic_scope)}</strong>
          </div>
          <div>
            <span>UAE relevance</span>
            <strong>
              {formatUaeRelevanceWithConfidence(
                article.uae_relevance_status,
                article.uae_relevance_confidence,
              ).label}
            </strong>
          </div>
        </section>
      </article>
    </main>
  );
}
