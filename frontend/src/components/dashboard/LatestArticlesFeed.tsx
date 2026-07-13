"use client";

import { FormEvent, useEffect, useMemo, useState } from "react";
import Link from "next/link";

import { StatusBadge } from "@/components/dashboard/StatusBadge";
import { fetchArticles } from "@/services/articleApi";
import type {
  ArticleCategory,
  ArticleListResponse,
  GeographicScope,
  UaeRelevanceStatus,
} from "@/types/article";
import type { BadgeTone } from "@/types/dashboard";
import { formatUaeRelevanceWithConfidence } from "@/utils/uaeConfidence";

const categoryOptions: readonly {
  label: string;
  value: ArticleCategory | "";
}[] = [
  { label: "All categories", value: "" },
  { label: "Security advisory", value: "security_advisory" },
  { label: "Cyber news", value: "cyber_news" },
  { label: "Threat report", value: "threat_report" },
  { label: "UAE official alert", value: "uae_official_alert" },
  { label: "Other defensive intel", value: "other_defensive_intel" },
] as const;

const scopeOptions: readonly {
  label: string;
  value: GeographicScope | "";
}[] = [
  { label: "All scopes", value: "" },
  { label: "Global", value: "global" },
  { label: "Regional", value: "regional" },
  { label: "UAE", value: "uae" },
  { label: "Unknown", value: "unknown" },
] as const;

const limit = 6;

type FeedState =
  | { status: "loading" }
  | { status: "success"; data: ArticleListResponse }
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

function summarize(value: string | null): string {
  if (!value?.trim()) {
    return "No summary is available for this stored article.";
  }

  const normalized = value.trim().replace(/\s+/g, " ");

  return normalized.length > 220 ? `${normalized.slice(0, 217)}...` : normalized;
}

export function LatestArticlesFeed() {
  const [queryInput, setQueryInput] = useState("");
  const [query, setQuery] = useState("");
  const [category, setCategory] = useState<ArticleCategory | "">("");
  const [scope, setScope] = useState<GeographicScope | "">("");
  const [offset, setOffset] = useState(0);
  const [state, setState] = useState<FeedState>({ status: "loading" });

  useEffect(() => {
    const controller = new AbortController();

    async function loadArticles() {
      setState({ status: "loading" });

      try {
        const result = await fetchArticles(
          {
            category: category || undefined,
            geographic_scope: scope || undefined,
            limit,
            offset,
            q: query,
          },
          controller.signal,
        );

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

    void loadArticles();

    return () => controller.abort();
  }, [category, offset, query, scope]);

  const articles = useMemo(
    () => (state.status === "success" ? state.data.items : []),
    [state],
  );

  const total = state.status === "success" ? state.data.total : 0;
  const pageStart = total === 0 ? 0 : offset + 1;
  const pageEnd = state.status === "success" ? Math.min(offset + limit, total) : 0;
  const canGoBack = offset > 0 && state.status !== "loading";
  const canGoForward =
    state.status === "success" && offset + limit < state.data.total;

  function applyFilters(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setOffset(0);
    setQuery(queryInput.trim());
  }

  function clearFilters() {
    setQueryInput("");
    setQuery("");
    setCategory("");
    setScope("");
    setOffset(0);
  }

  return (
    <div className="articleFeedShell">
      <form className="articleFilters" onSubmit={applyFilters}>
        <label>
          <span>Search articles</span>
          <input
            maxLength={120}
            onChange={(event) => setQueryInput(event.target.value)}
            placeholder="Title or summary"
            type="search"
            value={queryInput}
          />
        </label>
        <label>
          <span>Category</span>
          <select
            onChange={(event) => {
              setCategory(event.target.value as ArticleCategory | "");
              setOffset(0);
            }}
            value={category}
          >
            {categoryOptions.map((option) => (
              <option key={option.label} value={option.value}>
                {option.label}
              </option>
            ))}
          </select>
        </label>
        <label>
          <span>Scope</span>
          <select
            onChange={(event) => {
              setScope(event.target.value as GeographicScope | "");
              setOffset(0);
            }}
            value={scope}
          >
            {scopeOptions.map((option) => (
              <option key={option.label} value={option.value}>
                {option.label}
              </option>
            ))}
          </select>
        </label>
        <div className="filterActions">
          <button type="submit">Apply</button>
          <button onClick={clearFilters} type="button">
            Clear
          </button>
        </div>
      </form>

      {state.status === "error" ? (
        <div className="emptyState" role="status">
          <p className="panelEyebrow">Backend data</p>
          <h3>Articles unavailable</h3>
          <p>
            Stored articles could not be loaded right now. The dashboard remains
            usable while the backend or database is offline.
          </p>
        </div>
      ) : null}

      {state.status === "success" && articles.length === 0 ? (
        <div className="emptyState" role="status">
          <p className="panelEyebrow">No matching articles</p>
          <h3>No articles found</h3>
          <p>Try a different search term, category, or scope filter.</p>
        </div>
      ) : null}

      {state.status !== "error" && articles.length > 0 ? (
        <div className="articleFeedList">
          {articles.map((article) => (
            <article className="articleFeedCard" key={article.public_id}>
              <div className="articleFeedMeta">
                <StatusBadge
                  label={formatCategory(article.category)}
                  tone="info"
                />
                <StatusBadge
                  label={formatUaeRelevanceWithConfidence(
                    article.uae_relevance_status,
                    article.uae_relevance_confidence,
                  ).label}
                  tone={uaeRelevanceTone(article.uae_relevance_status)}
                />
              </div>
              <h3>
                <Link href={`/articles/${encodeURIComponent(article.public_id)}`}>
                  {article.title}
                </Link>
              </h3>
              <p>{summarize(article.summary)}</p>
              <dl className="articleMetadataGrid">
                <div>
                  <dt>Source</dt>
                  <dd>{article.source_name ?? article.source_slug ?? "Unknown"}</dd>
                </div>
                <div>
                  <dt>Published</dt>
                  <dd>{formatDate(article.published_at)}</dd>
                </div>
                <div>
                  <dt>Updated</dt>
                  <dd>{formatDate(article.modified_at ?? article.last_seen_at)}</dd>
                </div>
                <div>
                  <dt>Scope</dt>
                  <dd>{formatScope(article.geographic_scope)}</dd>
                </div>
              </dl>
              <div className="articleActionRow">
                <Link
                  className="safeSourceLink"
                  href={`/articles/${encodeURIComponent(article.public_id)}`}
                >
                  View details
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
            </article>
          ))}
        </div>
      ) : null}

      {state.status === "loading" ? (
        <div className="tableLoadingState" aria-busy="true" role="status">
          Loading stored articles
        </div>
      ) : null}

      <div className="paginationControls" aria-label="Latest articles pagination">
        <p>
          Showing {pageStart}-{pageEnd} of {total.toLocaleString()} stored articles
        </p>
        <div>
          <button
            disabled={!canGoBack}
            onClick={() => setOffset(Math.max(0, offset - limit))}
            type="button"
          >
            Previous
          </button>
          <button
            disabled={!canGoForward}
            onClick={() => setOffset(offset + limit)}
            type="button"
          >
            Next
          </button>
        </div>
      </div>
    </div>
  );
}
