"use client";

import { FormEvent, Suspense, useEffect, useMemo, useState } from "react";
import Link from "next/link";
import { useSearchParams } from "next/navigation";

import { SafeExternalLink } from "@/components/SafeExternalLink";
import { StatusBadge } from "@/components/dashboard/StatusBadge";
import { fetchArticles } from "@/services/articleApi";
import type {
  ArticleCategory,
  ArticleListResponse,
  GeographicScope,
  ListSort,
  UaeRelevanceStatus,
} from "@/types/article";
import type { BadgeTone } from "@/types/dashboard";
import { buildDetailHref } from "@/utils/detailNavigation";
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
  { label: "UAE", value: "uae" },
  { label: "Regional", value: "regional" },
  { label: "Global", value: "global" },
  { label: "Unknown", value: "unknown" },
] as const;

const relevanceOptions: readonly {
  label: string;
  value: UaeRelevanceStatus | "";
}[] = [
  { label: "All relevance statuses", value: "" },
  { label: "Confirmed", value: "confirmed" },
  { label: "Probable", value: "probable" },
  { label: "Possible", value: "possible" },
  { label: "Not relevant", value: "not_relevant" },
  { label: "Unknown", value: "unknown" },
] as const;

const sourceOptions = [
  { label: "All sources", value: "" },
  {
    label: "CERT-EU Security Advisories",
    value: "cert-eu-security-advisories",
  },
  { label: "Censys ARC Research", value: "censys-arc-research" },
  {
    label: "Censys Rapid Response Advisories",
    value: "censys-rapid-response-advisories",
  },
  { label: "Anomali Cyber Watch", value: "anomali-cyber-watch" },
  {
    label: "IBM X-Force Public Research",
    value: "ibm-x-force-public-research",
  },
  {
    label: "IBM X-Force Public OSINT Advisories",
    value: "ibm-x-force-public-osint-advisories",
  },
  {
    label: "Google Threat Intelligence Public Research",
    value: "google-threat-intelligence-public-research",
  },
  {
    label: "Mandiant Public Threat Research",
    value: "mandiant-public-threat-research",
  },
] as const;

const limit = 6;
const sortOptions: readonly { label: string; value: ListSort }[] = [
  { label: "Recently ingested", value: "recently_ingested" },
  { label: "Newest published", value: "newest_published" },
  { label: "Oldest published", value: "oldest_published" },
] as const;

type FeedState =
  | { status: "loading" }
  | { status: "success"; data: ArticleListResponse }
  | { status: "error" };

type InitialFeedState = Readonly<{
  category: ArticleCategory | "";
  offset: number;
  query: string;
  relevance: UaeRelevanceStatus | "";
  scope: GeographicScope | "";
  source: string;
  sort: ListSort;
}>;

function initialFeedState(originPath: "/" | "/threat-feed", search: string): InitialFeedState {
  if (originPath === "/") {
    return { category: "", offset: 0, query: "", relevance: "", scope: "", source: "", sort: "recently_ingested" };
  }
  const params = new URLSearchParams(search);
  const category = categoryOptions.some((option) => option.value === params.get("category"))
    ? params.get("category") as ArticleCategory
    : "";
  const scope = scopeOptions.some((option) => option.value === params.get("scope"))
    ? params.get("scope") as GeographicScope
    : "";
  const relevance = relevanceOptions.some((option) => option.value === params.get("relevance"))
    ? params.get("relevance") as UaeRelevanceStatus
    : "";
  const source = sourceOptions.some((option) => option.value === params.get("source"))
    ? params.get("source") ?? ""
    : "";
  const parsedOffset = Number(params.get("offset"));
  return {
    category,
    offset: Number.isSafeInteger(parsedOffset) && parsedOffset >= 0 ? parsedOffset : 0,
    query: (params.get("q") ?? "").slice(0, 120),
    relevance,
    scope,
    source,
    sort: sortOptions.some((option) => option.value === params.get("sort"))
      ? params.get("sort") as ListSort
      : "recently_ingested",
  };
}

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

function summarize(value: string | null): string {
  if (!value?.trim()) {
    return "No summary is available for this stored article.";
  }

  const normalized = value.trim().replace(/\s+/g, " ");

  return normalized.length > 220 ? `${normalized.slice(0, 217)}...` : normalized;
}

function LatestArticlesFeedContent({ originPath = "/threat-feed" }: Readonly<{ originPath?: "/" | "/threat-feed" }>) {
  const routeSearch = useSearchParams().toString();
  const initial = useMemo(() => initialFeedState(originPath, routeSearch), [originPath, routeSearch]);
  const [queryInput, setQueryInput] = useState(initial.query);
  const [query, setQuery] = useState(initial.query);
  const [category, setCategory] = useState<ArticleCategory | "">(initial.category);
  const [sourceInput, setSourceInput] = useState(initial.source);
  const [source, setSource] = useState(initial.source);
  const [scope, setScope] = useState<GeographicScope | "">(initial.scope);
  const [relevance, setRelevance] = useState<UaeRelevanceStatus | "">(initial.relevance);
  const [offset, setOffset] = useState(initial.offset);
  const [sort, setSort] = useState<ListSort>(initial.sort);
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
            source_slug: source || undefined,
            sort,
            uae_relevance_status: relevance || undefined,
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
  }, [category, offset, query, relevance, scope, source, sort]);

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
    setSource(sourceInput);
  }

  function clearFilters() {
    setQueryInput("");
    setQuery("");
    setCategory("");
    setSourceInput("");
    setSource("");
    setScope("");
    setRelevance("");
    setOffset(0);
  }

  const hasActiveFilters =
    query !== "" ||
    category !== "" ||
    source !== "" ||
    scope !== "" ||
    relevance !== "";

  const returnPath = useMemo(() => {
    if (originPath === "/") return "/";
    const params = new URLSearchParams();
    if (query) params.set("q", query);
    if (category) params.set("category", category);
    if (source) params.set("source", source);
    if (scope) params.set("scope", scope);
    if (relevance) params.set("relevance", relevance);
    if (offset) params.set("offset", String(offset));
    if (sort !== "recently_ingested") params.set("sort", sort);
    const search = params.toString();
    return `/threat-feed${search ? `?${search}` : ""}`;
  }, [category, offset, originPath, query, relevance, scope, source, sort]);

  return (
    <div className="articleFeedShell">
      <form className="articleFilters" onSubmit={applyFilters}>
        <label>
          <span>Search articles</span>
          <input
            id="article-search"
            maxLength={120}
            name="article_search"
            onChange={(event) => setQueryInput(event.target.value)}
            placeholder="Title or summary"
            type="search"
            value={queryInput}
          />
        </label>
        <label>
          <span>Category</span>
          <select
            id="article-category"
            name="article_category"
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
          <span>Source</span>
          <select
            id="article-source"
            name="article_source"
            onChange={(event) => setSourceInput(event.target.value)}
            value={sourceInput}
          >
            {sourceOptions.map((option) => (
              <option key={option.label} value={option.value}>
                {option.label}
              </option>
            ))}
          </select>
        </label>
        <label>
          <span>Geographic scope</span>
          <select
            id="article-scope"
            name="article_scope"
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
        <label>
          <span>Sort</span>
          <select
            id="article-sort"
            name="article_sort"
            onChange={(event) => {
              setSort(event.target.value as ListSort);
              setOffset(0);
            }}
            value={sort}
          >
            {sortOptions.map((option) => (
              <option key={option.value} value={option.value}>
                {option.label}
              </option>
            ))}
          </select>
        </label>
        <label>
          <span>UAE relevance</span>
          <select
            id="article-relevance"
            name="article_relevance"
            onChange={(event) => {
              setRelevance(event.target.value as UaeRelevanceStatus | "");
              setOffset(0);
            }}
            value={relevance}
          >
            {relevanceOptions.map((option) => (
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
          <p className="panelEyebrow">
            {hasActiveFilters ? "No matching articles" : "No stored articles"}
          </p>
          <h3>
            {hasActiveFilters
              ? "No articles match the selected filters"
              : "No articles found"}
          </h3>
          <p>
            {hasActiveFilters
              ? "Try a different search term, category, source, scope, or UAE relevance filter."
              : "Stored article records will appear here after manual ingestion writes them to the database."}
          </p>
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
                <Link href={buildDetailHref(`/articles/${encodeURIComponent(article.public_id)}`, returnPath)}>
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
                  href={buildDetailHref(`/articles/${encodeURIComponent(article.public_id)}`, returnPath)}
                >
                  View details
                </Link>
                <SafeExternalLink
                  className="safeSourceLink"
                  url={article.source_url}
                >
                  Open source
                </SafeExternalLink>
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

export function LatestArticlesFeed(props: Readonly<{ originPath?: "/" | "/threat-feed" }>) {
  return (
    <Suspense fallback={<div className="tableLoadingState" aria-busy="true" role="status">Loading stored articles</div>}>
      <LatestArticlesFeedContent {...props} />
    </Suspense>
  );
}
