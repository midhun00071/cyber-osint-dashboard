"use client";

import { FormEvent, Suspense, useEffect, useMemo, useState } from "react";
import Link from "next/link";
import { useSearchParams } from "next/navigation";

import { StatusBadge } from "@/components/dashboard/StatusBadge";
import { fetchVulnerabilities } from "@/services/vulnerabilityApi";
import type { BadgeTone } from "@/types/dashboard";
import type {
  GeographicScope,
  KevStatus,
  UaeRelevanceStatus,
  VulnerabilityListResponse,
  VulnerabilitySeverity,
} from "@/types/vulnerability";
import { buildDetailHref } from "@/utils/detailNavigation";

const severityOptions: readonly {
  label: string;
  value: VulnerabilitySeverity | "";
}[] = [
  { label: "All severities", value: "" },
  { label: "Critical", value: "critical" },
  { label: "High", value: "high" },
  { label: "Medium", value: "medium" },
  { label: "Low", value: "low" },
  { label: "None", value: "none" },
  { label: "Unknown", value: "unknown" },
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

const limitOptions = [10, 25, 50] as const;
const currentUtcYear = new Date().getUTCFullYear();
const publishedYearOptions = Array.from(
  { length: currentUtcYear - 2019 },
  (_value, index) => currentUtcYear - index,
);

type TableState =
  | { status: "loading" }
  | { status: "success"; data: VulnerabilityListResponse }
  | { status: "error" };

type InitialTableState = Readonly<{
  limit: number;
  offset: number;
  publishedYear: number | "";
  query: string;
  relevance: UaeRelevanceStatus | "";
  scope: GeographicScope | "";
  severity: VulnerabilitySeverity | "";
}>;

function initialTableState(originPath: "/" | "/vulnerabilities", search: string): InitialTableState {
  if (originPath === "/") {
    return { limit: 10, offset: 0, publishedYear: "", query: "", relevance: "", scope: "", severity: "" };
  }
  const params = new URLSearchParams(search);
  const parsedLimit = Number(params.get("limit"));
  const parsedOffset = Number(params.get("offset"));
  const parsedYear = Number(params.get("year"));
  return {
    limit: limitOptions.includes(parsedLimit as (typeof limitOptions)[number]) ? parsedLimit : 10,
    offset: Number.isSafeInteger(parsedOffset) && parsedOffset >= 0 ? parsedOffset : 0,
    publishedYear: publishedYearOptions.includes(parsedYear) ? parsedYear : "",
    query: (params.get("q") ?? "").slice(0, 120),
    relevance: relevanceOptions.some((option) => option.value === params.get("relevance"))
      ? params.get("relevance") as UaeRelevanceStatus
      : "",
    scope: scopeOptions.some((option) => option.value === params.get("scope"))
      ? params.get("scope") as GeographicScope
      : "",
    severity: severityOptions.some((option) => option.value === params.get("severity"))
      ? params.get("severity") as VulnerabilitySeverity
      : "",
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

function formatCvss(score: number | null, version: string | null): string {
  if (score === null) {
    return "Unknown";
  }

  return version ? `${score.toFixed(1)} / ${version}` : score.toFixed(1);
}

function formatEpss(score: number | null, percentile: number | null): string {
  if (score === null && percentile === null) {
    return "Unknown";
  }

  if (score !== null && percentile !== null) {
    return `${(score * 100).toFixed(2)}% / P${(percentile * 100).toFixed(1)}`;
  }

  if (score !== null) {
    return `${(score * 100).toFixed(2)}%`;
  }

  if (percentile !== null) {
    return `P${(percentile * 100).toFixed(1)}`;
  }

  return "Unknown";
}

function severityLabel(severity: VulnerabilitySeverity | null): string {
  if (!severity) {
    return "Unknown";
  }

  return severity.charAt(0).toUpperCase() + severity.slice(1).replace("_", " ");
}

function kevLabel(status: KevStatus | null): string {
  if (status === "listed") {
    return "KEV listed";
  }

  if (status === "not_listed") {
    return "Not listed";
  }

  return "Unknown";
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

function kevTone(status: KevStatus | null): BadgeTone {
  if (status === "listed") {
    return "critical";
  }

  if (status === "not_listed") {
    return "success";
  }

  return "neutral";
}

function VulnerabilitiesTableContent({ originPath = "/vulnerabilities" }: Readonly<{ originPath?: "/" | "/vulnerabilities" }>) {
  const routeSearch = useSearchParams().toString();
  const initial = useMemo(() => initialTableState(originPath, routeSearch), [originPath, routeSearch]);
  const [queryInput, setQueryInput] = useState(initial.query);
  const [query, setQuery] = useState(initial.query);
  const [severity, setSeverity] = useState<VulnerabilitySeverity | "">(initial.severity);
  const [publishedYearInput, setPublishedYearInput] = useState<number | "">(initial.publishedYear);
  const [publishedYear, setPublishedYear] = useState<number | "">(initial.publishedYear);
  const [scope, setScope] = useState<GeographicScope | "">(initial.scope);
  const [relevance, setRelevance] = useState<UaeRelevanceStatus | "">(initial.relevance);
  const [limit, setLimit] = useState<number>(initial.limit);
  const [offset, setOffset] = useState(initial.offset);
  const [state, setState] = useState<TableState>({ status: "loading" });

  useEffect(() => {
    const controller = new AbortController();

    async function loadVulnerabilities() {
      setState({ status: "loading" });

      try {
        const result = await fetchVulnerabilities(
          {
            geographic_scope: scope || undefined,
            limit,
            offset,
            published_year: publishedYear || undefined,
            q: query,
            severity: severity || undefined,
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

    void loadVulnerabilities();

    return () => controller.abort();
  }, [limit, offset, publishedYear, query, relevance, scope, severity]);

  const total = state.status === "success" ? state.data.total : 0;
  const pageStart = total === 0 ? 0 : offset + 1;
  const pageEnd = state.status === "success" ? Math.min(offset + limit, total) : 0;
  const canGoBack = offset > 0 && state.status !== "loading";
  const canGoForward =
    state.status === "success" && offset + limit < state.data.total;

  const tableRows = useMemo(
    () => (state.status === "success" ? state.data.items : []),
    [state],
  );

  function applyFilters(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setOffset(0);
    setPublishedYear(publishedYearInput);
    setQuery(queryInput.trim());
  }

  function clearFilters() {
    setQueryInput("");
    setQuery("");
    setSeverity("");
    setPublishedYearInput("");
    setPublishedYear("");
    setScope("");
    setRelevance("");
    setOffset(0);
  }

  const hasActiveFilters =
    query !== "" ||
    severity !== "" ||
    publishedYear !== "" ||
    scope !== "" ||
    relevance !== "";

  const returnPath = useMemo(() => {
    if (originPath === "/") return "/";
    const params = new URLSearchParams();
    if (query) params.set("q", query);
    if (severity) params.set("severity", severity);
    if (publishedYear) params.set("year", String(publishedYear));
    if (scope) params.set("scope", scope);
    if (relevance) params.set("relevance", relevance);
    if (limit !== 10) params.set("limit", String(limit));
    if (offset) params.set("offset", String(offset));
    const search = params.toString();
    return `/vulnerabilities${search ? `?${search}` : ""}`;
  }, [limit, offset, originPath, publishedYear, query, relevance, scope, severity]);

  return (
    <div className="vulnerabilityTableShell">
      <form className="vulnerabilityFilters" onSubmit={applyFilters}>
        <label>
          <span>Search CVEs</span>
          <input
            id="vulnerability-search"
            maxLength={120}
            name="vulnerability_search"
            onChange={(event) => setQueryInput(event.target.value)}
            placeholder="CVE ID, title, or summary"
            type="search"
            value={queryInput}
          />
        </label>
        <label>
          <span>Severity</span>
          <select
            id="vulnerability-severity"
            name="vulnerability_severity"
            onChange={(event) => {
              setSeverity(event.target.value as VulnerabilitySeverity | "");
              setOffset(0);
            }}
            value={severity}
          >
            {severityOptions.map((option) => (
              <option key={option.label} value={option.value}>
                {option.label}
              </option>
            ))}
          </select>
        </label>
        <label>
          <span>Publication year</span>
          <select
            id="vulnerability-year"
            name="vulnerability_year"
            onChange={(event) => {
              const value = event.target.value;
              setPublishedYearInput(value ? Number(value) : "");
            }}
            value={publishedYearInput}
          >
            <option value="">All years</option>
            {publishedYearOptions.map((year) => (
              <option key={year} value={year}>
                {year}
              </option>
            ))}
          </select>
        </label>
        <label>
          <span>Geographic scope</span>
          <select
            id="vulnerability-scope"
            name="vulnerability_scope"
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
          <span>UAE relevance</span>
          <select
            id="vulnerability-relevance"
            name="vulnerability_relevance"
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
        <label>
          <span>Rows</span>
          <select
            id="vulnerability-row-limit"
            name="vulnerability_row_limit"
            onChange={(event) => {
              setLimit(Number(event.target.value));
              setOffset(0);
            }}
            value={limit}
          >
            {limitOptions.map((option) => (
              <option key={option} value={option}>
                {option}
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
          <h3>Vulnerabilities unavailable</h3>
          <p>
            Stored CVEs could not be loaded right now. The dashboard remains
            usable while the backend or database is offline.
          </p>
        </div>
      ) : null}

      {state.status === "success" && tableRows.length === 0 ? (
        <div className="emptyState" role="status">
          <p className="panelEyebrow">
            {hasActiveFilters ? "No matching CVEs" : "No stored CVEs"}
          </p>
          <h3>
            {hasActiveFilters
              ? "No vulnerabilities match the selected filters"
              : "No vulnerabilities found"}
          </h3>
          <p>
            {hasActiveFilters
              ? "Try a different search term, severity, publication year, scope, or UAE relevance filter."
              : "Stored vulnerability records will appear here after manual ingestion writes them to the database."}
          </p>
        </div>
      ) : null}

      {state.status !== "error" && tableRows.length > 0 ? (
        <div className="vulnerabilityTableScroller">
          <table className="vulnerabilityTable">
            <thead>
              <tr>
                <th scope="col">CVE</th>
                <th scope="col">Severity</th>
                <th scope="col">CVSS</th>
                <th scope="col">EPSS</th>
                <th scope="col">KEV</th>
                <th scope="col">Published</th>
                <th scope="col">Source</th>
              </tr>
            </thead>
            <tbody>
              {tableRows.map((item) => (
                <tr key={item.public_id}>
                  <td>
                    <strong>
                      <Link href={buildDetailHref(`/vulnerabilities/${encodeURIComponent(item.public_id)}`, returnPath)}>
                        {item.cve_id ?? "Unassigned CVE"}
                      </Link>
                    </strong>
                    <span>{item.title}</span>
                    <small>
                      <Link href={buildDetailHref(`/vulnerabilities/${encodeURIComponent(item.public_id)}`, returnPath)}>
                        Open vulnerability detail
                      </Link>
                    </small>
                  </td>
                  <td>
                    <StatusBadge
                      label={severityLabel(item.severity)}
                      tone={severityTone(item.severity)}
                    />
                  </td>
                  <td>{formatCvss(item.cvss_score, item.cvss_version)}</td>
                  <td>
                    <span>{formatEpss(item.epss_score, item.epss_percentile)}</span>
                    <small>{item.epss_score_date ?? "No score date"}</small>
                  </td>
                  <td>
                    <StatusBadge
                      label={kevLabel(item.kev_status)}
                      tone={kevTone(item.kev_status)}
                    />
                  </td>
                  <td>
                    <span>{formatDate(item.source_published_at)}</span>
                    <small>Modified {formatDate(item.source_modified_at)}</small>
                  </td>
                  <td>
                    <span>{item.source_name ?? item.source_slug ?? "Unknown source"}</span>
                    <small>Last seen {formatDate(item.last_seen_at)}</small>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : null}

      {state.status === "loading" ? (
        <div className="tableLoadingState" aria-busy="true" role="status">
          Loading stored vulnerabilities
        </div>
      ) : null}

      <div className="paginationControls" aria-label="Vulnerability table pagination">
        <p>
          Showing {pageStart}-{pageEnd} of {total.toLocaleString()} stored CVEs
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

export function VulnerabilitiesTable(props: Readonly<{ originPath?: "/" | "/vulnerabilities" }>) {
  return (
    <Suspense fallback={<div className="tableLoadingState" aria-busy="true" role="status">Loading stored vulnerabilities</div>}>
      <VulnerabilitiesTableContent {...props} />
    </Suspense>
  );
}
