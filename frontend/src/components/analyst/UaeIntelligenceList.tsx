"use client";

import { FormEvent, useEffect, useState } from "react";
import Link from "next/link";
import { SafeExternalLink } from "@/components/SafeExternalLink";
import { StatusBadge } from "@/components/dashboard/StatusBadge";
import { fetchUaeIntelligence } from "@/services/analystApi";
import { fetchSources } from "@/services/operationsApi";
import type { AnalystList, UaeIntelligenceItem } from "@/types/analyst";
import type { SourceSummary } from "@/types/operations";

type State = { status: "loading" | "error" } | { status: "success"; data: AnalystList<UaeIntelligenceItem> };

function date(value: string | null) { if (!value) return "Unknown"; const parsed = new Date(value); return Number.isNaN(parsed.getTime()) ? "Unknown" : parsed.toLocaleString("en-CA", { timeZone: "UTC" }); }
function sourceState(source: SourceSummary | undefined) { if (!source) return "State unavailable"; if (source.operator_state === "disabled") return "Disabled"; if (source.freshness === "never" && source.latest_run === null) return "Never run"; return `${source.freshness} · ${source.effective_state}`; }

export function UaeIntelligenceList() {
  const [input, setInput] = useState(""); const [query, setQuery] = useState(""); const [relevance, setRelevance] = useState(""); const [offset, setOffset] = useState(0);
  const [state, setState] = useState<State>({ status: "loading" });
  const [sourceStates, setSourceStates] = useState<Record<string, SourceSummary>>({});
  useEffect(() => { const controller = new AbortController(); void fetchSources(controller.signal).then((result) => { if (result.status === "success") setSourceStates(Object.fromEntries(result.data.items.map((source) => [source.slug, source]))); }); return () => controller.abort(); }, []);
  useEffect(() => { const controller = new AbortController(); setState({ status: "loading" }); void fetchUaeIntelligence(relevance, query, offset, controller.signal).then((result) => setState(result.status === "success" ? { status: "success", data: result.data } : { status: "error" })).catch((error: unknown) => { if (!(error instanceof DOMException && error.name === "AbortError")) setState({ status: "error" }); }); return () => controller.abort(); }, [offset, query, relevance]);
  function submit(event: FormEvent) { event.preventDefault(); setOffset(0); setQuery(input.trim()); }
  const items = state.status === "success" ? state.data.items : []; const total = state.status === "success" ? state.data.total : 0;
  return <div className="vulnerabilityTableShell"><form className="vulnerabilityFilters" onSubmit={submit}><label><span>Search UAE intelligence</span><input maxLength={120} onChange={(event) => setInput(event.target.value)} placeholder="Title, summary, or CVE" type="search" value={input} /></label><label><span>Evidence category</span><select onChange={(event) => { setRelevance(event.target.value); setOffset(0); }} value={relevance}><option value="">All categories</option><option value="direct">Direct UAE evidence</option><option value="potential">Potential UAE relevance</option><option value="global">Global relevance</option><option value="no_evidence">No demonstrated UAE relevance</option></select></label><div className="filterActions"><button type="submit">Apply</button><button onClick={() => { setInput(""); setQuery(""); setRelevance(""); setOffset(0); }} type="button">Clear</button></div></form>
    <p className="panelNote">Approved UAE authority evidence can automatically establish direct UAE evidence. Structured UAE scope is potential relevance, not automatic direct evidence. Protected reviewed or source-declared classification may remain.</p>
    {state.status === "loading" ? <div className="tableLoadingState" aria-busy="true" role="status">Loading UAE intelligence</div> : null}
    {state.status === "error" ? <div className="emptyState" role="status"><h3>UAE intelligence unavailable</h3><p>The bounded stored-data query could not be completed.</p></div> : null}
    {state.status === "success" && !items.length ? <div className="emptyState" role="status"><h3>No matching UAE intelligence</h3><p>No stored records match the selected evidence category and search.</p></div> : null}
    {items.length ? <div className="articleFeedList">{items.map((item) => <article className="articleFeedCard" key={item.public_id}><div className="articleFeedMeta"><StatusBadge label={item.relevance_label} tone={item.relevance_label === "Direct UAE evidence" ? "uae" : item.relevance_label === "Potential UAE relevance" ? "info" : "neutral"} />{item.severity ? <StatusBadge label={item.severity} tone="warning" /> : null}</div><h3><Link href={item.item_type === "vulnerability" ? `/vulnerabilities/${encodeURIComponent(item.public_id)}` : `/articles/${encodeURIComponent(item.public_id)}`}>{item.cve_id ?? item.title}</Link></h3><p>{item.summary ?? "No summary available."}</p><p><strong>Evidence:</strong> {item.relevance_reason ?? "No demonstrated UAE relevance evidence."} {item.relevance_confidence === null ? "Confidence not asserted." : `Confidence ${Math.round(item.relevance_confidence * 100)}%.`}</p>
      <div className="articleFeedMeta">{item.classification_tags.map((tag) => <span className="statusBadge statusBadge-neutral" title={tag.evidence} key={tag.slug}>{tag.label} · {Math.round(tag.confidence * 100)}%</span>)}</div>
      <dl className="articleMetadataGrid"><div><dt>Authority/source</dt><dd>{item.source_name ?? item.source_slug ?? "Unknown"}</dd></div><div><dt>Source state</dt><dd>{sourceState(item.source_slug ? sourceStates[item.source_slug] : undefined)}</dd></div><div><dt>Published</dt><dd>{date(item.published_at)}</dd></div><div><dt>Collected</dt><dd>{date(item.collected_at)}</dd></div><div><dt>Last seen</dt><dd>{date(item.last_seen_at)}</dd></div></dl><SafeExternalLink className="safeSourceLink" url={item.source_url}>Open source</SafeExternalLink></article>)}</div> : null}
    <div className="paginationControls"><p>Showing {total ? offset + 1 : 0}-{Math.min(offset + 25, total)} of {total}</p><div><button disabled={!offset || state.status === "loading"} onClick={() => setOffset(Math.max(0, offset - 25))} type="button">Previous</button><button disabled={state.status !== "success" || offset + 25 >= total} onClick={() => setOffset(offset + 25)} type="button">Next</button></div></div>
  </div>;
}
