"use client";

import { FormEvent, useEffect, useState } from "react";
import { fetchIndicators } from "@/services/analystApi";
import type { AnalystList, Indicator } from "@/types/analyst";

type State = { status: "idle" | "loading" | "error" } | { status: "success"; data: AnalystList<Indicator> };

export function IndicatorSearch() {
  const [input, setInput] = useState(""); const [query, setQuery] = useState(""); const [offset, setOffset] = useState(0);
  const [state, setState] = useState<State>({ status: "idle" });
  useEffect(() => {
    if (!query) { setState({ status: "idle" }); return; }
    const controller = new AbortController(); setState({ status: "loading" });
    void fetchIndicators(query, offset, controller.signal).then((result) => setState(result.status === "success" ? { status: "success", data: result.data } : { status: "error" })).catch((error: unknown) => { if (!(error instanceof DOMException && error.name === "AbortError")) setState({ status: "error" }); });
    return () => controller.abort();
  }, [offset, query]);
  function submit(event: FormEvent) { event.preventDefault(); const value = input.trim(); if (value.length >= 2) { setOffset(0); setQuery(value); } }
  const items = state.status === "success" ? state.data.items : []; const total = state.status === "success" ? state.data.total : 0;
  return <div className="vulnerabilityTableShell"><form className="vulnerabilityFilters" onSubmit={submit}><label><span>Indicator value</span><input minLength={2} maxLength={120} onChange={(event) => setInput(event.target.value)} placeholder="IPv4, IPv6, domain, URL, or file hash" required type="search" value={input} /></label><div className="filterActions"><button type="submit">Search stored indicators</button><button onClick={() => { setInput(""); setQuery(""); setOffset(0); }} type="button">Clear</button></div></form>
    {state.status === "idle" ? <div className="emptyState" role="status"><h3>Enter an indicator to search</h3><p>Searches are authenticated, rate limited, and restricted to normalized stored metadata. No network probing is performed.</p></div> : null}
    {state.status === "loading" ? <div className="tableLoadingState" aria-busy="true" role="status">Searching stored indicators</div> : null}
    {state.status === "error" ? <div className="emptyState" role="status"><h3>Indicator search unavailable</h3><p>The bounded stored-data query could not be completed.</p></div> : null}
    {state.status === "success" && !items.length ? <div className="emptyState" role="status"><h3>No stored indicators match</h3><p>No active normalized indicator matched the search value.</p></div> : null}
    {items.length ? <div className="vulnerabilityTableScroller"><table className="vulnerabilityTable"><thead><tr><th>Indicator</th><th>Type</th><th>Status</th><th>Confidence</th><th>Provenance</th><th>Publications</th></tr></thead><tbody>{items.map((item) => <tr key={item.public_id}><td><strong>{item.normalized_value}</strong><span>{item.context_summary ?? "No context summary"}</span></td><td>{item.observable_type.replaceAll("_", " ")}</td><td>{item.status.replaceAll("_", " ")}</td><td>{item.confidence === null ? "Not asserted" : `${Math.round(item.confidence * 100)}%`}</td><td>{item.provenance_count}</td><td>{item.publication_count}</td></tr>)}</tbody></table></div> : null}
    {query ? <div className="paginationControls"><p>Showing {total ? offset + 1 : 0}-{Math.min(offset + 25, total)} of {total}</p><div><button disabled={!offset || state.status === "loading"} onClick={() => setOffset(Math.max(0, offset - 25))} type="button">Previous</button><button disabled={state.status !== "success" || offset + 25 >= total} onClick={() => setOffset(offset + 25)} type="button">Next</button></div></div> : null}
  </div>;
}
