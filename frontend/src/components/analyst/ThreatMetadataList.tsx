"use client";

import { FormEvent, useEffect, useState } from "react";
import { SafeExternalLink } from "@/components/SafeExternalLink";
import { StatusBadge } from "@/components/dashboard/StatusBadge";
import { fetchThreatEntities } from "@/services/analystApi";
import type { AnalystList, ThreatEntity } from "@/types/analyst";

type State = { status: "loading" } | { status: "error" } | { status: "success"; data: AnalystList<ThreatEntity> };

export function ThreatMetadataList() {
  const [input, setInput] = useState("");
  const [query, setQuery] = useState("");
  const [offset, setOffset] = useState(0);
  const [state, setState] = useState<State>({ status: "loading" });

  useEffect(() => {
    const controller = new AbortController();
    setState({ status: "loading" });
    void fetchThreatEntities(query, offset, controller.signal).then((result) => {
      if (result.status === "success") setState({ status: "success", data: result.data });
      else setState({ status: "error" });
    }).catch((error: unknown) => {
      if (!(error instanceof DOMException && error.name === "AbortError")) setState({ status: "error" });
    });
    return () => controller.abort();
  }, [offset, query]);

  function submit(event: FormEvent) {
    event.preventDefault(); setOffset(0); setQuery(input.trim());
  }

  const items = state.status === "success" ? state.data.items : [];
  const total = state.status === "success" ? state.data.total : 0;
  return <div className="vulnerabilityTableShell">
    <form className="vulnerabilityFilters" onSubmit={submit}>
      <label><span>Search threat metadata</span><input maxLength={120} onChange={(event) => setInput(event.target.value)} placeholder="Name, alias, or ATT&CK ID" type="search" value={input} /></label>
      <div className="filterActions"><button type="submit">Apply</button><button onClick={() => { setInput(""); setQuery(""); setOffset(0); }} type="button">Clear</button></div>
    </form>
    {state.status === "loading" ? <div className="tableLoadingState" aria-busy="true" role="status">Loading stored threat metadata</div> : null}
    {state.status === "error" ? <div className="emptyState" role="status"><h3>Threat metadata unavailable</h3><p>The bounded stored-data query could not be completed.</p></div> : null}
    {state.status === "success" && items.length === 0 ? <div className="emptyState" role="status"><h3>No threat metadata found</h3><p>{query ? "No entities match this search." : "Validated threat entities will appear after an approved offline import."}</p></div> : null}
    {items.length ? <div className="articleFeedList">{items.map((item) => <article className="articleFeedCard" key={item.public_id}>
      <div className="articleFeedMeta"><StatusBadge label={item.entity_type.replaceAll("_", " ")} tone="info" />{item.attack_id ? <StatusBadge label={item.attack_id} tone="neutral" /> : null}</div>
      <h3>{item.name}</h3><p>{item.aliases.length ? `Aliases: ${item.aliases.join(", ")}` : "No aliases recorded."}</p>
      <dl className="articleMetadataGrid"><div><dt>Source</dt><dd>{item.source_name}</dd></div><div><dt>Confidence</dt><dd>{item.confidence === null ? "Not asserted" : `${Math.round(item.confidence * 100)}%`}</dd></div><div><dt>STIX modified</dt><dd>{new Date(item.stix_modified_at).toLocaleDateString("en-CA", { timeZone: "UTC" })}</dd></div><div><dt>Content SHA-256</dt><dd>{item.content_sha256 ?? "Unavailable"}</dd></div></dl>
      <SafeExternalLink className="safeSourceLink" url={item.source_url}>Open source</SafeExternalLink>
    </article>)}</div> : null}
    <div className="paginationControls"><p>Showing {total ? offset + 1 : 0}-{Math.min(offset + 25, total)} of {total}</p><div><button disabled={offset === 0 || state.status === "loading"} onClick={() => setOffset(Math.max(0, offset - 25))} type="button">Previous</button><button disabled={state.status !== "success" || offset + 25 >= total} onClick={() => setOffset(offset + 25)} type="button">Next</button></div></div>
  </div>;
}
