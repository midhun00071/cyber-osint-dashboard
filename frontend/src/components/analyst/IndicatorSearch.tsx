"use client";

import { FormEvent, useEffect, useState } from "react";
import { fetchIndicators } from "@/services/analystApi";
import type { AnalystList, Indicator } from "@/types/analyst";

type State = { status: "idle" | "loading" | "error" } | { status: "success"; data: AnalystList<Indicator> };
const MAX_INDICATOR_LENGTH = 128;

function isIpv4(value: string): boolean {
  const parts = value.split(".");
  return parts.length === 4 && parts.every((part) => /^\d{1,3}$/.test(part) && Number(part) <= 255);
}

function isIpv6(value: string): boolean {
  if (!value.includes(":") || value.includes("%")) return false;
  try {
    const parsed = new URL(`http://[${value}]/`);
    return parsed.hostname.startsWith("[") && parsed.hostname.endsWith("]");
  } catch {
    return false;
  }
}

function isDomain(value: string): boolean {
  if (value.length > 253 || /[\s/@:_]/.test(value) || value.startsWith(".") || value.endsWith(".")) return false;
  const labels = value.split(".");
  return labels.every((label) => label.length > 0 && label.length <= 63 && /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/i.test(label));
}

function isSupportedUrl(value: string): boolean {
  try {
    const parsed = new URL(value);
    return (parsed.protocol === "http:" || parsed.protocol === "https:") && Boolean(parsed.hostname);
  } catch {
    return false;
  }
}

export function indicatorValidationMessage(value: string): string | null {
  if (value.length < 2) return "Enter at least two characters.";
  if (/^\d+(?:\.\d+){3}$/.test(value)) return isIpv4(value) ? null : "Enter a valid IPv4 address with four values from 0 to 255.";
  if (isSupportedUrl(value) || isIpv4(value) || isIpv6(value) || isDomain(value)) return null;
  if (/^[a-f0-9]+$/i.test(value) && [32, 40, 64, 128].includes(value.length)) return null;
  return "Enter a valid IPv4 or IPv6 address, domain, HTTP(S) URL, or 32/40/64/128-character hexadecimal file hash.";
}

export function IndicatorSearch() {
  const [input, setInput] = useState(""); const [query, setQuery] = useState(""); const [offset, setOffset] = useState(0);
  const [state, setState] = useState<State>({ status: "idle" });
  const [validationMessage, setValidationMessage] = useState<string | null>(null);
  useEffect(() => {
    if (!query) { setState({ status: "idle" }); return; }
    const controller = new AbortController(); setState({ status: "loading" });
    void fetchIndicators(query, offset, controller.signal).then((result) => setState(result.status === "success" ? { status: "success", data: result.data } : { status: "error" })).catch((error: unknown) => { if (!(error instanceof DOMException && error.name === "AbortError")) setState({ status: "error" }); });
    return () => controller.abort();
  }, [offset, query]);
  function submit(event: FormEvent) { event.preventDefault(); const value = input.trim(); const message = indicatorValidationMessage(value); setValidationMessage(message); if (!message) { setOffset(0); setQuery(value); } }
  const items = state.status === "success" ? state.data.items : []; const total = state.status === "success" ? state.data.total : 0;
  return <div className="vulnerabilityTableShell"><form className="vulnerabilityFilters indicatorSearchForm" noValidate onSubmit={submit}><label><span>Indicator value</span><input aria-describedby={validationMessage ? "indicator-validation" : "indicator-help"} aria-invalid={validationMessage ? "true" : undefined} aria-label="Indicator value" id="indicator-value" name="indicator_value" minLength={2} maxLength={MAX_INDICATOR_LENGTH} onChange={(event) => { setInput(event.target.value); if (validationMessage) setValidationMessage(null); }} placeholder="IPv4, IPv6, domain, URL, or file hash" required type="search" value={input} /><small id="indicator-help">Offline lookup only. No probing, resolution, or external request is performed.</small></label><div className="filterActions"><button type="submit">Search stored indicators</button><button onClick={() => { setInput(""); setQuery(""); setOffset(0); setValidationMessage(null); }} type="button">Clear</button></div></form>
    {validationMessage ? <p className="fieldError" id="indicator-validation" role="alert">{validationMessage}</p> : null}
    {state.status === "idle" ? <div className="emptyState" role="status"><h3>Enter an indicator to search</h3><p>Searches are authenticated, rate limited, and restricted to normalized stored metadata. No network probing is performed.</p></div> : null}
    {state.status === "loading" ? <div className="tableLoadingState" aria-busy="true" role="status">Searching stored indicators</div> : null}
    {state.status === "error" ? <div className="emptyState" role="status"><h3>Indicator search unavailable</h3><p>The bounded stored-data query could not be completed.</p></div> : null}
    {state.status === "success" && !items.length ? <div className="emptyState" role="status"><h3>No stored indicators match</h3><p>No active normalized indicator matched the search value.</p></div> : null}
    {items.length ? <div className="vulnerabilityTableScroller"><table className="vulnerabilityTable"><thead><tr><th>Indicator</th><th>Type</th><th>Status</th><th>Confidence</th><th>Provenance</th><th>Publications</th></tr></thead><tbody>{items.map((item) => <tr key={item.public_id}><td><strong>{item.normalized_value}</strong><span>{item.context_summary ?? "No context summary"}</span></td><td>{item.observable_type.replaceAll("_", " ")}</td><td>{item.status.replaceAll("_", " ")}</td><td>{item.confidence === null ? "Not asserted" : `${Math.round(item.confidence * 100)}%`}</td><td>{item.provenance_count}</td><td>{item.publication_count}</td></tr>)}</tbody></table></div> : null}
    {query ? <div className="paginationControls"><p>Showing {total ? offset + 1 : 0}-{Math.min(offset + 25, total)} of {total}</p><div><button disabled={!offset || state.status === "loading"} onClick={() => setOffset(Math.max(0, offset - 25))} type="button">Previous</button><button disabled={state.status !== "success" || offset + 25 >= total} onClick={() => setOffset(offset + 25)} type="button">Next</button></div></div> : null}
  </div>;
}
