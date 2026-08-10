"use client";

import { useEffect, useState } from "react";
import { SafeExternalLink } from "@/components/SafeExternalLink";
import { fetchItemProvenance } from "@/services/analystApi";
import type { ItemProvenance } from "@/types/analyst";
import { formatStatusLabel } from "@/utils/statusLabel";

type State = { status: "loading" | "error" | "not_found" } | { status: "success"; data: ItemProvenance };
const MAX_SOURCES = 25;
const MAX_IMPORT_RUNS = 20;
const MAX_CLASSIFICATION_TAGS = 16;
const MAX_INDICATORS = 100;

export function ItemProvenancePanel({ publicId }: Readonly<{ publicId: string }>) {
  const [state, setState] = useState<State>({ status: "loading" });
  useEffect(() => { const controller = new AbortController(); void fetchItemProvenance(publicId, controller.signal).then((result) => setState(result.status === "success" ? { status: "success", data: result.data } : { status: result.status })).catch((error: unknown) => { if (!(error instanceof DOMException && error.name === "AbortError")) setState({ status: "error" }); }); return () => controller.abort(); }, [publicId]);
  if (state.status === "loading") return <section className="vulnerabilityDetailSummary" aria-busy="true"><h2>Provenance</h2><p>Loading provenance evidence…</p></section>;
  if (state.status !== "success") return <section className="vulnerabilityDetailSummary"><h2>Provenance</h2><p>{state.status === "not_found" ? "No provenance record was found." : "Provenance evidence is temporarily unavailable."}</p></section>;
  const sources = state.data.sources.slice(0, MAX_SOURCES); const tags = state.data.classification_tags.slice(0, MAX_CLASSIFICATION_TAGS); const indicators = state.data.indicators.slice(0, MAX_INDICATORS);
  return <section className="vulnerabilityDetailSummary"><h2>Provenance and relationships</h2>{sources.map((source) => <article key={`${source.source_slug}-${source.content_sha256 ?? source.collected_at}`}><h3>{source.source_name}</h3><p>Published {source.published_at ?? "Unknown"} · collected {source.collected_at} · last seen {source.last_seen_at}</p><p>Content SHA-256: <code>{source.content_sha256 ?? "Unavailable"}</code></p><p>Import evidence: {source.import_runs.length ? source.import_runs.slice(0, MAX_IMPORT_RUNS).map((run) => `${run.action} (${formatStatusLabel(run.status)})`).join(", ") : "No linked import run evidence"}</p><SafeExternalLink className="safeSourceLink" url={source.source_url}>Open source evidence</SafeExternalLink></article>)}<h3>Classification tags</h3><p>{tags.length ? tags.map((tag) => `${tag.label} (${Math.round(tag.confidence * 100)}%)`).join(", ") : "No controlled classification tags"}</p><h3>Indicators</h3><p>{indicators.length ? indicators.map((indicator) => `${indicator.observable_type}: ${indicator.normalized_value}`).join(", ") : "No normalized indicators linked to this publication"}</p></section>;
}
