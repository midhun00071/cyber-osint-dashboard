"use client";

import { type FormEvent, useCallback, useEffect, useRef, useState } from "react";

import { ProtectedRoute } from "@/components/auth/ProtectedRoute";
import { fetchRun, fetchRunEvents, fetchRuns, requestRetry } from "@/services/operationsApi";
import type { RunEventList, RunFilters, RunList, RunSummary } from "@/types/operations";

type FilterForm = {
  sourceSlug: string; status: string; triggerType: string; retryable: "" | "true" | "false";
  from: string; to: string; limit: number;
};

const EMPTY_FILTERS: FilterForm = { sourceSlug: "", status: "", triggerType: "", retryable: "", from: "", to: "", limit: 25 };

function isAbortError(error: unknown): boolean {
  return error instanceof DOMException && error.name === "AbortError";
}

function timestamp(value: string | null): string {
  return value ? new Date(value).toLocaleString() : "Not available";
}

function aware(value: string): string | undefined {
  return value ? new Date(value).toISOString() : undefined;
}

function eventStatus(from: string | null, to: string | null): string {
  if (from && to) return `${from} → ${to}`;
  return to ?? from ?? "No status change";
}

export default function RunHistoryPage() {
  const [form, setForm] = useState<FilterForm>(EMPTY_FILTERS);
  const [filters, setFilters] = useState<RunFilters>({ limit: 25, offset: 0 });
  const [data, setData] = useState<RunList | null>(null);
  const [error, setError] = useState(false);
  const [refreshing, setRefreshing] = useState(false);
  const [busy, setBusy] = useState<string | null>(null);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [detail, setDetail] = useState<RunSummary | null>(null);
  const [events, setEvents] = useState<RunEventList | null>(null);
  const [detailError, setDetailError] = useState(false);
  const controllerRef = useRef<AbortController | null>(null);
  const inFlightRef = useRef(false);
  const queuedRefreshRef = useRef(false);
  const mountedRef = useRef(false);
  const filtersRef = useRef(filters);

  const refresh = useCallback(async function refreshData(queueIfBusy = false) {
    if (!mountedRef.current || document.visibilityState !== "visible") return;
    if (inFlightRef.current) {
      if (queueIfBusy) queuedRefreshRef.current = true;
      return;
    }
    inFlightRef.current = true;
    queuedRefreshRef.current = false;
    const controller = new AbortController();
    controllerRef.current = controller;
    setRefreshing(true);
    try {
      const result = await fetchRuns(filtersRef.current, controller.signal);
      if (!controller.signal.aborted && mountedRef.current) {
        if (result.status === "success") {
          setData(result.data);
          setError(false);
        } else {
          setError(true);
        }
      }
    } catch (requestError) {
      if (!controller.signal.aborted && !isAbortError(requestError) && mountedRef.current) setError(true);
    } finally {
      if (controllerRef.current === controller) controllerRef.current = null;
      inFlightRef.current = false;
      if (mountedRef.current) setRefreshing(false);
      if (queuedRefreshRef.current && mountedRef.current && document.visibilityState === "visible") {
        queuedRefreshRef.current = false;
        void refreshData(true);
      }
    }
  }, []);

  useEffect(() => {
    mountedRef.current = true;
    void refresh();
    const interval = window.setInterval(() => void refresh(), 15_000);
    const visibility = () => {
      if (document.visibilityState === "hidden") controllerRef.current?.abort();
      else void refresh(true);
    };
    document.addEventListener("visibilitychange", visibility);
    return () => {
      mountedRef.current = false;
      queuedRefreshRef.current = false;
      window.clearInterval(interval);
      document.removeEventListener("visibilitychange", visibility);
      controllerRef.current?.abort();
    };
  }, [refresh]);

  useEffect(() => {
    if (filtersRef.current !== filters) {
      filtersRef.current = filters;
      void refresh(true);
    }
  }, [filters, refresh]);

  useEffect(() => {
    setDetail(null);
    setEvents(null);
    setDetailError(false);
    if (!selectedId) return;
    const controller = new AbortController();
    void (async () => {
      try {
        const run = await fetchRun(selectedId, controller.signal);
        if (run.status !== "success" || controller.signal.aborted) throw new Error("detail");
        const eventList = await fetchRunEvents(selectedId, controller.signal);
        if (eventList.status !== "success" || controller.signal.aborted) throw new Error("events");
        setDetail(run.data);
        setEvents({ ...eventList.data, items: [...eventList.data.items].sort((left, right) => left.sequence - right.sequence) });
      } catch (requestError) {
        if (!controller.signal.aborted && !isAbortError(requestError)) setDetailError(true);
      }
    })();
    return () => controller.abort();
  }, [selectedId]);

  function applyFilters(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setFilters({
      sourceSlug: form.sourceSlug || undefined,
      status: form.status || undefined,
      triggerType: form.triggerType || undefined,
      retryable: form.retryable === "" ? undefined : form.retryable === "true",
      from: aware(form.from),
      to: aware(form.to),
      limit: form.limit,
      offset: 0,
    });
  }

  async function retry(publicId: string) {
    if (!window.confirm("Create the next bounded retry attempt?")) return;
    setBusy(publicId);
    const result = await requestRetry(publicId);
    if (mountedRef.current) setBusy(null);
    if (result.status === "success") await refresh(true);
    else if (mountedRef.current) setError(true);
  }

  return (
    <ProtectedRoute permission="ingestion.read">
      <section className="operationsPage">
        <header className="pageHeader"><p className="pageKicker">Operational evidence</p><h1>Run history</h1><p>Newest committed attempts first, with deterministic retry lineage and safe summaries.</p></header>
        <form onSubmit={applyFilters}>
          <label>Source slug<input maxLength={80} value={form.sourceSlug} onChange={(event) => setForm({ ...form, sourceSlug: event.target.value })} /></label>
          <label>Status<input maxLength={40} value={form.status} onChange={(event) => setForm({ ...form, status: event.target.value })} /></label>
          <label>Trigger type<input maxLength={40} value={form.triggerType} onChange={(event) => setForm({ ...form, triggerType: event.target.value })} /></label>
          <label>Retryable<select value={form.retryable} onChange={(event) => setForm({ ...form, retryable: event.target.value as FilterForm["retryable"] })}><option value="">Any</option><option value="true">Yes</option><option value="false">No</option></select></label>
          <label>From<input type="datetime-local" value={form.from} onChange={(event) => setForm({ ...form, from: event.target.value })} /></label>
          <label>To<input type="datetime-local" value={form.to} onChange={(event) => setForm({ ...form, to: event.target.value })} /></label>
          <label>Page size<select value={form.limit} onChange={(event) => setForm({ ...form, limit: Number(event.target.value) })}><option value={25}>25</option><option value={50}>50</option><option value={100}>100</option></select></label>
          <button type="submit">Apply filters</button>
        </form>
        {refreshing && data ? <p role="status">Refreshing run history…</p> : null}
        {error ? <p className="inlineAlert" role="alert">Run history could not be refreshed safely.</p> : null}
        {!data ? <p role="status" aria-busy="true">Loading run history…</p> : data.items.length === 0 ? <p>No runs match the selected filters.</p> : <>
          <div className="responsiveTable"><table><thead><tr><th>Source</th><th>Status</th><th>Trigger</th><th>Attempt/lineage</th><th>Timing</th><th>Retryable</th><th>Safe summary</th><th>Safe counters</th><th>Actions</th></tr></thead><tbody>{data.items.map((run) => <tr key={run.public_id}><td>{run.source_name}<small>{run.source_slug}</small></td><td>{run.status}</td><td>{run.trigger_type}</td><td>Attempt {run.attempt_number}<small>Retry parent: {run.retry_of_public_id ?? "None"}</small></td><td>Accepted: {timestamp(run.accepted_at)}<small>Started: {timestamp(run.started_at)}</small><small>Finished: {timestamp(run.finished_at)}</small><small>Duration: {run.duration_seconds === null ? "Not available" : `${run.duration_seconds}s`}</small></td><td>{run.retryable ? "Yes" : "No"}</td><td>{run.summary_message ?? "No safe summary"}</td><td>Fetched {run.counters.fetched}; created {run.counters.created}; updated {run.counters.updated}; unchanged {run.counters.unchanged}; skipped {run.counters.skipped}; failed {run.counters.failed}; errors {run.counters.error_count}</td><td><button type="button" onClick={() => setSelectedId(run.public_id)}>View details</button>{run.retryable ? <button disabled={busy !== null} onClick={() => void retry(run.public_id)} type="button">{busy === run.public_id ? "Working…" : "Retry"}</button> : null}</td></tr>)}</tbody></table></div>
          <div className="tableActions"><button disabled={(filters.offset ?? 0) === 0} type="button" onClick={() => setFilters({ ...filters, offset: Math.max(0, (filters.offset ?? 0) - (filters.limit ?? 25)) })}>Previous</button><button disabled={(filters.offset ?? 0) + (filters.limit ?? 25) >= data.total} type="button" onClick={() => setFilters({ ...filters, offset: (filters.offset ?? 0) + (filters.limit ?? 25) })}>Next</button></div>
        </>}
        {selectedId ? <section className="dashboardPanel"><h2>Selected run</h2>{detailError ? <p role="alert">Run detail could not be loaded safely.</p> : !detail || !events ? <p role="status">Loading run detail…</p> : <><p>{detail.source_name} · {detail.status} · attempt {detail.attempt_number}</p><p>Retry parent: {detail.retry_of_public_id ?? "None"}</p><p>Accepted: {timestamp(detail.accepted_at)} · Started: {timestamp(detail.started_at)} · Finished: {timestamp(detail.finished_at)}</p><p>Duration: {detail.duration_seconds === null ? "Not available" : `${detail.duration_seconds}s`} · Retryable: {detail.retryable ? "Yes" : "No"}</p><p>{detail.summary_message ?? "No safe summary"}</p><h3>Ordered events</h3>{events.items.length === 0 ? <p>No run events are available.</p> : <ol>{events.items.map((item) => <li key={item.sequence}><strong>{item.sequence}. {item.event_type}</strong> · {eventStatus(item.from_status, item.to_status)} · {item.message ?? "No safe message"} · {timestamp(item.occurred_at)}</li>)}</ol>}</>}</section> : null}
      </section>
    </ProtectedRoute>
  );
}
