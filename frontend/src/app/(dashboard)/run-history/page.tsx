"use client";

import { type FormEvent, useCallback, useEffect, useRef, useState } from "react";

import { ProtectedRoute } from "@/components/auth/ProtectedRoute";
import { NativeDateTimeFields } from "@/components/forms/NativeDateTimeFields";
import { fetchRun, fetchRunEvents, fetchRuns, requestRetry } from "@/services/operationsApi";
import type { RunEventList, RunFilters, RunList, RunSummary } from "@/types/operations";
import type { LocalDateTimeParts } from "@/utils/localDateTime";
import { emptyLocalDateTime, isPartialLocalDateTime, localDateTimeToIso } from "@/utils/localDateTime";
import { formatStatusLabel } from "@/utils/statusLabel";

type FilterForm = {
  sourceSlug: string; status: string; triggerType: string; retryable: "" | "true" | "false";
  from: LocalDateTimeParts; to: LocalDateTimeParts; limit: number;
};

function emptyFilterForm(): FilterForm {
  return { sourceSlug: "", status: "", triggerType: "", retryable: "", from: emptyLocalDateTime(), to: emptyLocalDateTime(), limit: 25 };
}

function isAbortError(error: unknown): boolean {
  return error instanceof DOMException && error.name === "AbortError";
}

function timestamp(value: string | null): string {
  return value ? new Date(value).toLocaleString() : "Not available";
}

function eventStatus(from: string | null, to: string | null): string {
  if (from && to) return `${formatStatusLabel(from)} → ${formatStatusLabel(to)}`;
  return to || from ? formatStatusLabel(to ?? from ?? "") : "No status change";
}

export default function RunHistoryPage() {
  const [form, setForm] = useState<FilterForm>(emptyFilterForm);
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
  const detailDialogRef = useRef<HTMLElement | null>(null);
  const detailCloseRef = useRef<HTMLButtonElement | null>(null);
  const detailTriggerRef = useRef<HTMLButtonElement | null>(null);

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

  useEffect(() => {
    if (!selectedId) return undefined;
    const previousOverflow = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    detailCloseRef.current?.focus();
    const focusableSelector = "a[href], button:not([disabled]), input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex='-1'])";
    const focusableElements = () => Array.from(detailDialogRef.current?.querySelectorAll<HTMLElement>(focusableSelector) ?? []).filter((element) => element.getAttribute("aria-hidden") !== "true");
    const containKeyboardFocus = (event: KeyboardEvent) => {
      if (event.key === "Escape") {
        event.preventDefault();
        closeDetail();
        return;
      }
      if (event.key !== "Tab") return;
      const focusable = focusableElements();
      if (!focusable.length) {
        event.preventDefault();
        detailDialogRef.current?.focus();
        return;
      }
      const first = focusable[0];
      const last = focusable[focusable.length - 1];
      const active = document.activeElement;
      if (event.shiftKey && (active === first || !detailDialogRef.current?.contains(active))) {
        event.preventDefault();
        last.focus();
      } else if (!event.shiftKey && (active === last || !detailDialogRef.current?.contains(active))) {
        event.preventDefault();
        first.focus();
      }
    };
    const containProgrammaticFocus = (event: FocusEvent) => {
      if (event.target instanceof Node && !detailDialogRef.current?.contains(event.target)) {
        (focusableElements()[0] ?? detailDialogRef.current)?.focus();
      }
    };
    document.addEventListener("keydown", containKeyboardFocus);
    document.addEventListener("focusin", containProgrammaticFocus);
    return () => {
      document.removeEventListener("keydown", containKeyboardFocus);
      document.removeEventListener("focusin", containProgrammaticFocus);
      document.body.style.overflow = previousOverflow;
    };
  }, [selectedId]);

  function applyFilters(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (isPartialLocalDateTime(form.from) || isPartialLocalDateTime(form.to)) return;
    setFilters({
      sourceSlug: form.sourceSlug || undefined,
      status: form.status || undefined,
      triggerType: form.triggerType || undefined,
      retryable: form.retryable === "" ? undefined : form.retryable === "true",
      from: localDateTimeToIso(form.from),
      to: localDateTimeToIso(form.to),
      limit: form.limit,
      offset: 0,
    });
  }

  function resetFilters() {
    setForm(emptyFilterForm());
    setFilters({ limit: 25, offset: 0 });
  }

  function openDetail(publicId: string, trigger: HTMLButtonElement) {
    detailTriggerRef.current = trigger;
    setSelectedId(publicId);
  }

  function closeDetail() {
    setSelectedId(null);
    setDetail(null);
    setEvents(null);
    window.setTimeout(() => detailTriggerRef.current?.focus(), 0);
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
        <form className="controlForm" onSubmit={applyFilters}>
          <label>Source slug<input id="run-source" name="source_slug" maxLength={80} value={form.sourceSlug} onChange={(event) => setForm({ ...form, sourceSlug: event.target.value })} /></label>
          <label>Status<input id="run-status" name="status" maxLength={40} value={form.status} onChange={(event) => setForm({ ...form, status: event.target.value })} /></label>
          <label>Trigger type<input id="run-trigger" name="trigger_type" maxLength={40} value={form.triggerType} onChange={(event) => setForm({ ...form, triggerType: event.target.value })} /></label>
          <label>Retryable<select id="run-retryable" name="retryable" value={form.retryable} onChange={(event) => setForm({ ...form, retryable: event.target.value as FilterForm["retryable"] })}><option value="">Any</option><option value="true">Yes</option><option value="false">No</option></select></label>
          <NativeDateTimeFields id="run-from" label="From" name="from" onChange={(from) => setForm({ ...form, from })} value={form.from} />
          <NativeDateTimeFields id="run-to" label="To" name="to" onChange={(to) => setForm({ ...form, to })} value={form.to} />
          <label>Page size<select id="run-limit" name="limit" value={form.limit} onChange={(event) => setForm({ ...form, limit: Number(event.target.value) })}><option value={25}>25</option><option value={50}>50</option><option value={100}>100</option></select></label>
          <div className="filterActions"><button type="submit">Apply filters</button><button onClick={resetFilters} type="button">Reset</button></div>
        </form>
        {refreshing && data ? <p role="status">Refreshing run history…</p> : null}
        {error ? <p className="inlineAlert" role="alert">Run history could not be refreshed safely.</p> : null}
        {!data ? <p role="status" aria-busy="true">Loading run history…</p> : data.items.length === 0 ? <p>No runs match the selected filters.</p> : <>
          <div className="responsiveTable runHistoryTable"><table><thead><tr><th>Source</th><th>Status</th><th>Trigger</th><th>Attempt</th><th>Core timing</th><th>Summary</th><th>Action</th></tr></thead><tbody>{data.items.map((run) => <tr key={run.public_id}><td><strong>{run.source_name}</strong><small>{run.source_slug}</small></td><td><strong>{formatStatusLabel(run.status)}</strong><small>{run.retryable ? "Retryable" : "Not retryable"}</small></td><td>{formatStatusLabel(run.trigger_type)}</td><td><strong>{run.attempt_number}</strong><small>{run.retry_of_public_id ? "Has retry parent" : "Initial lineage"}</small></td><td><strong>{timestamp(run.started_at)}</strong><small>Duration: {run.duration_seconds === null ? "Not available" : `${run.duration_seconds}s`}</small></td><td><span className="boundedSummary">{run.summary_message ?? "No safe summary"}</span><small>Fetched {run.counters.fetched} · Created {run.counters.created} · Failed {run.counters.failed}</small></td><td><div className="tableActions actionStack"><button className="buttonPrimary" type="button" onClick={(event) => openDetail(run.public_id, event.currentTarget)}>View details</button>{run.retryable ? <button className="buttonDanger" disabled={busy !== null} onClick={() => void retry(run.public_id)} type="button">{busy === run.public_id ? "Working…" : "Retry run"}</button> : null}</div></td></tr>)}</tbody></table></div>
          <div className="paginationControls" aria-label="Run history pagination"><p>Showing {data.total ? (filters.offset ?? 0) + 1 : 0}–{Math.min((filters.offset ?? 0) + data.items.length, data.total)} of {data.total}</p><div><button disabled={(filters.offset ?? 0) === 0} type="button" onClick={() => setFilters({ ...filters, offset: Math.max(0, (filters.offset ?? 0) - (filters.limit ?? 25)) })}>Previous</button><button disabled={(filters.offset ?? 0) + (filters.limit ?? 25) >= data.total} type="button" onClick={() => setFilters({ ...filters, offset: (filters.offset ?? 0) + (filters.limit ?? 25) })}>Next</button></div></div>
        </>}
        {selectedId ? <div className="runDetailLayer"><div aria-hidden="true" className="runDetailBackdrop" onMouseDown={closeDetail} /><section aria-labelledby="run-detail-title" aria-modal="true" className="runDetailDialog" ref={detailDialogRef} role="dialog" tabIndex={-1}><div className="runDetailHeader"><div><p className="pageKicker">Operational evidence</p><h2 id="run-detail-title">Run details</h2></div><button className="buttonSecondary" onClick={closeDetail} ref={detailCloseRef} type="button">Close</button></div>{detailError ? <p className="inlineAlert" role="alert">Run detail could not be loaded safely.</p> : !detail || !events ? <p aria-busy="true" role="status">Loading run detail…</p> : <div className="runDetailContent"><dl className="runDetailGrid"><div><dt>Source</dt><dd>{detail.source_name}<small>{detail.source_slug}</small></dd></div><div><dt>Status</dt><dd>{formatStatusLabel(detail.status)}</dd></div><div><dt>Trigger</dt><dd>{formatStatusLabel(detail.trigger_type)}</dd></div><div><dt>Attempt</dt><dd>{detail.attempt_number}</dd></div><div><dt>Retryable</dt><dd>{detail.retryable ? "Yes" : "No"}</dd></div><div><dt>Retry parent</dt><dd className="identifierValue">{detail.retry_of_public_id ?? "None"}</dd></div></dl><section><h3>Timing</h3><p>Accepted: {timestamp(detail.accepted_at)}</p><p>Started: {timestamp(detail.started_at)}</p><p>Finished: {timestamp(detail.finished_at)}</p><p>Duration: {detail.duration_seconds === null ? "Not available" : `${detail.duration_seconds}s`}</p></section><section><h3>Safe summary and counters</h3><p>{detail.summary_message ?? "No safe summary"}</p><p>Fetched {detail.counters.fetched}; created {detail.counters.created}; updated {detail.counters.updated}; unchanged {detail.counters.unchanged}; skipped {detail.counters.skipped}; failed {detail.counters.failed}; errors {detail.counters.error_count}</p></section><section><h3>Ordered events</h3>{events.items.length === 0 ? <p>No run events are available.</p> : <ol className="runEventList">{events.items.map((item) => <li key={item.sequence}><strong>{item.sequence}. {formatStatusLabel(item.event_type)}</strong><span>{eventStatus(item.from_status, item.to_status)}</span><span>{item.message ?? "No safe message"}</span><time>{timestamp(item.occurred_at)}</time></li>)}</ol>}</section></div>}</section></div> : null}
      </section>
    </ProtectedRoute>
  );
}
