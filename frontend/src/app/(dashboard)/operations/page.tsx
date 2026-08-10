"use client";

import { useCallback, useEffect, useRef, useState } from "react";

import { ProtectedRoute } from "@/components/auth/ProtectedRoute";
import { fetchCycles, fetchOperationsSummary, fetchRuns } from "@/services/operationsApi";
import type { CycleList, OperationsSummary, RunList } from "@/types/operations";
import { formatStatusLabel } from "@/utils/statusLabel";

type OperationsData = { summary: OperationsSummary; cycles: CycleList; runs: RunList };

type StatusCountRow = Readonly<{ count: number; label: string }>;

function isAbortError(error: unknown): boolean {
  return error instanceof DOMException && error.name === "AbortError";
}

function timestamp(value: string | null): string {
  return value ? new Date(value).toLocaleString() : "Not available";
}

function statusCountRows(counts: Readonly<Record<string, number>>): StatusCountRow[] {
  const aggregated = new Map<string, number>();
  for (const [rawStatus, count] of Object.entries(counts)) {
    const label = formatStatusLabel(rawStatus);
    aggregated.set(label, (aggregated.get(label) ?? 0) + count);
  }
  return Array.from(aggregated, ([label, count]) => ({ count, label }))
    .sort((left, right) => left.label.localeCompare(right.label));
}

export default function OperationsPage() {
  const [data, setData] = useState<OperationsData | null>(null);
  const [error, setError] = useState(false);
  const [refreshing, setRefreshing] = useState(false);
  const [lastRefreshed, setLastRefreshed] = useState<string | null>(null);
  const controllerRef = useRef<AbortController | null>(null);
  const inFlightRef = useRef(false);
  const queuedRefreshRef = useRef(false);
  const mountedRef = useRef(false);

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
      const summary = await fetchOperationsSummary(controller.signal);
      if (summary.status !== "success" || controller.signal.aborted) throw new Error("summary");
      const cycles = await fetchCycles(controller.signal);
      if (cycles.status !== "success" || controller.signal.aborted) throw new Error("cycles");
      const runs = await fetchRuns({ limit: 25, offset: 0 }, controller.signal);
      if (runs.status !== "success" || controller.signal.aborted) throw new Error("runs");
      if (mountedRef.current) {
        setData({ summary: summary.data, cycles: cycles.data, runs: runs.data });
        setLastRefreshed(new Date().toISOString());
        setError(false);
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

  const running = data?.summary.run_counts_by_status.running ?? 0;
  const checkpointPending = data?.summary.run_counts_by_status.checkpoint_pending ?? 0;
  const statusCounts = data ? statusCountRows(data.summary.run_counts_by_status) : [];

  return (
    <ProtectedRoute permission="ingestion.read">
      <section className="operationsPage">
        <header className="pageHeader"><p className="pageKicker">Durable evidence</p><h1>Ingestion operations</h1><p>Committed cycle and run state. Acceptance never implies successful ingestion.</p></header>
        {refreshing && data ? <p role="status">Refreshing operations…</p> : null}
        {error ? <p className="inlineAlert" role="alert">Operations could not be refreshed safely. Existing committed evidence remains visible.</p> : null}
        {!data ? <p role="status" aria-busy="true">Loading operations…</p> : <>
          <p>Generated: {timestamp(data.summary.generated_at)} · Last refreshed: {timestamp(lastRefreshed)}</p>
          <div className="summaryGrid">
            <article><span>Execution</span><strong>{data.summary.deployment_state === "available" ? "Available" : "Unavailable"}</strong></article>
            <article><span>Configured handlers</span><strong>{data.summary.configured_handler_count}</strong></article>
            <article><span>Active cycles</span><strong>{data.summary.active_cycle_count}</strong></article>
            <article><span>Running runs</span><strong>{running}</strong></article>
            <article><span>Checkpoint pending runs</span><strong>{checkpointPending}</strong></article>
            <article><span>Sources needing attention</span><strong>{data.summary.source_attention_count}</strong></article>
          </div>
          <section className="dashboardPanel"><h2>Status counts</h2>{statusCounts.length === 0 ? <p>No run status evidence is available.</p> : <ul className="statusList">{statusCounts.map(({ label, count }) => <li key={label}><span>{label}</span><strong>{count}</strong></li>)}</ul>}</section>
          <section className="dashboardPanel"><h2>Active or recent cycles</h2>{data.cycles.items.length === 0 ? <p>No cycle activity has been recorded.</p> : <ul className="statusList">{data.cycles.items.map((cycle) => <li key={cycle.public_id}><span>{formatStatusLabel(cycle.status)} · {formatStatusLabel(cycle.trigger_type)} · {timestamp(cycle.started_at)}</span><strong>{cycle.sources_completed}/{cycle.sources_expected}</strong></li>)}</ul>}</section>
          <section className="dashboardPanel"><h2>Active or recent runs</h2>{data.runs.items.length === 0 ? <p>No run activity has been recorded.</p> : <ul className="statusList">{data.runs.items.map((run) => <li key={run.public_id}><span>{run.source_name} · {formatStatusLabel(run.status)} · {formatStatusLabel(run.trigger_type)}</span><strong>Attempt {run.attempt_number}</strong></li>)}</ul>}</section>
        </>}
      </section>
    </ProtectedRoute>
  );
}
