"use client";

import { useCallback, useEffect, useRef, useState } from "react";

import { StatusBadge } from "@/components/dashboard/StatusBadge";
import { controlSource, fetchSources, requestManualRun } from "@/services/operationsApi";
import type { SourceList, SourceOperation, SourceSummary } from "@/types/operations";
import { formatStatusLabel } from "@/utils/statusLabel";

function timestamp(value: string | null): string {
  return value ? new Date(value).toLocaleString() : "Not available";
}

function isAbortError(error: unknown): boolean {
  return error instanceof DOMException && error.name === "AbortError";
}

function actionLabel(action: SourceOperation): string {
  return {
    manual_run: "Run once",
    retry: "Retry",
    pause: "Pause temporarily",
    resume: "Resume source",
    disable: "Disable source",
    enable: "Enable source",
  }[action];
}

function actionDescription(action: SourceOperation): string {
  if (action === "pause") return "Pause stops execution temporarily while retaining the source configuration.";
  if (action === "disable") return "Disable takes the source out of service until it is explicitly enabled.";
  if (action === "manual_run") return "Run one bounded source attempt outside the normal parent-cycle evaluation.";
  return `${actionLabel(action)} using the existing governed source policy.`;
}

function scheduleText(source: SourceSummary): { primary: string; secondary: string } {
  if (source.next_scheduled_at) return { primary: `Next evaluation: ${timestamp(source.next_scheduled_at)}`, secondary: "Coordinated scheduling evidence" };
  if (source.latest_run?.trigger_type === "scheduled") return { primary: "Evaluated by parent cycle", secondary: "No independent source schedule" };
  return { primary: "No independent source schedule", secondary: source.operator_state === "enabled" ? "Parent-cycle eligibility is evaluated centrally" : "Source is not currently eligible" };
}

export default function SourcesPage() {
  const [data, setData] = useState<SourceList | null>(null);
  const [error, setError] = useState(false);
  const [refreshing, setRefreshing] = useState(false);
  const [busy, setBusy] = useState<string | null>(null);
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
      const result = await fetchSources(controller.signal);
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

  async function operate(slug: string, action: SourceOperation) {
    if (action === "retry") return;
    if (!window.confirm(`${actionDescription(action)}\n\nConfirm for ${slug}?`)) return;
    setBusy(`${slug}:${action}`);
    const result = action === "manual_run"
      ? await requestManualRun(slug, crypto.randomUUID())
      : await controlSource(slug, action);
    if (mountedRef.current) setBusy(null);
    if (result.status === "success") await refresh(true);
    else if (mountedRef.current) setError(true);
  }

  return (
    <section className="operationsPage">
      <header className="pageHeader">
        <p className="pageKicker">Governed integrations</p>
        <h1>Sources</h1>
        <p>Safe policy, readiness, progress, and operator-state metadata. Raw checkpoints and credential references are never displayed.</p>
      </header>
      {refreshing && data ? <p role="status">Refreshing source metadata…</p> : null}
      {error ? <p className="inlineAlert" role="alert">Source information could not be refreshed safely.</p> : null}
      {!data ? <p role="status" aria-busy="true">Loading approved sources…</p> : data.items.length === 0 ? (
        <p>No approved sources are available.</p>
      ) : (
        <div className="responsiveTable sourcesTable"><table><thead><tr><th>Source</th><th>State and readiness</th><th>Progress evidence</th><th>Latest run</th><th>Scheduling</th><th>Actions</th></tr></thead><tbody>
          {data.items.map((source) => {
            const schedule = scheduleText(source);
            return (
            <tr key={source.public_id}>
              <td><strong>{source.name}</strong><small>{source.slug}</small><small>{source.source_type} · {source.content_type}</small></td>
              <td><div className="sourcePrimaryState"><StatusBadge label={formatStatusLabel(source.effective_state)} tone={source.execution_available ? "success" : source.operator_state === "paused" ? "warning" : "neutral"} /><strong>{source.execution_available ? "Ready for governed execution" : "Execution unavailable"}</strong></div><small>Operator: {formatStatusLabel(source.operator_state)} · Policy: {formatStatusLabel(source.policy_state)}</small><small>Freshness: {formatStatusLabel(source.freshness)}</small><small>Credentials: {source.credential_required ? source.credential_configured ? "Configured" : "Required" : "Not required"} · Quota: {source.quota_state ? formatStatusLabel(source.quota_state) : "Not limited"}</small><small>Backoff until: {timestamp(source.backoff_until)}</small></td>
              <td><span>Kind: {source.progress.kind}</span><small>Version: {source.progress.version ?? "None"}</small><small>Committed: {timestamp(source.progress.committed_at)}</small><small>Fingerprint: {source.progress.fingerprint ?? "None"}</small></td>
              <td>{source.latest_run ? <><strong>{formatStatusLabel(source.latest_run.status)}</strong><small>Trigger: {formatStatusLabel(source.latest_run.trigger_type)} · Attempt: {source.latest_run.attempt_number}</small><small>Started: {timestamp(source.latest_run.started_at)}</small><small>Finished: {timestamp(source.latest_run.finished_at)}</small></> : "No runs"}</td>
              <td><strong>{schedule.primary}</strong><small>{schedule.secondary}</small></td>
              <td><div className="tableActions actionStack">{source.available_actions.map((action) => action === "retry" ? <span key={action}>Retry from Run History</span> : <button aria-label={`${actionLabel(action)} for ${source.name}`} className={action === "disable" ? "buttonDanger" : action === "manual_run" ? "buttonPrimary" : "buttonSecondary"} disabled={busy !== null} key={action} onClick={() => void operate(source.slug, action)} title={actionDescription(action)} type="button">{busy === `${source.slug}:${action}` ? "Working…" : actionLabel(action)}</button>)}{source.available_actions.length === 0 ? "None" : null}</div></td>
            </tr>
          );})}
        </tbody></table></div>
      )}
    </section>
  );
}
