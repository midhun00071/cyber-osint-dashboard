"use client";

import { FormEvent, useCallback, useEffect, useRef, useState } from "react";

import { ProtectedRoute } from "@/components/auth/ProtectedRoute";
import { fetchAuditEvents } from "@/services/auditApi";
import type { AuditFilters, AuditList } from "@/types/audit";

const PAGE_SIZE = 25;
function utc(value: string): string | undefined { return value ? new Date(value).toISOString() : undefined; }

export default function AuditLogPage() {
  const [data, setData] = useState<AuditList | null>(null);
  const [filters, setFilters] = useState<AuditFilters>({ limit: PAGE_SIZE, offset: 0 });
  const [draft, setDraft] = useState({ action: "", outcome: "", correlationId: "", from: "", to: "" });
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(false);
  const controllerRef = useRef<AbortController | null>(null);

  const load = useCallback(async (requested: AuditFilters) => {
    controllerRef.current?.abort();
    const controller = new AbortController();
    controllerRef.current = controller;
    setLoading(true);
    const result = await fetchAuditEvents(requested, controller.signal);
    if (!controller.signal.aborted) {
      if (result.status === "success") { setData(result.data); setError(false); }
      else setError(true);
      setLoading(false);
    }
  }, []);
  useEffect(() => { void load(filters); return () => controllerRef.current?.abort(); }, [filters, load]);
  function apply(event: FormEvent) {
    event.preventDefault();
    setFilters({ action: draft.action || undefined, outcome: draft.outcome || undefined, correlationId: draft.correlationId || undefined, from: utc(draft.from), to: utc(draft.to), limit: PAGE_SIZE, offset: 0 });
  }

  return <ProtectedRoute permission="audit.read"><section className="operationsPage">
    <header className="pageHeader"><p className="pageKicker">Administrator evidence</p><h1>Audit Log</h1><p>Bounded security-event search. Request bodies, credentials, cookies, and raw errors are not available here.</p></header>
    <form className="auditFilters" onSubmit={apply}>
      <label>Action<select value={draft.action} onChange={(event) => setDraft({ ...draft, action: event.target.value })}><option value="">All actions</option><option value="auth.login">Login</option><option value="auth.login.failed">Login failed</option><option value="authorization.denied">Authorization denied</option><option value="report.export.requested">Report export requested</option></select></label>
      <label>Outcome<select value={draft.outcome} onChange={(event) => setDraft({ ...draft, outcome: event.target.value })}><option value="">All outcomes</option><option value="success">Success</option><option value="denied">Denied</option><option value="failed">Failed</option><option value="no_change">No change</option></select></label>
      <label>Correlation ID<input maxLength={36} value={draft.correlationId} onChange={(event) => setDraft({ ...draft, correlationId: event.target.value })} /></label>
      <label>From UTC<input type="datetime-local" value={draft.from} onChange={(event) => setDraft({ ...draft, from: event.target.value })} /></label>
      <label>To UTC<input type="datetime-local" value={draft.to} onChange={(event) => setDraft({ ...draft, to: event.target.value })} /></label>
      <button type="submit">Search</button>
    </form>
    {loading ? <p aria-busy="true" role="status">Loading audit events…</p> : null}
    {error ? <p className="inlineAlert" role="alert">Audit events could not be loaded safely.</p> : null}
    {data && !loading ? data.items.length === 0 ? <p>No audit events match these filters.</p> : <div className="responsiveTable"><table><thead><tr><th>Time</th><th>Action</th><th>Outcome</th><th>Actor</th><th>Target</th><th>Correlation</th><th>Safe detail</th></tr></thead><tbody>{data.items.map((item) => <tr key={item.public_id}><td>{new Date(item.occurred_at).toLocaleString()}</td><td>{item.action}</td><td>{item.outcome}</td><td>{item.actor_type}: {item.actor_ref}</td><td>{item.target_type}: {item.target_ref}</td><td>{item.correlation_id ?? "None"}</td><td>{item.safe_detail ? Object.entries(item.safe_detail).map(([key, value]) => <span key={key}>{key}: {value}</span>) : "None"}</td></tr>)}</tbody></table></div> : null}
    {data ? <div className="paginationControls"><button disabled={(filters.offset ?? 0) === 0 || loading} onClick={() => setFilters({ ...filters, offset: Math.max(0, (filters.offset ?? 0) - PAGE_SIZE) })} type="button">Previous</button><p>{data.offset + 1}–{Math.min(data.offset + data.items.length, data.total)} of {data.total}</p><button disabled={data.offset + data.items.length >= data.total || loading} onClick={() => setFilters({ ...filters, offset: (filters.offset ?? 0) + PAGE_SIZE })} type="button">Next</button></div> : null}
  </section></ProtectedRoute>;
}
