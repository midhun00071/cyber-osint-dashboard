"use client";

import { FormEvent, useCallback, useEffect, useRef, useState } from "react";

import { ProtectedRoute } from "@/components/auth/ProtectedRoute";
import { NativeDateTimeFields } from "@/components/forms/NativeDateTimeFields";
import { fetchAuditEvents } from "@/services/auditApi";
import type { AuditFilters, AuditList } from "@/types/audit";
import { emptyLocalDateTime, isPartialLocalDateTime, localDateTimeToIso } from "@/utils/localDateTime";

const PAGE_SIZE = 25;

function emptyDraft() {
  return { action: "", outcome: "", correlationId: "", from: emptyLocalDateTime(), to: emptyLocalDateTime() };
}

export default function AuditLogPage() {
  const [data, setData] = useState<AuditList | null>(null);
  const [filters, setFilters] = useState<AuditFilters>({ limit: PAGE_SIZE, offset: 0 });
  const [draft, setDraft] = useState(emptyDraft);
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
    if (isPartialLocalDateTime(draft.from) || isPartialLocalDateTime(draft.to)) return;
    setFilters({ action: draft.action || undefined, outcome: draft.outcome || undefined, correlationId: draft.correlationId || undefined, from: localDateTimeToIso(draft.from), to: localDateTimeToIso(draft.to), limit: PAGE_SIZE, offset: 0 });
  }
  function reset() {
    setDraft(emptyDraft());
    setFilters({ limit: PAGE_SIZE, offset: 0 });
  }

  return <ProtectedRoute permission="audit.read"><section className="operationsPage">
    <header className="pageHeader"><p className="pageKicker">Administrator evidence</p><h1>Audit Log</h1><p>Bounded security-event search. Request bodies, credentials, cookies, and raw errors are not available here.</p></header>
    <form className="auditFilters" onSubmit={apply}>
      <label>Action<select id="audit-action" name="action" value={draft.action} onChange={(event) => setDraft({ ...draft, action: event.target.value })}><option value="">All actions</option><option value="auth.login">Login</option><option value="auth.login.failed">Login failed</option><option value="authorization.denied">Authorization denied</option><option value="report.export.requested">Report export requested</option></select></label>
      <label>Outcome<select id="audit-outcome" name="outcome" value={draft.outcome} onChange={(event) => setDraft({ ...draft, outcome: event.target.value })}><option value="">All outcomes</option><option value="success">Success</option><option value="denied">Denied</option><option value="failed">Failed</option><option value="no_change">No change</option></select></label>
      <label>Correlation ID<input id="audit-correlation" name="correlation_id" maxLength={36} value={draft.correlationId} onChange={(event) => setDraft({ ...draft, correlationId: event.target.value })} /></label>
      <NativeDateTimeFields id="audit-from" label="From UTC" name="from" onChange={(from) => setDraft({ ...draft, from })} value={draft.from} />
      <NativeDateTimeFields id="audit-to" label="To UTC" name="to" onChange={(to) => setDraft({ ...draft, to })} value={draft.to} />
      <div className="filterActions"><button type="submit">Search</button><button onClick={reset} type="button">Reset filters</button></div>
    </form>
    {loading ? <p aria-busy="true" role="status">Loading audit events…</p> : null}
    {error ? <p className="inlineAlert" role="alert">Audit events could not be loaded safely.</p> : null}
    {data && !loading ? data.items.length === 0 ? <p>No audit events match these filters.</p> : <div className="responsiveTable auditTable"><table><thead><tr><th>Time</th><th>Action</th><th>Outcome</th><th>Actor</th><th>Target</th><th>Correlation</th><th>Safe detail</th></tr></thead><tbody>{data.items.map((item) => <tr key={item.public_id}><td>{new Date(item.occurred_at).toLocaleString()}</td><td><code>{item.action}</code></td><td>{item.outcome}</td><td><span>{item.actor_type}</span><code className="identifierValue" title={item.actor_ref}>{item.actor_ref}</code></td><td><span>{item.target_type}</span><code className="identifierValue" title={item.target_ref}>{item.target_ref}</code></td><td><code className="identifierValue" title={item.correlation_id ?? undefined}>{item.correlation_id ?? "None"}</code></td><td>{item.safe_detail ? <dl className="safeDetailList">{Object.entries(item.safe_detail).map(([key, value]) => <div key={key}><dt>{key}</dt><dd>{value}</dd></div>)}</dl> : "None"}</td></tr>)}</tbody></table></div> : null}
    {data ? <div className="paginationControls"><button disabled={(filters.offset ?? 0) === 0 || loading} onClick={() => setFilters({ ...filters, offset: Math.max(0, (filters.offset ?? 0) - PAGE_SIZE) })} type="button">Previous</button><p>{data.offset + 1}–{Math.min(data.offset + data.items.length, data.total)} of {data.total}</p><button disabled={data.offset + data.items.length >= data.total || loading} onClick={() => setFilters({ ...filters, offset: (filters.offset ?? 0) + PAGE_SIZE })} type="button">Next</button></div> : null}
  </section></ProtectedRoute>;
}
