"use client";

import { useCallback, useEffect, useRef, useState } from "react";

import { ProtectedRoute } from "@/components/auth/ProtectedRoute";
import { fetchSystemHealth } from "@/services/systemHealthApi";
import type { SystemHealth } from "@/types/systemHealth";

function label(value: string): string { return value.replaceAll("_", " "); }

export default function SystemHealthPage() {
  const [data, setData] = useState<SystemHealth | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(false);
  const controllerRef = useRef<AbortController | null>(null);
  const inFlight = useRef(false);

  const refresh = useCallback(async () => {
    if (inFlight.current) return;
    inFlight.current = true;
    const controller = new AbortController();
    controllerRef.current = controller;
    try {
      const result = await fetchSystemHealth(controller.signal);
      if (!controller.signal.aborted) {
        if (result.status === "success") { setData(result.data); setError(false); }
        else setError(true);
      }
    } catch (requestError) {
      if (!(requestError instanceof DOMException && requestError.name === "AbortError")) setError(true);
    } finally {
      if (!controller.signal.aborted) setLoading(false);
      inFlight.current = false;
      if (controllerRef.current === controller) controllerRef.current = null;
    }
  }, []);

  useEffect(() => {
    void refresh();
    const timer = window.setInterval(() => void refresh(), 30_000);
    return () => { window.clearInterval(timer); controllerRef.current?.abort(); };
  }, [refresh]);

  return <ProtectedRoute permission="source.read"><section className="operationsPage">
    <header className="pageHeader"><p className="pageKicker">Truthful operational state</p><h1>System Health</h1><p>Internal probes, committed source evidence, and deployment identity. Unknown or disabled states are never shown as healthy.</p></header>
    {loading && !data ? <p aria-busy="true" role="status">Loading system health…</p> : null}
    {error ? <p className="inlineAlert" role="alert">Health could not be refreshed safely.{data ? " Last known evidence remains visible." : ""}</p> : null}
    {data ? <>
      <div className={`healthSummary health-${data.status}`}><strong>Overall: {data.status}</strong><span>Generated {new Date(data.generated_at).toLocaleString()}</span><span>Version {data.version}</span><span>Commit {data.commit_sha ?? "unknown"}</span></div>
      <div className="healthComponentGrid">{data.components.map((item) => <article className={`healthComponent health-${item.status}`} key={item.name}><h2>{label(item.name)}</h2><strong>{item.status}</strong><p>{item.summary}</p>{Object.keys(item.observations).length ? <dl>{Object.entries(item.observations).map(([name, value]) => <div key={name}><dt>{label(name)}</dt><dd>{value === null ? "unknown" : String(value)}</dd></div>)}</dl> : null}</article>)}</div>
    </> : !loading && !error ? <p>No health evidence is available.</p> : null}
  </section></ProtectedRoute>;
}
