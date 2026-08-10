"use client";

import { useEffect, useState } from "react";

import { ProtectedRoute } from "@/components/auth/ProtectedRoute";
import { useAuth } from "@/components/auth/AuthProvider";
import { exportReport, fetchReportCatalog } from "@/services/reportsApi";
import type { ReportCatalog, ReportFormat, ReportType } from "@/types/report";

export default function ReportsPage() {
  const { hasPermission } = useAuth();
  const [catalog, setCatalog] = useState<ReportCatalog | null>(null);
  const [reportType, setReportType] = useState<ReportType>("uae_intelligence");
  const [format, setFormat] = useState<ReportFormat>("csv");
  const [limit, setLimit] = useState(50);
  const [loading, setLoading] = useState(true);
  const [downloading, setDownloading] = useState(false);
  const [error, setError] = useState(false);

  useEffect(() => {
    const controller = new AbortController();
    void fetchReportCatalog(controller.signal).then((result) => {
      if (controller.signal.aborted) return;
      if (result.status === "success") setCatalog(result.data);
      else setError(true);
      setLoading(false);
    }).catch(() => { if (!controller.signal.aborted) { setError(true); setLoading(false); } });
    return () => controller.abort();
  }, []);

  async function download() {
    setDownloading(true);
    setError(false);
    const result = await exportReport({ report_type: reportType, format, limit });
    if (result.status === "success") {
      const url = URL.createObjectURL(result.data.blob);
      const anchor = document.createElement("a");
      anchor.href = url;
      anchor.download = result.data.filename;
      anchor.click();
      window.setTimeout(() => URL.revokeObjectURL(url), 0);
    } else setError(true);
    setDownloading(false);
  }

  return <ProtectedRoute permission="report.read"><section className="operationsPage">
    <header className="pageHeader"><p className="pageKicker">Bounded analyst exports</p><h1>Reports</h1><p>Exports are generated on the server from allow-listed fields. Each file is limited to 100 rows and 2 MiB.</p></header>
    {loading ? <p aria-busy="true" role="status">Loading report catalog…</p> : null}
    {error ? <p className="inlineAlert" role="alert">The report service could not complete the request safely.</p> : null}
    {catalog ? <form className="c09Form" onSubmit={(event) => { event.preventDefault(); void download(); }}>
      <label>Report type<select id="report-type" name="report_type" value={reportType} onChange={(event) => setReportType(event.target.value as ReportType)}>{catalog.reports.map((item) => <option key={item.report_type} value={item.report_type}>{item.label}</option>)}</select></label>
      <label>Format<select id="report-format" name="format" value={format} onChange={(event) => setFormat(event.target.value as ReportFormat)}><option value="csv">CSV</option><option value="pdf">PDF</option></select></label>
      <label>Row limit<input id="report-limit" name="limit" type="number" min={1} max={catalog.maximum_rows} value={limit} onChange={(event) => setLimit(Math.min(100, Math.max(1, Number(event.target.value))))} /></label>
      {hasPermission("report.export") ? <button disabled={downloading} type="submit">{downloading ? "Preparing download…" : "Export report"}</button> : <p>You can view report options but do not have export permission.</p>}
    </form> : null}
  </section></ProtectedRoute>;
}
