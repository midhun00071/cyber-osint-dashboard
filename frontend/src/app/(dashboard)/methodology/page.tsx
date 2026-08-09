import { ProtectedRoute } from "@/components/auth/ProtectedRoute";

export default function MethodologyPage() {
  return <ProtectedRoute><article className="methodologyPage">
    <header className="pageHeader"><p className="pageKicker">Evidence and limitations</p><h1>Methodology</h1><p>How approved defensive OSINT is normalized, attributed, classified, and presented without overstating evidence.</p></header>
    <section><h2>Defensive OSINT and approved sources</h2><p>The dashboard uses approved public cybersecurity intelligence under fixed source policies, licence, rate, quota, and path controls. Disabled or approval-gated sources do not imply live collection.</p></section>
    <section><h2>Normalization, provenance, evidence, and inference</h2><p>Stored intelligence is normalized while retaining safe source provenance. Direct evidence is distinct from analyst inference. Controlled authority, emirate, sector, and language tags support classification; keyword matches alone do not establish attribution.</p></section>
    <section><h2>UAE relevance</h2><ul><li><strong>Direct UAE evidence:</strong> authoritative or explicit UAE evidence.</li><li><strong>Potential UAE relevance:</strong> bounded evidence supports possible relevance but not direct attribution.</li><li><strong>Global relevance:</strong> material is globally relevant without a UAE-specific claim.</li><li><strong>No demonstrated UAE relevance:</strong> available evidence does not support a UAE claim.</li></ul></section>
    <section><h2>Freshness and operational state</h2><p>Fresh means a successful collection is within the policy window; stale means it is outside that window; never means no successful run is recorded; not applicable applies when policy or implementation does not produce freshness. Disabled sources remain disabled rather than appearing healthy.</p></section>
    <section><h2>Known limitations</h2><p>CVE, IOC, and threat metadata can be incomplete, delayed, revoked, or revised by publishers. Reports contain allow-listed fields only, at most 100 rows and 2 MiB. Audit access is administrator-authorized and bounded. No page proves public staging, external alert delivery, or live collection for disabled sources.</p></section>
  </article></ProtectedRoute>;
}
