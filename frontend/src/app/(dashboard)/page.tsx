import { HealthStatusCard } from "@/components/HealthStatusCard";
import { DashboardSummaryCards } from "@/components/dashboard/DashboardSummaryCards";
import { DashboardPanel } from "@/components/dashboard/DashboardPanel";
import { LatestArticlesFeed } from "@/components/dashboard/LatestArticlesFeed";
import { StatusBadge } from "@/components/dashboard/StatusBadge";
import { VulnerabilitiesTable } from "@/components/dashboard/VulnerabilitiesTable";
import { collectionOverview, operationalStatuses } from "@/data/dashboardPreview";

export default function DashboardOverviewPage() {
  return (
    <div className="dashboardPage">
      <section className="overviewHero" aria-labelledby="dashboard-title">
        <div>
          <p className="pageKicker">Backend-connected summary, CVEs, and articles</p>
          <h1 id="dashboard-title">Cyber OSINT Dashboard</h1>
          <p className="pageSubtitle">
            KPI cards load from the backend summary endpoint, vulnerabilities
            load from the read-only intelligence API, and latest articles load
            from the read-only article feed. Remaining preview sections stay
            clearly labeled until their data views are connected.
          </p>
        </div>
        <div className="previewCallout" aria-label="Preview data scope">
          <span className="previewDot" aria-hidden="true" />
          KPI cards, CVEs, and articles use backend data
        </div>
      </section>

      <DashboardSummaryCards />

      <div className="dashboardGrid">
        <DashboardPanel
          className="panelFull"
          eyebrow="Backend CVE data"
          title="Vulnerabilities"
        >
          <VulnerabilitiesTable />
        </DashboardPanel>

        <DashboardPanel
          className="panelFull"
          eyebrow="Backend article data"
          title="Latest articles"
        >
          <LatestArticlesFeed />
        </DashboardPanel>

        <DashboardPanel eyebrow="Environment" title="Backend health">
          <HealthStatusCard />
        </DashboardPanel>

        <DashboardPanel eyebrow="Operations" title="Operational status">
          <div className="statusList">
            {operationalStatuses.map((status) => (
              <div className="statusRow" key={status.label}>
                <div>
                  <h3>{status.label}</h3>
                  <p>{status.description}</p>
                </div>
                <StatusBadge label={status.stateLabel} tone={status.tone} />
              </div>
            ))}
          </div>
        </DashboardPanel>

        <DashboardPanel eyebrow="Collection" title="Source overview">
          <div className="collectionGrid">
            {collectionOverview.map((item) => (
              <div className="collectionMetric" key={item.label}>
                <span>{item.value}</span>
                <p>{item.label}</p>
              </div>
            ))}
          </div>
          <p className="panelNote">
            These values describe the deterministic P1-12 synthetic development
            dataset. No database query is performed by this frontend shell.
          </p>
        </DashboardPanel>

        <DashboardPanel
          className="panelWide"
          eyebrow="Scope"
          title="Defensive workflow preview"
        >
          <div className="workflowGrid">
            <div>
              <h3>Normalize</h3>
              <p>
                Preview records are grouped by type, severity, exploitation
                state, and regional relevance.
              </p>
            </div>
            <div>
              <h3>Review</h3>
              <p>
                Analysts can scan summaries and safe example-source links while
                full filtering remains planned.
              </p>
            </div>
            <div>
              <h3>Report</h3>
              <p>
                Future reporting surfaces can build on this shell without
                changing the defensive preview boundaries.
              </p>
            </div>
          </div>
        </DashboardPanel>
      </div>
    </div>
  );
}
