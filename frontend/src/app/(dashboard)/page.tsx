import { HealthStatusCard } from "@/components/HealthStatusCard";
import { DashboardSummaryCards } from "@/components/dashboard/DashboardSummaryCards";
import { DashboardPanel } from "@/components/dashboard/DashboardPanel";
import { StatusBadge } from "@/components/dashboard/StatusBadge";
import { VulnerabilitiesTable } from "@/components/dashboard/VulnerabilitiesTable";
import {
  collectionOverview,
  operationalStatuses,
  previewIntelligenceItems,
} from "@/data/dashboardPreview";
import type { IntelligencePreviewItem } from "@/types/dashboard";

function isApprovedExternalUrl(url: string): boolean {
  try {
    const parsedUrl = new URL(url);

    return (
      parsedUrl.protocol === "https:" &&
      ["example.com", "example.org", "example.net"].includes(parsedUrl.hostname)
    );
  } catch {
    return false;
  }
}

function RecentIntelligenceList({
  items,
}: Readonly<{
  items: readonly IntelligencePreviewItem[];
}>) {
  if (items.length === 0) {
    return (
      <div className="emptyState">
        <p className="panelEyebrow">Empty state</p>
        <h3>No synthetic intelligence records to preview</h3>
        <p>
          Once local preview data is available, recent defensive intelligence
          records will appear here.
        </p>
      </div>
    );
  }

  return (
    <div className="intelList">
      {items.map((item) => (
        <article className="intelCard" key={item.id}>
          <div className="intelCardHeader">
            <StatusBadge label={item.severity} tone={item.severity} />
            <span className="intelMeta">{item.categoryLabel}</span>
          </div>
          <h3>{item.title}</h3>
          <p>{item.summary}</p>
          <div className="intelCardFooter">
            <StatusBadge label={item.exploitationLabel} tone={item.exploitation} />
            {item.uaeRelevant ? (
              <StatusBadge label="UAE defensive relevance" tone="uae" />
            ) : null}
          </div>
          {item.sourceUrl && isApprovedExternalUrl(item.sourceUrl) ? (
            <a
              className="safeSourceLink"
              href={item.sourceUrl}
              rel="noreferrer noopener"
              target="_blank"
            >
              View safe example source
            </a>
          ) : null}
        </article>
      ))}
    </div>
  );
}

export default function DashboardOverviewPage() {
  return (
    <div className="dashboardPage">
      <section className="overviewHero" aria-labelledby="dashboard-title">
        <div>
          <p className="pageKicker">Backend-connected summary and CVEs</p>
          <h1 id="dashboard-title">Cyber OSINT Dashboard</h1>
          <p className="pageSubtitle">
            KPI cards load from the backend summary endpoint, and the
            vulnerabilities table loads from the read-only intelligence API.
            Preview sections remain synthetic until their data views are
            connected.
          </p>
        </div>
        <div className="previewCallout" aria-label="Preview data scope">
          <span className="previewDot" aria-hidden="true" />
          KPI cards and CVEs use backend data
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
          className="panelWide"
          eyebrow="Recent intelligence"
          title="Preview feed"
        >
          <RecentIntelligenceList items={previewIntelligenceItems} />
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
