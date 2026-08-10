import { HealthStatusCard } from "@/components/HealthStatusCard";
import { DashboardSummaryCards } from "@/components/dashboard/DashboardSummaryCards";
import { DashboardPanel } from "@/components/dashboard/DashboardPanel";
import { DashboardTrendsPanel } from "@/components/dashboard/DashboardTrendsPanel";
import { LatestArticlesFeed } from "@/components/dashboard/LatestArticlesFeed";
import { VulnerabilitiesTable } from "@/components/dashboard/VulnerabilitiesTable";

export default function DashboardOverviewPage() {
  return (
    <div className="dashboardPage">
      <section className="overviewHero" aria-labelledby="dashboard-title">
        <div>
          <p className="pageKicker">
            Backend-connected summary, trends, CVEs, and articles
          </p>
          <h1 id="dashboard-title">Cyber OSINT Dashboard</h1>
          <p className="pageSubtitle">
            KPI cards, trends, vulnerabilities, articles, health, and the
            analyst navigation load from authenticated backend endpoints and
            bounded stored records.
          </p>
        </div>
        <div className="previewCallout" aria-label="Dashboard data scope">
          <span className="previewDot" aria-hidden="true" />
          Stored backend data · no live collection
        </div>
      </section>

      <DashboardSummaryCards />

      <div className="dashboardGrid">
        <DashboardPanel
          className="panelFull"
          eyebrow="Backend stored-data trends"
          title="Recent trends"
        >
          <DashboardTrendsPanel />
        </DashboardPanel>

        <DashboardPanel
          className="panelFull"
          eyebrow="Backend CVE data"
          title="Vulnerabilities"
        >
          <VulnerabilitiesTable originPath="/" />
        </DashboardPanel>

        <DashboardPanel
          className="panelFull"
          eyebrow="Backend article data"
          title="Latest articles"
        >
          <LatestArticlesFeed originPath="/" />
        </DashboardPanel>

        <DashboardPanel eyebrow="Environment" title="Backend health">
          <HealthStatusCard />
        </DashboardPanel>

      </div>
    </div>
  );
}
