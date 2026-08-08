import { DashboardPanel } from "@/components/dashboard/DashboardPanel";
import { VulnerabilitiesTable } from "@/components/dashboard/VulnerabilitiesTable";

export default function VulnerabilitiesPage() {
  return <div className="dashboardPage"><section className="overviewHero"><div><p className="pageKicker">Stored vulnerability intelligence</p><h1>Vulnerabilities</h1><p className="pageSubtitle">Search normalized CVEs with CVSS, EPSS, KEV, source, freshness, and UAE relevance metadata.</p></div></section><DashboardPanel className="panelFull" eyebrow="Authenticated read-only API" title="CVE intelligence"><VulnerabilitiesTable /></DashboardPanel></div>;
}
