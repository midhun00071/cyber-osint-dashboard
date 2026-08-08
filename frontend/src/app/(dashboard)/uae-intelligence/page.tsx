import { UaeIntelligenceList } from "@/components/analyst/UaeIntelligenceList";
import { DashboardPanel } from "@/components/dashboard/DashboardPanel";

export default function UaeIntelligencePage() {
  return <div className="dashboardPage"><section className="overviewHero"><div><p className="pageKicker">Evidence-based regional view</p><h1>UAE Intelligence</h1><p className="pageSubtitle">Distinguish direct UAE evidence, potential relevance, global context, and records with no demonstrated UAE relevance. Controlled authority, emirate, sector, and language tags include confidence and evidence.</p></div></section><DashboardPanel className="panelFull" eyebrow="Stored metadata only" title="UAE relevance and freshness"><UaeIntelligenceList /></DashboardPanel></div>;
}
