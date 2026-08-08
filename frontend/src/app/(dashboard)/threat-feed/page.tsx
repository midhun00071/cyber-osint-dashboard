import { ThreatMetadataList } from "@/components/analyst/ThreatMetadataList";
import { DashboardPanel } from "@/components/dashboard/DashboardPanel";
import { LatestArticlesFeed } from "@/components/dashboard/LatestArticlesFeed";

export default function ThreatFeedPage() {
  return <div className="dashboardPage"><section className="overviewHero"><div><p className="pageKicker">Stored defensive intelligence</p><h1>Threat Feed</h1><p className="pageSubtitle">Review normalized publications and validated threat-entity metadata with source evidence. This page performs no live collection.</p></div></section><div className="dashboardGrid"><DashboardPanel className="panelFull" eyebrow="Bounded stored-data API" title="Publications"><LatestArticlesFeed /></DashboardPanel><DashboardPanel className="panelFull" eyebrow="Validated STIX metadata" title="Threat entities"><ThreatMetadataList /></DashboardPanel></div></div>;
}
