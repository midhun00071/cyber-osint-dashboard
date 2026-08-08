import { IndicatorSearch } from "@/components/analyst/IndicatorSearch";
import { ProtectedRoute } from "@/components/auth/ProtectedRoute";
import { DashboardPanel } from "@/components/dashboard/DashboardPanel";

export default function IocSearchPage() {
  return <ProtectedRoute permission="analysis.use"><div className="dashboardPage"><section className="overviewHero"><div><p className="pageKicker">Offline defensive lookup</p><h1>IOC Search</h1><p className="pageSubtitle">Search normalized indicators already stored in the platform. Results include confidence and relationship counts; searches never probe targets or fetch external content.</p></div></section><DashboardPanel className="panelFull" eyebrow="Authenticated and rate limited" title="Indicator lookup"><IndicatorSearch /></DashboardPanel></div></ProtectedRoute>;
}
