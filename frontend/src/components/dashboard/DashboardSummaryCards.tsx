"use client";

import { useEffect, useMemo, useState } from "react";

import { KpiCard } from "@/components/dashboard/KpiCard";
import { fetchDashboardSummary } from "@/services/dashboardSummaryApi";
import type { KpiTone } from "@/types/dashboard";
import type { DashboardSummary } from "@/types/dashboardSummary";

type SummaryCardsState =
  | { status: "loading" }
  | { status: "success"; data: DashboardSummary }
  | { status: "error" };

type SummaryKpi = Readonly<{
  description: string;
  label: string;
  tone: KpiTone;
  value: string;
}>;

function formatCount(value: number): string {
  return Math.trunc(value).toLocaleString();
}

function buildSummaryKpis(summary: DashboardSummary): readonly SummaryKpi[] {
  const { metrics } = summary;

  return [
    {
      label: "Critical vulnerabilities",
      value: formatCount(metrics.critical_vulnerability_count),
      description: "Active stored CVEs with critical severity",
      tone: "critical",
    },
    {
      label: "KEV-listed CVEs",
      value: formatCount(metrics.kev_vulnerability_count),
      description: "Active vulnerabilities listed by CISA KEV",
      tone: "warning",
    },
    {
      label: "Active articles",
      value: formatCount(metrics.active_article_count),
      description: "Stored active advisories, news, and reports",
      tone: "neutral",
    },
    {
      label: "UAE-related items",
      value: formatCount(metrics.uae_related_item_count),
      description: "Confirmed or probable UAE relevance",
      tone: "success",
    },
  ] as const;
}

function SummaryCardPlaceholder({
  description,
  label,
}: Readonly<{ description: string; label: string }>) {
  return (
    <article className="kpiCard kpiCard-neutral" aria-busy="true">
      <p>{label}</p>
      <strong>--</strong>
      <span>{description}</span>
      <small>Loading backend summary</small>
    </article>
  );
}

const loadingCards: readonly Pick<SummaryKpi, "description" | "label">[] = [
  {
    label: "Critical vulnerabilities",
    description: "Active stored CVEs with critical severity",
  },
  {
    label: "KEV-listed CVEs",
    description: "Active vulnerabilities listed by CISA KEV",
  },
  {
    label: "Active articles",
    description: "Stored active advisories, news, and reports",
  },
  {
    label: "UAE-related items",
    description: "Confirmed or probable UAE relevance",
  },
] as const;

export function DashboardSummaryCards() {
  const [state, setState] = useState<SummaryCardsState>({ status: "loading" });

  useEffect(() => {
    const controller = new AbortController();

    async function loadSummary() {
      try {
        const result = await fetchDashboardSummary(controller.signal);

        if (result.status === "success") {
          setState({ status: "success", data: result.data });
          return;
        }

        setState({ status: "error" });
      } catch (error: unknown) {
        if (error instanceof DOMException && error.name === "AbortError") {
          return;
        }

        setState({ status: "error" });
      }
    }

    void loadSummary();

    return () => controller.abort();
  }, []);

  const kpis = useMemo(
    () => (state.status === "success" ? buildSummaryKpis(state.data) : []),
    [state],
  );

  if (state.status === "loading") {
    return (
      <section
        className="kpiGrid"
        aria-busy="true"
        aria-label="Dashboard summary KPI cards"
      >
        {loadingCards.map((card) => (
          <SummaryCardPlaceholder
            description={card.description}
            key={card.label}
            label={card.label}
          />
        ))}
      </section>
    );
  }

  if (state.status === "error") {
    return (
      <section className="kpiGrid" aria-label="Dashboard summary KPI cards">
        <div className="kpiErrorState" role="status">
          <p className="panelEyebrow">Dashboard summary</p>
          <h2>Summary unavailable</h2>
          <p>
            The KPI cards could not load from the backend summary endpoint.
            Existing preview sections remain available below.
          </p>
        </div>
      </section>
    );
  }

  return (
    <section className="kpiGrid" aria-label="Dashboard summary KPI cards">
      {kpis.map((kpi) => (
        <KpiCard
          description={kpi.description}
          key={kpi.label}
          label={kpi.label}
          sourceLabel="Backend summary"
          tone={kpi.tone}
          value={kpi.value}
        />
      ))}
    </section>
  );
}
