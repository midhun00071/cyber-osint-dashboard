import type {
  CollectionMetric,
  IntelligencePreviewItem,
  KpiPreview,
  OperationalStatus,
} from "@/types/dashboard";

export const dashboardKpis: readonly KpiPreview[] = [
  {
    label: "Total intelligence items",
    value: "10",
    description: "P1-12 synthetic dataset total",
    tone: "neutral",
  },
  {
    label: "Critical severity",
    value: "1",
    description: "Preview item marked critical",
    tone: "critical",
  },
  {
    label: "Known exploited",
    value: "2",
    description: "Fictional preview exploitation state",
    tone: "warning",
  },
  {
    label: "UAE-relevant items",
    value: "3",
    description: "Fictional defensive regional relevance",
    tone: "success",
  },
] as const;

export const previewIntelligenceItems: readonly IntelligencePreviewItem[] = [
  {
    id: "alpha-preview-vulnerability-001",
    title: "Fictional gateway validation flaw under review",
    summary:
      "Synthetic vulnerability record for analyst triage practice. The summary describes defensive review priority without exploit steps or payload detail.",
    category: "vulnerability",
    categoryLabel: "Vulnerability",
    severity: "Critical",
    exploitation: "known_exploited",
    exploitationLabel: "Known exploited",
    uaeRelevant: true,
    sourceUrl: "https://example.com/security/advisory",
  },
  {
    id: "alpha-preview-advisory-002",
    title: "Example vendor publishes hardening advisory",
    summary:
      "Fictional security advisory reminding teams to verify exposed management interfaces, review access policy, and prioritize supported versions.",
    category: "security_advisory",
    categoryLabel: "Security advisory",
    severity: "High",
    exploitation: "not_known_exploited",
    exploitationLabel: "Not known exploited",
    uaeRelevant: false,
    sourceUrl: "https://example.org/advisories/hardening",
  },
  {
    id: "alpha-preview-news-003",
    title: "Regional defensive monitoring notes phishing trend",
    summary:
      "Synthetic cyber news item for UAE-focused awareness. It contains only defensive monitoring context and no phishing content or instructions.",
    category: "cyber_news",
    categoryLabel: "Cyber news",
    severity: "Medium",
    exploitation: "unknown",
    exploitationLabel: "Exploitation unknown",
    uaeRelevant: true,
    sourceUrl: "https://example.net/news/defensive-awareness",
  },
  {
    id: "alpha-preview-report-004",
    title: "Threat report summarizes cloud control-plane exposure",
    summary:
      "Fictional threat report preview describing common configuration-review themes for public cloud environments and audit planning.",
    category: "threat_report",
    categoryLabel: "Threat report",
    severity: "Low",
    exploitation: "not_known_exploited",
    exploitationLabel: "Not known exploited",
    uaeRelevant: false,
  },
  {
    id: "alpha-preview-uae-alert-005",
    title: "UAE defensive alert highlights patch prioritization",
    summary:
      "Synthetic regional alert for practicing prioritization of internet-facing services, asset ownership review, and safe stakeholder reporting.",
    category: "uae_defensive_alert",
    categoryLabel: "UAE defensive alert",
    severity: "High",
    exploitation: "known_exploited",
    exploitationLabel: "Known exploited",
    uaeRelevant: true,
  },
] as const;

export const operationalStatuses: readonly OperationalStatus[] = [
  {
    label: "Backend API",
    description: "Health card performs the live safe availability check.",
    stateLabel: "Checked separately",
    tone: "info",
  },
  {
    label: "Data ingestion",
    description: "Collectors remain out of scope for this frontend shell.",
    stateLabel: "Planned",
    tone: "neutral",
  },
  {
    label: "Search",
    description: "Header search is a nonfunctional visual placeholder.",
    stateLabel: "Coming soon",
    tone: "warning",
  },
] as const;

export const collectionOverview: readonly CollectionMetric[] = [
  { label: "Sources", value: "4" },
  { label: "Tags", value: "12" },
  { label: "Identifiers", value: "14" },
  { label: "Vulnerabilities", value: "4" },
  { label: "Source records", value: "10" },
  { label: "Item-tag associations", value: "36" },
] as const;
