export type Severity = "Critical" | "High" | "Medium" | "Low";

export type IntelligenceCategory =
  | "vulnerability"
  | "security_advisory"
  | "cyber_news"
  | "threat_report"
  | "uae_defensive_alert";

export type ExploitationState =
  | "known_exploited"
  | "not_known_exploited"
  | "unknown";

export type KpiTone = "neutral" | "critical" | "warning" | "success";

export type BadgeTone =
  | Severity
  | ExploitationState
  | "info"
  | "success"
  | "warning"
  | "critical"
  | "neutral"
  | "uae";

export type KpiPreview = {
  description: string;
  label: string;
  tone: KpiTone;
  value: string;
};

export type IntelligencePreviewItem = {
  category: IntelligenceCategory;
  categoryLabel: string;
  exploitation: ExploitationState;
  exploitationLabel: string;
  id: string;
  severity: Severity;
  sourceUrl?: string;
  summary: string;
  title: string;
  uaeRelevant: boolean;
};

export type OperationalStatus = {
  description: string;
  label: string;
  stateLabel: string;
  tone: BadgeTone;
};

export type CollectionMetric = {
  label: string;
  value: string;
};
