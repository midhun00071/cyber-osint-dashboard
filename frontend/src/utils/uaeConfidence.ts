export type UaeConfidenceLevel = "High" | "Medium" | "Low";

export type UaeRelevanceDisplayStatus =
  | "confirmed"
  | "probable"
  | "possible"
  | "not_relevant"
  | "unknown";

export type UaeRelevanceDisplay = Readonly<{
  label: string;
  confidenceLevel: UaeConfidenceLevel | null;
  percentage: number | null;
}>;

function formatUaeStatus(status: UaeRelevanceDisplayStatus): string {
  if (status === "not_relevant") {
    return "Not relevant";
  }

  return status.charAt(0).toUpperCase() + status.slice(1);
}

function normalizedConfidence(confidence: number | null): number | null {
  if (confidence === null || !Number.isFinite(confidence)) {
    return null;
  }

  if (confidence < 0 || confidence > 1) {
    return null;
  }

  return confidence;
}

export function getUaeConfidenceLevel(
  confidence: number | null,
): UaeConfidenceLevel | null {
  const value = normalizedConfidence(confidence);

  if (value === null) {
    return null;
  }

  if (value >= 0.9) {
    return "High";
  }

  if (value >= 0.75) {
    return "Medium";
  }

  return "Low";
}

export function formatUaeRelevanceWithConfidence(
  status: UaeRelevanceDisplayStatus,
  confidence: number | null,
): UaeRelevanceDisplay {
  const statusLabel = formatUaeStatus(status);
  const value = normalizedConfidence(confidence);
  const confidenceLevel = getUaeConfidenceLevel(value);

  if (value === null || confidenceLevel === null) {
    return {
      label: statusLabel,
      confidenceLevel: null,
      percentage: null,
    };
  }

  const percentage = Math.round(value * 100);

  return {
    label: `${statusLabel} · ${confidenceLevel} confidence (${percentage}%)`,
    confidenceLevel,
    percentage,
  };
}
