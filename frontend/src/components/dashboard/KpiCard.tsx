import type { KpiTone } from "@/types/dashboard";

type KpiCardProps = Readonly<{
  description: string;
  label: string;
  sourceLabel?: string;
  tone: KpiTone;
  value: string;
}>;

export function KpiCard({
  description,
  label,
  sourceLabel = "Synthetic preview data",
  tone,
  value,
}: KpiCardProps) {
  return (
    <article className={`kpiCard kpiCard-${tone}`}>
      <p>{label}</p>
      <strong>{value}</strong>
      <span>{description}</span>
      <small>{sourceLabel}</small>
    </article>
  );
}
