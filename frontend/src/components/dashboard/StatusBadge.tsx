import type { BadgeTone } from "@/types/dashboard";

type StatusBadgeProps = Readonly<{
  label: string;
  tone: BadgeTone;
}>;

export function StatusBadge({ label, tone }: StatusBadgeProps) {
  return <span className={`statusBadge statusBadge-${tone}`}>{label}</span>;
}
