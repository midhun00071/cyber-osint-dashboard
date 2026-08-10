export function formatStatusLabel(value: string): string {
  const normalized = value.trim().toLowerCase();
  if (normalized === "success" || normalized === "succeeded") return "Succeeded";
  if (normalized === "failure" || normalized === "failed") return "Failed";
  if (normalized === "no_change") return "No change";
  return normalized
    .split("_")
    .filter(Boolean)
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
    .join(" ");
}
