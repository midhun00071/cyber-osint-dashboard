export type DetailReturn = Readonly<{
  href: string;
  label: string;
}>;

const RETURN_LABELS: Readonly<Record<string, string>> = {
  "/": "Back to Overview",
  "/threat-feed": "Back to Threat Feed",
  "/uae-intelligence": "Back to UAE Intelligence",
  "/vulnerabilities": "Back to Vulnerabilities",
};

function canonicalReturnPath(value: string | null): string | null {
  if (!value || !value.startsWith("/") || value.startsWith("//") || value.includes("\\")) {
    return null;
  }

  try {
    const parsed = new URL(value, "https://dashboard.invalid");
    if (parsed.origin !== "https://dashboard.invalid" || parsed.hash) return null;
    if (!Object.hasOwn(RETURN_LABELS, parsed.pathname)) return null;
    return `${parsed.pathname}${parsed.search}`;
  } catch {
    return null;
  }
}

export function buildDetailHref(
  detailPath: string,
  returnPath: string,
): string {
  const safeReturn = canonicalReturnPath(returnPath);
  if (!safeReturn) return detailPath;
  const params = new URLSearchParams({ returnTo: safeReturn });
  return `${detailPath}?${params.toString()}`;
}

export function getDetailReturn(
  search: string,
  fallbackPath: "/threat-feed" | "/vulnerabilities",
): DetailReturn {
  const requested = canonicalReturnPath(new URLSearchParams(search).get("returnTo"));
  const href = requested ?? fallbackPath;
  const pathname = new URL(href, "https://dashboard.invalid").pathname;
  return { href, label: RETURN_LABELS[pathname] ?? RETURN_LABELS[fallbackPath] };
}
