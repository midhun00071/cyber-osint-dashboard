const UNSAFE_URL_CHARACTER = /[\s\p{Cc}\p{Cf}\p{Cs}\p{Zl}\p{Zp}]/u;

function trimSurroundingAsciiSpaces(value: string): string {
  return value.replace(/^ +| +$/g, "");
}

export function getSafeExternalUrl(value: unknown): string | null {
  if (typeof value !== "string") {
    return null;
  }

  const candidate = trimSurroundingAsciiSpaces(value);

  if (!candidate || UNSAFE_URL_CHARACTER.test(candidate)) {
    return null;
  }

  try {
    const parsed = new URL(candidate);

    if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
      return null;
    }

    if (!parsed.hostname || parsed.username || parsed.password) {
      return null;
    }

    if (parsed.port === "0") {
      return null;
    }

    const authority = candidate.match(/^[a-z][a-z0-9+.-]*:\/\/([^/?#]*)/i)?.[1];

    if (!authority || authority.includes("@") || authority.endsWith(":")) {
      return null;
    }

    return parsed.toString();
  } catch {
    return null;
  }
}
