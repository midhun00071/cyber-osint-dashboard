const UNSAFE_URL_CHARACTER = /[\\\s\p{Cc}\p{Cf}\p{Cs}\p{Zl}\p{Zp}]/u;
const MALFORMED_PERCENT_ESCAPE = /%(?![0-9a-f]{2})/i;
const ENCODED_CONTROL_BYTE = /%(?:0[0-9a-f]|1[0-9a-f]|7f|8[0-9a-f]|9[0-9a-f])/i;
const ASCII_AUTHORITY = /^[\x21-\x7e]+$/;

export function getSafeExternalUrl(value: unknown): string | null {
  if (typeof value !== "string") {
    return null;
  }

  const candidate = value;

  if (
    !candidate ||
    UNSAFE_URL_CHARACTER.test(candidate) ||
    MALFORMED_PERCENT_ESCAPE.test(candidate) ||
    ENCODED_CONTROL_BYTE.test(candidate)
  ) {
    return null;
  }

  try {
    const parsed = new URL(candidate);

    if (parsed.protocol !== "https:") {
      return null;
    }

    if (!parsed.hostname || parsed.username || parsed.password) {
      return null;
    }

    if (parsed.port) {
      return null;
    }

    const authority = candidate.match(/^[a-z][a-z0-9+.-]*:\/\/([^/?#]*)/i)?.[1];

    if (
      !authority ||
      !ASCII_AUTHORITY.test(authority) ||
      authority.includes("@") ||
      authority.includes("%") ||
      authority.endsWith(":")
    ) {
      return null;
    }

    return parsed.toString();
  } catch {
    return null;
  }
}
