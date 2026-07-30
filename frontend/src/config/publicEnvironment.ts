export type PublicEnvironmentIdentity =
  | "local"
  | "test"
  | "staging"
  | "production";

export type PublicEnvironment = Readonly<{
  apiBaseUrl: string;
}>;

type EnvironmentValues = Readonly<Record<string, string | undefined>>;

const LOCAL_API_FALLBACK = "http://localhost:8000";
const APPROVED_PUBLIC_SETTINGS = new Set([
  "NEXT_PUBLIC_API_BASE_URL",
  "NEXT_PUBLIC_APP_ENV",
]);
const SUPPORTED_ENVIRONMENTS = new Set([
  "local",
  "test",
  "staging",
  "production",
  "development",
]);
const SECRET_LIKE_NAME =
  /(?:api[_-]?key|authorization|cookie|credential|database[_-]?url|password|private[_-]?key|secret|session|token)/i;

export function normalizePublicEnvironmentIdentity(
  value: string,
): PublicEnvironmentIdentity {
  const normalized = value.trim().toLowerCase();

  if (!normalized) {
    throw new Error("APP_ENV must not be blank.");
  }
  if (!SUPPORTED_ENVIRONMENTS.has(normalized)) {
    throw new Error(
      "APP_ENV must be local, test, staging, or production.",
    );
  }

  return normalized === "development"
    ? "local"
    : (normalized as PublicEnvironmentIdentity);
}

function validatePublicSettingNames(environment: EnvironmentValues): void {
  for (const name of Object.keys(environment)) {
    if (!name.startsWith("NEXT_PUBLIC_") || APPROVED_PUBLIC_SETTINGS.has(name)) {
      continue;
    }

    if (SECRET_LIKE_NAME.test(name)) {
      throw new Error(
        `${name} is secret-like and must not be exposed to browser code.`,
      );
    }

    throw new Error(`${name} is not an approved public setting.`);
  }
}

function normalizeApiBaseUrl(
  configuredValue: string | undefined,
  environment: PublicEnvironmentIdentity,
): string {
  const configured = configuredValue?.trim();
  const protectedEnvironment =
    environment === "staging" || environment === "production";

  if (!configured) {
    if (protectedEnvironment) {
      throw new Error(
        "NEXT_PUBLIC_API_BASE_URL must be set explicitly for staging and production.",
      );
    }
    return LOCAL_API_FALLBACK;
  }

  let parsed: URL;
  try {
    parsed = new URL(configured);
  } catch {
    throw new Error("NEXT_PUBLIC_API_BASE_URL must be a valid URL.");
  }

  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
    throw new Error("NEXT_PUBLIC_API_BASE_URL must use HTTP or HTTPS.");
  }
  if (parsed.username || parsed.password) {
    throw new Error(
      "NEXT_PUBLIC_API_BASE_URL must not contain credentials.",
    );
  }
  if (parsed.search || parsed.hash) {
    throw new Error(
      "NEXT_PUBLIC_API_BASE_URL must not contain a query or fragment.",
    );
  }
  if (protectedEnvironment && parsed.protocol !== "https:") {
    throw new Error(
      "NEXT_PUBLIC_API_BASE_URL must use HTTPS in staging and production.",
    );
  }
  if (protectedEnvironment && isLoopbackOrUnspecifiedHost(parsed.hostname)) {
    throw new Error(
      "NEXT_PUBLIC_API_BASE_URL must use a non-loopback host in staging and production.",
    );
  }

  return parsed.toString().replace(/\/+$/, "");
}

function isLoopbackOrUnspecifiedHost(hostname: string): boolean {
  const unbracketedHost = hostname.toLowerCase().replace(/^\[|\]$/g, "");
  const host = unbracketedHost.replace(/\.+$/, "");
  return (
    host === "localhost" ||
    host.endsWith(".localhost") ||
    host === "::" ||
    host === "::1" ||
    host.startsWith("::ffff:") ||
    host === "0.0.0.0" ||
    host.startsWith("127.")
  );
}

export function validatePublicEnvironment(
  environmentValues: EnvironmentValues,
): PublicEnvironment {
  validatePublicSettingNames(environmentValues);
  const configuredIdentity = environmentValues.NEXT_PUBLIC_APP_ENV;
  if (configuredIdentity === undefined) {
    throw new Error("NEXT_PUBLIC_APP_ENV must be set by the frontend build.");
  }
  const environment = normalizePublicEnvironmentIdentity(configuredIdentity);

  return Object.freeze({
    apiBaseUrl: normalizeApiBaseUrl(
      environmentValues.NEXT_PUBLIC_API_BASE_URL,
      environment,
    ),
  });
}
