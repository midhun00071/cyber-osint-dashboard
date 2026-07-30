const configuredEnvironment = (process.env.APP_ENV ?? "local")
  .trim()
  .toLowerCase();
const effectiveEnvironment =
  configuredEnvironment === "development" ? "local" : configuredEnvironment;
const supportedEnvironments = new Set([
  "local",
  "test",
  "staging",
  "production",
]);

if (!supportedEnvironments.has(effectiveEnvironment)) {
  throw new Error("APP_ENV must be local, test, staging, or production.");
}

if (process.env.NEXT_PUBLIC_APP_ENV !== undefined) {
  const configuredPublicEnvironment = process.env.NEXT_PUBLIC_APP_ENV
    .trim()
    .toLowerCase();
  const effectivePublicEnvironment =
    configuredPublicEnvironment === "development"
      ? "local"
      : configuredPublicEnvironment;
  if (
    !supportedEnvironments.has(effectivePublicEnvironment) ||
    effectivePublicEnvironment !== effectiveEnvironment
  ) {
    throw new Error(
      "NEXT_PUBLIC_APP_ENV must match the normalized APP_ENV build identity.",
    );
  }
}

const approvedPublicSettings = new Set([
  "NEXT_PUBLIC_API_BASE_URL",
  "NEXT_PUBLIC_APP_ENV",
]);
const secretLikeName =
  /(?:api[_-]?key|authorization|cookie|credential|database[_-]?url|password|private[_-]?key|secret|session|token)/i;

for (const name of Object.keys(process.env)) {
  if (!name.startsWith("NEXT_PUBLIC_") || approvedPublicSettings.has(name)) {
    continue;
  }
  if (secretLikeName.test(name)) {
    throw new Error(
      `${name} is secret-like and must not be exposed to browser code.`,
    );
  }
  throw new Error(`${name} is not an approved public setting.`);
}

const protectedEnvironment =
  effectiveEnvironment === "staging" || effectiveEnvironment === "production";
const configuredApiBaseUrl = process.env.NEXT_PUBLIC_API_BASE_URL?.trim();

function isLoopbackOrUnspecifiedHost(hostname) {
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

if (!configuredApiBaseUrl && protectedEnvironment) {
  throw new Error(
    "NEXT_PUBLIC_API_BASE_URL must be set explicitly for staging and production.",
  );
}

let normalizedApiBaseUrl = configuredApiBaseUrl || "http://localhost:8000";
try {
  const parsedApiBaseUrl = new URL(normalizedApiBaseUrl);
  if (parsedApiBaseUrl.protocol !== "http:" && parsedApiBaseUrl.protocol !== "https:") {
    throw new Error("unsupported-scheme");
  }
  if (parsedApiBaseUrl.username || parsedApiBaseUrl.password) {
    throw new Error("credentials");
  }
  if (parsedApiBaseUrl.search || parsedApiBaseUrl.hash) {
    throw new Error("query-or-fragment");
  }
  if (
    protectedEnvironment &&
    (parsedApiBaseUrl.protocol !== "https:" ||
      isLoopbackOrUnspecifiedHost(parsedApiBaseUrl.hostname))
  ) {
    throw new Error("protected-url");
  }
  normalizedApiBaseUrl = parsedApiBaseUrl.toString().replace(/\/+$/, "");
} catch {
  throw new Error(
    "NEXT_PUBLIC_API_BASE_URL must be a credential-free HTTP(S) URL; staging and production require non-loopback HTTPS.",
  );
}

/** @type {import('next').NextConfig} */
const nextConfig = {
  env: {
    NEXT_PUBLIC_APP_ENV: effectiveEnvironment,
    NEXT_PUBLIC_API_BASE_URL: normalizedApiBaseUrl,
  },
  output: "standalone",
  poweredByHeader: false,
  reactStrictMode: true,
};

export default nextConfig;
