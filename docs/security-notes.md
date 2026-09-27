# Security Notes

C06 uses Argon2id, opaque database-backed browser sessions, exact Origin and
CSRF validation, a closed role-to-permission map, account-wide session
versioning, generic login failures, and immutable audit events. Only SHA-256
session-token and CSRF-token hashes are stored. It does not implement JWT,
bearer authentication, SSO, self-registration, or a frontend bypass.

Backend authorization is authoritative. Content routes require `content.read`;
user-management routes and audit search are Administrator-only. Hiding a
frontend button is not authorization. C07 implements frontend login,
authenticated bootstrap, protected navigation, and permission-aware controls.
Repository validation does not provision a real staging account or execute the
manual bootstrap CLI. SSO remains absent and approval-gated.

## Purpose

This document tracks security decisions and safeguards for Cyber Sentinel, a Cybersecurity OSINT Dashboard.

## Core Security Principles

- Do not commit real .env files.
- Do not hardcode API keys, passwords, tokens, or credentials.
- Use environment variables for configuration.
- Validate backend query parameters.
- Use safe database access through ORM or parameterized queries.
- Render external text safely in the frontend.
- Log errors without exposing secrets.
- Use approved public data sources only.
- Do not download malware samples or unsafe files.
- Keep the project defensive and educational.

## Environment Variable Handling

Example files:

- .env.example
- backend/.env.example
- frontend/.env.example

Real local environment files must remain untracked by Git.

## Docker Security

Dockerfiles should:

- Avoid copying real .env files.
- Use .dockerignore files.
- Run application services as non-root users where practical.
- Avoid embedding secrets into images.

## Backend Security

Implemented backend controls:

- Pydantic validation.
- Controlled error responses.
- Centralized allow-listed application logging.
- Server-generated request IDs and sanitized unexpected-error handling.
- CORS restricted to validated exact frontend origins.
- Request timeouts for external sources.

P5-02 uses `BACKEND_CORS_ALLOWED_ORIGINS` as the single comma-separated origin
allow-list. Development defaults are exactly `http://localhost:3000` and
`http://127.0.0.1:3000`. Production mode requires explicitly configured HTTPS
origins. Production also rejects `localhost`, `.localhost` subdomains, and
IPv4/IPv6 loopback addresses. Origins with wildcards, paths, queries, fragments,
user information, unsupported schemes, malformed ports, empty entries, or
control, format, whitespace, or non-printable characters fail before URL
parsing; configuration never falls back to allow-all. Default HTTP port `80`
and HTTPS port `443` are removed during normalization, non-default ports are
preserved, and IP addresses use canonical representation.

The credentialed browser policy permits only `GET`, `POST`, `PATCH`, and
`OPTIONS`. Configured request headers are `Content-Type` and `X-CSRF-Token`;
Starlette also advertises its standard safelisted headers. `Authorization`,
wildcard origins, wildcard methods, and wildcard request headers are not
granted. The middleware returns the exact configured origin and
`Access-Control-Allow-Credentials: true` only for an approved origin.

Unsafe authenticated requests require exact Origin validation and a matching
CSRF cookie/header token. Session cookies are HttpOnly; the separate CSRF cookie
is non-HttpOnly. Both are `SameSite=Strict`, and staging/production require
`Secure` cookies.

The backend adds these headers to successful API responses, CORS preflight,
and handled `404`, `422`, and `500` responses:

- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: DENY`
- `Referrer-Policy: no-referrer`
- `Permissions-Policy: camera=(), microphone=(), geolocation=()`
- `Content-Security-Policy: default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'`

FastAPI's enabled `/docs` and `/redoc` HTML routes receive the first four
headers but omit the strict API CSP because that policy would block the
framework's existing interactive documentation assets. This exception is
route-specific and does not weaken API responses.

`Strict-Transport-Security` is not emitted. The repository has no established
trusted HTTPS-termination or reverse-proxy design, so setting HSTS locally or
using an untrusted `X-Forwarded-Proto` value would be unsafe. HSTS remains
deferred until production HTTPS assumptions and trusted proxy handling are
implemented and documented.

### Request logging and unexpected errors

P5-04 owns one standard-library handler under the `app` logger namespace.
`LOG_LEVEL` supports `DEBUG`, `INFO`, `WARNING`, `ERROR`, and `CRITICAL`, with
`INFO` as the development, test, and production default. Unsupported values fail
configuration without echoing the rejected value. Production also rejects
`DEBUG=true`, and application request events replace Uvicorn's raw access log so
query values are not recorded.

Each request receives a fresh server-generated canonical UUID. An incoming
`X-Request-ID` is never trusted or reused; the generated value is returned in
the `X-Request-ID` response header. Request events contain only `event`,
`request_id`, an allow-listed `method`, the matched internal `route` template or
`unmatched`, `status_code`, and `duration_ms`. Server failures additionally use
the stable category `handled_server_error` or `unexpected_exception`.

Request and response bodies, raw paths and query values, headers, cookies,
authorization and API-key values, database URLs, environment mappings, raw
external payloads, client addresses, exception messages, and tracebacks are not
included. Unexpected request-time failures return the deterministic body
`{"detail":"An unexpected server error occurred."}` while retaining the
request ID, applicable CORS behavior, and P5-02 security headers. Existing P5-01
validation and route-specific handled-error bodies remain stable. No detailed
exception traces, remote telemetry, SIEM export, or log shipping are enabled.

Still planned:

- Admin ingestion endpoint protection if such endpoints are introduced.

## Frontend Security

Implemented P5-03 controls:

- Do not store secrets in frontend variables.
- Only use NEXT_PUBLIC_ variables for safe public values.
- Render external feed and API strings as React text rather than raw HTML.
- Centrally validate external URLs and allow only absolute HTTP or HTTPS links.
- Reject credentials, unsafe schemes, malformed hosts or ports, and control,
  format, whitespace, or other non-printable URL characters.
- Render rejected external-link labels as non-clickable text.
- Use `rel="noopener noreferrer"` for external links opened in a new tab.

These frontend controls are defense in depth and do not replace safe backend
ingestion, normalization, validation, or storage. Raw feed HTML remains
untrusted and is not rendered. The P5-02 API Content Security Policy remains a
separate response-layer control.

## Current Status

P5-02/C06 credentialed CORS and HTTP response-header hardening, P5-03 frontend
content-rendering hardening, P5-04 safe logging/request correlation, and C06
authentication, RBAC, user administration, and audit search are implemented.
A broader structured error envelope, remote telemetry, edge rate limiting, and
future ingestion-control administration remain deferred.

The four C05 public-source adapters remain disabled and unscheduled; the
production `DEFAULT_SOURCE_HANDLERS` mapping remains empty.

## C07 operations security boundary

C07 extends the C06 opaque-session, exact-Origin, CSRF, and backend permission
boundary to source and ingestion operations. Reads are allow-listed and
non-cacheable. Mutations reject extra fields, never replay automatically, and
commit state/evidence atomically. Manual acceptance uses the existing bounded
idempotency-key derivation; retry uses deterministic nonbranching lineage.
Audit actions, target types, outcomes, and safe-detail fields remain closed.
Credential references, raw progress values, cookies, tokens, idempotency keys,
provider data, SQL, exceptions, and stack traces are not exposed.

Frontend 401 handling expires the session; 403 handling preserves the valid
principal and presents access denied for the current route. Role-aware links
and buttons are defense in depth only. The production handler registry remains
empty and the four C05 sources remain disabled and unscheduled. See
[C07 authenticated operations experience](c07-authenticated-operations-experience.md).

## C09 operations and recovery security boundary

Reports enforce backend permissions, CSRF, strict enums/limits, allow-listed
fields, CSV formula neutralization, plain-string PDF rendering, output ceilings,
and fail-closed audit commit. Health uses only fixed internal Prefect URLs and
does not accept probe targets. Metrics are private and fixed-label. Caddy uses
an exact host, HTTPS-only HSTS, bounded bodies/timeouts, browser security
headers, and no routing to internal services.

Backup writes no plaintext dump/archive at rest, validates bounded non-symlink
secret files, rejects privileged backup identities, uses SHA-256 metadata, and
restores only to strict isolated targets. Prefect backup requires quiescence and
restore rejects traversal/links/devices. Missing backup evidence is alertable,
not fabricated. No public staging, external receiver, off-host transfer, or
RPO/RTO achievement is claimed.
