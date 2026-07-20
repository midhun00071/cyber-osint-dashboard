# Security Notes

## Purpose

This document tracks security decisions and safeguards for the Cyber OSINT Dashboard / Alpha Data project.

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
- Safe logging.
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

The browser method policy permits only `GET`, configures no additional
non-safelisted request headers, and keeps credentials disabled. Starlette's
standard CORS safelist advertises `Accept`, `Accept-Language`, `Content-Language`,
and `Content-Type`; wildcard, authorization, and unsupported custom headers are
not granted. `Content-Type` does not enable write endpoints because only `GET`
is allowed. The middleware does not reflect request origins. Requests without
an `Origin` header remain ordinary API requests.

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

Still planned:

- Admin ingestion endpoint protection if such endpoints are introduced.

## Frontend Security

Planned frontend controls:

- Do not store secrets in frontend variables.
- Only use NEXT_PUBLIC_ variables for safe public values.
- Escape or safely render external source content.
- Avoid rendering untrusted HTML.

## Current Status

P5-02 CORS validation and HTTP response-header hardening are implemented and
covered by backend tests. Frontend content-rendering hardening and broader
error-envelope work remain separate P5-03 and P5-04 tasks.
