# C10 API security inventory

Generated from the FastAPI OpenAPI document on 2026-08-09 with explicit synthetic test configuration and checked against the route implementations. The generated surface contains 42 paths and 43 operations. `/internal/metrics` and the four FastAPI documentation endpoints are listed separately because they are intentionally absent from the application OpenAPI contract.

## Common enforcement

- Authentication uses an opaque `__Host-` secure, HTTP-only, SameSite cookie. Anonymous access to a protected operation returns 401; an authenticated principal without the required permission receives 403.
- Mutating cookie-authenticated operations require the approved Origin, the CSRF header, and (where a body is accepted) `application/json`. Unknown query parameters and extra body properties are rejected.
- `RequestBodyLimitMiddleware` rejects invalid/duplicate `Content-Length` and declared or streamed bodies over 1,000,000 bytes before route parsing. Caddy applies the same edge ceiling.
- UUID paths use typed/canonical UUID validation. List operations have bounded limits and offsets; search, slug, enum, date, and identifier filters are length- and grammar-bounded.
- Responses use allow-listed Pydantic schemas. Authentication and sensitive responses are `no-store`; errors are sanitized.

## Role and permission contract

| Role | Permissions |
|---|---|
| viewer | `content.read`, `source.read` |
| analyst | viewer permissions plus `analysis.use`, `report.read`, `report.export` |
| ingestion_operator | viewer permissions plus `ingestion.read`, `ingestion.run`, `ingestion.retry`, `ingestion.pause` |
| administrator | all declared permissions, including user, session, source-management, and audit permissions |

## Complete generated operation inventory

`JSON+CSRF` means strict JSON, approved Origin, authenticated session, and CSRF token. `Read limiter` is the bounded process-local analyst read limiter. `Global body` is the common 1,000,000-byte middleware ceiling.

| Method | Path | Exposure | Authentication / permission | CSRF / media type | Principal bounds |
|---|---|---|---|---|---|
| GET | `/` | Public | None | N/A | No query; fixed metadata |
| GET | `/api/health` | Public | None | N/A | No query; shallow liveness only |
| GET | `/api/version` | Public | None | N/A | No query; allow-listed version fields |
| GET | `/api/v1/articles` | Protected | `content.read` | N/A | limit 1-100; offset capped; bounded search/filter/date fields |
| GET | `/api/v1/articles/{public_id}` | Protected | `content.read` | N/A | Canonical UUID; no query |
| GET | `/api/v1/analysis/threat-entities` | Protected | `content.read` | N/A | limit 1-100; offset 0-10,000; bounded filters; Read limiter |
| GET | `/api/v1/analysis/threat-entities/{public_id}` | Protected | `content.read` | N/A | Canonical UUID; no query; Read limiter |
| GET | `/api/v1/analysis/indicators` | Protected | `analysis.use` | N/A | limit 1-100; offset 0-10,000; allow-listed types/states; Read limiter |
| GET | `/api/v1/analysis/indicators/{public_id}` | Protected | `analysis.use` | N/A | Canonical UUID; no query; Read limiter |
| GET | `/api/v1/analysis/items/{public_id}/provenance` | Protected | `content.read` | N/A | Canonical UUID; no query; Read limiter |
| GET | `/api/v1/analysis/uae-intelligence` | Protected | `content.read` | N/A | limit 1-100; offset 0-10,000; allow-listed relevance/type; Read limiter |
| GET | `/api/v1/dashboard/summary` | Protected | `content.read` | N/A | `window_days` 1-365; exact query allow-list |
| GET | `/api/v1/intelligence/items` | Protected | `content.read` | N/A | limit 1-100; capped offset; bounded/allow-listed filters |
| GET | `/api/v1/intelligence/items/{item_public_id}` | Protected | `content.read` | N/A | Canonical UUID; no query |
| POST | `/api/v1/auth/login` | Public auth flow | Login policy | Approved Origin + JSON | username 3-64; password 12-128; login failure/window/block limits; Global body |
| GET | `/api/v1/auth/me` | Protected | Authenticated session | N/A | No query; `no-store` |
| POST | `/api/v1/auth/logout` | Protected | Authenticated session | CSRF; no body | No query; Global body |
| POST | `/api/v1/auth/refresh` | Protected | Authenticated session | CSRF; no body | No query; absolute/session expiry enforced; Global body |
| POST | `/api/v1/auth/change-password` | Protected | Authenticated session | JSON+CSRF | strict current/new password schema; Global body |
| GET | `/api/v1/admin/users` | Protected | `user.read` | N/A | limit 1-100; offset 0-100,000; exact query allow-list |
| POST | `/api/v1/admin/users` | Protected | `user.manage` | JSON+CSRF | strict username/display/password/role/expiry schema; Global body |
| GET | `/api/v1/admin/users/{user_public_id}` | Protected | `user.read` | N/A | UUID; no query |
| PATCH | `/api/v1/admin/users/{user_public_id}/status` | Protected | `user.manage` | JSON+CSRF | strict allow-listed status; self/last-admin invariants; Global body |
| PATCH | `/api/v1/admin/users/{user_public_id}/role` | Protected | `user.manage` | JSON+CSRF | strict role enum; last-admin invariant; Global body |
| PATCH | `/api/v1/admin/users/{user_public_id}/expiry` | Protected | `user.manage` | JSON+CSRF | strict bounded expiry model; Global body |
| POST | `/api/v1/admin/users/{user_public_id}/sessions/revoke` | Protected | `session.revoke` | CSRF; no body | UUID; no query; Global body |
| GET | `/api/v1/audit/events` | Protected | `audit.read` | N/A | limit/offset capped; action/outcome/correlation/date grammar validated |
| GET | `/api/v1/sources` | Protected | `source.read` | N/A | limit 1-100; offset 0-100,000; state filters allow-listed |
| GET | `/api/v1/sources/{source_slug}` | Protected | `source.read` | N/A | source slug grammar, max 80; no query |
| GET | `/api/v1/ingestion/operations/summary` | Protected | `ingestion.read` | N/A | No query; truthful persisted counts |
| GET | `/api/v1/ingestion/cycles` | Protected | `ingestion.read` | N/A | limit 1-100; offset 0-100,000; status/trigger/date bounds |
| GET | `/api/v1/ingestion/runs` | Protected | `ingestion.read` | N/A | limit 1-100; offset 0-100,000; source/status/trigger/date bounds |
| GET | `/api/v1/ingestion/runs/{run_public_id}` | Protected | `ingestion.read` | N/A | UUID; no query |
| GET | `/api/v1/ingestion/runs/{run_public_id}/events` | Protected | `ingestion.read` | N/A | limit 1-500; offset 0-100,000 |
| POST | `/api/v1/sources/{source_slug}/runs` | Protected | `ingestion.run` | JSON+CSRF | strict empty operation model; idempotency key 16-128 and grammar; source policy/enablement gate; Global body |
| POST | `/api/v1/ingestion/runs/{run_public_id}/retry` | Protected | `ingestion.retry` | JSON+CSRF | strict model; UUID; persisted retryability and replay rules; Global body |
| POST | `/api/v1/sources/{source_slug}/pause` | Protected | `ingestion.pause` | JSON+CSRF | strict model; slug grammar; lifecycle transition validation; Global body |
| POST | `/api/v1/sources/{source_slug}/resume` | Protected | `ingestion.pause` | JSON+CSRF | strict model; slug grammar; lifecycle transition validation; Global body |
| POST | `/api/v1/sources/{source_slug}/disable` | Protected | `ingestion.pause` | JSON+CSRF | strict model; slug grammar; lifecycle transition validation; Global body |
| POST | `/api/v1/sources/{source_slug}/enable` | Protected | `source.manage` | JSON+CSRF | strict model; approval/configuration policy still applies; Global body |
| GET | `/api/v1/reports/catalog` | Protected | `report.read` | N/A | No query; fixed catalog and published limits |
| POST | `/api/v1/reports/export` | Protected | `report.export` | JSON+CSRF | report enum; limit 1-100; bounded row/byte/cell generation; Global body |
| GET | `/api/v1/system/health` | Protected | `source.read` | N/A | No query; exactly eight sanitized component results |

## Non-OpenAPI and edge-only inventory

| Method | Path | State | Security disposition |
|---|---|---|---|
| GET | `/internal/metrics` | Private, excluded from OpenAPI | Backend exact-host/private-network surface; Caddy rejects `/internal/*`; Prometheus uses fixed Compose networking. Not an end-user API. |
| GET | `/openapi.json` | Backend internal | FastAPI documentation asset; Caddy does not proxy it. Reassess if backend network exposure changes. |
| GET | `/docs` | Backend internal | Same disposition. |
| GET | `/docs/oauth2-redirect` | Backend internal | Same disposition. |
| GET | `/redoc` | Backend internal | Same disposition. |

## Authorization and integrity conclusions

- Object lookups use public UUIDs/slugs plus backend permission dependencies; tests cover cross-role 401/403 behavior and not-found responses. No BOLA or BFLA bypass was demonstrated.
- Mutation schemas reject extra properties, and service methods construct explicit fields. No mass-assignment path was demonstrated.
- The frontend navigation is not treated as authorization; the backend permission contract is authoritative.
- Remaining accepted limitation: read/login rate limits are process-local and must be revisited before horizontal scale-out.

Reviewer/sign-off: **Pending independent review**.
