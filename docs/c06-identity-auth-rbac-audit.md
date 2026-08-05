# C06 identity, authentication, RBAC, and security audit

## Frozen scope and checkpoint

C06 implements B7-01 through B7-04 from checkpoint `740e4ecdbd1233fba003133c0e47151d789b5506`. Migration `f4a1c2d3e5b6` appends to `e91f4c2a7b60` and creates `auth_users`, `auth_identities`, `auth_local_credentials`, `auth_user_roles`, `auth_sessions`, and `auth_login_throttles`. It seeds no rows.

The work does not implement or claim SSO. `IdentityProvider` and immutable `VerifiedIdentity` contracts keep a future provider replaceable, while C06 server-selects only `local`. There is no self-registration, recovery email, JWT, bearer authentication, default account, or startup bootstrap.

## Password and failed-login controls

Local credentials use `argon2-cffi` directly with Argon2id. Passwords are 12–128 characters, bounded to 512 UTF-8 bytes, and reject NUL and control characters without normalization or truncation. Only `$argon2id$` hashes are stored. Unknown, disabled, expired, blocked, and known identities take one Argon2 verification path; unknown identities use one process-created dummy hash. The public failure is always `Invalid credentials.`

Failed-login state stores only a SHA-256 hash of the canonical login key. Defaults are five attempts in 15 minutes and a 15-minute block. Updates lock the throttle record, reset on successful authentication, and never store or audit a submitted username.

An active block is fixed rather than sliding: every submitted attempt still
performs exactly one real-or-dummy Argon2 verification and returns the same
generic failure, but it does not increment the counter, reset the window, or
extend `blocked_until`. After expiry, normal failure-window behavior resumes;
successful authentication clears the throttle state.

## Roles and permissions

- `viewer`: `content.read`, `source.read`.
- `analyst`: viewer permissions plus `analysis.use`, `report.read`, `report.export`.
- `ingestion_operator`: viewer permissions plus `ingestion.read`, `ingestion.run`, `ingestion.retry`, `ingestion.pause`.
- `administrator`: all permissions above plus `user.read`, `user.manage`, `session.revoke`, `source.manage`, `audit.read`.

Report, source-management, ingestion-control, and manual-run permissions are reserved vocabulary only; C06 adds none of those endpoints.

## Session, cookie, Origin, and CSRF boundary

Browser authentication uses cryptographically random opaque values from `secrets`; the database stores only SHA-256 hashes. The default idle lifetime is 60 minutes, the absolute lifetime is eight hours, refresh cannot pass that boundary, and a user may have at most five active sessions. Refresh revokes its predecessor, password change revokes all sessions and rotates the current browser, logout revokes the current session, and administrator/status/role actions invalidate affected accounts. `session_version` makes account-wide invalidation and replay denial immediate.

Naturally expired accounts cannot regain access through an old session. Extending
or removing an already-reached account expiry increments `session_version` and
revokes every unrevoked historical session with `admin_revocation`; no prior
browser session is restored.

`rotated_at` records only an actual refresh-predecessor rotation. Password-change
revocation sets `revoked_at`, `revocation_reason=password_change`, and
`updated_at` without creating rotation evidence; any valid earlier
`rotated_at` is preserved. This permits already absolute-expired but previously
unrevoked sessions to be revoked without violating the migration's time-order
constraint.

The session cookie is HttpOnly; the separate CSRF cookie is readable by the frontend. Both use `SameSite=Strict`, `Path=/`, no Domain, and bounded Max-Age. Staging and production require `Secure`. Unsafe authenticated requests require an exact configured Origin, exact constant-time cookie/header agreement using `X-CSRF-Token`, the stored CSRF hash, and JSON for body-bearing requests. CORS allows credentials and only GET, POST, PATCH, OPTIONS with Content-Type and X-CSRF-Token; it does not allow Authorization.

Bounded settings are `AUTH_COOKIE_SECURE`, `AUTH_SESSION_TTL_MINUTES`, `AUTH_SESSION_ABSOLUTE_TTL_MINUTES`, `AUTH_MAX_ACTIVE_SESSIONS`, `AUTH_LOGIN_FAILURE_LIMIT`, `AUTH_LOGIN_FAILURE_WINDOW_SECONDS`, and `AUTH_LOGIN_BLOCK_SECONDS`. Local/test defaults use a non-Secure cookie only for loopback development; staging/production must set `AUTH_COOKIE_SECURE=true`.

## Routes and authorization

Public routes are `/`, `/api/health`, `/api/version`, and `POST /api/v1/auth/login`. Self-service routes are `/api/v1/auth/me`, `/logout`, `/refresh`, and `/change-password`. Existing article, dashboard, and intelligence routes require `content.read`. Administrator user operations and `/api/v1/audit/events` require explicit Administrator permissions.

Backend permission checks precede protected object lookup. Request models forbid extra fields and no arbitrary update dictionary is accepted. The content scope remains shared; no tenancy field was invented. DTOs continue excluding internal IDs and raw payloads.

The frontend is intentionally unchanged. Until B7-05 integrates login and protected navigation, unauthenticated frontend data requests receive 401. There is no bypass, anonymous viewer, test header, or authentication-disabling flag.

Expected invalid administrator input uses a typed safe service boundary and the
fixed `400 {"detail":"Invalid request."}` response. Audit-filter validation uses
the fixed `400 {"detail":"Invalid audit query."}` response, while database or
query-service failures use the sanitized generic `500` response. Conflict `409`,
missing-user `404`, authorization, rollback, and `Cache-Control: no-store`
boundaries remain distinct.

## Audit and bootstrap boundaries

`SecurityAuditService` writes closed actions, targets, outcomes, and safe detail to the existing append-only table. HTTP correlation comes only from the server UUIDv4 request context. Actor references use public UUIDs or fixed service/system references; username, password, cookie, token, CSRF value, database ID, request body, query, and headers are prohibited. The service flushes but never commits. ORM listeners reject updates/deletes, and grants continue denying audit UPDATE, DELETE, and TRUNCATE. Audit search is bounded and deterministic.

The bootstrap CLI is separate from application, Docker, migration, and test startup. It works only when `auth_users` is empty, has no password argument or environment option, reads password and confirmation through `getpass`, creates one local Administrator in one transaction, and records `system.bootstrap_admin`. APR-13 remains pending, so the CLI is not executed by C06.

No real account has been provisioned and bootstrap has not been executed. SSO
is absent and remains separately approval-gated. The four C05 public sources
remain disabled and unscheduled, and `DEFAULT_SOURCE_HANDLERS` remains empty.
