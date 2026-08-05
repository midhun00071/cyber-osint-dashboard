# B0-06 Threat Model

## C06 current-state reconciliation — 5 August 2026

C06 closes the earlier missing-authentication implementation gap with local
Argon2id credentials, opaque database-backed browser sessions, exact Origin and
CSRF enforcement, and backend-authoritative RBAC. Only SHA-256 hashes of session
and CSRF tokens are stored. Content routes require `content.read`; user
management and audit search are Administrator-only. Frontend hiding never
substitutes for backend authorization.

Credentialed exact-origin CORS permits only `GET`, `POST`, `PATCH`, and
`OPTIONS`, with `Content-Type` and `X-CSRF-Token`; `Authorization` is excluded.
Frontend login/protected navigation remain pending. No real account exists,
APR-13 remains pending, bootstrap has not run, and SSO is absent and
approval-gated. C05 sources remain disabled and unscheduled.

## Historical B0 threat baseline

The numbered threat register below is retained as dated pre-C06 risk evidence.
Rows saying authentication, RBAC, account/session code, cookies, or protected
routes were absent describe the earlier B0 checkpoint and are superseded by the
current-state reconciliation above. Residual risks and controls not addressed by
C06 remain applicable.

## 1. Document control

| Field | Value |
| --- | --- |
| Task | B0-06 — Create production architecture and threat model |
| Status | Proposed threat model pending independent review |
| Checkpoint | `46e85607fce7c39d6ea33ce29bd39a0560858ef0` |
| Prepared | 30 July 2026 |
| Method | STRIDE with likelihood × impact design-priority scoring |

## 2. Scope and checkpoint

Scope covers browser, edge, Next.js, FastAPI, local identity/RBAC, PostgreSQL,
Prefect server/worker, scheduled/manual ingestion, fixed-policy external clients,
secrets, reports/exports, audit/logging, health, deployment and backup/restore.
It models both implemented checkpoint state and required Phase B staging state.

The Git gate passed on clean `dev`; local and refreshed `origin/dev` both equal
`46e85607fce7c39d6ea33ce29bd39a0560858ef0`. Threat scores are design
priorities, not allegations that exploitation occurred.

## 3. Methodology

STRIDE categories are Spoofing, Tampering, Repudiation, Information disclosure,
Denial of service and Elevation of privilege. Every register row identifies the
component, boundary/flow, asset, actor, precondition, abuse case, current
evidence/control/gap, risk, mitigation, owner, validation, release consequence
and residual-risk rule.

```text
Likelihood: 1–5
Impact: 1–5
Risk score: Likelihood × Impact

1–4   Low
5–9   Medium
10–16 High
17–25 Critical
```

High/Critical risk blocks the affected required release function unless an
approval-gated optional component is safely disabled and truthfully represented.
Only an authorized final approver may accept bounded residual risk under APR-15;
Critical/High security or integrity defects cannot be relabelled limitations.

## 4. Assumptions

- External content, requests, redirect targets, files and source responses are untrusted.
- Authenticated users and operators may be compromised or mistaken.
- Current read-only routes reduce mutation exposure but do not satisfy release authentication.
- Frontend state never authorizes backend work.
- PostgreSQL is authoritative only after committed, validated persistence.
- Fixed policy does not grant licence, account, credential or automation approval.
- Missing credentials and approval are non-request states, not source failures.
- Docker/host access can bypass application controls and therefore requires separate protection.
- No control is credited as implemented without exact checkpoint evidence.

## 5. Assets

| Asset ID | Asset | Primary objective |
| --- | --- | --- |
| AST-001 | Intelligence-data integrity | Prevent fabricated, stale, duplicated or corrupted intelligence |
| AST-002 | Source provenance | Preserve exact source, collection and transformation lineage |
| AST-003 | User identity and role assignments | Prevent impersonation and unauthorized privilege |
| AST-004 | Sessions | Preserve confidentiality, expiry and revocation |
| AST-005 | API credentials and secret references | Prevent disclosure, misuse and cross-service reuse |
| AST-006 | Database contents and schema | Preserve confidentiality, integrity, availability and least privilege |
| AST-007 | Ingestion checkpoints | Advance only after committed durable work |
| AST-008 | Prefect schedules and flow state | Prevent unauthorized/duplicate/overlapping execution |
| AST-009 | Audit history | Preserve attributable, sanitized and immutable evidence |
| AST-010 | Reports and exports | Prevent unauthorized, unsafe or misleading output |
| AST-011 | Deployment configuration | Preserve secure hosts, networks, images and exact candidate identity |
| AST-012 | Backups | Preserve encrypted recoverable compatible copies |
| AST-013 | Staging availability | Resist bounded resource exhaustion and cascading failure |
| AST-014 | Mentor trust in visible state | Prevent fake success, synthetic-live and unsupported claims |

## 6. Security objectives

The shared security invariants are the release objectives:

| ID | Objective | Principal threats | Responsible tasks |
| --- | --- | --- | --- |
| INV-001 | No protected operation without backend authentication and authorization. | THR-001–004, THR-022/027 | B7-01 through B7-06, B2-06 |
| INV-002 | No outbound request outside an approved fixed source policy. | THR-012–015 | B3-01 through B3-06, B5-01 through B5-04, B6-02 through B6-08, B10-05 |
| INV-003 | No checkpoint advancement before successful committed persistence. | THR-019/020/023 | B1-04, B2-05 |
| INV-004 | No failed or partial operation reported as full success. | THR-006/016/019/020/024/028/033 | B1-04, B1-06, B2-04, B10-06 |
| INV-005 | No secret value in Git, UI, reports, logs or approval documentation. | THR-025–027/030 | B1-01, B9-04, B10-07 |
| INV-006 | No raw external payload or unsafe exception exposed to users. | THR-007/010/013/014/025 | B8-07, B10-05 |
| INV-007 | No production-visible synthetic data presented as live. | THR-006/028/033 | B8-01, B10-06 |
| INV-008 | No public PostgreSQL or unprotected Prefect administration. | THR-017/022/030 | B2-01, B9-02, B9-03 |
| INV-009 | No report or export without authorization and bounded output. | THR-027/028 | B7-03, B8-06 |
| INV-010 | No approval-gated source activated without recorded approval and required configuration. | THR-015/025/026 | B0-05, B2-04, B5-01 through B5-04, B6-01 through B6-08 |
| INV-011 | No malware handling, active scanning or exploit execution. | THR-014/015 | B3-01 through B3-06, B5-01 through B5-06, B6-01 through B6-08, B10-05 |
| INV-012 | No release with an open Critical/High security or integrity defect. | THR-001–033 | B10-01 through B10-08, B11-01 through B11-05 |

## 7. Threat actors

| Actor | Capabilities and error modes |
| --- | --- |
| Unauthenticated external user | Direct route/API requests, malformed inputs and resource consumption |
| Authenticated Viewer | Attempts access outside read scope or relies on stale role/session |
| Malicious or compromised Analyst | Queries/exports unauthorized records or injects unsafe content |
| Malicious or compromised Ingestion Operator | Starts/retries/changes flows or supplies poisoned parameters |
| Compromised Administrator | Alters users, roles, source state, secrets or deployment controls |
| Compromised external source | Supplies malicious, oversized, deceptive or stale content |
| Compromised vendor API | Misuses credentials, redirects or returns licensed/sensitive unexpected fields |
| Redirect/response-controlling attacker | Attempts SSRF boundary escape, parser exhaustion or header/cookie injection |
| Host/container attacker | Reads env/volumes/logs, changes images or accesses internal services |
| Accidental operator | Misconfigures schedule, retention, roles, secret delivery, backup or release state |
| Dependency/supply-chain attacker | Compromises package/image/build input or exploits unreviewed dependency |

## 8. Attacker goals

- Impersonate a user, service or approver.
- Escalate Viewer/Analyst/Operator permissions or bypass object/function scope.
- Trigger unapproved ingestion, external requests, reports or administration.
- Exfiltrate credentials, sessions, database contents, audit data or licensed fields.
- Corrupt intelligence, provenance, checkpoints, schedules, schema or backup.
- Hide actions by suppressing rollback/audit failures or fabricating success.
- Exhaust API, parser, database, source quota, worker, report or storage capacity.
- Cause visible synthetic, stale, disabled or failed state to appear live/healthy.
- Undermine release evidence or mentor trust in the exact candidate.

## 9. Trust boundaries

| Boundary | Highest concerns | Required control |
| --- | --- | --- |
| TB-001 browser/network → edge | Spoofing, hostile request, TLS/Host bypass, DoS | Approved TLS edge, host/rate/size validation |
| TB-002 edge → frontend | Direct bypass, stale deployment, unsafe forwarded state | Private application network and exact deployment identity |
| TB-003 client/frontend → FastAPI | Auth bypass, BOLA/BFLA, injection, CSRF | Backend auth/RBAC, validation and generic errors |
| TB-004 services → PostgreSQL | Privilege abuse, SQL/transaction corruption | Separate identities, ORM/constraints and explicit transactions |
| TB-005 protected FastAPI operator-control API → Prefect | Unauthorized run/control and poisoned parameters | Backend service identity, closed authorized actions and no normal operator administration path |
| TB-006 worker → source | SSRF, malicious response, quota/licence abuse | Fixed policy, bounds, approval and sanitized error |
| TB-007 secret delivery/configuration governance → approved service | Credential disclosure/reuse | Non-secret reference lookup, scoped secret delivery through the approved channel, rotation and no logs |
| TB-008 privileged operator → edge/FastAPI controls | Compromise/error/repudiation | Unique account, least role, edge path, backend validation, confirmation and audit |
| TB-009 service → audit/monitoring | Log injection, leakage and fake health | Allow-listed correlated events and restricted access |
| TB-010 store → backup/restore | Theft, tampering and incompatible restore | Encryption, integrity, isolation and compatibility checks |

## 10. Abuse-case catalogue

| Abuse ID | Category | Abuse cases covered | Defensive outcome |
| --- | --- | --- | --- |
| AB-001 | Identity/authorization | Missing/bypassed authentication, BOLA, BFLA, role escalation, frontend-only checks, direct routes, mass assignment, stale sessions, shared/default accounts and cookie-session CSRF | Deny in backend; unique revocable identities; negative matrix evidence |
| AB-002 | Browser/frontend | Stored/reflected XSS, unsafe canonical URLs, reverse-tabnabbing, untrusted text, stale/fabricated/fake-success UI, client error leakage and dead controls | React text rendering, safe links, no preview fallback, sanitized explicit states |
| AB-003 | API/validation | Unbounded pagination/bodies, malformed filters, injection, raw errors, sensitive fields, unsupported updates and DoS | Pydantic/DTO allow-lists, bounds, ORM, rate/size controls and generic errors |
| AB-004 | Outbound/ingestion | SSRF, arbitrary host/path/redirect/header/cookie, response/parser exhaustion, malicious content, provenance loss, quota exhaustion, false success, unapproved live/commercial access | Fixed policy, no redirects, bounds, provenance, approval and typed non-success |
| AB-005 | Database/integrity | Privileged role reuse, unsafe SQL, missing constraints/indexes, transaction confusion, swallowed rollback, early checkpoint, retry duplicates, false partial success, stale overwrite, unsafe retention and incompatible migration/restore | Least privilege, constraints, caller-owned transactions, commit-before-checkpoint and recovery tests |
| AB-006 | Prefect/operations | Public admin, unauthorized run/retry/pause/enable/disable, overlap, duplicate schedule, compromised worker, poisoned params, failure cascade and invisible deferred/partial state | Protected Prefect, closed actions, one schedule, isolation and explicit state |
| AB-007 | Secrets/configuration | Git/log/UI/approval/database-URL leakage, unsafe defaults, cross-service use and missing rotation/owner | Approved service-specific secret references and canary scans |
| AB-008 | Reporting/deployment | Unauthorized report, CSV injection, unbounded/sensitive/stale export, report DoS, missing TLS/Host controls, broad CORS, dev server, exposed services, privileged containers, fake health, insecure backup/logs | Authorization/bounds/formula safety, approved edge, private networks, hardened images and restore proof |
| AB-009 | Supply chain/generated logic | Vulnerable/compromised package/image, missing SBOM, fake success, swallowed exception, allow-on-error, weakened tests and production mocks | Locked/reviewed dependencies, SBOM, fail-closed tests and source-to-visible-state reconciliation |

## 11. STRIDE analysis

| STRIDE | Principal surfaces | Representative threats | Required evidence |
| --- | --- | --- | --- |
| Spoofing | Login/session, service identity, source/redirect identity, release approver | THR-001/004/012/025 | Authentication/session tests, exact policy, signed/attributable evidence |
| Tampering | Roles, requests, source content, database, checkpoints, schedules, reports, backups | THR-003/009/014/017–023/027/031 | RBAC, validation, constraints, transaction, no-overlap and integrity tests |
| Repudiation | Operator actions, failed rollback, approval/release changes | THR-016/019/022/024/033 | Correlated actor/action/result, immutable decision/evidence history |
| Information disclosure | Errors, secrets, sessions, DB, licensed data, reports/logs/volumes | THR-007/010/025–027/030 | Canary scans, field allow-lists, generic errors, restricted storage |
| Denial of service | API/parser/source quota/database/Prefect/report/storage | THR-008/011/013/015/023/024/028/031/032 | Bounds, rate/quota, isolation, capacity and recovery evidence |
| Elevation of privilege | BOLA/BFLA, mass assignment, DB/Prefect/admin compromise | THR-002/003/017/022/030 | Direct-request RBAC, least DB grants and network exposure tests |

## 12. Threat register

| ID | STRIDE | Component | Boundary/flow | Asset | Actor | Precondition | Abuse case | Current repository evidence | Current control | Control gap | L | I | Score | Rating | Required mitigation | Task | Validation evidence | Release consequence | Residual-risk rule |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | ---: | ---: | ---: | --- | --- | --- | --- | --- | --- |
| THR-001 | S/E | CMP-004/005 | TB-003; DF-003, DF-004, DF-031 | AST-003/004/014 | External user | Protected staging routes exist without enforced identity | Bypass or omit authentication and invoke protected operation | `backend/app/main.py:67-71` registers routers without auth dependency; SEC-0004 | Current routes are GET-only and bounded | No login/session/backend auth | 5 | 4 | 20 | Critical | Implement unique local identity, revocable session and deny-by-default backend dependency | B7-01, B7-02, B7-03 | Anonymous and invalid-session denial across every protected route | Block release | No acceptance while auth bypass exists |
| THR-002 | E/T | CMP-004/005/018 | TB-003; DF-004, DF-010, DF-031 | AST-002/003/010 | Viewer/analyst | Auth exists but object/function scope is absent or frontend-only | BOLA/BFLA/direct-route access to another record, report, audit or control | No ownership/role dependency in current routes; `docs/b0-03-production-mvp-scope.md:168-184` requires it | Public DTOs omit raw payloads | Object/function authorization absent | 4 | 5 | 20 | Critical | Central backend permissions, object-scope filters and direct-request negatives | B7-03, B7-05, B7-06 | Complete role × endpoint × object matrix including hidden/direct routes | Block affected protected functions and release | Cannot accept frontend hiding as residual control |
| THR-003 | E/T | CMP-005/023 | TB-003/008; DF-005, DF-031 | AST-003/009 | Analyst/operator/admin | Role or user-management input is mass assignable or insufficiently restricted | Assign elevated role, alter restricted source/user field or invoke admin function | No user/role model exists; `docs/b0-03-production-mvp-scope.md:168-184` freezes role requirements | No current mutation endpoint | Required role/admin boundary absent | 4 | 5 | 20 | Critical | Server-owned fields, admin-only role lifecycle, allow-listed schemas and audit | B7-01, B7-03, B7-06 | Mass-assignment and escalation negatives plus actor audit | Block release | No acceptance of self-assigned privilege |
| THR-004 | S/R/E | CMP-005 | TB-003/008; DF-003–005, DF-031 | AST-003/004 | User/operator | Session expiry/revocation/default-account controls are weak; cookie mode lacks CSRF | Reuse stale/shared session, default account or cross-site protected request | No session/account code exists; `docs/b0-03-production-mvp-scope.md:168-176` requires expiry/revocation/no defaults | Not applicable to current public GET-only API | Full session lifecycle absent | 3 | 4 | 12 | High | Bounded expiry, rotation/revocation, unique accounts, secure cookie and CSRF if cookies | B7-01, B7-02, B7-06 | Login/logout/disable/revoke/default-account/CSRF tests | Block authenticated staging | Residual session risk needs APR-15 evidence after all High defects close |
| THR-005 | T/I | CMP-003 | TB-002/003; DF-009/030 | AST-001/002/014 | Source/analyst | Untrusted text or URL reaches browser | Stored/reflected XSS, unsafe canonical URL or reverse-tabnabbing | `frontend/src/utils/safeExternalUrl.ts:1-43`; `frontend/src/components/SafeExternalLink.tsx:16-35`; React text rendering | HTTP/S allow-list, no URL credentials, noopener/noreferrer | Complete page/CSP regression still required | 2 | 4 | 8 | Medium | Retain text rendering and safe links; test all new fields/pages and CSP | B8-01, B8-07, B10-03 | Malicious text/URL/component tests and browser CSP review | Fix before affected page acceptance | Medium residual may be accepted only with complete coverage and no executable path |
| THR-006 | T/R | CMP-003/020 | TB-002; DF-009/019/023/030 | AST-001/014 | Accidental developer/generated logic | UI imports fixture/preview or converts failure to success | Present synthetic, stale, disabled or failed data as live/healthy | Dashboard imports preview at `frontend/src/app/(dashboard)/page.tsx:8,64-121`; data at `frontend/src/data/dashboardPreview.ts:101-129`; SEC-0003 | Some panels are accurately labelled and API failures show unavailable | Preview remains production-visible; full truth contract absent | 5 | 4 | 20 | Critical | Remove production preview imports; reconcile API/DB/network; explicit states and no allow-on-error | B8-01, B10-06 | Import search, DB counts, network/browser states and failure injection | Block release | No residual acceptance for synthetic-live or fake success |
| THR-007 | I/R | CMP-003/004/019 | TB-003/009; DF-009/022 | AST-005/006/009 | External user | Rejected values or exceptions are echoed | Learn stack, SQL, path, token, body or configuration from client error/log | `backend/app/core/request_context.py:90-138`; route handlers use fixed errors; tests `backend/tests/test_logging_and_errors.py:145-390` | Generic errors, route-template logging and correlation IDs | New auth/operator/report paths untested | 3 | 3 | 9 | Medium | Apply same error/log allow-list to all new paths and evidence | B8-07, B9-04, B10-07 | Canary values across 4xx/5xx/logs/UI | Fix before affected path acceptance | Bounded residual only with no sensitive disclosure |
| THR-008 | D/T | CMP-004 | TB-003; DF-006/007 | AST-006/013 | External user | Inputs lack type/count/byte/depth/page bounds | Send oversized body or unbounded pagination/malformed filters | Article limits `backend/app/api/v1/routes/articles.py:55-103`; intelligence limits `backend/app/api/v1/routes/intelligence.py:60-117` | Pydantic/query bounds and max offset | Future write/operator/report schemas absent | 3 | 4 | 12 | High | Global/request-specific byte/count/depth/time bounds and rate controls | B8-07, B10-02, B10-08 | Boundary and oversized-body/pagination/load tests | Block affected API/release | No acceptance for unbounded public input |
| THR-009 | T/E | CMP-004/006 | TB-003/004; DF-007/008/020 | AST-001/006 | External/analyst | Malformed filters or unsupported fields reach query/persistence | SQL/command/template/header injection or unauthorized field update | SQLAlchemy services and validators at `backend/app/api/v1/routes/articles.py:75-106`; named constraints at `backend/alembic/versions/f8d739439ed0_create_initial_schema.py:95-247` | ORM, allow-listed filters and response models | Mutation schemas and complete injection suite not implemented | 3 | 5 | 15 | High | Parameterized access, closed DTOs, server-owned fields and injection tests | B7-03, B10-02 | SQL/command/template/header negatives and unchanged DB | Block affected functionality | No residual acceptance for demonstrated injection |
| THR-010 | I | CMP-004 | TB-003; DF-009/022 | AST-005/006/009 | External user | Response/error schema includes internal/sensitive fields | Receive raw exception, payload, internal IDs, SQL or secret-bearing fields | Safe response schemas at `backend/app/api/v1/schemas/articles.py:1-35` and `backend/app/api/v1/schemas/intelligence.py:1-51`; fixed route errors | Response models and generic failures | New report/audit/control DTOs absent | 3 | 4 | 12 | High | Field allow-lists, public IDs and sensitive canary tests for every endpoint | B8-07, B10-07 | Schema snapshots and leak canaries | Block affected endpoint | No acceptance of secret/raw payload exposure |
| THR-011 | D | CMP-004/006 | TB-003/004; DF-006–008 | AST-013 | External user | Requests are cheap to send but expensive to query | Exhaust workers, DB pool or expensive filters | Pool bounds `backend/app/db/session.py:21-31`; query limits ≤100 | Bounded pool/pagination | Edge rate/body/time limits absent | 3 | 4 | 12 | High | Proxy/API rate, timeout, concurrency and query-plan controls | B9-02, B10-08 | Load/slow-query/pool exhaustion tests | Block untrusted staging exposure | Residual capacity risk requires measured limits |
| THR-012 | S/T/I | CMP-013 | TB-006/007; DF-015, DF-016, DF-034 | AST-005/011/013 | Redirect/response attacker | User-controlled host/path/redirect/header/cookie enters transport | SSRF, destination escape, credential forwarding or proxy-environment use | Exact HTTPS policy `backend/app/ingestion/source_registry.py:316-339`; TAXII `backend/app/ingestion/stix_taxii/taxii_client.py:364-372,523-592` | Fixed hosts/paths, redirects off, trust_env off, cookie clearing | Every future source needs equivalent policy/tests | 3 | 5 | 15 | High | Central fixed-policy client with pre-transport guard and zero arbitrary inputs | B3-01 through B3-06, B5-01 through B5-04, B6-02 through B6-08, B10-05 | Host confusion, redirect, header/cookie/proxy zero-transport tests | Disable source; block if required | Optional gated source may remain disabled with truthful state |
| THR-013 | D | CMP-013 | TB-006; DF-016/017 | AST-013 | Compromised source | Source returns large/compressed/deep/malformed content | Exhaust memory/CPU/parser or pagination | TAXII byte/page/object/depth bounds at `backend/app/ingestion/stix_taxii/policy.py:82-117`; client `backend/app/ingestion/stix_taxii/taxii_client.py:418-509,523-592` | Bounded bytes/pages/objects/deadline and encoding/type checks | Equivalent evidence incomplete for every future source | 2 | 4 | 8 | Medium | Per-source aggregate bounds, streaming and parser limits | B3-01 through B3-06, B5-02 through B5-04, B6-03, B6-05, B6-07, B10-05, B10-08 | Content-length, stream, compression, depth and pagination tests | Fix before source enablement | Medium residual only within measured bound |
| THR-014 | T/I | CMP-009/013/006 | TB-006/004; DF-017/020/030 | AST-001/002/006 | Compromised source | Malicious or misleading content passes weak normalization | Persist unsafe fields, lose provenance or inject analyst-visible content | STIX validation rebuilds persistable data at `backend/app/ingestion/stix_taxii/stix_validation.py:232-375`; source provenance schema is defined at `backend/alembic/versions/a6c9d4e2f107_add_indicator_ioc_models.py:50-125` | Allow-listed normalization, safe payload and provenance | All source families and UI/report paths need reconciliation | 3 | 5 | 15 | High | Validate before use/persist/display; preserve source/version and reject unsafe payload | B1-03, B1-04, B3-01 through B3-06, B4-01 through B4-04, B5-02 through B5-06, B6-03, B6-05, B6-07, B8-04, B8-05, B10-03, B10-05 | Malicious fixture, provenance and source-to-UI/report tests | Block affected source/page | No acceptance for lost provenance or unsafe content |
| THR-015 | T/D/R | CMP-015/016 | TB-006/007; DF-015, DF-016, DF-018, DF-034 | AST-005/008/014 | Operator/vendor | Approval, entitlement, quota or credential is absent | Activate unapproved live request, exhaust quota or claim commercial/UAE coverage | `docs/b0-05-mentor-approval-pack.md:599-624`; all APR rows remain `Need Approval` | Explicit disabled fallbacks | No implemented gated adapters/approval enforcement yet | 4 | 4 | 16 | High | Approval/config gate before transport; quota/rate state; accurate UI | B0-05, B2-04, B5-01 through B5-04, B6-01 through B6-08 | Register/config/policy reconciliation and zero-request proof | Disable gated source; required release truth must pass | Safely disabled optional source is acceptable, not approved |
| THR-016 | R/T | CMP-012/019 | TB-006/009; DF-019/022/028 | AST-007/009/014 | Generated logic/operator | Failure/defer/partial path is collapsed | Record source/cycle as success or hide failure | RSS explicit status `backend/app/ingestion/rss_cli.py:163-195`; audit run models at `backend/alembic/versions/f8d739439ed0_create_initial_schema.py:95-247` | Explicit current statuses and sanitized summaries | Cross-source Prefect aggregation absent; SEC-0020 gap | 4 | 4 | 16 | High | Closed state machine, reconciled counters and non-success on any required failure | B1-04, B1-06, B2-04, B10-06 | Inject each failure/defer path; compare DB, Prefect, UI/log | Block affected cycle/health acceptance | Optional source can be disabled, but failure cannot be success |
| THR-017 | E/T/I/D | CMP-006–008 | TB-004; DF-008/011/020/029 | AST-006/012 | Backend/host attacker or operator error | Application shares initialization/migration DB owner | Perform destructive schema/data operation beyond application need | Same credentials at `compose.prod.yml:21-23,61-63,132-134`; SEC-0019 | Internal DB network; non-root app containers | No restricted application identity | 4 | 5 | 20 | Critical | Separate migration/application roles; deny DDL/superuser and bound pool | B1-05, B9-01 | Sanitized grants plus denied schema/role/superuser tests | Block release | Privileged application access is never an accepted fallback |
| THR-018 | T/D | CMP-004/006 | TB-004; DF-008/020 | AST-001/006/013 | Developer/attacker | Query or schema omits parameterization, constraints or critical index | Inject SQL, create invalid duplicate or force unbounded scan | SQLAlchemy ORM and named constraints/indexes at `backend/alembic/versions/f8d739439ed0_create_initial_schema.py:20-247`; 13 mapped tables at `backend/app/models/__init__.py:1-31` | Parameterized ORM, unique/check constraints | Representative query/index review still required | 2 | 4 | 8 | Medium | Preserve constraints and validate query-critical indexes on migrated PostgreSQL | B1-03, B1-05, B10-02, B10-08 | Alembic, EXPLAIN/query and duplicate/constraint tests | Fix before affected query release | Bounded index residual may be accepted with measured performance |
| THR-019 | T/R | CMP-006/012 | TB-004/009; DF-020/021/028 | AST-001/007/009 | Operator/error | Transaction error or rollback cleanup fails | Advance checkpoint, hide uncertain session or report partial persistence as success | `backend/app/ingestion/services/anomali_publications_ingestion_service.py:549-560` and `backend/app/ingestion/services/censys_publications_ingestion_service.py:553-564` suppress ordinary rollback exceptions; SEC-0020 | Other paths rollback and sanitize | Observable rollback cleanup and orchestrated transaction contract incomplete | 4 | 4 | 16 | High | Caller-owned transaction, observable cleanup failure, unchanged checkpoint and non-success | B1-04, B1-06, B2-05 | Inject flush/commit/rollback failures and inspect state/log/checkpoint | Block release as approved Must Fix | No acceptance while SEC-0020 remains unresolved |
| THR-020 | T/R | CMP-006/012 | TB-004; DF-020/021 | AST-001/002/007 | Operator/retry | Retry, stale update or partial batch lacks deterministic semantics | Duplicate records, overwrite newer data or claim partial batch as success | Unique constraints plus idempotent/stale STIX cases at `backend/tests/test_stix_import_service.py:427-493,874-906`; explicit run counters | Current idempotency and stale controls in implemented paths | Whole Prefect/retry model absent | 3 | 4 | 12 | High | Deterministic idempotency, stale rules, atomicity and reconciled counters | B1-03, B1-04, B2-04, B2-05 | Duplicate/concurrent/retry/stale/partial tests | Block affected ingestion release | No acceptance for corruption or false success |
| THR-021 | T/D | CMP-006/021/022 | TB-004/010; DF-024–027 | AST-001/002/006/012 | Operator/error | Retention/backup/restore lacks lifecycle or compatibility | Delete active evidence, restore incompatible schema or fail recovery | Named volume only; `docs/b0-03-production-mvp-scope.md:331-345` requires backup/restore | Persistent PostgreSQL volume and linear migrations | No encrypted backup or isolated restore | 3 | 5 | 15 | High | Approved retention, encrypted hashed backup and isolated compatible restore | B1-05, B9-05, B9-06 | Retention dependency, backup hash, restore counts/permissions/RPO/RTO | Block release | No recovery claim without successful restore |
| THR-022 | S/E/R | CMP-009/023 | TB-005/008; DF-005, DF-013, DF-014, DF-032 | AST-003/008/009 | External/operator | Prefect admin/control is public or protected FastAPI action lacks RBAC | Bypass the edge/FastAPI control path, invoke run/retry/pause/enable/disable or poison parameters without authority | No Prefect implementation; `compose.prod.yml:15-150`; SEC-0005 | No current Prefect attack surface | Required protected control boundary absent | 3 | 5 | 15 | High | Private Prefect reachable for controls only from the protected FastAPI operator-control API using backend-authorized closed actions and service identity | B2-01, B2-06, B7-03, B7-04 | Direct-Prefect network denial, edge/API role matrix, parameter-schema and audit tests | Block orchestration/release | No public or normal operator direct administration accepted |
| THR-023 | T/D | CMP-009–012 | TB-005; DF-012–014, DF-021, DF-032 | AST-007/008/013 | Operator/error | Schedule/no-overlap/idempotency controls absent | Create duplicate schedules or overlapping cycles and duplicate/quota load | No Prefect/schedule exists; `docs/b0-03-production-mvp-scope.md:188-210` specifies one cycle | Manual flows only | Target concurrency and schedule controls absent | 3 | 4 | 12 | High | One approved schedule, lease/lock, idempotent parent and bounded concurrency | B2-03, B2-04, B2-05 | Schedule inventory and forced-overlap/restart tests | Block scheduled-cycle gate | APR-06 may permit rehearsal only; no production claim |
| THR-024 | T/R/D | CMP-010–012/019 | TB-005/009; DF-014, DF-019, DF-028, DF-032 | AST-008/009/013/014 | Worker attacker/source failure | Worker compromised or aggregate logic couples flows | Poison run, cascade one source failure or hide deferred/partial state | No worker implementation; existing manual run records provide safe states | Source-specific services and run/error models | Worker isolation, deployment policy and aggregate truth absent | 3 | 5 | 15 | High | Least service identity, closed deployments, isolation and explicit per-flow state | B2-01, B2-03, B2-04 | Compromised-param, source-failure isolation and state reconciliation tests | Block orchestration acceptance | Disabled source allowed; hidden/cascading failure is not |
| THR-025 | I/S | CMP-017/019 | TB-007/009; DF-018, DF-022, DF-023, DF-031, DF-034 | AST-004/005/009/011 | Host/admin/source attacker | Secret value enters Git, URL, log, UI, report, audit or approval | Exfiltrate credential/session/database URL or replay it | `backend/app/core/config.py:47-64` uses SecretStr; `docs/b0-05-mentor-approval-pack.md:384-414` defines security rules; logging allow-list at `backend/app/core/request_context.py:90-138` | Secret wrappers and no current auth token | Approved delivery/rotation and new-path canary evidence absent | 3 | 5 | 15 | High | Reference-only approved delivery, redaction, scoped values and secret scanning | B1-01, B9-04, B10-07 | Git/image/env/log/UI/report canary scans and rotation/revoke test | Block credential-dependent staging; disable integrations | No acceptance of exposed secret value |
| THR-026 | E/I/R | CMP-017/004/010 | TB-007; DF-018, DF-031, DF-034 | AST-005/011 | Admin/operator error | Unsafe default, shared credential or missing owner/rotation | Reuse overprivileged secret across services or leave stale credential active | Development defaults and production required values are defined separately at `docker-compose.yml:6-9,29-42` and `compose.prod.yml:20-23,60-63`; no approved provider exists | Production Compose fail-required values; service configs separate logically | Service-specific ownership/rotation not operational | 3 | 5 | 15 | High | Separate identities, no weak defaults, owner, expiry, rotation and revocation | B1-01, B9-04 | Missing/default/rotation/revoke/cross-service misuse tests | Block required service; gated source stays disabled | No residual acceptance for shared privileged production credential |
| THR-027 | E/I/T | CMP-018/004 | TB-003/004; DF-010, DF-029, DF-033 | AST-006/009/010 | Viewer/analyst | Report endpoint lacks role/row/field/encoding controls | Access unauthorized records, inject CSV formula or include sensitive audit/source data | No report/export implementation; `docs/b0-02-repository-ui-audit.md:281`; `docs/b0-03-production-mvp-scope.md:297-310` | No current reachable export | Entire report authorization/safety boundary absent | 3 | 5 | 15 | High | Server authorization, bounded field/row/byte scope and formula neutralization | B7-03, B8-06, B10-02 | Role/object, CSV formula, content canary and sample review | Block Reports page/release | No acceptance for unauthorized or executable export |
| THR-028 | T/D/R | CMP-018/003 | TB-003; DF-010, DF-029, DF-030, DF-033 | AST-010/013/014 | User/generated logic | Export query is unbounded or uses stale/synthetic fallback | Exhaust service or publish stale/fabricated report claim | Reports absent; Overview has future-report preview prose at `frontend/src/app/(dashboard)/page.tsx:93-121` | No current generation path | Bounds, provenance and truthfulness not implemented | 3 | 4 | 12 | High | Time/row/byte limits, asynchronous bound if needed, exact provenance and failure state | B8-06, B10-06, B10-08 | Load/cancel/stale/failure/source reconciliation tests | Block Reports acceptance | No fake report success; optional report may remain unavailable |
| THR-029 | S/T/I | CMP-002/003/004 | TB-001–003; DF-001/002 | AST-003/004/011/013 | Network attacker | No TLS/host validation or broad CORS/dev server is exposed | Intercept/spoof traffic, abuse Host/origin or expose debug/reload behaviour | No proxy in Compose; exact CORS at `backend/app/main.py:52-61`; production settings enforce HTTPS origin at `backend/app/core/config.py:127-147` | Loopback default binds, exact GET-only no-credentials CORS, production images | Approved TLS/Host proxy absent | 3 | 5 | 15 | High | Approved reverse proxy, TLS, host allow-list, private services and production commands | B9-02, B9-03, B10-07 | TLS/Host/CORS/direct-port/dev-mode negative tests | Block untrusted/public staging access | Secure local fallback needs explicit mentor acceptance |
| THR-030 | E/I/T | CMP-006/009/018/021/024 | TB-004/005/010; DF-032, DF-033 | AST-005/006/008/011/012 | Host/container attacker | DB/Prefect/report workspace/volumes/logs public or container excessively privileged | Access internals, secrets or data; tamper state/logs | DB network internal and caps dropped at `compose.prod.yml:3-13,34-44,146-150`; no Prefect or report workspace | Non-root app images, no-new-privileges, internal DB network, bounded logs | Host hardening, Prefect isolation, report-workspace isolation and secret/log/volume access review absent | 3 | 5 | 15 | High | Private networks, least container/host permissions and protected volumes/logs/workspaces | B2-01, B9-01, B9-03, B9-04 | Port/network/user/capability/volume/log/workspace access tests | Block release | Host compromise residual requires documented operational controls, not app claims |
| THR-031 | D/T | CMP-020–022 | TB-009/010; DF-023–026, DF-032 | AST-009/012/013/014 | Operator/error | Health missing/allow-on-error; persisted orchestration state or backup insecure; restore untested | Report healthy while dependency failed or lose run/recovery data | Basic health `backend/app/api/v1/routes/health.py:12-23`; Compose checks; no Prefect or backup service | Backend/container health and persistence volume | Full dependency health, Prefect-state restart, encrypted backup and restore evidence absent | 3 | 4 | 12 | High | Truthful dependency states, controlled restart, failure alerts, encrypted backup and isolated restore | B8-06, B9-03, B9-04, B9-05, B9-06 | Fault/restart injection, alert/redaction, hash/restore/count/RPO/RTO | Block release | Manual observation only if explicitly accepted; no recovery claim without restore |
| THR-032 | T/I/D | CMP-003/004/024 | Build/supply chain | AST-011/013 | Supply-chain attacker | Dependency/image is vulnerable/compromised or inventory absent | Execute compromised package/image or hide production/test drift | `backend/Dockerfile.prod:12-15` installs `backend/requirements.txt:1-15`, including tests; SEC-0021 | Deterministic frontend `npm ci`; non-root images; tests exist | No SBOM/final vulnerability review; shared Python deps | 3 | 3 | 9 | Medium | Pin/review dependencies and images, generate SBOM and remove/review test deps | B9-01, B10-07 | SBOM/image package inventory, scanner disposition and reproducible build | Follow-up unless evidence raises risk; fix Critical/High findings | SEC-0021 stays non-blocking unless later evidence escalates |
| THR-033 | T/R | All generated paths | All visible/state flows | AST-001/007/008/009/014 | Generated logic/developer | Code swallows errors, allows on failure, weakens tests or ships mocks | Produce fake success, advance state or conceal defect | Preview state exists at `frontend/src/app/(dashboard)/page.tsx:8,64-121`; rollback suppression is evidenced at `backend/app/ingestion/services/anomali_publications_ingestion_service.py:549-560` and `backend/app/ingestion/services/censys_publications_ingestion_service.py:553-564`; generated-logic review rules are at `AGENTS.md:494-518` | Extensive negative tests and explicit current statuses | Full Phase B AI-logic review and mock exclusion pending | 4 | 5 | 20 | Critical | Independent complete-file review, fail-closed paths, assertion integrity and source-to-visible-state proof | B10-06, B11-01 | Search/tests for fake success, swallowed errors, disabled validation, mocks and checkpoints | Block release | No residual acceptance for fake success or weakened security tests |

Threat rating totals: **Critical 6, High 22, Medium 5, Low 0**.

## 13. Existing controls

- GET-only FastAPI routes with bounded pagination/filter validation and response models (`backend/app/main.py:52-71`; `backend/app/api/v1/routes/articles.py:55-106`; `backend/app/api/v1/routes/intelligence.py:60-117`).
- Exact-origin, no-credentials, GET-only CORS plus security headers (`backend/app/main.py:52-65`; `backend/app/core/security_headers.py:9-44`).
- Server-generated request IDs, route-template logs and sanitized exceptions (`backend/app/core/request_context.py:65-138`).
- SQLAlchemy ORM, named constraints, unique indexes and linear migrations (`backend/alembic/versions/f8d739439ed0_create_initial_schema.py:20-247`; `backend/app/models/__init__.py:1-31`).
- Safe React text rendering and HTTP/S credential-free external links (`frontend/src/utils/safeExternalUrl.ts:1-43`; `frontend/src/components/SafeExternalLink.tsx:16-35`).
- Fixed source registries and bounded clients; TAXII disables redirects/environment trust and bounds bytes/pages/objects (`backend/app/ingestion/source_registry.py:316-339`; `backend/app/ingestion/stix_taxii/policy.py:70-117`; `backend/app/ingestion/stix_taxii/taxii_client.py:364-372,418-509,523-592`).
- Sanitized ingestion run/error evidence and current transaction/idempotency tests (`backend/app/ingestion/rss_cli.py:163-195`; `backend/tests/test_stix_import_service.py:427-493,874-906`).
- Non-root application images, dropped capabilities, no-new-privileges, bounded logs and internal database network in production Compose (`compose.prod.yml:3-13,34-44,76-112,146-150`).
- No public mutation/ingestion endpoint, arbitrary callback, file submission, malware retrieval, active scanning or exploit path was identified.

These controls are credited only for their current scope; they do not prove the
required identity, orchestration, report, edge or recovery controls.

## 14. Required controls

- Implement backend identity, session and RBAC before protected functionality.
- Enforce exact source policies and approval/config state before any transport.
- Separate application and migration PostgreSQL identities and prove denied privilege.
- Make rollback/commit/partial/checkpoint states observable and fail closed.
- Keep Prefect private and accept normal operator controls only through the
  reverse proxy and protected FastAPI operator-control API, using closed,
  authorized and audited actions.
- Keep gated integrations zero-request until approvals and prerequisites exist.
- Deliver service-specific secrets through approved references with rotation/revocation.
- Authorize and bound reports; neutralize CSV formula cells and exclude sensitive data.
- Use an approved TLS/Host-validating edge and private internal services.
- Produce truthful full-stack health, encrypted backup and isolated restore evidence.
- Review SBOM/dependencies/images and generated logic before the release candidate.
- Close every Critical/High defect before APR-15; do not convert required controls into limitations.

## 15. B0-02 finding traceability

| Finding | Related threats | Assets | Task | Release consequence | Required closure evidence |
| --- | --- | --- | --- | --- | --- |
| SEC-0001 required release-page gap | THR-006/027/028/033 | AST-010/013/014 | B8-01 | Release blocker | All 12 routes/sidebar entries, tests and mentor-visible browser evidence |
| SEC-0002 Coming Soon/dead controls | THR-006/033 | AST-014 | B8-01 | Release blocker | UI crawl, control inventory, interaction tests and browser evidence |
| SEC-0003 synthetic preview | THR-006/028/033 | AST-001/014 | B8-01 | Release blocker | Import search, network/DB reconciliation and honest browser states |
| SEC-0004 authentication/RBAC absent | THR-001–004/027 | AST-003/004/009/010 | B7-01 through B7-06 | Release blocker | Role matrix, direct-request BOLA/BFLA/mass-assignment/session/UAT evidence |
| SEC-0005 Prefect/operator controls absent | THR-016/022–024 | AST-007/008/009/013/014 | B2-01 through B2-06 | Release blocker | Protected deployment, one schedule, no-overlap, failure isolation, RBAC and UI history |
| SEC-0019 privileged DB account | THR-017/030 | AST-001/006/012 | B9-01 with B1-05 | Release blocker | Sanitized grants, distinct identities and denied DDL/role/superuser tests |
| SEC-0020 swallowed rollback cleanup | THR-019/020/033 | AST-001/007/009 | B1-06 | Release blocker as approved Must Fix | Injected rollback failure, non-success, unchanged checkpoint and safe log |
| SEC-0021 production test dependencies | THR-032 | AST-011/013 | B9-01 | Non-blocking follow-up unless escalated | SBOM/image package inventory and final bounded disposition |

## 16. Approval-dependent threats

| Approval | Threat effect while pending | Required safe state |
| --- | --- | --- |
| APR-01–04 | THR-015/025/026 commercial entitlement, quota and credential risk | Commercial integrations disabled; no live coverage claim |
| APR-05 | THR-012–015 UAE automation/terms/policy risk | Every unapproved UAE collector disabled |
| APR-06 | THR-023 schedule/overlap/ownership risk | No production schedule; controlled rehearsal only if authorized |
| APR-07/08 | THR-029/030 hosting/TLS/exposure risk | Private local fallback only with explicit mentor acceptance where required |
| APR-09 | THR-017/021 database hosting/retention risk | Explicit accepted staging fallback; privileged application role never acceptable |
| APR-10 | THR-025/026 delivery/rotation risk | Credential-dependent services disabled |
| APR-11 | THR-021/031 backup lifecycle risk | No production recovery claim; release needs restore evidence |
| APR-12 | THR-031 monitoring ownership/routing risk | Self-hosted/manual bounded observation only if explicitly accepted |
| APR-13/14 | THR-001–004 identity/user/SSO risk | No staging access until unique users/local RBAC accepted; no SSO claim |
| APR-15 | All residual release risk | No release without exact candidate sign-off |

No pending approval reduces a risk score by itself. A safely disabled optional
component removes its live attack path but remains visibly unavailable.

## 17. Security test requirements

| Test family | Threats | Minimum evidence |
| --- | --- | --- |
| Authentication/session/RBAC | THR-001–004 | Unique users, expiry/revocation, generic 401/403, CSRF if cookies, role/function/object matrix and direct-route negatives |
| Browser/XSS/truthfulness | THR-005–007/033 | Malicious strings/URLs, CSP, no raw HTML, import search, API/network/DB reconciliation and explicit error/disabled states |
| API/input/injection/load | THR-008–011 | Type/length/count/body/page bounds, injection suites, DTO leak canaries, rate/pool/load tests |
| External-source policy | THR-012–016 | Zero-transport host/path/redirect/header/cookie/proxy cases, byte/parser/page/quota limits, malicious fixtures and explicit states |
| Database/transaction | THR-017–021 | Grants, denied DDL/superuser, migrations, constraints/indexes, commit/rollback/checkpoint, retry/stale/concurrency/retention/restore |
| Prefect/operations | THR-022–024 | Private admin, closed parameters, operator RBAC/audit, one schedule, no-overlap, worker/source failure isolation |
| Secrets/config | THR-025/026 | Git/image/log/UI/report/evidence scans, missing/default config, scoped delivery, rotate/revoke and cross-service misuse |
| Reports/exports | THR-027/028 | Role/object authorization, row/byte/time bounds, safe filename, CSV formulas, sensitive canaries and failure/load cases |
| Deployment/recovery | THR-029–032 | TLS/Host/CORS/direct ports, non-root/caps/networks/volumes/logs, SBOM/image review, health faults, encrypted backup and isolated restore |
| Generated logic | THR-006/016/019/024/028/033 | Search and negative tests for fake success, swallowed exceptions, allow-on-error, weakened assertions and production mocks |

No security-test result is claimed by this design document. The B0-06 commands
validate structure only.

## 18. Residual-risk rules

1. Critical/High security or integrity defects block affected required release behaviour.
2. Approval-gated optional functionality may remain disabled only with zero transport and truthful UI/documentation.
3. Missing required identity, edge, database-privilege, Prefect, report or recovery control is not an Accepted Limitation.
4. SEC-0021 remains non-blocking unless SBOM/image evidence raises its risk.
5. Medium/Low residual risks require named owner, evidence, bounded consequence and review date.
6. Residual risk is accepted only for the exact candidate by an authorized APR-15 approver after UAT and evidence review.
7. A changed candidate, control, dependency, source policy, approval or deployment boundary triggers reassessment.

## 19. Out-of-scope offensive activity

The design supports public defensive intelligence only. It provides no exploit
execution, active scanning/probing, credential theft, phishing, malware sample
retrieval/upload/delivery, persistence, stealth/evasion, control bypass, binary
retrieval, arbitrary callback, unrestricted enrichment or attacks against real
systems. Threat cases describe defensive controls and validation outcomes, not
procedures for exploitation.

## 20. Known limitations

1. No threat proves exploitation occurred; scores are design priorities.
2. B0-06 implements no mitigation and runs no security test.
3. All target identity, Prefect, report, edge and recovery controls remain required later.
4. All APR-01 through APR-15 remain `Need Approval`.
5. No live source or ingestion was invoked.
6. Current evidence is repository-static plus import/config checks; no staging runtime was assessed.
7. The workbook predates Git completion of B0-02 through B0-05.
8. Mermaid tool validation was unavailable; companion diagrams received manual/fence review.
9. Docker Compose validation used the installed `docker-compose` fallback and emitted a non-blocking user-config access warning.
10. SEC-0021 remains a non-blocking follow-up unless evidence escalates it.
11. The existing Windows CRLF migration-hash limitation is unrelated and unchanged.

## 21. Sign-off record

| Field | Value |
| --- | --- |
| Prepared by | Pending |
| Independent reviewer | Pending |
| Architecture owner | Pending |
| Security reviewer | Pending |
| Review date | Pending |
| Residual-risk decision | Pending |
| Evidence reference | Pending |

## 22. B0-06 threat-model definition-of-done assessment

| Criterion | Assessment |
| --- | --- |
| Assets, actors, goals and assumptions | Recorded |
| Trust boundaries and abuse cases | Recorded with all mandatory categories |
| Data-flow traceability | 34 flows, including DF-031 through DF-034 for declared stores |
| STRIDE register | 33 stable threats with every required field |
| Risk totals | Critical 6; High 22; Medium 5; Low 0 |
| Critical/High release rule | Blocking unless optional approval-gated capability remains safely disabled |
| B0-02 traceability | SEC-0001–0005 and SEC-0019–0021 mapped |
| Invariants | INV-001 through INV-012 traced |
| Approvals | Pending; no fallback treated as approval |
| Security-test claims | None fabricated |
| Complete-file review and focused validation | Passed; no documentation defect remains identified |
| Review archive | Prepared after final validation; external path and SHA-256 reported at handoff |

This threat-model artifact does not make B0-06 approved or complete and does not
start B1-01.
