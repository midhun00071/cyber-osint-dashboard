# B0-06 Architecture Decision Register

> **C05 supersession (5 August 2026):** Paid commercial-source plans and their
> APR-01 through APR-04 gates are retired. References below to Censys Platform,
> VirusTotal premium/business, Recorded Future, paid credentials, licences, or
> later commercial implementation are historical only, not pending work. Public
> Censys ARC/Rapid Response publication metadata remains permitted and distinct.

## Document control

| Field | Value |
| --- | --- |
| Task | B0-06 — Create production architecture and threat model |
| Checkpoint | `46e85607fce7c39d6ea33ce29bd39a0560858ef0` |
| Prepared | 30 July 2026 |
| Register status | Proposed decisions pending B0-06 independent review |
| Approval state | APR-01 through APR-15 remain `Need Approval` |

The decisions below define required Phase B architecture. They do not claim
implementation, deployment, security-test success or mentor approval. Each ADR
has the exact status `Proposed — pending B0-06 independent review`.

## ADR-001 — Reverse proxy as the staging entry boundary

| Field | Record |
| --- | --- |
| Status | Proposed — pending B0-06 independent review |
| Context | Current production Compose binds frontend/backend to loopback but has no TLS/Host-validating edge (`compose.prod.yml:46-112`). Mentor staging needs one controlled entry boundary. |
| Decision | Browser and operator traffic enters through an approved reverse proxy. TLS and Host validation terminate or are enforced there. Next.js and FastAPI are routed explicitly; PostgreSQL and Prefect administration have no public path. |
| Security rationale | Enforces TB-001/TB-002/TB-003, INV-008 and reduces THR-029/030 exposure. |
| Alternatives considered | Direct public Next.js/FastAPI ports rejected; application-only TLS rejected as incomplete for routing/Host controls; local loopback retained only as explicitly accepted fallback. |
| Consequences | Requires proxy configuration, certificate ownership, trusted forwarding rules, request bounds and direct-port denial. |
| Implementation tasks | B9-02, B9-03, B10-07 |
| Validation evidence | TLS/hostname tests, unapproved Host/origin rejection, direct-port/network inventory and sanitized proxy logs. |
| Approval dependency | APR-07 hosting/access and APR-08 hostname/TLS; no approval currently recorded. |
| Review trigger | Host/provider/proxy/certificate/network change or evidence of edge bypass. |

## ADR-002 — Self-hosted Prefect for development and staging orchestration

| Field | Record |
| --- | --- |
| Status | Proposed — pending B0-06 independent review |
| Context | Manual ingestion CLIs exist, but no Prefect package, service, worker, flow, schedule or operator surface exists (`backend/requirements.txt:1-15`; `compose.prod.yml:15-150`; SEC-0005). |
| Decision | Use one protected self-hosted Prefect server and worker. One APR-06-approved two-hour parent deployment starts independent source flows. Parent overlap and duplicate schedules are prevented. A normal application operator reaches Prefect only through the reverse proxy and the protected FastAPI operator-control API, which performs authentication, authorization, closed-schema validation and audit; Prefect has no public or direct normal-operator administration path. No separate infrastructure-maintenance path is defined by this decision. |
| Security rationale | Enforces INV-001/003/004/008 and addresses THR-022–024. |
| Alternatives considered | APScheduler rejected as a second scheduler; public Prefect rejected; monolithic fail-together flow rejected; manual-only operation is not the target schedule. |
| Consequences | Requires persistent Prefect state, service identities, closed deployments/parameters, no-overlap, bounded retries/backoff and explicit states. |
| Implementation tasks | B2-01 through B2-06, B9-03, B9-04 |
| Validation evidence | Private-network test, one-schedule inventory, forced-overlap test, failure-isolation runs, role matrix, persisted state and UI reconciliation. |
| Approval dependency | APR-06 for cadence/timezone; APR-07/12 for staging/monitoring. Until then no production schedule claim. |
| Review trigger | Scheduler/orchestrator change, new worker pool, new control action or cadence decision. |

## ADR-003 — PostgreSQL as system of record with least-privilege identities

| Field | Record |
| --- | --- |
| Status | Proposed — pending B0-06 independent review |
| Context | PostgreSQL and 13 mapped tables are implemented, but database, backend and migration reuse one initialization identity (`compose.prod.yml:21-23,61-63,132-134`; SEC-0019). |
| Decision | PostgreSQL remains authoritative. Use separate migration and restricted application identities, explicit caller-owned transactions, commit-before-checkpoint, named constraints, deterministic keys and query-critical indexes. |
| Security rationale | Enforces INV-003/004/008 and mitigates THR-017–021. |
| Alternatives considered | Privileged shared role rejected; application-managed schema migration rejected; client/local state as authority rejected. |
| Consequences | Provisioning and grants become deployment evidence; services must surface rollback/commit failure and preserve provenance/retention. |
| Implementation tasks | B1-02 through B1-06, B2-05, B9-01, B9-03, B9-05, B9-06 |
| Validation evidence | One Alembic head/history, migrated PostgreSQL inspection, grants, denied DDL/role/superuser operations, transaction/checkpoint/retry/concurrency/index/restore tests. |
| Approval dependency | APR-09 hosting/retention and APR-11 backup destination; privileged application access is never a fallback. |
| Review trigger | Schema/role/pool/transaction/checkpoint/retention/backup design change. |

## ADR-004 — Fixed-policy outbound clients

| Field | Record |
| --- | --- |
| Status | Proposed — pending B0-06 independent review |
| Context | Current registry and TAXII client already demonstrate exact HTTPS hosts, no URL credentials, disabled redirects/environment trust and bounded transport (`backend/app/ingestion/source_registry.py:316-339`; `backend/app/ingestion/stix_taxii/policy.py:70-117`; `backend/app/ingestion/stix_taxii/taxii_client.py:364-372,523-592`). Every future source requires the same closed boundary. |
| Decision | Source identity, host, base path, endpoint, method, headers, authentication class, fields, redirects, timeouts, bytes, pages, objects, rate and quota are developer-controlled. No arbitrary endpoint, callback, header or cookie. |
| Security rationale | Enforces INV-002/006/011 and mitigates THR-012–016. |
| Alternatives considered | User-editable base URLs, generic HTTP proxy/enrichment endpoints and unrestricted redirects rejected. |
| Consequences | New sources require policy, fixtures, zero-transport negatives and source-specific approval/config state before activation. |
| Implementation tasks | B3-01 through B3-06, B5-01 through B5-04, B6-02 through B6-08, B10-05 |
| Validation evidence | Host confusion, path, redirect, header/cookie/proxy, timeout, byte/page/object/parser/quota and sanitized-error tests. |
| Approval dependency | APR-01–05 for gated commercial/UAE sources; policy alone is not approval. |
| Review trigger | Any source/vendor/host/path/field/auth/redirect/quota change. |

## ADR-005 — Secure local RBAC as the required identity baseline

| Field | Record |
| --- | --- |
| Status | Proposed — pending B0-06 independent review |
| Context | Current routes have no authentication/role dependency (`backend/app/main.py:67-71`; SEC-0004). The frozen roles are Viewer, Analyst, Ingestion Operator and Administrator. |
| Decision | Implement unique local accounts, secure revocable sessions and backend-enforced roles/functions/object scope. Missing/invalid role denies. Frontend role-aware navigation is non-authoritative. SSO is optional and APR-14-gated. |
| Security rationale | Enforces INV-001/005/009 and mitigates THR-001–004/022/027. |
| Alternatives considered | Shared/default accounts, frontend-only hiding and SSO-only dependency rejected. |
| Consequences | Requires user lifecycle, password/session protection, generic errors, direct-request tests and audit. Cookie sessions require CSRF protection. |
| Implementation tasks | B7-01 through B7-06 |
| Validation evidence | Unique user/role inventory, login/logout/expiry/revocation/disable tests, BOLA/BFLA/mass-assignment and role × endpoint × object matrix. |
| Approval dependency | APR-13 user list/local RBAC acceptance; APR-14 only for SSO. No staging access before authorized users. |
| Review trigger | Role, permission, session, identity provider or protected-route change. |

## ADR-006 — Approval-gated integrations default to disabled

| Field | Record |
| --- | --- |
| Status | Proposed — pending B0-06 independent review |
| Context | APR-01 through APR-04 are retired by C05 and require no commercial decision. Other unrelated approval records retain their own current states. |
| Decision | Gated integrations have no transport until approval, entitlement, policy, credential reference, quota and enabled state all pass. UI/API show `Need Approval`, `Licence Required`, `Credentials Not Configured` or `Disabled` truthfully. |
| Security rationale | Enforces INV-002/004/007/010/011 and mitigates THR-015/016/025/026/033. |
| Alternatives considered | Fail-open activation, placeholder credentials, treating missing credentials as a failed source run and presenting mocked data as live rejected. |
| Consequences | Offline adapter work may continue; live coverage remains unavailable without fabricated failure or claim. |
| Implementation tasks | B0-05, B2-04, B5-01 through B5-04; former paid-source B6-02 through B6-08 are retired by C05 B6-01 |
| Validation evidence | Approval/config matrix, zero-transport tests, disabled-state UI/API evidence and no-live-claim review. |
| Approval dependency | APR-01–05; every record currently pending. |
| Review trigger | Any proposal to reverse C05 paid-source retirement requires a new separately frozen task; no such follow-up is currently planned. |

## ADR-007 — Secrets are referenced, never stored in Git or documentation

| Field | Record |
| --- | --- |
| Status | Proposed — pending B0-06 independent review |
| Context | Current settings use `SecretStr` (`backend/app/core/config.py:47-64`), but staging secret delivery/provider is undecided under APR-10. |
| Decision | Store non-secret reference identifiers in configuration/evidence. Deliver scoped values only to approved services through the approved channel. Record owner, mechanism, reference and rotation—not values. |
| Security rationale | Enforces INV-005/006/010 and mitigates THR-025/026/030. |
| Alternatives considered | Git/env templates with values, chat/email delivery, approval-register values, browser variables and shared cross-service credentials rejected. |
| Consequences | Requires provider integration, service-specific access, rotation/revocation, canary scans and incident ownership. |
| Implementation tasks | B1-01, B9-04, B10-07 |
| Validation evidence | Git/image/config/log/UI/report/evidence scans, missing/default failure, secure delivery, rotate/revoke and cross-service denial. |
| Approval dependency | APR-10; credential-dependent services stay disabled while pending. |
| Review trigger | Provider/delivery/owner/reference/service scope/rotation or incident change. |

## ADR-008 — Server-authorized bounded reports and exports

| Field | Record |
| --- | --- |
| Status | Proposed — pending B0-06 independent review |
| Context | No report/export endpoint or page exists (SEC-0010). Phase B requires bounded PDF/CSV without secrets, raw payloads or unauthorized audit data. |
| Decision | FastAPI authorizes report scope before generation. Server-selected fields and bounded rows/bytes/time drive output. CSV formulas are neutralized and filenames/content are safe. |
| Security rationale | Enforces INV-001/005/006/009 and mitigates THR-027/028. |
| Alternatives considered | Client-only export, unbounded database dump, public report URL and raw audit/vendor payload export rejected. |
| Consequences | Requires report permission, query/worker limits, temporary output isolation, provenance and explicit failure/stale state. |
| Implementation tasks | B7-03, B8-06, B10-02, B10-06, B10-08 |
| Validation evidence | Role/object tests, row/byte/time bounds, CSV formula cases, safe filename, canary scan, load/cancel and reviewed artifacts. |
| Approval dependency | None for design; APR-15 for release acceptance. |
| Review trigger | Format, field, scope, storage, generation mode or report permission change. |

## ADR-009 — Sanitized observability and auditable state transitions

| Field | Record |
| --- | --- |
| Status | Proposed — pending B0-06 independent review |
| Context | Current middleware creates correlation IDs and safe route-template logs (`backend/app/core/request_context.py:65-138`), and ingestion persists run/error states. Actor/control audit and full-stack health remain incomplete. |
| Decision | Emit correlation IDs, authenticated actor/action/target/result, closed state and sanitized error category. Never log raw request/response payload, unsafe URL/query, credentials or exception. Preserve deferred, partial and failed states. |
| Security rationale | Enforces INV-004/005/006/007/012 and mitigates THR-006/007/010/016/019/024/025/028/031/033. |
| Alternatives considered | Raw access logs, stack traces, swallowed errors and allow-on-error health rejected. |
| Consequences | Requires allow-listed schemas, restricted audit access/retention, failure injection and correlation across edge/API/Prefect/DB/UI. |
| Implementation tasks | B1-06, B2-04, B2-06, B7-04, B8-06, B8-07, B9-04 |
| Validation evidence | Canary/redaction tests, actor/action audit, injected partial/failure, correlation sample and truthful health/browser evidence. |
| Approval dependency | APR-12 for monitoring recipient/provider; operational logs can remain self-hosted. |
| Review trigger | New event/state/error/recipient/log sink or health dependency. |

## ADR-010 — Docker Compose staging boundary for the submission

| Field | Record |
| --- | --- |
| Status | Proposed — pending B0-06 independent review |
| Context | Production Compose provides hardened frontend/backend/PostgreSQL and manual migration with persistent DB volume and health checks (`compose.prod.yml:15-150`). It lacks proxy, Prefect and backup. |
| Decision | Use Docker Compose for the submission staging boundary, adding required protected services and persistence through assigned tasks. Run production images/commands, expose exact commit/version, and control restart. Kubernetes remains post-submission backlog. |
| Security rationale | Enforces INV-005/008/012 and mitigates THR-029–032. |
| Alternatives considered | Development Compose/run scripts and Kubernetes for the submission rejected; public database/Prefect rejected. |
| Consequences | Requires approved host, edge, networks, least roles, secrets, health, persistence, backup and recovery evidence. |
| Implementation tasks | B9-01 through B9-06, B11-01, B11-02 |
| Validation evidence | Compose config, images/SBOM, ports/networks/users/caps/health, deployed identity, restart and isolated restore evidence. |
| Approval dependency | APR-07–12 and APR-15; local fallback must be explicitly accepted where required. |
| Review trigger | Orchestrator, host, network, image, service, volume, secret or deployment-mode change. |

## ADR-011 — No malware handling or active offensive behaviour

| Field | Record |
| --- | --- |
| Status | Proposed — pending B0-06 independent review |
| Context | Project authorization is defensive OSINT. Current source policies prohibit scanning, malware retrieval and file submission. |
| Decision | Process metadata-only defensive intelligence. Do not retrieve/upload malware samples or binaries, execute exploits, scan/probe targets, steal credentials, create persistence or bypass controls. |
| Security rationale | Enforces INV-002/006/010/011 and bounds THR-014/015. |
| Alternatives considered | Malware sandbox, active exposure validation, file submission and unrestricted enrichment rejected. |
| Consequences | Interfaces and tests remain metadata-only/offline; unsupported data is rejected or omitted. |
| Implementation tasks | B3-01 through B3-06, B5-01 through B5-06, B6-01 through B6-08, B10-05 |
| Validation evidence | Static interface/network review, safe synthetic fixtures, zero file/binary/scan path and no-live-request evidence. |
| Approval dependency | Approval cannot authorize work outside the project defensive boundary. |
| Review trigger | Any proposed file, binary, scan, active-validation, submission or offensive capability. |

## ADR-012 — Truthful UI and no production mock fallback

| Field | Record |
| --- | --- |
| Status | Proposed — pending B0-06 independent review |
| Context | Overview still imports deterministic operational/collection preview state (`frontend/src/app/(dashboard)/page.tsx:8,64-121`; SEC-0003) and sidebar/search expose nonfunctional controls. |
| Decision | Dynamic production state comes from authorized API/PostgreSQL/Prefect evidence. Missing data becomes explicit loading, empty, stale, permission, disabled or failure state. Synthetic fixtures stay in tests/dev tools and never replace failed production data. |
| Security rationale | Enforces INV-004/006/007/012 and mitigates THR-006/016/028/033. |
| Alternatives considered | Labelled production preview, cached demo fallback, fake health/success and Coming Soon/dead release controls rejected. |
| Consequences | Remove preview imports/dead controls and reconcile visible values to API, DB, source and run evidence. |
| Implementation tasks | B8-01 through B8-07, B10-06, B11-01, B11-02 |
| Validation evidence | Import/control crawl, network capture, exact DB/run reconciliation, failure/stale/disabled/browser states and mentor UAT. |
| Approval dependency | Disabled-state approval semantics follow APR-01–14; APR-15 accepts only the exact truthful candidate. |
| Review trigger | New mock/fixture/cache/fallback, health/status claim, page/control or data-source change. |

## Shared invariant traceability

| Invariant | ADRs | Components/flows | Threats | Required validation |
| --- | --- | --- | --- | --- |
| INV-001 | ADR-005/008/009 | CMP-004/005/018/023; DF-003–005, DF-010, DF-013, DF-031 | THR-001–004/022/027 | Backend role/object/function/direct-request tests |
| INV-002 | ADR-004/006/011 | CMP-012–016; DF-015, DF-016, DF-034 | THR-012–015 | Zero-transport SSRF/redirect/policy tests |
| INV-003 | ADR-002/003 | CMP-006/011/012; DF-020/021 | THR-019/020/023 | Commit/rollback/checkpoint/no-overlap tests |
| INV-004 | ADR-002/003/009/012 | CMP-011/012/019; DF-019–023/028 | THR-006/016/019/020/024/028/033 | Failure/partial/counter/state reconciliation |
| INV-005 | ADR-005/007–010 | CMP-017–019; DF-005, DF-010, DF-018, DF-022, DF-023, DF-031, DF-033, DF-034 | THR-025–027/030 | Secret canary and access tests |
| INV-006 | ADR-004/008/009/011/012 | CMP-003/004/013/018/019; DF-009/017/022 | THR-005/007/010/013/014/025 | DTO/error/payload/rendering tests |
| INV-007 | ADR-009/012 | CMP-003/018/020; DF-009/019/023/030 | THR-006/028/033 | Import/network/DB/browser reconciliation |
| INV-008 | ADR-001–003/010 | CMP-002/006/009; DF-011–014, DF-032 | THR-017/022/030 | Port/network/admin/grant negatives |
| INV-009 | ADR-005/008 | CMP-004/018; DF-010, DF-029, DF-033 | THR-027/028 | Export RBAC/formula/bounds/content tests |
| INV-010 | ADR-006/007 | CMP-015–017; DF-015, DF-018, DF-034 | THR-015/025/026 | Approval/config/zero-request reconciliation |
| INV-011 | ADR-004/006/011 | CMP-013–016; DF-015–017 | THR-014/015 | Static interface and safe-fixture review |
| INV-012 | ADR-009/010/012 | All release components/flows | THR-001–033 | Final findings, candidate, UAT and APR-15 evidence |

## Gap and approval impact summary

| Gap group | ADR response | Approval state |
| --- | --- | --- |
| GAP-001–003 UI scope/truth | ADR-012 | No approval can waive required truthful pages |
| GAP-004/017 identity/access | ADR-005 | APR-13/14 remain `Need Approval` |
| GAP-005/006 orchestration | ADR-002 | APR-06 remains `Need Approval` |
| GAP-007/008/016 edge/deployment | ADR-001/010 | APR-07/08 remain `Need Approval` |
| GAP-009 reports | ADR-008 | Required control; APR-15 later |
| GAP-010/011 database/transaction | ADR-003/009 | APR-09 pending; privileged role/SEC-0020 cannot be waived |
| GAP-012 supply chain | ADR-010 | SEC-0021 bounded follow-up pending image review |
| GAP-013/014 recovery/monitoring | ADR-009/010 | APR-11/12 remain `Need Approval` |
| GAP-015/018 secrets/gated sources | ADR-006/007 | APR-01–05/10 remain `Need Approval`; integrations disabled |

## Known limitations and next action

- These ADRs are proposed and not implemented or approved.
- All approval fields remain pending; safe fallbacks are not decisions.
- Current evidence is repository-static plus read-only import/config validation.
- Companion traceability covers 34 flows, DF-001 through DF-034; the four
  hardened store flows remain target requirements rather than implementation.
- No Mermaid tool, live source, ingestion, deployment, security test or browser
  runtime was used for B0-06.
- The official workbook predates Git completion of B0-02 through B0-05.
- The existing Windows CRLF migration-hash limitation is unchanged.

After independent review and a separately authorized staging/commit lifecycle,
the exact next task is B1-01. B1-01 is not started here.
