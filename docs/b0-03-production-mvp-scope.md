# B0-03 Production MVP Definition of Done

## 1. Document control

| Field | Frozen value |
| --- | --- |
| Task | B0-03 — Freeze production MVP definition of done |
| Artifact status | Scope-freeze artifacts ready for independent review; not approved or complete |
| Scope-freeze date | 29 July 2026 |
| Branch | `dev` |
| Source checkpoint | `bdcf13d2053297c0c09f6d7ef5c4505a7edfa455` |
| Source commit | `bdcf13d B0-02 Audit repository and UI scope` |
| Dependency | B0-02 completed, independently reviewed, committed and pushed |
| Release deadline | 11 August 2026 |
| Release target | Mentor-accessible staging with truthful, secure, functional release behaviour |
| Detailed acceptance register | `docs/b0-03-release-acceptance-checklist.csv` |

This document freezes release scope and acceptance criteria. It does not implement
release functionality, prove future runtime criteria, approve B0-03, or record
mentor acceptance.

## 2. Task, dependency and checkpoint

The mandatory checkpoint gate passed before drafting:

- branch was exactly `dev`;
- the initial working tree was clean;
- `git fetch origin` succeeded;
- local `HEAD` and refreshed `origin/dev` both equalled
  `bdcf13d2053297c0c09f6d7ef5c4505a7edfa455`;
- `HEAD` was `B0-02 Audit repository and UI scope`;
- B0-02 was the completed dependency; and
- B0-03 was the next task.

The official workbook snapshot predates the pushed B0-02 completion and still
shows B0-02 as Not Started. That is a timing limitation, not the current
repository state. B0-03 does not edit the workbook. No pull, branch switch,
stage, commit, push, reset, restore, clean, deletion, or history rewrite is
authorized by this task.

## 3. Executive release definition

The 11 August 2026 release is one mentor-accessible staging deployment of the
defensive Cyber OSINT Dashboard. It must expose the exact 12-page top-level
sidebar defined below, protect users and privileged actions with backend-enforced
local RBAC, run approved ingestion through one self-hosted Prefect parent cycle
every two hours, persist truthful normalized data in PostgreSQL, and provide
auditable deployment, backup, restore, recovery, test, UAT, and sign-off evidence.

Release means all Required criteria are implemented, tested, evidenced, and
reviewed; each Approval-Gated capability is either approved within its exact
boundary or accurately disabled; each Removed or Post-Submission Backlog item is
absent; and every Accepted Limitation is bounded, safe, explicit, and accepted by
the authorized final approver.

The release must not contain visible Coming Soon items, dead controls,
fake-success states, hardcoded preview data presented as live, unsupported
claims, demo-only production behaviour, shared default credentials, unprotected
administrative surfaces, unapproved external requests, or application use of the
privileged PostgreSQL initialization role.

Any open evidence-backed Critical or High security defect, authorization bypass,
secret exposure, unsafe external access, corruption risk, broken required
function, fake success, production mock state, or unresolved approved Must Fix
finding blocks release. This scope document cannot waive those conditions.

## 4. Release classifications

| Classification | Frozen meaning |
| --- | --- |
| Required | Must be implemented, tested, evidenced, and accepted before release. |
| Approval-Gated | Live use requires a recorded approval, entitlement, credential, licence, owner, endpoint policy, or infrastructure decision. Without it the capability remains accurately disabled and makes no live claim. |
| Removed | Must not appear in navigation, routes, controls, documentation claims, or demonstration material. |
| Post-Submission Backlog | Not part of the 11 August release and must not appear as a Coming Soon item. |
| Accepted Limitation | A bounded, safe, documented limitation that does not undermine required functionality, security, integrity, or truthful operation. |

Accepted Limitation may not excuse a Critical or High defect, required
functionality, authorization failure, unsafe access, corruption risk, or false
success. `Pending Evidence` means a future runtime or implementation criterion
has not passed. `Approval Pending` means no approval is claimed. `Scope Frozen`
records a scope decision, not runtime acceptance.

## 5. Mentor-accessible staging definition

Mentor-accessible staging means all of the following are true for one exact
release-candidate commit:

1. The host and access method are approved under APR-07, or the mentor has
   explicitly accepted the documented local fallback.
2. Access is authenticated with unique role-based test users and no default or
   shared credentials.
3. Routing is TLS-ready and host-validated under APR-08, or an explicitly
   accepted secure local fallback is used.
4. PostgreSQL, the FastAPI backend, Next.js frontend, Prefect server, and worker
   are protected and show truthful health; PostgreSQL and Prefect administration
   are not publicly exposed.
5. PostgreSQL and required Prefect state persist through controlled restart.
6. Secrets arrive through the APR-10-approved mechanism and never appear in
   source, images, logs, UI, reports, or evidence.
7. The application uses a least-privilege database identity distinct from
   initialization and migration ownership.
8. Production images and commands run without reload or development server mode.
9. The deployed version and Git commit are visible and reconcile to the release
   manifest.
10. All 12 pages work, and no Coming Soon, dead, synthetic-live, or unsupported
    release surface remains.

Local validation alone is not mentor-accessible staging unless the mentor
explicitly accepts that fallback. A healthy availability endpoint does not
prove database, orchestration, source, page, or recovery readiness.

## 6. Final 12-page sidebar and canonical route matrix

| Page | Canonical route | Responsible task | Release classification | Scope-freeze status |
| --- | --- | --- | --- | --- |
| Overview | `/` | B8-01 | Required | Pending Evidence |
| Threat Feed | `/threat-feed` | B8-05 | Required | Pending Evidence |
| Vulnerabilities | `/vulnerabilities` | B8-05 | Required | Pending Evidence |
| UAE Intelligence | `/uae-intelligence` | B8-04 | Required | Pending Evidence |
| IOC Search | `/ioc-search` | B8-05 | Required | Pending Evidence |
| Ingestion Operations | `/ingestion-operations` | B8-02 | Required | Pending Evidence |
| Sources | `/sources` | B8-03 | Required | Pending Evidence |
| Run History | `/run-history` | B8-03 | Required | Pending Evidence |
| Reports | `/reports` | B8-06 | Required | Pending Evidence |
| System Health | `/system-health` | B8-06 | Required | Pending Evidence |
| Audit Log | `/audit-log` | B8-06 | Required | Pending Evidence |
| Methodology | `/methodology` | B8-06 | Required | Pending Evidence |

These are exactly the top-level sidebar pages. Existing article and
vulnerability detail routes may remain as subordinate workflow routes; they do
not create additional top-level sidebar items.

## 7. Page-level definition of done

Every page must have its canonical route and one accessible sidebar entry;
keyboard-operable navigation; responsive layout; API-backed truth where data is
dynamic; explicit loading, empty, sanitized error, and applicable stale or
freshness states; an applicable permission-denied state; safe React text and URL
rendering; bounded search, filters, and pagination; and no unsupported claim,
hardcoded preview presented as live, or nonfunctional control. Direct URL access
must not bypass backend authorization.

| Page | Minimum release behaviour | Required evidence |
| --- | --- | --- |
| Overview | API-backed KPIs, trends, freshness, source state, deployed version, and commit; no production import of synthetic preview values. | Route/component tests, browser and network evidence, database reconciliation, and deployed identity. |
| Threat Feed | Normalized publication and threat metadata, filters, timestamps, provenance, and validated canonical links. | API and UI tests, safe-link tests, browser evidence, and stored provenance. |
| Vulnerabilities | CVE, KEV, EPSS, and UAE evidence with bounded filtering and pagination and truthful missing fields. | API bounds, database-backed success/empty evidence, UI states, and detail navigation. |
| UAE Intelligence | Official UAE evidence, relevance rules, sectors, emirates, languages, related CVEs, provenance, and freshness without unsupported attribution. | Source-attributed fixtures/data, rule-semantic review, API/UI tests, and browser evidence. |
| IOC Search | Validated, bounded single-IOC search with provenance, enrichment state, safe output, and no unrestricted bulk lookup. | Input/rate negative tests, authorization evidence, source-policy checks, and browser evidence. |
| Ingestion Operations | Parent-cycle and source-run state, last attempt/success, next run, duration, counts, retry class, quota/freshness, and sanitized failure; authorized run/retry/pause/enable/disable. | Prefect/API state tests, RBAC matrix, audit correlation, and scheduled-run browser evidence. |
| Sources | Fixed policies, approved hosts, access class, approval/checkpoint state, and credential-configured boolean only; no endpoint editor or secret values. | Policy/API tests, zero-transport disabled cases, RBAC, UI evidence, and canary scan. |
| Run History | Paginated cycles, source runs, events, defer reasons, failure categories, and correlation evidence. | API pagination/filter tests, database-backed histories, correlation sample, and UI evidence. |
| Reports | Bounded authorized PDF and CSV export; formula-injection prevention, safe filenames, field allow-list, and no secrets/raw payloads. | Export/RBAC/security tests, reviewed sample artifacts, and size/row limits. |
| System Health | Truthful backend, PostgreSQL, Prefect server/worker, source freshness, storage/operations, and deployed commit; no allow-on-error health. | Fault injection, health contracts, restart evidence, browser capture, and sanitized logs. |
| Audit Log | Authorized bounded search over allow-listed fields and correlation IDs; no credentials, tokens, bodies, sensitive headers, or unbounded export. | RBAC and query tests, canary scan, representative audit records, and UI evidence. |
| Methodology | Sources, scoring, UAE relevance, provenance, freshness, limitations, security boundaries, and disabled/approval-gated meanings. | Complete content review, route/component tests, safe-link checks, and browser evidence. |

An honest empty, unavailable, disabled, or permission state is the only safe
fallback when live data or permission is absent. Fixture or preview content may
support tests but may not replace failed production data.

## 8. Authentication and RBAC definition of done

The required local roles are Viewer, Analyst, Ingestion Operator, and
Administrator. SSO is optional unless APR-14 requires it; secure local RBAC is
mandatory in every case.

Release acceptance requires unique accounts; no shared or default credentials;
no default administrator password; safe disabled-account handling; secure login
and logout; bounded session expiry; revocation after logout, disablement, or
administrator action; backend enforcement on every protected route; BOLA, BFLA,
and mass-assignment negative tests; administrator-only user and source controls;
operator-only ingestion actions; separately protected reporting and audit
access; role-appropriate navigation; direct-request denial; generic 401/403
responses; and no credential, token, session, cookie, or sensitive-header
exposure.

Ownership is explicit: B7-01 owns local identity and the role model; B7-02 owns
secure authentication, sessions, sensitive authentication data, and generic
errors; B7-03 owns backend authorization, privileged controls, BOLA/BFLA, mass
assignment, reports, and audit access; B7-05 owns role-aware navigation and
protected routes; and B7-06 owns final authentication-abuse and edge-case
validation. Frontend hiding is never authorization. Missing or invalid role data
denies access.

## 9. Two-hour ingestion-cycle definition of done

Self-hosted Prefect is the sole required development/staging orchestrator. One
parent deployment runs every two hours in the APR-06-approved timezone. Exactly
one approved schedule may exist, and a parent cycle may not overlap itself.

Each enabled source runs as an independently observable flow. One source failure
must not stop unrelated approved sources. Checkpoints advance only after
successful committed persistence. Retries and backoff are bounded and
classification-aware; quotas and rate limits are enforced; all outbound access
stays behind fixed source policies; and partial failure never becomes full
success.

Disabled, approval-gated, missing-credential, licence-required, quota-deferred,
rate-limited, no-change, partial, failed, and cancelled states are explicit.
Manual run, retry, pause, enable, and disable actions require backend
authorization and audit evidence. The demonstration includes either an observed
scheduled cycle or an explicitly approved staging rehearsal correlated across
Prefect, persisted run records, checkpoints, and UI history.

Task ownership separates the controls: B2-01 owns self-hosted Prefect; B2-03 owns
the two-hour schedule and independently observable flows; B2-04 owns overlap
protection, retry/backoff, quotas, truthful source states, and credential-state
semantics; B2-05 owns checkpoint advancement after committed persistence; and
B2-06 owns authorized operator actions. The relevant page tasks own final UI
evidence. Until APR-06 is recorded, operation is limited to controlled staging,
no general production schedule is claimed, and unapproved sources remain
disabled.

## 10. Database and data-integrity gates

Before release, evidence must establish:

- one linear Alembic head and preserved committed migration history;
- no edit to historical migrations, migration tests, or expected hashes to hide
  the Windows CRLF limitation;
- named constraints, deterministic keys, uniqueness, and idempotency controls;
- query-critical indexes validated against representative release query paths;
- distinct least-privilege application and migration roles and bounded pooling;
- explicit caller-owned transaction boundaries and observable rollback failure;
- no overlapping cycle, checkpoint movement only after commit, and no success
  after failed persistence;
- duplicate-safe retries and deterministic stale-update handling;
- explicit partial-failure state with reconciled counters and no false success;
- retention that preserves active evidence, provenance, and required
  relationships;
- auditable backup metadata and a restore tested against compatible migrations;
  and
- no raw payload, SQL, database error, stack trace, environment value, or secret
  leakage.

Ownership is separated by the official tasks: B1-03 owns Alembic history, named
constraints, keys, and uniqueness; B1-04 owns transaction and partial-failure
semantics; B1-05 owns least-privilege roles, pooling, query-critical indexes, and
retention; B1-06 owns safe persistence errors; B2-04 owns no-overlap execution;
and B2-05 owns checkpoint-after-commit behaviour. B9-05 and B9-06 own backup,
restore, and recovery evidence. Database evidence must include migrated
PostgreSQL inspection and exact counts; offline model tests alone are
insufficient for final acceptance.

## 11. Source and external-request gates

No live source request is permitted without its fixed approved policy. Policies
use exact approved HTTPS hosts and paths and reject arbitrary hosts, endpoints,
redirect targets, headers, cookies, callbacks, and environment-proxy influence.
Connect, read, write, pool, and total timeouts; response bytes; pages; objects;
rate; and quota are bounded. Inputs and outputs are normalized to allow-listed
fields and errors are sanitized.

Commercial sources remain disabled unless their approval, entitlement, module,
endpoint policy, credential custody, retention terms, and quota are configured.
UAE public-site automation remains disabled until APR-05 and its policy are
complete. Missing credentials are a configuration state, not source failure.
Approved display states include `Need Approval`, `Licence Required`,
`Credentials Not Configured`, `Quota Unavailable`, and `Disabled`.

Offline fixtures and mocked transports prove adapter behaviour only. They may
not be labelled live, current, or production data. Failed live ingestion has no
fake fallback. Raw vendor payloads, tokens, authorization headers, cookies,
unsafe exceptions, and restricted licensed fields do not enter public UI,
reports, logs, or evidence.

B10-05 owns bounded external-request, SSRF, and redirect-policy assurance;
B2-04 owns truthful credential-missing source states; and B10-06 owns the final
review that fixtures, mocks, and swallowed failures do not create production
fake success. Source-adapter implementation remains with its specific source
task.

## 12. Security and privacy gates

Release assurance requires traceable applicable-control evidence for OWASP Top
10:2025, OWASP API Security Top 10:2023, and OWASP ASVS 5.0.0. The project must
not claim blanket framework compliance.

Required tests and reviews cover SQL, command, template, header, CSV, and PDF
injection under B10-02; XSS, output encoding, unsafe URLs, and CSP under B10-03;
BOLA, BFLA, mass assignment, authentication, session abuse, and
logout/revocation under the B7 tasks; SSRF, redirects, and outbound policy under
B10-05; AI-generated logic, swallowed failures, fake success, stale mocks, and
unsafe defaults under B10-06; secrets, sensitive logging, dependencies, SBOM,
and containers under B10-07; and exceptional conditions, performance,
concurrency, and recovery under B10-08. B10-01 owns the traceable framework
assessment.

No evidence-backed Critical or High defect or unresolved approved Must Fix may
remain. Affected approval-gated or optional functionality may be disabled, but
required functionality and security boundaries may not be relabelled as
limitations.

## 13. Reporting, health and audit gates

Reports are role-protected and bounded by allowed fields, rows, bytes, and safe
filenames. CSV output neutralizes spreadsheet formulas, and PDF/CSV output
contains no secrets, raw payloads, sensitive headers, or unauthorized records.

System health distinguishes healthy, degraded, unhealthy, stale, disabled, and
unknown states for backend, PostgreSQL, Prefect server, worker, sources,
freshness, storage, and deployed identity. Exceptions and missing checks never
default to healthy.

The Audit Log exposes only authorized allow-listed fields, bounded search and
pagination, stable correlation IDs, safe actor/action/result metadata, and
sanitized failure categories. It excludes credentials, tokens, cookies, raw
bodies, raw paths with sensitive values, complete exceptions, and unbounded
exports.

## 14. Deployment and operational gates

The release uses production images and commands, not `run.cmd dev`, reload
servers, development Compose, source mounts, or default development settings.
Required evidence covers the approved host/access decision; TLS-ready or
accepted secure routing; host/origin validation; private PostgreSQL and Prefect
administration; authenticated role users; safe secret injection; least-privilege
database access; persistent PostgreSQL and Prefect state; backend/database/
orchestrator/worker health; bounded sanitized logs; deployed commit/version;
controlled restart; and accurate source states.

B9-03 owns approved staging access and persistent PostgreSQL and Prefect state;
B9-04 owns runtime health, monitoring and alert evidence, and safe secret
injection; B9-06 owns restart and recovery validation; and B11-01/B11-02 own
final release and demonstration evidence. Public-internet readiness is not
inferred from local Compose validation. No default credential, development
server, privileged application database role, public Prefect administration,
Coming Soon item, or dead control is permitted.

## 15. Backup, restore and recovery gates

The release needs a bounded backup procedure with safe filenames, encryption,
integrity hash, secret exclusion, PostgreSQL data, required Prefect state,
approved or explicitly temporary protected destination, access controls, and
retention. A named volume is not a backup.

The backup must be restored into an isolated environment. Evidence must compare
Alembic compatibility, representative table counts, constraints, and permissions
and record timed backup/restore results against approved RPO and RTO. B9-05 owns
backup and restore; B9-06 owns rollback and recovery.

Recovery evidence includes an application rollback rehearsal, migration-failure
rehearsal, worker/source/credential failure recovery, last-committed-checkpoint
recovery without duplicates, and accurate sanitized incident notes. A backup
file without a successful representative restore does not pass this gate.

## 16. Removed and post-submission features

| Feature | Frozen decision | Release acceptance | Checklist owner |
| --- | --- | --- | --- |
| Separate Threat Entities sidebar page | Removed as a separate page; safe metadata may be integrated into Threat Feed/provenance under B4-04 | No separate route, sidebar item, card, control, claim, or promise. | B4-04 |
| Advanced threat graph | Post-Submission Backlog | Entirely absent; no Coming Soon representation. | B8-01 |
| Machine-learning predictions | Removed | No prediction output or claim; deterministic rules remain accurately described. | B8-01 |
| Automated blocking or SOAR | Removed | No action endpoint, control, claim, or demonstration promise. | B8-01 |
| Malware sample processing | Prohibited and Removed | No upload, retrieval, storage, detonation, or binary processing. | B8-01 |
| VirusTotal file upload | Prohibited and Removed | No file submission, upload, or sample retrieval even if API access is approved. | B6-05 |
| Intelligence chatbot | Post-Submission Backlog | Entirely absent; no Coming Soon representation. | B8-01 |
| Slack, Teams, or email alerts | Post-Submission Backlog | No product alerting feature; APR-12 operational monitoring is separate and does not authorize Slack, Teams, or email product alerts. | B8-01 |
| Mobile application | Removed | No native application claim; responsive web is Required. | B8-01 |
| Custom dashboard builder | Removed | No route, control, claim, or promise. | B8-01 |
| Multi-tenant customer platform | Removed | No tenant selector, tenant administration, or multi-tenant claim. | B8-01 |
| Kubernetes deployment | Post-Submission Backlog | No Kubernetes readiness claim; approved Compose staging remains the release path. | B9-01 |
| Advanced SSO | Approval-Gated under APR-14 | Without approval, SSO is absent and secure local RBAC remains Required. | B7-01 |

Every item is checked across navigation, Coming Soon cards, controls, routes,
documentation claims, and demonstration material. B0-03 creates no backlog
implementation tasks. APR-12 remains an operational monitoring decision only;
it is not linked to or permission for the excluded product-alerting feature.

## 17. Approval-gated sources and infrastructure

B0-05 owns obtaining, recording, and evidencing each approval decision. The task
mappings in the table identify the later implementation or final release tasks
affected by that decision; they do not replace B0-05 as the approval-record
owner.

No decision below has been made during B0-03; every owner is
`Pending assignment`. APR-01 through APR-14 target 4 August 2026, and APR-15
targets 11 August 2026. Approval records must be attributable and dated but must
not expose credentials or protected access details.

| ID | Decision and why required | Later implementation area | Required evidence | Release-safe fallback and ability to proceed |
| --- | --- | --- | --- | --- |
| APR-01 | Commercial API budget and existing accounts establish whether gated integrations are affordable and available. | B6-01 through B6-08 | Decision owner, budget/account scope, and explicit enabled/disabled matrix. | Disable dependent commercial APIs and make no live claim; release may proceed with them disabled. |
| APR-02 | Censys entitlement, token owner, exact endpoints, capabilities, and credit budget bound authorized use. | B6-02 through B6-04 | Entitlement record, fixed policy, quota, custody, and zero-transport disabled evidence. | Retain approved public publication workflows only; gated Censys enrichment stays disabled and release may proceed. |
| APR-03 | VirusTotal permitted business use and API tier determine allowed metadata enrichment, storage, display, and quota. | B6-05 through B6-06 | Licence/tier record, permitted fields, quota, retention, and disabled-state evidence. | Disable API enrichment; file upload and malware retrieval remain prohibited; release may proceed. |
| APR-04 | Recorded Future subscription and licensed modules determine lawful structured access. | B6-07 through B6-08 | Subscription/module record, automation/storage/redistribution terms, policy, and quota. | Disable the integration and make no coverage claim; release may proceed. |
| APR-05 | UAE source automation approval establishes permitted official hosts, terms, cadence, ownership, and retention. | B5-01 through B5-04 | Approved-source register, fixed policies, limits, owner, and zero-request tests for disabled sources. | Use approved manual/offline evidence with accurate freshness; unapproved automation remains disabled. |
| APR-06 | Two-hour schedule and timezone establish the single cadence, staging timezone, maintenance, and operational owner. | B2-03 | Decision record, one Prefect schedule, owner, and observed cycle or approved rehearsal. | Controlled staging only after a timezone decision; no production claim. This is blocking for the scheduled-cycle gate. |
| APR-07 | Hosting provider and access method establish where and how the mentor reaches staging. | B9-03 | Host/environment identity, access method, owner, and successful mentor-path check. | A local fallback is valid only with explicit mentor acceptance; otherwise release is blocked. |
| APR-08 | Domain/subdomain and TLS ownership establish trusted routing, certificate lifecycle, and host validation. | B9-02 | Ownership record, certificate/hostname validation, proxy review, and renewal owner. | Keep services private/loopback; secure local fallback requires explicit acceptance. Public release is otherwise blocked. |
| APR-09 | PostgreSQL hosting and retention establish storage, encryption, maintenance, role separation, and lifecycle. | B1-05 and B9-03 | Hosting/retention decision, sanitized grants, persistence, and backup scope. | Only an explicitly approved temporary staging decision is allowed; privileged application access is never a fallback. |
| APR-10 | Secret-management provider and delivery establish custody, injection, rotation, revocation, and incident response. | B1-01 and B9-04 | Provider decision, delivery design, rotation/revocation test, and secret scan. | Credential-dependent services remain disabled; required authenticated staging is blocked without safe secrets. |
| APR-11 | Backup destination and retention establish protected storage, encryption, access, and lifecycle. | B9-05 | Destination decision, backup hash, isolated restore, retention test, RPO/RTO record. | An explicitly approved temporary protected destination may be used; no restore means no release. |
| APR-12 | Monitoring/alert provider and recipient establish operational detection, routing, retention, and ownership. | B9-04 | Decision, health/failure alert test, recipient confirmation, and redaction review. | Bounded manual staging observation requires explicit acceptance and cannot be called integrated alerting. |
| APR-13 | Staging user list and local RBAC acceptance authorize accounts and role assignments. | B7-01 | Approved user/role inventory without secrets and complete authorization matrix. | Staging remains inaccessible until approved unique users and roles exist. |
| APR-14 | SSO decision determines whether advanced SSO is required in addition to mandatory local RBAC. | B7-01 | Explicit identity decision and, if required, separately reviewed SSO acceptance evidence. | Secure local RBAC is the default; omit SSO claims. Release may proceed without SSO when local RBAC is accepted. |
| APR-15 | Final release acceptance and residual risk authorize handover of the exact candidate. | B11-02 and B11-05 | Exact commit, complete evidence index, UAT, limitations, findings, approvals, and attributable final decision. | No release approval or accepted-handover claim. This gate is always blocking. |

For all approval-gated sources, the UI reports only the safe state and a
credential-configured boolean. It never displays a token, header, cookie, secret,
or editable arbitrary endpoint. Approval of one capability does not authorize a
different vendor family, module, host, path, active scan, file upload, or
malware-processing feature.

## 18. B0-02 finding closure matrix

| B0-02 ID | Frozen closure criterion | Responsible task | Required closure evidence | Consequence if unresolved |
| --- | --- | --- | --- | --- |
| SEC-0001 | All 12 required routes and sidebar entries are present, functional, and meet page acceptance. | B8-01 | Route/sidebar inventory, automated tests, and mentor-visible browser evidence. | Release blocker. |
| SEC-0002 | All Coming Soon items and dead controls are removed; every remaining visible control works and is authorized. | B8-01 | UI crawl, control inventory, interaction tests, and browser evidence. | Release blocker. |
| SEC-0003 | Production-visible preview imports and synthetic-live behaviour are absent; UI data traces to API/PostgreSQL or honest empty/error states. | B8-01 | Import search, network evidence, exact database reconciliation, and browser states. | Release blocker. |
| SEC-0004 | Unique local identity and backend-enforced Viewer, Analyst, Ingestion Operator, and Administrator RBAC pass direct-request negative tests. | B7-01 | B7-01 through B7-06 tests, role matrix, and UAT. | Release blocker. |
| SEC-0005 | Self-hosted Prefect, one two-hour parent schedule, independent flows, truthful states, and authorized operator controls are evidenced. | B2-01 | Prefect deployment/run evidence, checkpoint reconciliation, RBAC tests, and UI history. | Release blocker. |
| SEC-0019 | Application database access is least privilege and distinct from initialization/migration ownership. | B9-01 | Sanitized grants, denied schema/superuser actions, pool configuration, and deployment review. | Release blocker. |
| SEC-0020 | Anomali and Censys rollback cleanup failures are observable, sanitized, non-successful, and do not advance checkpoints. | B1-06 | Focused injected-failure tests, transaction assertions, and logs. | Release blocker as an approved Must Fix. |
| SEC-0021 | Production test dependencies are removed or explicitly reviewed as bounded residual image risk. | B9-01 | SBOM/image package inventory and final disposition. | Non-blocking follow-up unless final review escalates the demonstrated risk. |

The seven promoted findings are not Accepted Limitations. B0-03 records closure
criteria only and does not remediate any finding.

## 19. Release evidence requirements

Evidence must be tied to the exact release-candidate commit, dated, reproducible,
sanitized, and explicit about commands, exit codes, totals, warnings, skips,
failures, environments, and limitations. Required evidence includes:

- Git branch, clean status, local and remote commit identity, diff, and release
  manifest;
- complete automated backend/frontend tests, TypeScript check, production build,
  Compose validation, migrations, database/role inspection, and exact counts;
- route, sidebar, browser, keyboard, responsive, permission, API/network, safe
  rendering, empty/error/stale, and no-dead-control evidence for all pages;
- authentication, BOLA/BFLA, mass assignment, session, injection, XSS, SSRF,
  redirects, source-policy, log/secret, dependency/SBOM/container, concurrency,
  exceptional-condition, and recovery evidence;
- the single Prefect schedule, observed cycle or approved rehearsal, independent
  source states, checkpoints, retries, quotas, and correlation evidence;
- deployment identity, TLS/accepted routing, health, persistence, restart,
  monitoring, backup, isolated restore, rollback, RPO, and RTO evidence;
- approval register, accepted limitations, mentor UAT, task-sheet reconciliation,
  operations guide, and final attributable residual-risk decision.

Each checklist criterion is mapped to the official Phase B task that owns its
implementation or final evidence. Where one criterion previously crossed task
boundaries, the requirements were split into independently testable criteria
rather than assigned to an unrelated single task.

Current B0-03 checklist reconciliation:

| Measure | Final CSV count |
| --- | ---: |
| Total checklist rows | 121 |
| Required | 86 |
| Approval-Gated | 16 |
| Removed | 8 |
| Post-Submission Backlog | 4 |
| Accepted Limitation | 7 |
| Scope Frozen status | 12 |
| Pending Evidence status | 86 |
| Approval Pending status | 16 |
| Accepted Limitation status | 7 |
| Primary required page rows | 12 |
| Approval-register rows | 15 |
| Promoted B0-02 finding rows | 7 |

The six historical evidence limitations plus the SEC-0021 follow-up account for
the seven Accepted Limitation rows. The additional Approval-Gated row is
Advanced SSO; APR-01 through APR-15 account for the 15 approval-register rows.
No future implementation or runtime criterion is marked passed.

Focused B0-03 validation is documentation-only. The final validation record is:

| Command or check | Result |
| --- | --- |
| `git diff --check` | Exit 0; no tracked-diff whitespace error. |
| `git status --short` | Exit 0; exactly the two authorized B0-03 files are untracked. |
| `git diff -- docs/b0-03-production-mvp-scope.md docs/b0-03-release-acceptance-checklist.csv` | Exit 0 with no output because both authorized files are untracked; their complete contents were reviewed directly. |
| Artifact-tool workbook-to-Markdown-to-CSV approval reconciliation | Exit 0; read `Approval Register!A1:H16` and all 74 task IDs from the official 29 July Phase B workbook, then matched APR-01 through APR-15 to Markdown and CSV Notes with 15 PASS results while retaining B0-05 ownership. |
| Artifact-tool CSV import, inspection, formula scan, and render | Exit 0; imported 122 rows including the header and 15 columns, found no unexpected row width or formula-error cell, and rendered the official Approval Register and final approval-row fields for visual review. |

The full backend and frontend suites are intentionally not rerun solely for this
documentation task. Historical automated and deployment results remain dated
evidence, not current B0-03 executions.

## 20. Release-candidate gate

A release candidate exists only when one exact commit is identified; `dev` and
`origin/dev` match; the tree is clean; migrations, PostgreSQL, roles, full
regression, TypeScript, production frontend build, and production Compose pass;
enabled-source prerequisites and the scheduled cycle are evidenced; all 12 pages
work; excluded features are absent; no blocking security or Must Fix finding
remains; approval-gated sources are approved or accurately disabled; backup and
restore pass; limitations are documented; and the operational evidence package
is internally reconciled.

Failure of any Required criterion blocks nomination. An unrun test is not a pass,
an availability response is not a full health result, and a disabled
approval-gated source is not live coverage.

## 21. Mentor UAT gate

Mentor UAT runs against the exact staged release-candidate commit with approved
Viewer, Analyst, Ingestion Operator, and Administrator test accounts. It covers
all 12 pages; keyboard and responsive navigation; permitted and denied actions;
API-backed success, empty, error, stale, disabled, and permission states;
truthful source and cycle status; safe links/text; reports and audit; deployed
identity; key restart/recovery evidence; and absence of removed/backlog features.

The UAT record contains actual results, evidence references, defects, retests,
limitations, and an attributable decision. It remains Not Run until executed.
Automated tests do not change manual UAT status. B11-02 owns execution and
APR-15 owns final acceptance.

## 22. Residual-risk and accepted-limitation rules

An Accepted Limitation must identify its bounded condition, evidence, impact,
owner/reviewer, safe operating boundary, expiry or follow-up, and why it does not
undermine a Required gate. It must be reviewed against the exact candidate and
accepted only by the authorized final approver under APR-15.

Critical or High security defects, authorization bypass, secret exposure,
unsafe external access, data corruption, transaction failure, broken required
functionality, production mock/fake success, or unresolved approved Must Fix
cannot be accepted. A limitation that becomes materially riskier is reclassified
and blocks release. Pending approval is not acceptance, and silence is not
approval.

## 23. Known evidence limitations

1. The B0-01 PDF report was unavailable in the active review session and was not
   independently verified.
2. The available B0-01 focused evidence was reconstructed from committed files
   and is not the unavailable original archive.
3. The original 28 July P9-10 independent-review ZIP is unavailable; later
   reconstructed material must not be described as original.
4. The Windows CRLF raw-byte migration-hash assertion is environment-specific.
   Historical migrations, migration tests, and expected hashes must not be
   changed to hide it; migration semantics and history still require evidence.
5. The workbook snapshot predates pushed B0-02 completion and therefore still
   shows B0-02 as Not Started. B11-04 owns authorized reconciliation.
6. B0-02 did not establish PostgreSQL-backed UI success or empty-state acceptance
   for the final release. That evidence remains mandatory under later
   implementation and B11-02 testing; this limitation is not permission to
   release untested UI behaviour.

None of these limitations marks a future runtime criterion passed.

## 24. Sign-off record

| Sign-off field | Value |
| --- | --- |
| Prepared by | Pending |
| Independent reviewer | Pending |
| Project owner | Pending |
| Mentor/release approver | Pending |
| Scope-freeze decision | Pending |
| Decision date | Pending |
| Final residual-risk acceptance | Pending |

No name, signature, date, approval, acceptance, or decision has been fabricated.
The artifacts may be submitted for independent review but do not claim mentor
sign-off.

## 25. B0-03 definition-of-done assessment

| Criterion | Assessment |
| --- | --- |
| Mandatory Git checkpoint | Met at `bdcf13d2053297c0c09f6d7ef5c4505a7edfa455` |
| Required governance and B0-02 sources inspected | Met |
| Final 12-page scope and canonical routes | Frozen; runtime evidence pending |
| Shared and page-specific acceptance | Frozen; runtime evidence pending |
| Local identity and four-role RBAC | Frozen; implementation/evidence pending |
| Two-hour Prefect cycle and controls | Frozen; APR-06 and implementation/evidence pending |
| Data-integrity and security gates | Frozen; implementation/evidence pending |
| Fifteen approvals and safe fallbacks | Frozen; all Approval Pending |
| Removed and backlog scope | Frozen; release absence evidence pending |
| Deployment backup restore and recovery | Frozen; implementation/evidence pending |
| Seven promoted B0-02 findings | Closure criteria frozen; all evidence pending |
| Sign-off | Pending; no approval fabricated |
| Markdown/CSV reconciliation | 121 rows with counts shown in section 19 |
| Focused artifact validation and complete-file review | Met; both complete files read and reconciled after final edits |
| Focused review ZIP | Created outside the repository after final validation; path and SHA-256 are recorded in the handoff and manifest |
| Repository scope | Exactly the two authorized B0-03 files |
| Git writes | None authorized or performed |

The scope-freeze artifacts are not approved or complete. Their artifact-level
criteria are met, so they are ready for independent review; future release
implementation, evidence, approvals, UAT, and sign-off remain pending.

## 26. Exact next task: B0-04

After independent review, any separately authorized staging/commit lifecycle,
and confirmation that B0-03 remains internally consistent, the exact next Phase
B task is B0-04. B0-04 has not been started and is not part of this work unit.

Immediate next action: upload the focused B0-03 review ZIP and both complete
files for independent review before any staging or commit.
