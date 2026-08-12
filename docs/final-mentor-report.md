# Alpha Data / Cyber OSINT Dashboard — Final Mentor Report

**Release task:** C11 — Final Regression and Release Candidate
**Repository checkpoint:** `beeba6522eeac8c9a361c52d17624f02d92da5f5`
**Assessment date:** 10 August 2026
**Target branch:** `dev`
**Release target:** mentor-accessible staging deployment by 11 August 2026

> Historical scope: this report records the C11 assessment at the checkpoint
> and date above. It is not the final Git, activation, staging, or handover
> evidence for `HANDOVER-CLEANUP-01`. For current local operation, use the
> [operator guide](operator-guide.md); preserve this report's test totals and
> runtime claims as historical evidence.

## Executive summary

The Alpha Data / Cyber OSINT Dashboard is a full-stack defensive intelligence platform for collecting, normalising, correlating, searching, visualising, and reporting approved public cybersecurity information. The release candidate provides authenticated analyst and operator workflows, bounded and allow-listed APIs, PostgreSQL persistence and migrations, source governance, Prefect-oriented ingestion controls, reporting, audit trails, system health, monitoring, and local backup/recovery tooling.

C11 did not add product scope. It froze the release boundary, added repeatable release and reliability assertions, ran focused and broad regression, reconciled release documentation with the implemented system, and recorded external activation gates. The release candidate is suitable for mentor staging evaluation after the manual gates in this report are completed.

The full backend run produced **5,080 passed, 255 skipped, 56 failed**. Every failure is confined to two unchanged tests with a known Windows PowerShell/checkout byte-hash boundary. A complementary run excluding only those two files produced **5,053 passed, 255 skipped**. The frontend produced **200 passing tests**, a successful TypeScript check, and a successful production build. The new C11 tests passed. No demonstrated C11 Blocker or approved Must Fix finding remains.

This report does not claim that staging deployment, external TLS/DNS, live source activation, off-host backup storage, alert delivery, or recovery rehearsal on staging has occurred. Those are explicit manual release gates.

## Objective and release scope

The release candidate is designed for defensive, educational, and authorised use. It supports approved public cyber-intelligence workflows without active scanning, exploitation, credential collection, malware retrieval, arbitrary target access, or unrestricted outbound requests.

The visible release scope contains these twelve pages:

1. Overview
2. Threat Feed
3. Vulnerabilities
4. UAE Intelligence
5. IOC Search
6. Ingestion Operations
7. Sources
8. Run History
9. Reports
10. System Health
11. Audit Log
12. Methodology

Removed, deferred, or unsupported features are not advertised as production-ready. The release does not contain visible “Coming Soon” pages or knowingly dead release controls. Internal administration and compatibility routes may exist, but they are not part of the twelve-page mentor release navigation.

## Architecture

The system uses a Next.js and React TypeScript frontend, a FastAPI backend, PostgreSQL with SQLAlchemy and Alembic, source-specific HTTP/RSS adapters, and self-hosted Prefect orchestration. Docker Compose defines the production-shaped local service topology. Caddy is the documented reverse-proxy boundary for TLS and response security headers in the reference deployment.

The principal trust boundaries are:

- browser to reverse proxy over HTTPS;
- reverse proxy to frontend and backend services on private container networks;
- authenticated API to PostgreSQL;
- approved ingestion workers to allow-listed public sources;
- operator-controlled orchestration to source handlers;
- application services to report, audit, metrics, backup, and recovery storage;
- deployment environment to externally managed secrets, DNS, certificates, monitoring destinations, and backup destinations.

The detailed component, data-flow, and trust-boundary view is in [final-architecture-package.md](final-architecture-package.md).

## Security model

The application uses secure defaults and backend enforcement rather than relying on hidden frontend elements. Its release controls include:

- authenticated API access and backend role/permission checks;
- allow-listed response schemas and bounded request/query inputs;
- request body and ASGI receive-frame size controls;
- bounded database pools and transactional persistence;
- SQLAlchemy ORM or parameterised database access;
- fixed source hosts and paths, bounded timeouts, response/page/object limits, and redirect controls;
- sanitised API errors and structured logging;
- safe external URL handling and no untrusted `dangerouslySetInnerHTML` rendering;
- report and CSV/PDF injection protections where applicable;
- audit events for security-relevant and operator actions;
- CORS and reverse-proxy security-header configuration;
- health, metrics, and backup/recovery controls;
- environment/file-based secrets rather than hard-coded credentials.

The C10 production security audit remains the authoritative detailed security assessment. C11 rechecked the release boundary and did not weaken C10 controls. Accepted C10 limitations remain accepted unless changed by later evidence: process-local rate limiting, local single-factor authentication, an inline CSP allowance, internally accessible API documentation, and development dependency advisories that do not invalidate the verified production build.

## Authentication and authorisation

The frontend has a working authentication flow and protected release routes. The backend remains the enforcement point for authentication, authorisation, object access, and privileged operations. Operator and administrative controls are not authorised merely because the UI displays them.

Staging accounts, credentials, role assignments, credential delivery, and rotation are deployment actions. They must be configured outside source control and verified with least-privilege accounts before mentor access is issued.

## Data and migration integrity

PostgreSQL is the system of record. Persistence uses explicit models, named constraints and indexes, migrations, idempotency mechanisms, provenance relationships, checkpoints, and transaction boundaries. Checkpoints must advance only after successful persistence and commit.

C11 verified a single Alembic head, `c07a01b02c03`, and an eight-revision history. The expected migration inventory was included in the repeatable release assertions. No committed migration was rewritten during C11.

## Ingestion, sources, and UAE intelligence

The source catalogue describes approved sources and their governance state. Registration or enablement metadata is not equivalent to live activation. At the historical C11 release checkpoint, the runtime `DEFAULT_SOURCE_HANDLERS` mapping was intentionally empty. SIX-BIND-01 now code-binds exactly `nvd`, `first-epss`, `cisa-kev`, `cert-eu-security-advisories`, `google-threat-intelligence-public-research`, and `mandiant-public-threat-research` through the immutable reviewed builder. Binding does not equal activation: Prefect remains paused and SIX-BIND-01 executed no parent ingestion cycle. C05 and every other non-approved source remain unbound. A separate controlled activation-precondition task follows; a parent-cycle run still requires separate approval, and recurring Prefect unpause remains a later, separately approved step.

The C05-disabled sources remain disabled as frozen by prior work. Sources that require approval, licence, credentials, quota, or incomplete implementation retain explicit states such as `Need Approval`, `Licence Required`, `Credentials Required`, `Quota Unavailable`, or `Disabled`.

UAE intelligence pages and data structures are present, while source activation remains governed by the same approval and implementation boundaries. UAE CSC and NIBRAS are not silently treated as live production feeds.

## Orchestration and reliability

The deployment definition preserves one parent ingestion cycle every two hours using cron `17 */2 * * *` in `Asia/Dubai`, with deployment concurrency limited to one and paused-by-default activation. Source work is isolated so one source failure does not convert unrelated sources into false failures or false successes.

C11 added a mocked concurrent-source test across CISA KEV, NVD, and EPSS adapters. It verified failure isolation and independent checkpoint/progress behaviour without making live external requests. It also added isolated database-pool exhaustion/reuse coverage.

The local authenticated API workload made **132 requests** across eleven representative read paths at concurrency 12. Results were **132 successes, 0 failures**, with 28.118 ms median, 123.107 ms p95, and 130.368 ms maximum latency in the recorded run. This is local in-process evidence only; it is not a staging capacity benchmark or service-level objective.

## Operator and analyst workflows

Analysts can use the threat, vulnerability, UAE intelligence, and IOC views through bounded search, filtering, pagination, and detail workflows. Operators can inspect source governance, ingestion operations, and run history, and use authorised controls for supported run lifecycle actions. A manual control cannot bypass a missing handler, disabled source, credential requirement, licence requirement, quota restriction, or source policy.

The [operator-guide.md](operator-guide.md) documents startup, shutdown, health checks, source and run operations, reporting, audit review, monitoring, backup/restore, rollback, logging, and escalation practices.

## Reporting and auditability

Reports are generated from allow-listed application data through bounded, authorised workflows. Downloads and exports must retain filename, content, and formula-injection protections. Report records and relevant actions are auditable.

The audit log provides a release-visible review surface for authentication, administrative, operator, report, and other security-relevant activity. Audit records are not a substitute for external infrastructure logs, but they provide application-level accountability and investigation context.

## Deployment and reverse proxy

The production-shaped Docker Compose configuration was rendered successfully using process-local, non-secret placeholder file references and an explicit commit SHA. The quiet render returned exit code 0 and did not print configuration or secret values. Two sandbox warnings stated that the Docker client configuration under the host profile could not be read; these did not invalidate Compose parsing.

The deployment remains an operator-controlled action. Before staging exposure, the operator must provide real secret files, create the database and application roles, run migrations, configure DNS and TLS, validate CORS and public origins, apply firewall/network policy, and verify the deployed commit.

## Monitoring and system health

The application provides health and metrics surfaces intended for authenticated or infrastructure-restricted use as documented. Local health evidence does not prove public staging availability. External scraping, retention, dashboards, notification destinations, alert routing, ownership, and escalation acknowledgement must be configured and tested in the staging environment.

## Backup and recovery

C09 implemented local backup, restore, verification, and recovery-rehearsal tooling with documented evidence. C11 treats that work as implemented locally, not as proof of off-host storage or staging recovery readiness.

Before release, the operator must configure the approved backup destination, retention policy, encryption and access controls, run a staging backup, validate a safe restore/recovery rehearsal, record achieved recovery measurements, and compare them with the approved RPO/RTO. Destructive restore or rollback operations require explicit approval and a verified target.

## C11 validation evidence

### New C11 assertions

- Backend C11 tests: **9 passed**.
- Frontend C11 release-scope test: **4 passed**.
- Focused C11/directly affected backend group: **148 passed**.
- C11 plus changed current-state documentation contracts: **77 passed**.
- Direct lint of the C11 frontend test: passed.
- Local API reliability workload: **132/132 successful**.
- Anonymous access denial, request limits, database-pool behaviour, source isolation, schedule, migration inventory, source-handler state, and release route inventory were covered.

### Security and regression evidence

- C10 exact regression selection: **48 passed**.
- C09 safe recovery/operations selection: **103 passed, 2 skipped**. The skips were Windows symlink-capability checks.
- SQLAlchemy mapper validation: passed.
- Alembic: one head and expected history.
- Backend full suite: **5,080 passed, 255 skipped, 56 failed, 12 warnings**.
- Backend complementary suite excluding only the two known boundary files: **5,053 passed, 255 skipped, 12 warnings**.
- Frontend Vitest: **36 files, 200 tests passed**.
- TypeScript check: passed.
- Production frontend build: passed and generated 18 static pages.
- Docker Compose quiet render: passed with two host Docker-config access warnings.
- Project runner: stopped at the same known backend boundary and therefore did not reach frontend validation.

The 56 backend failures are limited to unchanged `backend/tests/test_c08_pre02_reconciliation.py` and `backend/tests/test_ioc_relationship_migration.py`. They reproduce a known Windows PowerShell/checkout byte-hash assumption. C11 did not modify those tests or the artifacts they verify. The exact full-suite result is retained rather than reported as a pass.

### Lint evidence

The full frontend lint command returned ten existing `react-hooks/set-state-in-effect` errors in unchanged frontend files. The C11 test file was not implicated. This is a follow-up quality item, not a newly introduced release regression. The successful TypeScript check, Vitest run, and production build are reported separately and do not erase the lint result.

Full command and warning detail is recorded in [c11-final-security-reliability-audit.md](c11-final-security-reliability-audit.md).

## Release findings

### Blockers

No demonstrated C11 Blocker remains in the frozen scope.

### Must Fix

No approved C11 Must Fix remains in the frozen scope.

### Accepted limitations

- The two known Windows byte-hash boundary tests prevent a literal green full-backend result on this checkout; their scope is isolated and the complementary suite passes.
- The project runner stops at that backend boundary before executing its frontend stage.
- Full frontend lint has ten pre-existing hook-rule findings in unchanged files.
- Exactly six reviewed runtime source handlers are code-bound but inactive; live ingestion is not claimed.
- Rate limiting is process-local.
- Authentication is the implemented local single-factor model; deployment credential operations remain manual.
- Caddy reports upstream dependency findings already accepted in C10; no C11 dependency regression is claimed.
- Local tests and Compose validation are not staging availability, performance, TLS, alerting, or disaster-recovery evidence.
- Formal assistive-technology testing and external load/capacity testing remain separate staging activities.

## Manual release gates

The release candidate should be promoted only after the accountable operator records evidence for each applicable gate:

- approve the exact release commit and ensure the deployment uses it;
- supply production/staging secrets through approved secret files or a secret provider;
- configure least-privilege database and application identities;
- run migrations and verify the deployed database revision;
- configure DNS, TLS, reverse proxy, CORS, trusted origins, and network policy;
- create and securely deliver mentor/analyst/operator accounts;
- keep source deployments paused until every intended live handler, licence, credential, quota, and source approval is complete;
- perform bounded, approved staging source validation before live scheduling;
- configure monitoring storage, dashboards, alerts, owners, and escalation routes;
- configure off-host backup retention and complete a staging recovery rehearsal;
- run deployed smoke tests across authentication, all twelve release pages, authorisation denials, reports, audit, health, and operator controls;
- record release sign-off, evidence locations, known limitations, rollback owner, and escalation contacts.

## Future backlog

The following are follow-up candidates and are not C11 acceptance expansion:

- remove the two Windows byte-hash portability assumptions;
- resolve the ten existing frontend hook lint findings;
- evaluate a shared/distributed rate-limit backend for multi-instance deployment;
- complete the separately approved activation preconditions and bounded staging validation before any parent-cycle run or recurring unpause;
- add formal assistive-technology and external capacity testing;
- automate external monitoring, backup evidence retention, and release evidence collection where organisational policy allows;
- review accepted upstream dependency findings on the normal maintenance cadence.

## Handover and recommendation

The repository remains on `dev` at the frozen checkpoint, equal to `origin/dev` with divergence `0 0`. All 15 intended C11 files are unstaged and the index is empty. Migration bytes remain unchanged and `git diff --check` passes. No stage, commit, push, reset, restore, clean, branch switch, history rewrite, live source call, or deployment was performed by C11.

Recommendation: treat the current changes as the C11 release-candidate package for mentor review. Independently review the changed files, approve and commit them using exact-file staging, then complete the manual staging gates above. The definitive release decision must be based on deployed evidence and organisational approval, not local test evidence alone.

## Document index

- [C11 final security and reliability audit](c11-final-security-reliability-audit.md)
- [C11 release-candidate checklist](c11-release-candidate-checklist.md)
- [Operator guide](operator-guide.md)
- [Final architecture package](final-architecture-package.md)
- [Production Docker deployment guide](production-docker-deployment.md)
- [Security notes](security-notes.md)
- [Architecture](architecture.md)
- [C09 production operations and recovery](c09-production-operations-recovery.md)
- [C10 production security audit](c10-security-audit.md)
