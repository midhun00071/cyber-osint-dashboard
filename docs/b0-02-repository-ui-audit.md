# B0-02 Repository and Visible Application Scope Audit

## 1. Document control

| Field | Value |
| --- | --- |
| Task | B0-02 — Audit current repository and visible application scope |
| Status | Hardened audit artifacts ready for final independent confirmation; not approved or complete |
| Audit date | 29 July 2026 |
| Branch | `dev` |
| Checkpoint | `ce41172e2f46f5250d9671e9427936c05fac0fa5` |
| Expected commit | `ce41172 B0-01 Add Phase A baseline register` |
| Detailed source of truth | `docs/b0-02-repository-ui-inventory.csv` |
| Authorized repository changes | This report and the inventory CSV only |
| Release target | Mentor-accessible staging by 11 August 2026 |

## 2. Task and checkpoint

The mandatory gate passed after a successful `git fetch origin`:

- task: B0-02;
- branch: `dev`;
- working tree before the audit: clean;
- local `HEAD`: `ce41172e2f46f5250d9671e9427936c05fac0fa5`;
- refreshed `origin/dev`: `ce41172e2f46f5250d9671e9427936c05fac0fa5`;
- completed dependency at `HEAD`: B0-01;
- B0-02 status from the supplied independently inspected workbook evidence: first unblocked Phase B task, Critical, and on the critical path.

No branch switch, Git staging, commit, push, reset, restore, clean, repository-file deletion, or history rewrite occurred.

The consolidated hardening-pass gate also passed after a fresh `git fetch origin`: branch `dev`; local `HEAD` and refreshed `origin/dev` both remained `ce41172e2f46f5250d9671e9427936c05fac0fa5`; and `git status --short` contained exactly the two authorized untracked B0-02 documentation files.

## 3. Executive summary

The repository contains a strong Phase A backend foundation but not the required Phase B release application. All 305 tracked files were inventoried individually. The runtime exposes eight read-only application GET routes and four framework documentation routes. The frontend exposes three routes: Overview plus dynamic article and vulnerability detail pages.

Only Overview is a working sidebar link. Five sidebar entries are disabled and labeled Coming soon, the header search is a read-only visual placeholder, and six final release pages are absent from navigation. Overview combines API-backed KPI, trend, vulnerability, article, and health components with visible static preview/status/collection content. The current UI therefore violates the frozen release target even though it labels preview and failure states honestly.

The six release-blocking findings are:

1. eleven required top-level routes are absent and the existing Overview remains incomplete;
2. visible Coming Soon and nonfunctional controls remain;
3. visible synthetic preview behaviour remains on the production route;
4. authentication and local RBAC are absent;
5. Prefect orchestration and operator controls are absent;
6. the production backend and migration services reuse the privileged PostgreSQL initialisation role.

One Must Fix finding records that ordinary rollback cleanup failures are silently suppressed in two ingestion services. A separate follow-up records that the production backend image includes `pytest` and `pytest-asyncio`. No source code, test, configuration, migration, existing documentation, environment template, dependency file, or task sheet was changed. This pass hardened only the two B0-02 artifacts; no implementation remediation was performed.

## 4. Scope and method

The audit used `git ls-files` as the authoritative file list. Every tracked file has an individual `FILE-####` row containing its repository-relative path, byte count, line count, and SHA-256 prefix at the checkpoint. Separate inventory rows cover HTTP routes, frontend routes, final release pages, sidebar items, controls, preview/sample states, database and ingestion boundaries, deployment assumptions, removed/conditional scope, and classified findings.

Inspection included:

- complete tracked-file inventory and repository-wide keyword/pattern searches;
- FastAPI startup, middleware, router registration, schemas, queries, and runtime OpenAPI enumeration;
- SQLAlchemy metadata introspection, mapper validation, models, constraints, indexes, relationships, migration history, and transaction patterns;
- ingestion registries, adapters, collectors, clients, services, CLIs, source policies, partial-run handling, and tests;
- all Next.js pages, navigation, controls, state handling, API clients, safe URL handling, fixtures, and tests;
- local rendering of every current frontend route in an isolated copy outside the repository;
- Dockerfiles, Compose files, environment templates, local runners, and deployment documentation;
- focused and full installed validation without live source requests or dependency installation.

No external source, commercial integration, scanning, probing, malware retrieval, file submission, or ingestion command was run.

## 5. Evidence inputs and limitations

| Evidence | Result |
| --- | --- |
| `AGENTS.md` | Read completely and applied before audit work |
| Official Phase B workbook | Supplied prior independent findings were used; the workbook was not present in the repository or parent tree and could not be re-opened or re-hashed |
| Supplied workbook SHA-256 | `5EBFCE55A401DDB2345529CF95B29A1339F3DC259B04C9B62353ECAB1726F777`; not independently reverified in this run |
| Repository archive SHA-256 | `B7EDDAA7C6CD53ED48AD8782F6F66D0CDCFD652D9432183DAC20C1FE1EEE7558`; independently reproduced from `git archive HEAD` |
| Supplied reconstructed B0-01 evidence SHA-256 | `30755A721E684767B4239C3C31A53582FDB323483E2AB202C937047F00138F42`; the referenced artifact was not present to re-hash |

Required evidence qualifications:

1. The B0-01 PDF was unavailable; its contents and hash were not independently verified.
2. The supplied B0-01 focused review ZIP was described as reconstructed from `ce41172`, not as the unavailable original.
3. The original 28 July P9-10 independent review ZIP was unavailable.
4. Any 29 July P9-10 archive remains reconstructed and must not be described as original.
5. The Windows CRLF raw-byte migration-hash assertion remains an environment-specific limitation. No migration or expected hash was changed.
6. The UI session did not start PostgreSQL. Backend health succeeded, while database-backed panels and detail pages were verified in loading and sanitized failure states rather than live-data success/empty states.
7. Earlier full-page capture attempts distorted evidence despite correct computed geometry. The final archive uses four genuine viewport screenshots, including a new undistorted lower-Overview capture; no full-page capture is presented as final evidence.

## 6. Repository coverage summary

The hardened inventory contains 442 records and reconciles to the complete 305-file tracked set.

| File component | Files |
| --- | ---: |
| Automated tests | 94 |
| Backend API | 15 |
| Backend application | 26 |
| Committed migration history | 3 |
| Database infrastructure | 1 |
| Database models | 15 |
| Documentation | 26 |
| Frontend API client | 6 |
| Frontend component | 14 |
| Frontend route | 7 |
| Frontend support | 15 |
| Ingestion | 52 |
| Repository governance or configuration | 18 |
| Runtime and deployment | 13 |
| **Tracked files reviewed** | **305** |

Cross-record counts derived from the CSV:

| Measure | Count |
| --- | ---: |
| Backend routes/surfaces | 12 |
| Frontend routes | 3 |
| Sidebar items | 6 |
| Visible or conditionally visible control patterns | 37 |
| Coming Soon or placeholder items | 7 |
| Preview/mock/sample states | 10 |

## 7. Backend route and API inventory summary

Runtime OpenAPI enumeration found eight application paths, all `GET` only:

- `/`;
- `/api/health`;
- `/api/version`;
- `/api/v1/articles`;
- `/api/v1/articles/{public_id}`;
- `/api/v1/dashboard/summary`;
- `/api/v1/intelligence/items`;
- `/api/v1/intelligence/items/{item_public_id}`.

FastAPI also enables `/openapi.json`, `/docs`, `/docs/oauth2-redirect`, and `/redoc`. These four surfaces require a production decision under B9-01.

The application performs no startup ingestion. Middleware applies sanitized unexpected-error handling, request IDs, exact-origin CORS, and security headers. Public query inputs are bounded by page, offset, text, date, enum, CVE, UUID, and allowed-parameter validation. Service exceptions are converted to stable public messages. Raw source payloads are not returned by the listed response schemas.

All current routes are unauthenticated. The absence of authentication, local RBAC, session handling, and protected audit/operations routes is a release blocker mapped to B7-01. Public route rate controls are external to the application and require a final proxy/deployment decision.

## 8. Database and migration summary

SQLAlchemy mapper validation registered 13 tables. Metadata inspection confirmed named checks, explicit uniqueness, indexes, foreign keys, and delete behaviour across intelligence items, sources, records, runs, errors, vulnerabilities, tags, identifiers, indicators, provenance, and association tables.

The migration chain is linear:

```text
<base> -> f8d739439ed0 -> a6c9d4e2f107 -> c4e8b2a91d30 (head)
```

Ingestion CLIs and services contain explicit flush, commit, rollback, and nested-savepoint paths. Repository/service queries use SQLAlchemy expressions. Static review found no untrusted SQL string concatenation; raw SQL-like text is limited to static migration/index predicates.

Production database separation is not least-privilege: the database container, backend, and migration services receive the same `POSTGRES_USER` and `POSTGRES_PASSWORD` configuration, and the deployment guide confirms that backend and migration reuse the privileged PostgreSQL initialisation role. No restricted application role is provisioned. SEC-0019 classifies this as a High database-integrity and blast-radius Blocker for B9-01, with database role/schema coordination potentially required under B1-02. No Compose or database remediation was performed.

The existing CRLF raw-byte migration-hash failure was reproduced and left unchanged, as required.

## 9. Ingestion and external-request boundary summary

The source registry contains eleven implemented, enabled, unauthenticated approved identities. Registry enablement does not itself authorize collection. Current execution remains manual and explicit; no FastAPI startup hook, public ingestion endpoint, background worker, scheduler, or frontend ingestion control exists.

Collectors and clients use fixed HTTPS source identities, bounded timeouts, response sizes, records/pages, approved redirect handling, safe content types, and sanitized errors. Tests cover malformed input, redirects, sizes, timeouts, partial records, rollback, and log-safety behaviour. No arbitrary outbound host/path/header/cookie/callback control was identified.

Two ingestion services weaken rollback auditability: `_rollback_safely` in the Anomali and Censys publication services catches ordinary `Exception` from `session.rollback()` and silently executes `pass`. The cleanup failure is neither propagated nor logged, leaving a failed session rollback unobservable. SEC-0020 records this as a Must Fix for B1-06. No service code was changed.

The STIX/TAXII area provides bounded safe local import plus a fixed-policy client foundation. It does not establish authorized live TAXII operation. Commercial or entitlement-dependent work remains `Approval-Gated / Disabled Safely`.

The required self-hosted Prefect parent cycle, source flows, persistent orchestration checkpoints, retries/backoff, and operator controls do not exist. This is a release blocker mapped to B2-01 and later UI work.

## 10. Frontend route, navigation, and control summary

Current frontend routes:

| Route | Current state |
| --- | --- |
| `/` | Renders Overview; mixes API-backed panels with labeled preview content |
| `/articles/[publicId]` | Renders loading, sanitized unavailable/not-found, and API-backed success states |
| `/vulnerabilities/[publicId]` | Renders loading, sanitized unavailable/not-found, and API-backed success states |

Sidebar state:

- Overview: enabled link;
- Threat Feed: disabled, Coming soon;
- Vulnerabilities: disabled, Coming soon;
- UAE Alerts: disabled, Coming soon, and inconsistent with final label UAE Intelligence;
- Sources: disabled, Coming soon;
- Methodology: disabled, Coming soon.

The 37 control-pattern records include desktop/mobile navigation, the read-only header search, vulnerability/article filters, Apply/Clear actions, pagination, detail links, source links, and detail-page return links. Search, select, and pagination parameters are bounded by frontend state and backend validation. External URLs pass through protocol, credential, authority, and unsafe-character checks before rendering.

Loading and sanitized failure states were visibly honest. The API-backed Overview controls remained usable while data calls failed. The current application does not implement stale or permission states because authentication and the relevant release pages do not yet exist.

## 11. Final 12-page release-scope matrix

| Final page | Route exists | In navigation | Current data/support | Decision | Responsible task |
| --- | --- | --- | --- | --- | --- |
| Overview | Yes, `/` | Yes | Mixed API-backed and preview | Complete Later | B8-01 |
| Threat Feed | No | Disabled Coming soon | Embedded article feed only | Complete Later | B8-05 |
| Vulnerabilities | No top-level route | Disabled Coming soon | Embedded table and dynamic detail | Complete Later | B8-05 |
| UAE Intelligence | No | `UAE Alerts` disabled | Filters only; no dedicated page/API | Complete Later | B8-04 |
| IOC Search | No | No | Indicator models only | Complete Later | B8-05 |
| Ingestion Operations | No | No | Manual CLIs only | Complete Later | B8-02 |
| Sources | No | Disabled Coming soon | Source registry only | Complete Later | B8-03 |
| Run History | No | No | Run models only | Complete Later | B8-03 |
| Reports | No | No | Static future-reporting claim | Complete Later | B8-06 |
| System Health | No | No | Embedded health card/API | Complete Later | B8-06 |
| Audit Log | No | No | Ingestion audit models only | Complete Later | B8-06 |
| Methodology | No | Disabled Coming soon | Documentation only | Complete Later | B8-06 |

Planned future behaviour is not recorded as operational.

## 12. Removed and conditional feature matrix

| Feature | Current repository state | Frozen release decision | Task |
| --- | --- | --- | --- |
| Separate Threat Entities page | No route/item; safe metadata references exist | Remove as separate page | B8-01 / B4-04 |
| Advanced threat graph | Absent | Remove from release; post-submission backlog | B0-03 |
| Machine-learning predictions | Absent; deterministic classifier explicitly excludes ML | Remove | B0-03 |
| Automated blocking or SOAR | Absent | Remove | B0-03 |
| Malware processing or file upload | No upload/retrieval; safe STIX malware metadata references only | Prohibited and remove | B0-03 |
| Intelligence chatbot | Absent | Remove from release; post-submission backlog | B0-03 |
| Slack, Teams, or email alerting | Absent | Remove from release; post-submission backlog | B0-03 |
| Mobile application | Responsive web only | Remove | B0-03 |
| Custom dashboard builder | Absent | Remove | B0-03 |
| Multi-tenant customer platform | Absent | Remove | B0-03 |
| Kubernetes | Documented as not implemented | Remove from release; post-submission backlog | B9-06 |
| Advanced SSO | Absent | Approval-Gated / Disabled Safely; local RBAC still required | B7-01 |

None is a visible nonfunctional sidebar item today. Documentation references are retained where they state safe exclusions or future/approval boundaries.

## 13. Sample, preview, mock, fixture, and demo-state assessment

Ten inventory rows distinguish production-visible preview state from safe test/development state.

Production-visible or dead preview content to remove under B8-01:

- six deterministic collection counts rendered on Overview;
- three static operational status rows;
- sidebar and header Synthetic preview indicators;
- static workflow preview claims;
- four unused preview KPI exports;
- five unused fictional intelligence-item exports.

Safe retained boundaries:

- the deterministic, manual development seed dataset with production refusal;
- frontend synthetic test fixtures;
- backend offline fixtures and mocked external-source tests.

No real target, credential, secret, or raw commercial payload is needed for these safe test/development states.

## 14. Runtime, Docker, environment, and staging assumptions

Development Compose is explicitly development-oriented and exposes database, backend, and frontend ports with local placeholder defaults. It must not be reused as staging production configuration.

Production Compose separately:

- requires database, CORS, and frontend API values;
- forces `APP_ENV=production` and `DEBUG=false`;
- uses production Dockerfiles and a migration service;
- drops Linux capabilities and enables `no-new-privileges`;
- defines health checks and separated application/database networks;
- expects approved loopback binding, reverse proxy, TLS, secret management, monitoring, backup, and host controls outside the repository.

The production backend image installs the shared `backend/requirements.txt`. That file includes `pytest` and `pytest-asyncio`, so development/test packages are present in the production image. SEC-0021 records their later removal under B9-01; APScheduler remains separately covered by SEC-0006 and is not double-counted. Production Compose also reuses the privileged database-initialisation identity described in SEC-0019. No Docker, dependency, or configuration file was changed.

The local runner performs setup, tests, build, Docker, and development startup. It does not invoke ingestion. No Prefect server/worker is defined in either Compose file.

The installed Docker CLI lacked the `docker compose` plugin. Both requested plugin-form commands were attempted and recorded as unavailable. The installed `docker-compose` fallback validated both files with quiet output and synthetic non-secret production values.

## 15. Security and data-integrity findings

| ID | Classification | Finding | Exact evidence | Decision/task |
| --- | --- | --- | --- | --- |
| SEC-0001 | BLOCKER | Required release-page gap | `frontend/src/app/(dashboard)/page.tsx`; `Sidebar.tsx:21-28` | Complete Later / B8-01 |
| SEC-0002 | BLOCKER | Visible Coming Soon and dead controls | `Sidebar.tsx:21-28,68-80`; `TopHeader.tsx:38-58` | Remove / B8-01 |
| SEC-0003 | BLOCKER | Visible synthetic preview behaviour | `dashboardPreview.ts:101-129`; dashboard page `64-121`; `Sidebar.tsx:92-98`; `TopHeader.tsx:61-64` | Remove / B8-01 |
| SEC-0004 | BLOCKER | Authentication and RBAC absent | `main.py:67-71`; all route dependencies | Complete Later / B7-01 |
| SEC-0005 | BLOCKER | Prefect and operator controls absent | repository-wide search; visible Planned ingestion status | Complete Later / B2-01 |
| SEC-0006 | FOLLOW-UP | Unused APScheduler dependency | `backend/requirements.txt:13` | Remove / B2-01 |
| SEC-0007 | FOLLOW-UP | Automatic API documentation surfaces | FastAPI runtime enumeration | Complete Later / B9-01 |
| SEC-0008 | FOLLOW-UP | Proxy-level request controls remain external | production deployment config/docs | Complete Later / B9-02 |
| SEC-0009 | FOLLOW-UP | Redundant markers and dead preview exports | `.gitkeep` inventory; `dashboardPreview.ts:8-99` | Remove / B8-01 |
| SEC-0010 | FOLLOW-UP | Report/export security not yet applicable | no Reports route/control | Complete Later / B8-06 |
| SEC-0019 | BLOCKER | Privileged production database account | `compose.prod.yml:21-23,61-63,132-134`; deployment guide `534-535` | Complete Later / B9-01 |
| SEC-0020 | MUST FIX | Rollback cleanup failures silently suppressed | Anomali service `549-560`; Censys service `553-564` | Complete Later / B1-06 |
| SEC-0021 | FOLLOW-UP | Development/test dependencies in production image | `Dockerfile.prod:12-15`; `requirements.txt:14-15`; deployment guide `536-537` | Remove / B9-01 |

Positive controls observed:

- read-only routes and bounded public inputs;
- sanitized validation and unexpected-error responses;
- exact-origin CORS, no credentials, GET-only methods;
- security headers and request correlation;
- SQLAlchemy query construction and explicit database constraints;
- safe URL rendering and normal React text escaping;
- fixed outbound source policies, bounded redirects/timeouts/sizes, and sanitized external failures;
- explicit transaction and partial-run evidence paths, with the two silently suppressed rollback-cleanup failures separately classified under SEC-0020;
- no public mutation, file upload, malware retrieval, scanning, exploit, arbitrary callback, or unrestricted live-ingestion path.

No fake success was observed. Runtime health success was based on a real local health response; database failures rendered unavailable states.

## 16. Dead, duplicate, unreachable, and superseded code

- `dashboardKpis` and `previewIntelligenceItems` in `frontend/src/data/dashboardPreview.ts` have no production import.
- Twelve `.gitkeep` markers are retained in nonempty or superseded directories; they are harmless but redundant.
- `apscheduler` remains unused in `backend/requirements.txt` and conflicts with the single-scheduler Prefect direction.
- The empty backend `app/schemas` placeholder is superseded by `app/api/v1/schemas`.
- The ingestion `jobs` and frontend `hooks` placeholders are not operational components; later tasks must either use or remove them.
- No unreachable frontend page file was identified; the two detail pages are reachable only through data-dependent links or direct URLs.
- Historical migrations and their tests are retained even when not directly user-visible.

## 17. Findings by classification

Counts include only the 21 `Finding` rows; 421 non-finding inventory rows use classification `None`.

| Classification | Count |
| --- | ---: |
| BLOCKER | 6 |
| MUST FIX | 1 |
| FOLLOW-UP | 6 |
| ACCEPTED LIMITATION | 8 |

These Blockers prevent release readiness, not preparation of the B0-02 audit artifacts for independent review. B0-02 did not implement their remediation.

## 18. Decisions by release disposition

Counts cover all 442 CSV records and therefore include file rows plus logical route/control/finding rows.

| Release decision | Count |
| --- | ---: |
| Retain | 341 |
| Complete Later | 45 |
| Remove | 44 |
| Approval-Gated / Disabled Safely | 2 |
| Accepted Limitation | 10 |
| **Total** | **442** |

## 19. Mapping to later Phase B tasks

| Work area | Narrowest next owner |
| --- | --- |
| Final scope confirmation and backlog exclusions | B0-03 |
| Architecture/threat model decisions | B0-06 |
| Secrets and configuration | B1-01 |
| Models, migrations, transactions, indexes | B1-02 through B1-06 |
| Prefect cycle, flows, retries, checkpoints, controls | B2-01 through B2-06 |
| Existing approved source conversion | B3-01 through B3-06 |
| Threat metadata and relationships | B4-01 through B4-04 |
| UAE data and page | B5-01 through B5-06; B8-04 |
| Commercial/entitlement-gated integrations | B6-01 through B6-08 |
| Authentication, RBAC, sessions, audit events | B7-01 through B7-06 |
| Coming Soon removal and final UI pages | B8-01 through B8-07 |
| Production Compose, TLS, monitoring, backup/recovery | B9-01 through B9-06 |
| Security and regression audits | B10-01 through B10-08 |
| UAT, release evidence, report, reconciliation, handover | B11-01 through B11-05 |

## 20. Validation commands and results

Validation used the installed environment. Application tests/builds ran from an external `git archive HEAD` copy so normal caches and build output did not create extra repository files.

| Command | Exit/result |
| --- | --- |
| Initial audit Git gate commands including `git fetch origin` | Passed; `dev`, clean pre-audit tree, `HEAD == origin/dev == ce41172...` |
| Consolidated hardening-pass Git gate | Passed after fresh fetch; `dev`, `HEAD == origin/dev == ce41172...`, and status contained exactly the two authorized untracked documentation files |
| `git ls-files` | Exit 0; 305 files |
| Runtime FastAPI/OpenAPI enumeration | Exit 0; 8 application paths and 4 documentation paths |
| Focused backend pytest command covering APIs, CORS, middleware, registry, STIX/TAXII, and source clients/services | Exit 0; 949 passed; 1 Starlette deprecation warning |
| Focused frontend Vitest command covering all current pages/components | Exit 0; 9 files and 70 tests passed |
| SQLAlchemy `configure_mappers()` validation | Exit 0; 13 tables |
| `python -m alembic -c alembic.ini heads` | Exit 0; `c4e8b2a91d30 (head)` |
| `python -m alembic -c alembic.ini history` | Exit 0; one linear three-migration chain |
| `docker compose config` | Exit 1; installed Docker CLI has no Compose plugin |
| `docker compose -f compose.prod.yml config` | Exit 125; same missing plugin |
| `docker-compose config --quiet` | Exit 0 |
| `docker-compose -f compose.prod.yml config --quiet` with synthetic non-secret required values | Exit 0 |
| `.\run.cmd test` with external pytest temp and process-local Git safe-directory | Exit 1; backend 3,677 passed, 6 skipped, 1 known CRLF migration-hash failure, 1 Starlette deprecation warning; runner stopped before frontend |
| `npm run test:run` after runner stop | Exit 0; 9 files and 70 tests passed |
| `npm run type-check` | Exit 0; Next route types and `tsc --noEmit` passed |
| `npm run build` in isolated junction copy | Exit 1; Turbopack rejected the external `node_modules` junction; environment limitation |
| `.\node_modules\.bin\next.cmd build --webpack` | Exit 0; production build compiled, TypeScript passed, four static pages generated; `/`, two dynamic detail routes, `/_not-found`, and `/icon.svg` reported |
| Isolated local UI render | Backend health HTTP 200; all three frontend routes rendered; four genuine viewport screenshots retained, including new undistorted `overview-preview-sections.png`; malformed duplicated `overview.png` excluded from final evidence |
| Hardened CSV/report reconciliation | Exit 0; exact 16-column schema, 442 rows and unique IDs, 305 File rows, 305/305 tracked paths, 21 Finding rows, 421 `None` rows, stated classifications/decisions reconciled, numeric single-file ranges bounded, and Markdown counts matched |
| Artifact safety checks | Exit 0; no CSV formula-injection cells, sensitive-value patterns, or trailing whitespace detected |
| `git diff --check` | Exit 0; no tracked-diff whitespace errors |
| `git status --short` | Exit 0; exactly the two authorized documentation files are untracked |
| `git diff -- docs/b0-02-repository-ui-audit.md docs/b0-02-repository-ui-inventory.csv` | Exit 0; no output because both authorized files are untracked; their complete contents were reviewed directly |

The full backend failure is pre-existing and explicitly frozen. B0-02 changed documentation only and did not introduce it. The documentation-only hardening pass did not rerun backend or frontend suites, as requested; it preserved the prior results above. No test was weakened, skipped manually, edited, or deleted.

A preparatory repeat of the focused command was invoked once from the external repository root instead of its `backend` directory. It exited 1 with 14 `ModuleNotFoundError: app` collection errors. Running the same explicit 14-file selection from the correct `backend` working directory produced the authoritative 949-pass result above; no application or test file was changed.

Final repository-specific commands are recorded in the focused review archive's validation log:

```powershell
git diff --check
git status --short
git diff -- docs/b0-02-repository-ui-audit.md docs/b0-02-repository-ui-inventory.csv
git ls-files
```

## 21. Known limitations

- The official workbook and unavailable original review artifacts could not be reopened; supplied independent findings were used with explicit qualifications.
- Formal manual QA remains Not Run. No UAT, penetration test, accessibility certification, public-internet deployment, load test, failover test, backup restore, or live commercial integration was performed.
- UI validation used an isolated local backend/frontend and no PostgreSQL service; it proves route rendering, controls, navigation, health success, and failure honesty, not live stored-data success.
- Full-page captures were unsuitable due to capture distortion. The final archive contains only four verified viewport screenshots: `overview-preview-sections.png`, `overview-states.png`, `article-detail-error.png`, and `vulnerability-detail-error.png`.
- The Docker Compose plugin form was unavailable; the installed legacy-compatible `docker-compose` executable validated both configurations.
- The CRLF raw-byte migration-hash assertion remains unresolved and unchanged.
- External TLS, reverse proxy, secrets provider, production monitoring, backup, and recovery remain future deployment work.

## 22. B0-02 definition-of-done assessment

| Criterion | Assessment |
| --- | --- |
| Git checkpoint gate | Met |
| `AGENTS.md` inspected | Met |
| Complete tracked repository covered | Met: 305/305 files |
| Backend routes inventoried | Met: 12 surfaces |
| Frontend routes/sidebar/controls inventoried | Met: 3 routes, 6 sidebar items, 37 control patterns |
| Twelve final pages assessed | Met |
| Coming Soon/placeholder items identified | Met: 7 records |
| Preview/mock/sample/fixture/seed states classified | Met: 10 records |
| External, database, Docker, security boundaries reviewed | Met |
| Findings classified and mapped | Met: 21 findings; 6 Blockers, 1 Must Fix, 6 Follow-ups, 8 Accepted Limitations |
| Markdown/CSV counts reconciled | Met: 442 records |
| Single-file numeric ranges checked | Met; API-0006, API-0008, and DEPLOY-0001 corrected and no range exceeds its file length |
| CSV formula-injection and sensitive-value checks | Met; no detected cells or values |
| Required validation run or recorded unavailable | Met with stated limitations |
| Complete-file self-review | Met before archive creation |
| Focused external review ZIP | Created after final validation and self-review; path/hash reported in the handoff |
| Only two repository files changed | Met |
| Git write prohibition | Met |

The hardened artifacts are ready for final independent confirmation. This statement does not approve or complete B0-02 and does not authorize staging or commit.

## 23. Exact recommended next action: B0-03

Immediate action: upload the hardened focused B0-02 review ZIP and both complete changed files for final independent confirmation before any staging or commit.

After the B0-02 artifacts are independently reviewed, findings are reconciled, and any separately approved Git lifecycle step is completed, begin B0-03 to freeze the final release definition and scope. Do not start B0-03 from this audit unit.
