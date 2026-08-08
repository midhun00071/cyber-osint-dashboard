# P8-04 Testing Report

## Purpose, audience, and evidence date

This report summarizes the automated, manual, security, ingestion, database,
container, and deployment-build evidence for the Alpha Data / Cyber OSINT
Dashboard. It is intended for a mentor, senior cybersecurity reviewer,
developer, or deployment reviewer deciding what has been demonstrated and what
still requires validation.

| Item | Evidence |
| --- | --- |
| Task | P8-04 — Write testing report |
| Evidence date | 22 July 2026 |
| Branch | `dev` |
| Validated parent checkpoint | `ef1307a29969c47c2289862a3ed9bd02ebbd5bc3` |
| Parent commit | `ef1307a P8-03 Complete architecture documentation` |
| Report status | Validated evidence snapshot ready for mentor review |

This report anchors its dated evidence to the clean pushed parent checkpoint
shown above and to validation performed on the two-file P8-04 working tree. The
eventual P8-04 commit is intentionally not self-referenced in this report;
reviewers should trace the final commit through Git history.

## Repository checkpoint and validation scope

The P8-04 checkpoint gate confirmed branch `dev`, a clean initial working tree,
a successful fetch, and equality between `HEAD` and `origin/dev` at the full
checkpoint above. Current validation covers the candidate working tree containing
only this report and its focused documentation-contract test.

Evidence in this report has four deliberately separate classes:

1. **Current evidence:** commands run on 22 July 2026 against the P8-04 candidate
   working tree.
2. **Historical automated evidence:** completed P6 and documentation-test work,
   re-exercised where it belongs to the current full regression.
3. **Historical deployment-build evidence:** the isolated P6-05 build, database,
   migration, HTTP, CORS, logging, restart, and shutdown exercise performed on
   21 July 2026.
4. **Available procedures or unvalidated areas:** P6-04 manual cases and other
   environments that have not been executed as formal evidence.

A documented procedure is not an executed test. A historical result is not
presented as if it were rerun during P8-04.

## Executive testing verdict

The current automated regression passed. The project is ready for a controlled
mentor demonstration and repeatable local or container validation within the
documented boundaries. The result supports review of the defensive MVP; it does
not certify the project for unrestricted public production deployment.

The strongest evidence is deterministic and offline: backend API, database,
ingestion, security, runner, Compose, and documentation tests; frontend
component/page tests; TypeScript validation; and a production frontend build.
P6-05 separately established one isolated local deployment-build result. Formal
manual browser execution, public-internet deployment, penetration testing,
backup recovery, load testing, and production operations remain unvalidated.

## Test environment and assumptions

### Current P8-04 host validation

| Component | Observed value or boundary |
| --- | --- |
| Operating system | Microsoft Windows `10.0.26200` |
| PowerShell | 7.6.3 Core |
| Python | 3.13.5 from `backend/.venv` |
| pytest | 9.1.1 |
| Node.js | v20.19.4 |
| npm | 10.8.2 |
| Git | 2.50.1.windows.1 |
| Time zone | Asia/Dubai |
| Test data | Synthetic fixtures, mocks, temporary files, and dependency overrides |
| Live source traffic | None in the current regression |
| Docker runtime | Not started or revalidated by the P8-04 regression |

Fresh directories below `$env:USERPROFILE` were used for Windows `TEMP`, `TMP`,
pytest base-temp, and pytest cache state. No secret-bearing environment value or
resolved Compose configuration was printed. The current full regression does
not require a live PostgreSQL instance, Docker service, or external OSINT
source.

The historical P6-05 environment is recorded separately in
[Deployment build validation](deployment-build-validation.md): Docker Engine
28.5.1, Docker Desktop 4.49.0, Docker Compose v2.40.3, and an isolated Compose
project on 21 July 2026. Those versions are historical evidence, not a statement
that Docker was rerun during P8-04.

## Current automated regression results

This is a dated snapshot from 22 July 2026. Future commits require a new run and
must not reuse these counts as a permanent guarantee.

| Gate | Exact result |
| --- | --- |
| P8-04 focused documentation/security gate | 134 passed, 1 warning in 8.91 seconds |
| Five-case skip-reason inspection | 5 skipped in 0.84 seconds; reasons listed below |
| Backend pytest | 2,747 passed, 5 skipped, 1 warning in 32.91 seconds |
| Frontend Vitest | 9 test files passed; 66 tests passed in 7.96 seconds |
| Frontend TypeScript check | Passed (`next typegen` and `tsc --noEmit`) |
| Frontend production build | Passed (`next build`) |
| Full project command | `.\run.cmd test` exited with code 0 |
| New warning introduced by P8-04 | No |

The backend count increased from the 2,735-test parent baseline only by the 12
new P8-04 documentation tests. The five skipped tests remain skips and are not
included in the passed count. The warning remains separate from both passed and
skipped results.

## Backend test coverage summary

The backend suite is organized by control area rather than one monolithic
end-to-end scenario.

| Control area | Verified automated evidence |
| --- | --- |
| Service metadata | Health and version response shape, settings-derived metadata, and safe errors |
| Dashboard | Summary totals, recent-ingestion state, database failures, and allow-listed output |
| Article APIs | List/detail routes, UUID handling, pagination, search, category, scope, UAE relevance, dates, ordering, unknown/repeated parameters, and safe failures |
| Intelligence APIs | List/detail routes, identifiers, severity, item type, scope, UAE relevance, CVE/date filters, combined filters, pagination, malformed input, and safe failures |
| Response boundaries | Pydantic allow-listed fields, stable public IDs, controlled 404/422/500 bodies, and exclusion of ORM/raw-source internals |
| Database configuration | Component settings, validated URLs, lazy engine/session creation, session close behavior, and safe configuration failures |
| Models and constraints | Intelligence items, sources, identifiers, source records, vulnerabilities, tags, ingestion runs, records, errors, relationships, uniqueness, and constraints |
| Alembic | Configuration, metadata wiring, migration environment, initial schema, head/current semantics, and image packaging |
| Source registry | Canonical immutable definitions, implemented/enabled state, exact allowed hosts, unknown sources, duplicates, and source-family boundaries |
| Vulnerability workflows | NVD collection/normalization/persistence, FIRST EPSS enrichment, CISA KEV enrichment, and CERT-EU RSS ingestion |
| Publication workflows | Censys, Anomali, IBM X-Force, Google Threat Intelligence/Mandiant, and the common publication pipeline |
| Publication integrity | Candidate validation, safe metadata, URL rules, identity, deduplication, update/unchanged behavior, cross-type collision handling, persistence, and audit counters |
| Processing | Deterministic UAE relevance classification, confidence, ownership preservation, dry-run/apply behavior, and enrichment preservation |
| Platform controls | CORS, security headers, request IDs, safe logging/errors, development runner, Dockerfiles, development/production Compose, and documentation contracts |

Fetcher, collector, adapter, service, and CLI tests exercise mocked timeouts,
HTTP status failures, malformed JSON/XML/HTML, content-type errors, redirect and
host rejection, response/file-size limits, record-count limits, duplicate input,
database failures, commit/rollback behavior, and sanitized audit outcomes.

This evidence does not claim complete path, branch, mutation, fuzz, load,
penetration, or live-provider coverage.

## Frontend test coverage summary

The frontend suite uses Vitest, jsdom, React Testing Library, user-event, and
synthetic fixtures with mocked service responses. Its 66 tests cover:

- dashboard composition, summary cards, health, trends, article lists, and
  vulnerability tables;
- loading, success, empty, not-found, and sanitized error states;
- search, category, severity, scope, UAE relevance, page size, pagination, and
  navigation behavior;
- article and vulnerability detail routes, direct links, back navigation, and
  request cancellation;
- runtime validation of backend JSON response shapes and rejection of malformed
  or unsafe data;
- React plain-text handling of markup-like untrusted OSINT strings;
- safe HTTP/HTTPS external URLs, rejected unsafe/credential-bearing URLs, and
  `target="_blank"` with `rel="noopener noreferrer"`; and
- the absence of `dangerouslySetInnerHTML` from the implemented rendering path.

The current gate also passed TypeScript route/type generation and the standalone
Next.js production build. It is not browser end-to-end automation and does not
establish a browser compatibility matrix, visual-regression baseline,
performance result, or accessibility certification.

## Security-control validation summary

| Security boundary | Automated evidence |
| --- | --- |
| API input | Bounded pagination, UUID/CVE formats, dates, enums, combined filters, unknown parameters, and repeated parameters |
| CORS | Exact environment-driven origins; production HTTPS/non-loopback rules; no wildcard; GET only; credentials disabled; unapproved origins not authorized |
| Headers | `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`, `Permissions-Policy`, API CSP, and route-specific documentation behavior |
| Responses | Allow-listed schemas and sanitized validation, not-found, database, and unexpected-error messages |
| Logging | Server-generated request IDs; route templates instead of raw targets; allow-listed fields; one managed handler; sanitized failure categories |
| Sensitive-data exclusion | Tests use canaries to check that secrets, authorization/cookie values, database URLs, raw SQL, stack traces, raw payloads, and private error detail do not appear publicly |
| Frontend content | React text rendering, no raw HTML injection, safe external schemes, no URL credentials, and safe new-tab attributes |
| Collection boundary | Fixed approved hosts/endpoints or reviewed files, no arbitrary URL option, bounded clients/files, and manual invocation |

Automated security regression is valuable evidence but is not an independent
penetration test, threat-led exercise, formal code audit, or security
certification.

## Ingestion and external-source test strategy

Source tests prioritize deterministic offline evidence:

- synthetic fixtures and reviewed local-input shapes;
- mocked HTTP clients, redirects, statuses, timeouts, and content types;
- approved fixed endpoints and exact-host/path validation;
- bounded response/file sizes and record counts;
- malformed, duplicate, conflicting, and partially valid input;
- normalization, source ownership, identity, and deduplication;
- transaction-specific commit/rollback and audit outcomes; and
- sanitized exceptions and console/log evidence.

The full regression performs no unrestricted live-source request, scanning,
active probing, active IOC validation, malware retrieval, file submission, or
exploit execution. Live validation requires a separate approved operator action
and must not be inferred from mocked tests.

Ingestion remains manual-only. There is no startup ingestion, scheduler,
recurring background worker, public ingestion API, or frontend ingestion
trigger.

## Database and migration validation

Current offline tests cover settings, engine/session construction, session
closure, ORM relationships and constraints, declarative metadata, Alembic
configuration, migration entry points, initial tables/indexes/constraints, and
packaging of `alembic.ini` and migration assets in backend images.

P6-05 separately validated a fresh PostgreSQL volume and packaged Alembic
execution in an isolated local Compose project: head `f8d739439ed0`, successful
first upgrade, matching `current`, and an idempotent second upgrade. P8-04 did
not recreate that database or rerun migration commands against a live service.

Production Compose currently reuses the privileged `POSTGRES_USER`
initialization role for backend and migration access. No separately provisioned
restricted application role exists. The named PostgreSQL volume provides
persistence, not backup.

## Container and deployment-build validation

### Current static validation

Current pytest contracts parse development and production Compose, Dockerfiles,
environment documentation, runner behavior, service sets, profile-controlled
migrations, health checks, internal database networking, no default production
database host port, non-root users, dropped capabilities, `no-new-privileges`,
bounded logs, and manual migration behavior.

### Historical P6-05 execution

On 21 July 2026, P6-05 performed one isolated local deployment-build exercise
at its recorded checkpoint. Evidence includes:

- isolated no-cache backend and frontend image builds;
- healthy PostgreSQL startup on an external override port;
- packaged Alembic head/current and idempotent migration checks;
- HTTP 200 checks for health, version, dashboard summary, frontend HTML, and a
  representative stylesheet;
- approved and unapproved CORS behavior plus security headers;
- zero matches in bounded sensitive-value, raw-exception, raw-SQL, retry, and
  unexpected-ingestion log scans;
- confirmation that startup/restart made no live intelligence-source request;
- backend/frontend restart recovery in 6.4 seconds while PostgreSQL remained
  healthy; and
- controlled `docker compose stop`, not destructive volume cleanup.

That exercise used the then-current local Compose/build architecture. It is
historical deployment-build evidence, not a P8-04 rerun, public production
certification, TLS/reverse-proxy test, load test, backup/restore test, disaster
recovery test, or monitoring/CI/CD validation.

## Manual test evidence and checklist status

[Manual test cases](manual-test-cases.md) defines 46 repeatable P6-04 cases and
a 12-case bounded regression-smoke subset covering setup, migrations and
prerequisites, backend/frontend availability, dashboard and detail flows,
filters, navigation, safe links/text, responsive behavior, basic accessibility,
CORS, security headers, safe logging, restart/recovery, and controlled shutdown.

All 46 formal cases remain **Not Run**. Their actual-result, evidence, defect,
and sign-off fields are blank. Automated regression does not change those
statuses.

Some P6-05 operational actions overlap checklist areas—startup, migrations,
selected HTTP routes, CORS, headers, log safety, restart recovery, and controlled
shutdown—but P6-05 did not record those actions as executed P6-04 case IDs.
Therefore this report treats them only as separate historical deployment-build
evidence and does not mark any manual case passed.

## Warning and skip inventory

### Warning

The full backend suite emitted one pre-existing, non-blocking
`StarletteDeprecationWarning`: the current FastAPI/Starlette `TestClient`
integration uses the `httpx` compatibility path that is deprecated in favor of
`httpx2`. P8-04 did not introduce the warning. It is technical debt to track,
not a hidden failure or a reason to suppress future compatibility work.

### Skips

The `-rs` skip inspection identified five Windows environment-dependent skips:

| Test family | Skipped cases | Verified reason |
| --- | ---: | --- |
| Censys local publication adapter | 3 | Direct-file, parent-directory, and nested-parent symlink rejection could not create the required symlink: `Symlink creation unavailable: OSError` |
| Anomali local publication adapter | 1 | Combined file/parent symlink rejection could not create the required symlink: `Symlink creation unavailable: OSError` |
| IBM X-Force local publication adapter | 1 | Missing-directory/symlink path rejection could not create the required symlink: `Symlink creation unavailable: OSError` |

These five cases did not pass. They are skipped because the current Windows
process lacks the symlink-creation capability needed to construct each negative
fixture. Other path/file validation tests still run, but this result is not a
substitute for executing the five symlink cases in an approved environment that
permits safe temporary symlink creation.

## Deployment-readiness assessment

| Area | Status | Basis |
| --- | --- | --- |
| Current automated regression | Passed | Current `.\run.cmd test` evidence snapshot |
| Frontend build | Passed | Current type-check and production build |
| Controlled local demonstration | Ready | Verified runner, API, component/page, and build contracts |
| Container build and local deployment | Validated with limitations | Historical P6-05 isolated evidence plus current static contracts |
| Manual operational checklist | Available; not executed | 46 P6-04 cases remain `Not Run` |
| Public production deployment | Not validated | Required external production controls and public-environment evidence are absent |
| Security certification | Not performed | No formal penetration test or independent certification |

The project is ready for controlled mentor demonstration and repeatable
local/container validation. It is not certified or fully validated for
unrestricted public production deployment.

## Known limitations and unvalidated areas

The repository does not currently implement or validate:

- TLS termination, trusted proxy handling, a reverse proxy, or load balancing;
- automated PostgreSQL backups or representative restore/disaster-recovery tests;
- centralized logging, production monitoring, or alerting;
- CI/CD deployment, Kubernetes, or another orchestration platform;
- automated secret rotation or a separately provisioned restricted application
  database role;
- zero-downtime deployment, production load/endurance/capacity testing, failover,
  or validated public-internet deployment;
- formal penetration testing or independent security certification;
- a real-browser compatibility matrix, visual-regression suite, or full
  accessibility/WCAG certification;
- authentication, authorization, roles, or protected analyst sessions;
- automatic/scheduled ingestion, arbitrary URL ingestion, active scanning,
  active IOC validation, malware retrieval, file submission, or exploit execution.

The production PostgreSQL initialization role is privileged and reused by the
backend and migration service. The persistent volume is not a backup.
`docker compose down -v` destroys the named database volume and is not routine
cleanup; it requires exact target verification, approved recovery evidence, and
explicit authorization.

## Reproduction commands

Run the authoritative complete local regression from the repository root:

```powershell
.\run.cmd test
```

Use fresh external Windows pytest state when local profile temp/cache permissions
are unreliable:

```powershell
$P8Temp = Join-Path $env:USERPROFILE "alpha-data-p8-04-pytest-temp"
$P8Cache = Join-Path $env:USERPROFILE "alpha-data-p8-04-pytest-cache"
New-Item -ItemType Directory -Force -Path $P8Temp, $P8Cache | Out-Null
$env:TEMP = $P8Temp
$env:TMP = $P8Temp

Push-Location backend
.\.venv\Scripts\python.exe -m pytest -q `
    --basetemp "$P8Temp\pytest-basetemp" `
    -o "cache_dir=$P8Cache"
Pop-Location
```

Run the frontend gates individually:

```powershell
Push-Location frontend
npm run test:run
npm run type-check
npm run build
Pop-Location
```

Run the P8-04 documentation contract and inspect the known skip reasons:

```powershell
Push-Location backend
.\.venv\Scripts\python.exe -m pytest -q `
    --basetemp "$P8Temp\report-basetemp" `
    -o "cache_dir=$P8Cache" `
    tests/test_testing_report_documentation.py

.\.venv\Scripts\python.exe -m pytest -q -rs `
    --basetemp "$P8Temp\skip-basetemp" `
    -o "cache_dir=$P8Cache" `
    tests/test_censys_publications_adapter.py::test_direct_file_symlink_is_rejected `
    tests/test_censys_publications_adapter.py::test_parent_directory_symlink_is_rejected `
    tests/test_censys_publications_adapter.py::test_nested_parent_directory_symlink_is_rejected `
    tests/test_anomali_publications_adapter.py::test_file_and_parent_symlinks_are_rejected `
    tests/test_ibm_x_force_publications_adapter.py::test_missing_directory_and_symlink_paths_are_rejected
Pop-Location
```

These commands use no live provider, target, malware, file-submission, or
secret-bearing argument.

## Evidence traceability

| Work item | Commit/checkpoint | Artifact or test area | Evidence purpose |
| --- | --- | --- | --- |
| P6-01 backend API tests | `3dfae978` | API, validation, dashboard, safe logging/error tests | Expanded read/query and failure coverage |
| P6-02 fetcher tests | `6135783` | Source clients, mocked failures, malformed responses, bounds | Expanded offline external-source boundary coverage |
| Supporting P6 lint correction | `553ab41` | Safe-rendering validation script | Kept validation tooling lint-clean |
| P6-03 frontend tests | `589df1d` | 9 Vitest files and 66 tests | Component, page, state, navigation, link, and text-rendering evidence |
| P6-04 manual cases | `e986a81` | `manual-test-cases.md` | Repeatable 46-case procedure; cases remain `Not Run` |
| P6-05 deployment build | `6f7c958` | `deployment-build-validation.md` | Historical isolated build/start/migrate/smoke/restart/stop evidence |
| Alembic image prerequisite | `6e64169` | Backend Dockerfile and test | Packages migration configuration/assets |
| Development runner database fix | `5c0c864` | `run.ps1` and runner tests | Safe host-only `db` to `localhost` child-process boundary |
| P7-01 production Docker | `446fd53` | Production Compose/images/tests | Hardened production-oriented static baseline |
| P7-02 environment/secrets | `26959f3` | Environment guide and contracts | Variable, secret, CORS, role, and lifecycle evidence |
| P7-03 deployment guide | `ea5d0fd` | Deployment guide and contracts | Repeatable production-oriented procedures and limitations |
| P8-01 README | `d3dee0a` | README documentation tests | Mentor handover contract |
| P8-02 data sources | `46c252e` | Source documentation tests | Implemented/candidate source and ownership contract |
| P8-03 architecture | `ef1307a` | Architecture documentation tests | Current component, trust, runtime, and topology contract |
| P8-04 evidence snapshot | Parent `ef1307a29969c47c2289862a3ed9bd02ebbd5bc3`; final task commit traceable through Git history | This report and focused contract test | Dated consolidated testing evidence for mentor review |

Commit history supports traceability but does not replace current inspection or
rerunning the relevant gate.

## Reviewer checklist

- [ ] Confirm the parent checkpoint and two-file P8-04 scope.
- [ ] Review the complete report and focused test rather than only the summary.
- [ ] Compare the exact current counts with captured command output.
- [ ] Confirm the five skips remain labeled as skips and the warning as pre-existing.
- [ ] Confirm all 46 P6-04 cases remain `Not Run` absent execution evidence.
- [ ] Confirm P6-05 is labeled historical local deployment-build evidence.
- [ ] Confirm no claim of public production readiness or security certification.
- [ ] Verify every relative documentation link resolves.
- [ ] Confirm the committed report and focused test retain consistent UTF-8 and repository line-ending conventions.

## Canonical references

- [Project handover](../README.md)
- [Testing plan](testing-plan.md)
- [Manual test cases](manual-test-cases.md)
- [Deployment build validation](deployment-build-validation.md)
- [Production Docker deployment](production-docker-deployment.md)
- [Environment and secret handling](environment-and-secrets.md)
- [Security notes](security-notes.md)
- [Architecture](architecture.md)
- [Data sources](data-sources.md)
- [Source integration policy](source-integration-policy.md)

## C08 automated-evidence addendum — 8 August 2026

This addendum records the authoritative final post-hardening C08 evidence for
B4-04, B5-05, B5-06, B8-01, B8-04, B8-05, and B8-07. The repository gate was `dev` at
`cfef7477c26f568e738a966c26c03100e640e53e`, equal to refreshed `origin/dev`
with divergence `0 0`. C08 changes remain unstaged and uncommitted for complete
file review. The historical P8-04 snapshot above remains intact and should not
be confused with this later evidence date.

These 8 August 2026 final post-hardening results supersede all earlier
pre-hardening C08 validation counts.

### C08 result summary

| Gate | Result |
| --- | --- |
| Full backend pytest | **PASS**; 5,267 collected, 5,014 passed, 253 skipped, 12 warnings |
| Full frontend Vitest | **PASS**; 25 test files passed, 151 tests passed |
| Frontend TypeScript check | **PASS** |
| Frontend production build | **PASS** |
| Alembic heads | Passed; single preserved head `c07a01b02c03` |
| Alembic history | Passed; one linear history from base through `c07a01b02c03` |
| Full project runner | **PASS**; `.\run.cmd test` exited with code 0 and its final output included `[OK] Command 'test' completed successfully.` |

The full project runner required the declared `argon2-cffi` dependency to be
installed into the stale backend virtual environment and a Windows-safe
external pytest base-temp supplied through a process-only `PYTEST_ADDOPTS`
override. The package was available from the local pip cache. The override was
restored after the run. Earlier runner attempts failed only during dependency
import or temporary-directory setup and are not counted as passing evidence.

The 253 skips are environment/optional PostgreSQL and Windows capability gates
already expressed by the test suite; they were not converted to passes. The 12
warnings are the known Starlette/httpx and per-request cookie deprecations. No
C08 test failed in the final full run.

### C08 security and integrity evidence

- New analyst routes enforce backend `content.read` or `analysis.use`, strict
  response models, allow-listed queries, bounded pagination, canonical public
  UUIDs, parameterized filters, sanitized errors, and per-session throttling.
- Threat, indicator, item-provenance, and UAE responses expose safe public
  metadata only; database IDs, raw payloads, SQL, stack traces, secrets,
  credentials, cookies, and authorization headers remain excluded.
- Text-only UAE or emirate mentions are `possible` and explicitly state that no
  attribution is asserted. Direct evidence requires a controlled UAE authority
  source. Global and no-demonstrated-evidence states remain distinct.
- Controlled authority, emirate, sector, and language tags reuse existing tag
  persistence. Protected analyst/source classifications and analyst-owned tag
  assignments remain protected, while system-controlled assignments are
  reconciled through the controlled relationship collection inside the
  caller-owned transaction.
- The UI renders normalized text through React and outbound links through the
  existing safe-link component. IOC search reads stored metadata only and does
  not probe, resolve, fetch, submit, or activate an indicator.
- The preview dataset is retired, the nonfunctional header search is absent,
  every visible C08 navigation item has a functional route, and later B8-06
  routes remain absent rather than appearing as placeholders.
- No migration, source registration, source activation, handler, schedule,
  deployment, credential, database mutation, or live OSINT request was part of
  C08 validation. `DEFAULT_SOURCE_HANDLERS` remains empty.

Formal browser/manual execution, visual responsive inspection, live database
content counts, staging deployment, source activation, and live provider
validation were not performed. All 46 formal manual cases therefore remain
`Not Run`. This automated C08 evidence supports final file review and controlled
local demonstration; it is not public-production certification or a penetration
test.
