# C11 final security and reliability audit

## Acceptance and evidence boundary

- Task: **C11** (`B10-08`, `B11-01`, `B11-03`).
- Release-candidate parent checkpoint: `beeba6522eeac8c9a361c52d17624f02d92da5f5`.
- Verified branch at start: `dev`.
- Verified `HEAD` and `origin/dev` at start: parent checkpoint above; divergence `0 0`; clean tree; zero staged files.
- Date: 10 August 2026, Asia/Dubai.
- Freeze: no new feature, source, schema, migration, broad refactor, or C10 reopening.
- Execution: local Windows host, mocked/synthetic data, in-process API traffic, no live OSINT request, no public target, no destructive Docker rehearsal.

This audit demonstrates a mentor-ready **local** release candidate. It does not demonstrate mentor-accessible staging, public DNS/TLS, external alert delivery, off-host backup activation, a real two-hour scheduled cycle, mentor UAT, or production RPO/RTO.

## Environment

| Component | Observed value |
|---|---|
| Operating/test host | Windows (`win32`) |
| Python | 3.13.14 |
| pytest | 9.1.1 |
| Node.js | 24.12.0 |
| npm | 11.6.2 |
| Next.js | 16.3.0 |
| Docker | 29.5.3 |
| Docker Compose | 5.1.4 |
| Database operational load target | None; local SQLAlchemy queue-pool boundary only |

## B10-08 methodology

The audit combined bounded C11 tests with the frozen C10 security suites, C09 recovery/operations contract suites, complete backend/frontend regression, mapper/Alembic checks, quiet Compose validation, complete-file route/control inspection, and documentation cross-checking. Timings use `time.perf_counter()` and are local observations only.

## API load and concurrency evidence

Command:

```powershell
Set-Location backend
.\.venv\Scripts\python.exe -m pytest tests\test_c11_reliability.py tests\test_c11_release_candidate.py -q -s
```

The C11 test issued 12 rounds across 11 representative authenticated read paths with 12 worker threads:

- requests: 132;
- concurrency: 12;
- success: 132;
- failure/unexpected 5xx: 0;
- elapsed: 0.416 seconds;
- median: 28.118 ms;
- p95: 123.107 ms;
- maximum: 130.368 ms.

Paths covered Overview, articles/Threat Feed, vulnerabilities, UAE intelligence, IOC search, operations summary, Sources, Run History, report catalog, System Health, and Audit Log. Responses passed their real FastAPI response schemas. The same path set returned the fixed `401 Authentication required` response without authorization overrides. These in-process timings are not staging/production latency and define no SLA.

## Database pool pressure

`test_bounded_pool_times_out_then_reuses_released_connection` used an isolated SQLAlchemy `QueuePool` with size 1, overflow 0, and a 0.05-second acquisition timeout. A second checkout timed out rather than waiting indefinitely; the exception contained no credential/configuration canary; releasing the first connection allowed a successful `SELECT 1`; checked-out count returned to zero.

Production settings remain bounded to pool size `1..20`, overflow `0..20`, combined maximum 30, timeout `1..60` seconds, recycle `60..3600` seconds, and connect timeout `1..30` seconds. PostgreSQL-specific operational pool exhaustion was **UNRUN** because C11 did not target a company/shared database and no isolated PostgreSQL load environment was required. This is an accepted environment limitation, not an operational pass.

## Source concurrency and failure isolation

Three approved policy identities (`cisa-kev`, `nvd`, and `first-epss`) ran concurrently against a thread-safe synthetic persistence adapter and mocked handlers. Two committed bounded success results and their own version-1 progress only. The timed-out NVD handler exhausted its fixed retry plan, ended `failed`, did not leak its raw diagnostic, and did not create or overwrite another source's progress. No network request occurred.

Existing orchestration regressions additionally proved truthful timeout/malformed/non-request states, source failure isolation, retry/backoff, quota/defer handling, checkpoint-after-commit recovery, cancellation, idempotent reuse, and no parent fake success. `DEFAULT_SOURCE_HANDLERS` remained an immutable empty mapping.

## Schedule delay and orchestration

The release contract remains:

- one deployment: `alpha-data-ingestion-cycle`;
- parent flow: `alpha-data-parent-ingestion-cycle`;
- cron: `17 */2 * * *`;
- timezone: `Asia/Dubai`;
- deployment concurrency: 1, collision strategy cancel-new;
- paused by default;
- fixed scheduled-slot validation and deterministic source staggering;
- source concurrency limit 1, fixed bounded retries, source failure isolation;
- activation allowed only in staging with explicit controlled evidence, a valid work pool, and all required scheduled handlers.

Mocked-clock/flow tests passed. No two-hour staging cycle was observed; B11-02/M26 owns that evidence.

## Large input and resource limits

The frozen C10 API security suite revalidated:

- backend body ceiling: 1,000,000 bytes;
- ASGI request-frame ceiling: 1,024;
- declared, streamed, duplicate, malformed, disconnected, and contradictory body handling;
- bounded list/search/audit parameters and canonical identifiers;
- report maximum: 100 rows, 2 MiB, 500 characters per cell;
- outbound decompressed-byte, page, object, parser-depth, and record bounds;
- fixed redirects/hosts/paths and proxy-environment rejection.

No dangerous allocation or public load test was performed.

## Exceptional conditions

Focused C11 and directly affected suites covered invalid/expired authentication, permission denial, CSRF and mass-assignment rejection, database exceptions, pool timeout/reuse, source timeout/malformed/failure isolation, report-generation and audit-commit failure, dependency-health failure, backup metadata/checksum/identity failure, recovery contract failure, transaction rollback, and failed checkpoint advancement. Failure states stayed truthful and public errors remained sanitized.

## Backup, restore, and rollback evidence

### Current C11 contract regression

The safe C09 group passed **103**, skipped **2**, and emitted **1** existing warning. Both skips state that Windows symlink creation is unavailable. Tests covered encrypted backup metadata, PostgreSQL/Prefect restore validation, retention selection, edge, monitoring, private metrics, reports, system health, rollback, failed deployment/migration, worker/source/credential failure, and partial-checkpoint contracts.

### Previously reviewed C09 operational rehearsal

[`c09-local-rehearsal-evidence.md`](c09-local-rehearsal-evidence.md) remains the historical operational record. It includes isolated synthetic PostgreSQL backup/restore to head `c07a01b02c03`, Prefect backup/restore, and the later hardened Docker recovery scenarios. C11 did not rerun or relabel that evidence and did not delete retained rehearsal resources. Public staging, off-host transfer, and production RPO/RTO remain unproved.

## Security regression

Exact command:

```powershell
Set-Location backend
.\.venv\Scripts\python.exe -m pytest -q `
  tests\test_c10_injection_security.py `
  tests\test_c10_api_security.py `
  tests\test_c10_outbound_security.py `
  tests\test_c10_logic_integrity.py `
  tests\test_c10_supply_chain.py
```

Result: **48 passed, 0 failed, 0 skipped, 1 warning**. The warning is the existing FastAPI TestClient/httpx2 deprecation. No assertion was weakened and no skip/xfail was added.

The prior C10 outcome remains authoritative: all frozen C10 Blockers/Must Fix findings are resolved. Current residual dependency/image risks and SBOM hashes remain in [`c10-supply-chain-evidence.md`](c10-supply-chain-evidence.md) and [`security/sbom/README.md`](../security/sbom/README.md). C11 changed no production manifest, lockfile, Dockerfile, or image configuration; image rebuild/rescan was therefore **UNRUN** and prior C10 evidence was referenced rather than presented as new.

## Focused C11 and directly affected regression

| Validation | Result |
|---|---|
| New backend C11 files | 9 passed, 1 warning |
| New frontend release-scope file | 4 passed |
| C11 plus changed current-state documentation contracts | 77 passed, 1 warning |
| C11 frontend file lint | PASS |
| C11 plus limits/orchestration/reports/health/audit/authorization | 148 passed, 1 warning |
| C10 security suites | 48 passed, 1 warning |
| C09 safe recovery/operations contracts | 103 passed, 2 skipped, 1 warning |

## Full backend regression

Command: `Set-Location backend; .\.venv\Scripts\python.exe -m pytest -q`

Result: **5,080 passed, 255 skipped, 56 failed, 12 warnings**. All 56 failures were confined to the two frozen Windows/environment files:

- `backend/tests/test_c08_pre02_reconciliation.py`;
- `backend/tests/test_ioc_relationship_migration.py`.

Both files were verified unchanged with `git diff --exit-code HEAD -- ...`. The demonstrated causes remain unavailable `pwsh` and inherited checkout-byte/hash behavior. No skip, xfail, hash weakening, migration edit, or test edit was made.

Complementary command excluding only those files passed **5,053**, skipped **255**, and emitted **12 warnings**. The prior C10 complementary total was 5,044; the difference is exactly the 9 new C11 backend tests. This is correctly classified as a complementary regression, not a full-suite pass.

## Frontend regression and release pages

| Command | Result |
|---|---|
| `npm run test:run -- src/security/c11-release-scope.test.tsx` | 1 file, 4 tests passed |
| `npm run test:run` | 36 files, 200 tests passed |
| `npm run type-check` | PASS; Next route types generated and TypeScript clean |
| `npm run build` | PASS; optimized Next 16.3.0 build, 18 static pages generated |
| `npm run lint` | FAIL; 10 existing `react-hooks/set-state-in-effect` errors in unchanged files |

No C11-changed frontend file has a lint error. The 10-error whole-tree lint baseline is the same C10 FOLLOW-UP and did not block tests, type-check, or build. The bounded C11 review was not a formal WCAG certification; labels, names, keyboard buttons/links, focus handling, status/alert semantics, and responsive table/overflow patterns were inspected/tested, so accessibility is **PASS / NOT FULLY AUTOMATED**.

After the documentation reconciliation, the C11 tests plus the directly affected README, architecture, deployment, environment, C05, C06, and C07 documentation contracts passed **77** tests with the existing TestClient warning. The C11 frontend test also passed a direct ESLint invocation.

All twelve release pages exist, build, are linked, use API-backed/truthful state, and are protected by the authenticated dashboard layout. Component/page tests cover loading, success, empty/unavailable, sanitized error, safe URL/text rendering, permission projection, and functional controls. No Coming Soon surface, dead release button, or removed top-level route was found.

## Mapper, Alembic, and migration integrity

- SQLAlchemy `configure_mappers()`: PASS.
- `alembic heads`: one head, `c07a01b02c03`.
- `alembic history`: eight revisions from base through `c07a01b02c03`.
- `git diff --exit-code HEAD -- backend/alembic/versions`: PASS; byte-identical.
- New migrations: none.

## Project runner

`.\run.cmd test` exited **1** after the backend phase with the same 5,080 passed / 255 skipped / 56 failed / 12 warning boundary. It correctly stopped and did not claim a project pass. No new runner failure occurred.

## Deployment-package validation

`docker compose --env-file .env.production.example -f compose.prod.yml config --quiet` was run with process-local non-secret placeholder file references and the verified parent SHA. Compose exited 0. The sandbox emitted two warnings because it could not read the user's Docker CLI configuration; no configuration value was printed.

Static/contract checks preserve digest/fixed image inputs, Caddy-only public ports, private PostgreSQL/Prefect/metrics/admin surfaces, non-root services, dropped capabilities/no-new-privileges, bounded logs/resources, health checks, and secret file references. No image rebuild, live container creation, public TLS check, or staging deployment was run.

## Findings and remediation

No production Blocker or Must Fix was frozen or remediated in C11. Two initial C11 test-harness failures (SQLAlchemy 2 raw-string execution and an incomplete synthetic protocol adapter) were corrected before the passing focused run; they were not product defects.

Documentation contradictions about completed C07/C09 local capabilities were corrected in `README.md`, `docs/architecture.md`, `docs/production-docker-deployment.md`, and `docs/security-notes.md`. The corrections do not claim external activation.

## Residual risk and accepted limitations

- **ACCEPTED LIMITATION:** full backend cannot be green on this Windows host because of the two unchanged environment/hash test files; complementary regression is green.
- **ACCEPTED LIMITATION:** PostgreSQL-specific operational pool-pressure testing was UNRUN; deterministic local pool bounds/recovery passed.
- **ACCEPTED LIMITATION:** accessibility review is bounded and not a formal WCAG certification.
- **ACCEPTED LIMITATION:** process-local API rate limiting, single-factor local authentication, internal-only FastAPI docs, and measured Next inline CSP requirements remain as recorded by C10.
- **FOLLOW-UP:** resolve the 10 unchanged-component React lint findings.
- **FOLLOW-UP:** separately refresh/retest retained vendor images and adopt a reviewed Python transitive lock/constraints workflow before public production, as recorded by C10.
- **BLOCKER:** none demonstrated.
- **MUST FIX:** none demonstrated.

## Manual gates

- **M20 / B9-03 — BLOCKED — MANUAL GATE:** mentor-accessible staging, real DNS/public TLS, external alert/off-host storage activation.
- **M26 / B11-02 — BLOCKED — MANUAL GATE:** role-based mentor staging UAT and observation of an actual scheduled cycle.
- **M28 / B11-04 + B11-05 — BLOCKED — MANUAL GATE:** final workbook/evidence reconciliation, mentor acceptance, and secure handover.

The final C11 release-candidate commit is intentionally not recorded here. It must be added only after independent complete-file review and approved Git closure.

## Final Git state

After the final origin refresh, the branch remained `dev`; `HEAD` and `origin/dev` both remained `beeba6522eeac8c9a361c52d17624f02d92da5f5`; divergence remained `0 0`; and the index remained empty. C11 leaves 15 intended files modified or untracked and unstaged. Migration bytes remain clean. `git diff --check` passed with Windows LF-to-CRLF working-copy notices only.
