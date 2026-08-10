# C11 release-candidate checklist

Status vocabulary: `PASS`, `FAIL`, `UNRUN`, `ACCEPTED LIMITATION`, `BLOCKED — MANUAL GATE`.

## Identity and freeze

| Field | Status | Evidence |
|---|---|---|
| Parent checkpoint | PASS | `beeba6522eeac8c9a361c52d17624f02d92da5f5` |
| Branch | PASS | `dev` |
| Initial `HEAD` / `origin/dev` | PASS | Both parent checkpoint; divergence `0 0` after fetch |
| Initial tree/index | PASS | Clean; staged count 0 |
| Final `HEAD` / `origin/dev` | PASS | Both parent checkpoint after final fetch; divergence `0 0` |
| Final tree/index | PASS | 15 intended C11 files unstaged; staged count 0 |
| Final migration/diff checks | PASS | Migration bytes clean; `git diff --check` passed with line-ending notices only |
| Release freeze | PASS | No feature, source, schema, migration, broad refactor, or C10 reopening |
| Final RC commit | UNRUN | To be recorded after independent review and approved Git closure |
| Reviewer | UNRUN | Independent reviewer not yet recorded |
| Date | PASS | 10 August 2026, Asia/Dubai |

## Database, source, and orchestration freeze

| Field | Status | Evidence |
|---|---|---|
| SQLAlchemy mappers | PASS | `configure_mappers()` completed |
| Alembic head | PASS | One head: `c07a01b02c03` |
| Alembic history | PASS | Eight committed revisions |
| Migration bytes | PASS | `git diff --exit-code HEAD -- backend/alembic/versions` |
| Production handler count | PASS | `DEFAULT_SOURCE_HANDLERS_COUNT = 0` |
| C05 disabled sources | PASS | MITRE ATT&CK Enterprise, CERT-FR alerts/advisories, UK NCSC all disabled/unscheduled |
| UAE automation | PASS | aeCERT and NibraS remain planned/manual; UAE CSC and DESC automation remain disabled/approval-gated |
| Parent schedule contract | PASS | One `17 */2 * * *` Asia/Dubai deployment; concurrency 1; paused by default |
| Actual staging schedule observation | BLOCKED — MANUAL GATE | B11-02/M26 |

## Twelve visible release pages

Every route below passed existence, navigation, production build, authenticated-layout, no-placeholder, functional-control, and truthful-state review. Loading/empty/error coverage is provided by the named page/component suites and the full 200-test frontend run.

| Page | Route | Primary backend state | Status |
|---|---|---|---|
| Overview | `/` | dashboard summary/trends, intelligence, articles, health | PASS |
| Threat Feed | `/threat-feed` | articles and bounded threat metadata | PASS |
| Vulnerabilities | `/vulnerabilities` | intelligence items filtered to vulnerabilities | PASS |
| UAE Intelligence | `/uae-intelligence` | bounded UAE analysis and source state | PASS |
| IOC Search | `/ioc-search` | stored indicators; `analysis.use` | PASS |
| Ingestion Operations | `/ingestion-operations` | operations summary/cycles/runs; `ingestion.read` | PASS |
| Sources | `/sources` | governed source readiness/progress/actions | PASS |
| Run History | `/run-history` | runs, details, events, authorized retry | PASS |
| Reports | `/reports` | catalog and bounded export | PASS |
| System Health | `/system-health` | eight-component truthful health | PASS |
| Audit Log | `/audit-log` | administrator-bounded audit query | PASS |
| Methodology | `/methodology` | evidence, inference, limitations | PASS |

The role-restricted `/admin/users` workflow exists for account administration but is not one of the twelve general release-page inventory entries. The duplicate implementation route `/operations` is not linked in release navigation; `/ingestion-operations` is the official route.

## Removed/non-release feature inventory

| Feature | Status | Evidence |
|---|---|---|
| Separate Threat Entities page | PASS | No top-level route/navigation; safe metadata is integrated into Threat Feed |
| Advanced threat graph | PASS | Absent |
| Machine-learning predictions | PASS | Absent; UAE logic is deterministic |
| Automated blocking/SOAR | PASS | Absent |
| Malware sample processing/VirusTotal upload | PASS | Absent/prohibited |
| Intelligence chatbot | PASS | Absent |
| Slack/Teams/email product alerts | PASS | Absent; internal operational Alertmanager is distinct |
| Native mobile application | PASS | Absent; responsive web only |
| Custom dashboard builder | PASS | Absent |
| Multi-tenant customer platform | PASS | Absent |
| Kubernetes deployment UI/claim | PASS | Absent |
| Advanced SSO UI | PASS | Absent; local RBAC only |
| Coming Soon/dead primary control | PASS | C11 static inventory plus full page/component tests |

## Accessibility release check

| Check | Status | Evidence |
|---|---|---|
| Page headings, form labels, button/link names | PASS | Static inspection and RTL role/name queries |
| Keyboard-operable native controls | PASS | Links/buttons/forms use native elements |
| Drawer focus/Escape/return focus | PASS | `DashboardShell` implementation/tests |
| Loading and sanitized error announcements | PASS | `role=status`, `aria-busy`, `role=alert` across workflows |
| Responsive overflow/core tables | PASS | Responsive table/shell classes inspected; production build passed |
| Formal WCAG certification/automated contrast measurement | ACCEPTED LIMITATION | Bounded release review only; not fully automated |

## Test and build evidence

| Gate | Status | Exact result |
|---|---|---|
| Focused backend C11 | PASS | 9 passed, 1 warning |
| C11 + changed documentation contracts | PASS | 77 passed, 1 warning |
| Focused C11/directly affected backend | PASS | 148 passed, 1 warning |
| C10 security regression | PASS | 48 passed, 1 warning |
| C09 recovery/operations contract regression | PASS | 103 passed, 2 skipped (Windows symlink unavailable), 1 warning |
| Bounded API load | PASS | 132/132 at concurrency 12; no unexpected 5xx |
| Full backend | ACCEPTED LIMITATION | 5,080 passed, 255 skipped, 56 known failures, 12 warnings |
| Complementary backend | PASS | 5,053 passed, 255 skipped, 12 warnings |
| Focused frontend C11 | PASS | 1 file, 4 tests |
| Full frontend Vitest | PASS | 36 files, 200 tests |
| Type-check | PASS | Next route types + `tsc --noEmit` |
| Production build | PASS | Next 16.3.0; 18 static pages |
| Whole-tree lint | ACCEPTED LIMITATION | 10 pre-existing errors in unchanged components; zero in C11-changed frontend file |
| C11 frontend file lint | PASS | Direct ESLint invocation exited 0 |
| `.\run.cmd test` | ACCEPTED LIMITATION | Exit 1 at exact known backend boundary |

## Security, recovery, and deployment evidence

| Field | Status | Evidence |
|---|---|---|
| C10 injection/API/outbound/logic/supply-chain suites | PASS | 48 tests |
| Authentication/authorization/CSRF/limits | PASS | Focused and full regression |
| Safe URLs/XSS/logging/errors | PASS | C10 plus 200 frontend tests |
| Source policies/UAE governance | PASS | Empty handler map; disabled gates preserved |
| Reports/audit/system health | PASS | Focused suites and release API load |
| Current backup/recovery contracts | PASS | 103-test C09 group |
| Prior C09 operational evidence | PASS | Referenced historical local isolated rehearsal; not rerun/relabelled |
| Quiet Compose validation | PASS | Exit 0 with placeholder-only inputs; Docker config access warning only |
| Image rebuild/current vulnerability rescan | UNRUN | No runtime/image input changed; C10 evidence referenced |
| Mentor staging/public TLS | BLOCKED — MANUAL GATE | M20 |

## Findings and release decision

- `BLOCKER`: none demonstrated.
- `MUST FIX`: none demonstrated.
- `FOLLOW-UP`: unchanged React lint baseline; separately scoped vendor-image refresh and Python transitive lock workflow.
- `ACCEPTED LIMITATION`: known Windows full-suite boundary; operational PostgreSQL pool load UNRUN; bounded/not-formal accessibility review; frozen C10 limitations.

Local release-candidate decision: **PASS within locally provable scope; ready for independent complete-file review.** External staging/UAT/acceptance is not closed.
