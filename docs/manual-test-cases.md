# Alpha Data / Cyber OSINT Dashboard Manual Test Cases

## 1. Document control

| Field | Value |
| --- | --- |
| Project name | Alpha Data / Cyber OSINT Dashboard |
| Task ID | P6-04 |
| Document title | Manual Test Cases |
| Version | 1.0 |
| Prepared date | 21 July 2026 |
| Prepared by | ______________________________ |
| Reviewed by | ______________________________ |
| Test environment | Local Windows development environment, PowerShell, a current Chromium-based browser, and a disposable PostgreSQL test database |
| Repository branch | `dev` |
| Verified starting commit | `589df1d592360450775e36b05bc0eb8578c4708a` |
| Status | Ready for manual execution |

This document defines cases for later execution. Automated regression results do
not change any manual case from **Not Run** to **Pass**.

## 2. Purpose

This manual suite validates user-visible dashboard behavior, operational
usability, defensive security boundaries, and real-browser interactions that
are not fully represented by the backend tests or the P6-03 jsdom suite. It is
written for developers, interns, mentors, and cybersecurity reviewers without
requiring knowledge of React, FastAPI, or database internals.

## 3. Scope

- Application startup and local availability
- Dashboard, health, summary, and trend views
- Article list, filters, pagination, detail routes, and navigation
- Vulnerability list, filters, pagination, detail routes, and navigation
- Loading, empty, filtered-empty, not-found, and controlled error states
- Safe rendering of untrusted text and protected external links
- Responsive layout and basic keyboard/accessibility behavior
- Error privacy, request IDs, CORS, and security-header regression checks

## 4. Out of scope

- Penetration testing, automated exploitation, or unauthorized scanning
- Load, stress, or formal performance testing
- Live-source reliability or production-data certification
- Production credentials, production data, or shared-system mutation
- Full browser/device matrix or WCAG certification
- Malware handling, dark-web access, or external-system testing
- CI validation or full browser end-to-end automation

## 5. Preconditions

1. Use the approved `dev` checkpoint shown in Document control. Record any later
   approved commit in the execution summary.
2. Confirm the working tree is clean before starting a formal execution.
3. Create required local environment files from repository examples without
   recording their values in evidence.
4. Install project dependencies with `.\run.cmd install` if they are not
   already available.
5. Use only a disposable local test database and synthetic or otherwise
   explicitly approved defensive data.
6. Use `.\run.cmd dev` for the database-in-Docker/local-app path, or the
   documented Docker workflow when the test plan selects it. Do not mix startup
   paths within a result set without noting the change.
7. Reserve local ports 3000 and 8000. Do not test against a public deployment.
8. Browser developer tools may be used only to observe the application's own
   local requests and responses. Redact sensitive values from evidence.

### Optional synthetic seed

If list and detail cases need deterministic records, use the repository's
idempotent manual seed against the disposable development database:

```powershell
Push-Location .\backend
$env:APP_ENV = "development"
.\.venv\Scripts\python.exe -m app.dev_data.cli
Pop-Location
```

The command must refuse production-like environments. Do not copy local
configuration values into this document or an issue.

## 6. Test data

| Placeholder | Safe use |
| --- | --- |
| `<ARTICLE_PUBLIC_ID>` | Public UUID copied from a synthetic article detail link |
| `<VULNERABILITY_PUBLIC_ID>` | Public UUID copied from a synthetic vulnerability detail link |
| `<MISSING_PUBLIC_ID>` | Random valid UUID known not to exist in the disposable dataset |
| `<SAFE_HTTPS_URL>` | Synthetic absolute HTTPS URL on an example domain |
| `<SAFE_HTTP_URL>` | Synthetic absolute HTTP URL on an example domain |
| `<UNSAFE_URL_SAMPLE>` | Harmless non-network value such as `javascript:alert(1)` supplied only through an approved local fixture |
| `<SEARCH_TERM_WITH_RESULTS>` | Distinct text copied from a visible synthetic title, summary, or CVE |
| `<SEARCH_TERM_WITH_NO_RESULTS>` | Harmless unique text absent from the selected dataset |
| `<MARKUP_LIKE_TEXT>` | Literal text such as `<img src=x onerror=alert(1)>`; it must never be executed |
| `<ALLOWED_FRONTEND_ORIGIN>` | Exact local frontend origin from approved, non-secret development configuration |
| `<UNAPPROVED_ORIGIN>` | Harmless unapproved origin such as `https://unapproved.example`, used only as an `Origin` header on a request to the local backend |

If an unsafe-link, markup, empty, delayed, or server-failure fixture is not
available in the approved disposable environment, mark that case **Blocked**.
Do not create it in production or a shared database.

## 7. Execution-status definitions

| Status | Use when |
| --- | --- |
| Not Run | The case has not started. This is the default. |
| Pass | Every step was executed and every observable expected result occurred. |
| Fail | At least one expected result did not occur; record evidence and a defect reference. |
| Blocked | A prerequisite, fixture, service, or environment prevented execution. |
| Not Applicable | The approved test environment does not support the case; explain why. |

## 8. Severity definitions

| Severity | Definition |
| --- | --- |
| Critical | A security boundary is bypassed, sensitive information is exposed, or the application is unusable for all primary workflows. |
| High | A primary workflow fails, unsafe content becomes active, or a serious privacy/security control is absent. |
| Medium | A significant state, filter, navigation, responsive, or accessibility behavior is incorrect but a safe workaround exists. |
| Low | A minor wording, layout, or usability defect has limited operational impact. |

## 9. Evidence requirements

For each executed case, attach at least one relevant item: screenshot, browser
console screenshot, redacted network-response screenshot, command output,
defect reference, or tester notes. Do not capture credentials, tokens, cookies,
authorization headers, local environment-file values, connection strings, or
private filesystem details. Crop or redact evidence before sharing it.

## 10. Manual test cases

The heading supplies both the stable **Test ID** and the **Title**. All result,
evidence, and defect fields intentionally remain blank for execution.

### P6-04-MT-001 — Confirm the approved repository checkpoint

**Area:** Environment and startup<br>
**Priority:** High<br>
**Regression Smoke:** No<br>
**Preconditions:** Repository clone is available.<br>
**Test data:** Approved branch and commit from Document control.<br>
**Steps:**
1. From the repository root, run `git branch --show-current` and `git status --short`.
2. Run `git rev-parse HEAD` and compare it with the approved execution commit.

**Expected result:** Branch is `dev`, the recorded commit is approved, and a
formal test run starts from a clean working tree. No command changes files.<br>
**Actual result:** ______________________________<br>
**Status:** Not Run<br>
**Evidence:** ______________________________<br>
**Defect ID:** ______________________________<br>
**Notes:** Stop the formal execution if the checkpoint is not approved.

### P6-04-MT-002 — Verify installed dependencies and automated prerequisites

**Area:** Environment and startup<br>
**Priority:** High<br>
**Regression Smoke:** No<br>
**Preconditions:** Local dependencies were installed; a writable external pytest temp directory is configured if required.<br>
**Test data:** None.<br>
**Steps:**
1. Run `.\run.cmd test` from the repository root.
2. Observe the backend tests, frontend tests, type-check, and production build sections.

**Expected result:** The command exits successfully; backend tests, 66 frontend
tests, type-check, and build pass. Output contains no secret values.<br>
**Actual result:** ______________________________<br>
**Status:** Not Run<br>
**Evidence:** ______________________________<br>
**Defect ID:** ______________________________<br>
**Notes:** The known Starlette/httpx deprecation warning is not a failure.

### P6-04-MT-003 — Start the local application with one command

**Area:** Environment and startup<br>
**Priority:** High<br>
**Regression Smoke:** Yes<br>
**Preconditions:** Docker is available, dependencies are installed, local ports are free, and local configuration exists.<br>
**Test data:** Disposable local database.<br>
**Steps:**
1. Run `.\run.cmd dev` from the repository root.
2. Observe database health, port checks, and backend/frontend startup output.
3. Keep the command running for the browser cases.

**Expected result:** The database becomes healthy; backend and frontend start at
the documented local addresses; no scheduler, ingestion, or external collection
starts automatically.<br>
**Actual result:** ______________________________<br>
**Status:** Not Run<br>
**Evidence:** ______________________________<br>
**Defect ID:** ______________________________<br>
**Notes:** Do not use production configuration.

### P6-04-MT-004 — Verify frontend and backend availability without secret output

**Area:** Environment and startup<br>
**Priority:** High<br>
**Regression Smoke:** No<br>
**Preconditions:** Local application is running.<br>
**Test data:** `http://127.0.0.1:3000/` and `http://127.0.0.1:8000/api/health`.<br>
**Steps:**
1. Open the frontend address and confirm an HTTP-success page is shown.
2. Open the backend health address in a separate tab.
3. Review startup output and both pages for sensitive configuration.

**Expected result:** Frontend and health endpoint are available. No secret,
credential, private header, connection string, stack trace, or private path is
printed or rendered.<br>
**Actual result:** ______________________________<br>
**Status:** Not Run<br>
**Evidence:** ______________________________<br>
**Defect ID:** ______________________________<br>
**Notes:** Redact environment-specific details from evidence.

### P6-04-MT-005 — Observe controlled dashboard behavior while the backend is unavailable

**Area:** Environment and startup<br>
**Priority:** High<br>
**Regression Smoke:** No<br>
**Preconditions:** Frontend can remain running while the local backend is safely stopped or paused.<br>
**Test data:** None.<br>
**Steps:**
1. Stop only the local backend using the selected development workflow.
2. Refresh the dashboard.
3. Observe health, summary, trends, article, and vulnerability areas.

**Expected result:** The page remains rendered. Controlled unavailable messages
replace backend data; no raw exception, stack trace, database detail, or endless
navigation loop appears.<br>
**Actual result:** ______________________________<br>
**Status:** Not Run<br>
**Evidence:** ______________________________<br>
**Defect ID:** ______________________________<br>
**Notes:** Restart the backend before continuing. Do not stop shared services.

### P6-04-MT-006 — Shut down local development processes cleanly

**Area:** Environment and startup<br>
**Priority:** Medium<br>
**Regression Smoke:** No<br>
**Preconditions:** `.\run.cmd dev` is running.<br>
**Test data:** None.<br>
**Steps:**
1. Press Ctrl+C in the development-runner terminal.
2. Wait for the shutdown confirmation.
3. Confirm the frontend and backend local addresses no longer respond.

**Expected result:** Runner-started frontend and backend process trees stop
cleanly. The database may remain running as documented, and no project data is
deleted.<br>
**Actual result:** ______________________________<br>
**Status:** Not Run<br>
**Evidence:** ______________________________<br>
**Defect ID:** ______________________________<br>
**Notes:** Restart the application before subsequent browser cases.

### P6-04-MT-007 — Render the primary dashboard composition

**Area:** Dashboard composition<br>
**Priority:** High<br>
**Regression Smoke:** Yes<br>
**Preconditions:** Application is running with approved synthetic data.<br>
**Test data:** Seeded disposable database.<br>
**Steps:**
1. Open `/`.
2. Locate the `Cyber OSINT Dashboard` level-one heading.
3. Review `Recent trends`, `Vulnerabilities`, `Latest articles`, `Backend health`, `Operational status`, and `Source overview`.

**Expected result:** Every named section is present once, readable, and contained
within the dashboard shell. No section is blank because of a rendering failure.<br>
**Actual result:** ______________________________<br>
**Status:** Not Run<br>
**Evidence:** ______________________________<br>
**Defect ID:** ______________________________<br>
**Notes:** Preview sections must remain clearly identified.

### P6-04-MT-008 — Verify sidebar, top header, and defensive-scope labels

**Area:** Dashboard composition<br>
**Priority:** Medium<br>
**Regression Smoke:** No<br>
**Preconditions:** Dashboard is open at desktop width.<br>
**Test data:** None.<br>
**Steps:**
1. Locate `Alpha Data`, `Overview`, and the disabled `Coming soon` navigation items.
2. Locate `Dashboard command center`, `Synthetic preview`, and `Defensive OSINT only`.
3. Try to activate a disabled navigation item.

**Expected result:** Overview is the active route; planned items do not navigate;
the shell states its defensive and synthetic-preview boundaries; the top header
does not imply the search placeholder is active.<br>
**Actual result:** ______________________________<br>
**Status:** Not Run<br>
**Evidence:** ______________________________<br>
**Defect ID:** ______________________________<br>
**Notes:** The `Search preview coming soon` control is intentionally read-only.

### P6-04-MT-009 — Verify health loading, available, and unavailable states

**Area:** Health and summary states<br>
**Priority:** High<br>
**Regression Smoke:** Yes<br>
**Preconditions:** Dashboard is open; browser network throttling and a separately controllable local backend are available.<br>
**Test data:** Local `/api/health`.<br>
**Steps:**
1. Throttle the local request and refresh; observe `Checking service availability…`.
2. Restore normal networking and confirm the operational state and environment appear.
3. Stop the backend, refresh, and observe `Service unavailable`.

**Expected result:** Loading is visibly announced, a valid response shows the
service and environment, and failure shows only the controlled unavailable text.
No exact locale-formatted timestamp is required.<br>
**Actual result:** ______________________________<br>
**Status:** Not Run<br>
**Evidence:** ______________________________<br>
**Defect ID:** ______________________________<br>
**Notes:** Restore network settings and backend availability afterward.

### P6-04-MT-010 — Verify populated summary metrics

**Area:** Health and summary states<br>
**Priority:** High<br>
**Regression Smoke:** No<br>
**Preconditions:** Backend is available with approved synthetic data.<br>
**Test data:** Seeded records.<br>
**Steps:**
1. Refresh the dashboard.
2. Read `Critical vulnerabilities`, `KEV-listed CVEs`, `Active articles`, and `UAE-related items`.
3. Compare displayed counts with the approved dataset or API response.

**Expected result:** Four cards appear with numeric, thousands-formatted values
that match the backend summary response; each card identifies the backend summary
as its source.<br>
**Actual result:** ______________________________<br>
**Status:** Not Run<br>
**Evidence:** ______________________________<br>
**Defect ID:** ______________________________<br>
**Notes:** Do not compare against production counts.

### P6-04-MT-011 — Verify summary loading, zero-count, and controlled failure

**Area:** Health and summary states<br>
**Priority:** Medium<br>
**Regression Smoke:** No<br>
**Preconditions:** Approved delayed-response, empty-database, and unavailable-backend local scenarios are available.<br>
**Test data:** Disposable empty database.<br>
**Steps:**
1. Observe the four `Loading backend summary` placeholders during a delayed request.
2. Use the empty database and confirm all valid summary values display as zero.
3. Make the local summary service unavailable and observe `Summary unavailable`.

**Expected result:** Loading, valid zero, and error are distinct states. No raw
exception, credential, internal path, or technical response body is rendered.<br>
**Actual result:** ______________________________<br>
**Status:** Not Run<br>
**Evidence:** ______________________________<br>
**Defect ID:** ______________________________<br>
**Notes:** Mark Blocked if the approved scenarios are unavailable.

### P6-04-MT-012 — Render successful trend distributions and timeline

**Area:** Trends<br>
**Priority:** High<br>
**Regression Smoke:** No<br>
**Preconditions:** Approved dated synthetic vulnerability and article records exist.<br>
**Test data:** Seeded trend records.<br>
**Steps:**
1. Open `Recent trends`.
2. Review `Latest vulnerability severity distribution` and `Latest article category distribution`.
3. Review `Recent stored activity timeline` and its CVE/article counts.

**Expected result:** Severity and category rows show readable labels and counts;
the timeline groups dated records; summary sample counts are visible. Exact bar
pixel sizes are not assessed.<br>
**Actual result:** ______________________________<br>
**Status:** Not Run<br>
**Evidence:** ______________________________<br>
**Defect ID:** ______________________________<br>
**Notes:** The panel is a bounded recent view, not historical certification.

### P6-04-MT-013 — Verify trend loading, empty, undated, and failure states

**Area:** Trends<br>
**Priority:** Medium<br>
**Regression Smoke:** No<br>
**Preconditions:** Approved delayed, empty, undated, and unavailable local scenarios are available.<br>
**Test data:** Disposable fixture variants.<br>
**Steps:**
1. Confirm delayed loading shows `Loading stored trend data`.
2. Confirm an empty dataset shows `No trend data available`.
3. Confirm records without usable dates show `No dated activity available`.
4. Confirm service failure shows `Trends unavailable`.

**Expected result:** Each scenario has a distinct readable status message and no
raw error details. Distribution labels remain legible where data exists.<br>
**Actual result:** ______________________________<br>
**Status:** Not Run<br>
**Evidence:** ______________________________<br>
**Defect ID:** ______________________________<br>
**Notes:** Mark unavailable fixture variants Blocked rather than altering shared data.

### P6-04-MT-014 — Check the dashboard for visibly broken sections

**Area:** Dashboard composition<br>
**Priority:** Medium<br>
**Regression Smoke:** No<br>
**Preconditions:** Dashboard has completed loading at desktop width.<br>
**Test data:** Approved dataset.<br>
**Steps:**
1. Scroll from the hero to the last dashboard panel.
2. Check headings, cards, charts, table, article cards, badges, and notes.
3. Open the browser console and note application rendering errors.

**Expected result:** No critical content overlaps, disappears, or renders outside
its panel; no uncaught rendering exception appears in the console.<br>
**Actual result:** ______________________________<br>
**Status:** Not Run<br>
**Evidence:** ______________________________<br>
**Defect ID:** ______________________________<br>
**Notes:** Record browser and viewport with evidence.

### P6-04-MT-015 — Render the default latest-articles list

**Area:** Article workflow<br>
**Priority:** High<br>
**Regression Smoke:** Yes<br>
**Preconditions:** At least one approved synthetic article exists.<br>
**Test data:** Seeded article.<br>
**Steps:**
1. Open `Latest articles` without active filters.
2. Inspect one card's title, summary, category, source, published/updated dates, scope, and UAE relevance.
3. Inspect `View details` and `Open source`.

**Expected result:** Stored fields appear as readable text; the detail link targets
`/articles/{publicId}`; pagination reports the visible range and total.<br>
**Actual result:** ______________________________<br>
**Status:** Not Run<br>
**Evidence:** ______________________________<br>
**Defect ID:** ______________________________<br>
**Notes:** Null summary or date values may use the documented fallback text.

### P6-04-MT-016 — Apply trimmed article search with and without results

**Area:** Article filters<br>
**Priority:** High<br>
**Regression Smoke:** Yes<br>
**Preconditions:** Article list has a known search term.<br>
**Test data:** `<SEARCH_TERM_WITH_RESULTS>` and `<SEARCH_TERM_WITH_NO_RESULTS>`.<br>
**Steps:**
1. Enter spaces around `<SEARCH_TERM_WITH_RESULTS>` in `Search articles`.
2. Confirm typing alone does not replace the current results; select `Apply`.
3. Verify matching results, then apply `<SEARCH_TERM_WITH_NO_RESULTS>`.

**Expected result:** Apply submits the trimmed term. Matching cards are relevant;
the absent term shows `No articles match the selected filters`, not the unfiltered
empty message.<br>
**Actual result:** ______________________________<br>
**Status:** Not Run<br>
**Evidence:** ______________________________<br>
**Defect ID:** ______________________________<br>
**Notes:** Search is backend-driven.

### P6-04-MT-017 — Apply article category, scope, relevance, and combined filters

**Area:** Article filters<br>
**Priority:** High<br>
**Regression Smoke:** No<br>
**Preconditions:** Dataset contains records suitable for selected combinations.<br>
**Test data:** `Category`, `Geographic scope`, and `UAE relevance` selections.<br>
**Steps:**
1. Select one non-default `Category` and verify the refreshed results.
2. Select a non-default `Geographic scope`, then a non-default `UAE relevance`.
3. Add a search term and select `Apply`.

**Expected result:** Results satisfy the active combination, each selection resets
the result range to the first page, and no unrelated record is presented as a
match.<br>
**Actual result:** ______________________________<br>
**Status:** Not Run<br>
**Evidence:** ______________________________<br>
**Defect ID:** ______________________________<br>
**Notes:** Use filter values actually present in the disposable dataset.

### P6-04-MT-018 — Clear article filters and distinguish empty states

**Area:** Article filters<br>
**Priority:** Medium<br>
**Regression Smoke:** No<br>
**Preconditions:** Article filters are active; an empty disposable dataset is available separately.<br>
**Test data:** Active combined filters and empty dataset.<br>
**Steps:**
1. With filtered-empty results visible, select `Clear`.
2. Confirm all controls return to their default values and the unfiltered first page loads.
3. Against the empty dataset, confirm `No articles found` and `No stored articles` appear.

**Expected result:** Clear removes search/category/scope/relevance filters and
resets pagination. Filtered-empty and unfiltered-empty wording is distinct.<br>
**Actual result:** ______________________________<br>
**Status:** Not Run<br>
**Evidence:** ______________________________<br>
**Defect ID:** ______________________________<br>
**Notes:** Do not clear real data to create the empty scenario.

### P6-04-MT-019 — Navigate article pagination and loading controls

**Area:** Article pagination<br>
**Priority:** High<br>
**Regression Smoke:** No<br>
**Preconditions:** More than six approved articles are available.<br>
**Test data:** Multi-page article dataset.<br>
**Steps:**
1. Confirm `Previous` is disabled on the first page and `Next` is enabled.
2. Select `Next`; observe `Loading stored articles`, the disabled controls, and the next range.
3. Select `Previous` and confirm the first range returns.
4. From a later page, change a filter and confirm the range resets to the first page.

**Expected result:** Pages move in six-record offsets, range text is accurate, and
loading prevents repeated unsafe navigation.<br>
**Actual result:** ______________________________<br>
**Status:** Not Run<br>
**Evidence:** ______________________________<br>
**Defect ID:** ______________________________<br>
**Notes:** Use network throttling only on local requests if loading is too brief.

### P6-04-MT-020 — Navigate from an article card to its detail page

**Area:** Article detail<br>
**Priority:** High<br>
**Regression Smoke:** Yes<br>
**Preconditions:** Default article list contains a record.<br>
**Test data:** `<ARTICLE_PUBLIC_ID>`.<br>
**Steps:**
1. Select the article title or `View details`.
2. Observe the resulting URL and level-one heading.

**Expected result:** Browser navigates to `/articles/{publicId}` for the selected
record and displays that record rather than another article or a full-page
external redirect.<br>
**Actual result:** ______________________________<br>
**Status:** Not Run<br>
**Evidence:** ______________________________<br>
**Defect ID:** ______________________________<br>
**Notes:** Record the public ID for direct-route cases.

### P6-04-MT-021 — Verify article detail content and Back to dashboard

**Area:** Article detail<br>
**Priority:** High<br>
**Regression Smoke:** No<br>
**Preconditions:** A valid article detail page is open.<br>
**Test data:** `<ARTICLE_PUBLIC_ID>`.<br>
**Steps:**
1. Review title, summary, category, source, published, modified, last-seen, geographic-scope, and UAE-relevance fields.
2. Compare them with the originating card or approved API response.
3. Select `Back to dashboard`.

**Expected result:** Available metadata is consistent and safely rendered; Back
to dashboard returns to `/` without an unexpected external navigation.<br>
**Actual result:** ______________________________<br>
**Status:** Not Run<br>
**Evidence:** ______________________________<br>
**Defect ID:** ______________________________<br>
**Notes:** Date formatting may be localized; compare the represented date, not exact punctuation.

### P6-04-MT-022 — Verify direct, refreshed, missing, and malformed article routes

**Area:** Article detail<br>
**Priority:** Medium<br>
**Regression Smoke:** No<br>
**Preconditions:** Application is running.<br>
**Test data:** `<ARTICLE_PUBLIC_ID>`, `<MISSING_PUBLIC_ID>`, and a harmless malformed value such as `not-a-uuid`.<br>
**Steps:**
1. Open `/articles/<ARTICLE_PUBLIC_ID>` directly and refresh it.
2. Open `/articles/<MISSING_PUBLIC_ID>`.
3. Open `/articles/not-a-uuid`.

**Expected result:** The valid route survives direct access and refresh. Missing or
malformed values show `Article not found` or the safe framework not-found result;
no raw validation or database detail appears.<br>
**Actual result:** ______________________________<br>
**Status:** Not Run<br>
**Evidence:** ______________________________<br>
**Defect ID:** ______________________________<br>
**Notes:** Do not enumerate identifiers outside the disposable local dataset.

### P6-04-MT-023 — Verify article loading and controlled service failure

**Area:** Article detail<br>
**Priority:** Medium<br>
**Regression Smoke:** No<br>
**Preconditions:** Valid detail link; local request can be delayed and backend can be stopped safely.<br>
**Test data:** `<ARTICLE_PUBLIC_ID>`.<br>
**Steps:**
1. Delay the local detail request and confirm `Loading article details`.
2. Restore normal networking and confirm the detail loads.
3. Stop the backend, refresh, and confirm `Article unavailable`.

**Expected result:** Loading and failure states are distinct and announced. Failure
keeps `Back to dashboard` and reveals no raw exception or response payload.<br>
**Actual result:** ______________________________<br>
**Status:** Not Run<br>
**Evidence:** ______________________________<br>
**Defect ID:** ______________________________<br>
**Notes:** Restart the backend and remove throttling afterward.

### P6-04-MT-024 — Render the default vulnerability table

**Area:** Vulnerability workflow<br>
**Priority:** High<br>
**Regression Smoke:** Yes<br>
**Preconditions:** At least one approved synthetic vulnerability exists.<br>
**Test data:** Seeded vulnerability.<br>
**Steps:**
1. Open `Vulnerabilities` without active filters.
2. Confirm table headers `CVE`, `Severity`, `CVSS`, `EPSS`, `KEV`, `Published`, and `Source`.
3. Inspect one row's CVE, title, scores/statuses, dates, source, and detail links.

**Expected result:** Headers identify every displayed column; values are readable;
the CVE and `Open vulnerability detail` links target
`/vulnerabilities/{publicId}`.<br>
**Actual result:** ______________________________<br>
**Status:** Not Run<br>
**Evidence:** ______________________________<br>
**Defect ID:** ______________________________<br>
**Notes:** Scope and UAE relevance are filterable here and displayed on detail.

### P6-04-MT-025 — Apply trimmed vulnerability search and severity filter

**Area:** Vulnerability filters<br>
**Priority:** High<br>
**Regression Smoke:** Yes<br>
**Preconditions:** A known CVE/title/summary term exists.<br>
**Test data:** `<SEARCH_TERM_WITH_RESULTS>` and a non-default `Severity`.<br>
**Steps:**
1. Enter spaces around the term in `Search CVEs`; confirm typing alone does not apply it.
2. Select a `Severity` value and then `Apply`.
3. Inspect returned rows and the displayed range.

**Expected result:** The submitted search is trimmed, every result satisfies the
search and severity selection, and the first-page offset is used.<br>
**Actual result:** ______________________________<br>
**Status:** Not Run<br>
**Evidence:** ______________________________<br>
**Defect ID:** ______________________________<br>
**Notes:** Use a severity represented in the synthetic data.

### P6-04-MT-026 — Combine vulnerability scope, relevance, and row-limit filters

**Area:** Vulnerability filters<br>
**Priority:** High<br>
**Regression Smoke:** No<br>
**Preconditions:** Suitable approved records exist.<br>
**Test data:** Non-default `Geographic scope`, `UAE relevance`, and `Rows` values.<br>
**Steps:**
1. Select a scope and UAE-relevance value.
2. Change `Rows` from 10 to 25 or 50.
3. Add severity and search selections, then select `Apply`.

**Expected result:** Results satisfy the combined filters; the selected row limit
controls the range; every change resets offset to zero.<br>
**Actual result:** ______________________________<br>
**Status:** Not Run<br>
**Evidence:** ______________________________<br>
**Defect ID:** ______________________________<br>
**Notes:** An empty combined result is valid if the filtered-empty message appears.

### P6-04-MT-027 — Clear vulnerability filters and reset pagination

**Area:** Vulnerability filters<br>
**Priority:** Medium<br>
**Regression Smoke:** No<br>
**Preconditions:** Search, severity, scope, relevance, and a later page are active.<br>
**Test data:** Multi-page filtered dataset.<br>
**Steps:**
1. Select `Clear`.
2. Inspect search, severity, scope, relevance, row limit, and range.
3. Change `Rows` and verify the range begins at the first result.

**Expected result:** Clear removes search/severity/scope/relevance and returns to
offset zero. The separately selected row limit remains stable; changing it also
resets pagination.<br>
**Actual result:** ______________________________<br>
**Status:** Not Run<br>
**Evidence:** ______________________________<br>
**Defect ID:** ______________________________<br>
**Notes:** This reflects current behavior; record any mismatch precisely.

### P6-04-MT-028 — Verify vulnerability pagination, empty, loading, and error states

**Area:** Vulnerability list states<br>
**Priority:** High<br>
**Regression Smoke:** No<br>
**Preconditions:** Multi-page, empty, delayed, and unavailable local scenarios are approved.<br>
**Test data:** Disposable fixture variants.<br>
**Steps:**
1. Use `Next` and `Previous`; verify ranges and disabled controls while `Loading stored vulnerabilities` appears.
2. Confirm an empty database shows `No vulnerabilities found` and `No stored CVEs`.
3. Apply an absent filter and confirm `No vulnerabilities match the selected filters`.
4. Stop the service and confirm `Vulnerabilities unavailable`.

**Expected result:** Navigation is accurate; unfiltered empty, filtered empty,
loading, and failure are distinct; no raw error is rendered.<br>
**Actual result:** ______________________________<br>
**Status:** Not Run<br>
**Evidence:** ______________________________<br>
**Defect ID:** ______________________________<br>
**Notes:** Do not delete data to create an empty database.

### P6-04-MT-029 — Navigate from a vulnerability row to detail

**Area:** Vulnerability detail<br>
**Priority:** High<br>
**Regression Smoke:** Yes<br>
**Preconditions:** Vulnerability table contains a row.<br>
**Test data:** `<VULNERABILITY_PUBLIC_ID>`.<br>
**Steps:**
1. Select the CVE link or `Open vulnerability detail`.
2. Observe the URL and level-one CVE heading.

**Expected result:** Browser navigates to `/vulnerabilities/{publicId}` for the
selected row and shows the matching CVE detail without an external redirect.<br>
**Actual result:** ______________________________<br>
**Status:** Not Run<br>
**Evidence:** ______________________________<br>
**Defect ID:** ______________________________<br>
**Notes:** Record the public ID for direct-route cases.

### P6-04-MT-030 — Verify vulnerability detail metadata

**Area:** Vulnerability detail<br>
**Priority:** High<br>
**Regression Smoke:** No<br>
**Preconditions:** Valid vulnerability detail is open.<br>
**Test data:** `<VULNERABILITY_PUBLIC_ID>`.<br>
**Steps:**
1. Review CVE, title, summary, severity, CVSS, EPSS score/percentile/date, and KEV status/dates.
2. Review ransomware use, affected systems, source, published/modified/last-seen, geographic scope, and UAE relevance.
3. Compare visible values with the originating row or approved API response.

**Expected result:** Available fields are consistent, readable, and safely
formatted. Unknown/null values use controlled fallback text rather than broken
markup or invented facts.<br>
**Actual result:** ______________________________<br>
**Status:** Not Run<br>
**Evidence:** ______________________________<br>
**Defect ID:** ______________________________<br>
**Notes:** Confidence labels are not threat severity or exploit probability.

### P6-04-MT-031 — Verify vulnerability direct, refreshed, missing, and malformed routes

**Area:** Vulnerability detail<br>
**Priority:** Medium<br>
**Regression Smoke:** No<br>
**Preconditions:** Application is running.<br>
**Test data:** `<VULNERABILITY_PUBLIC_ID>`, `<MISSING_PUBLIC_ID>`, and `not-a-uuid`.<br>
**Steps:**
1. Open `/vulnerabilities/<VULNERABILITY_PUBLIC_ID>` directly and refresh it.
2. Open `/vulnerabilities/<MISSING_PUBLIC_ID>`.
3. Open `/vulnerabilities/not-a-uuid`.
4. Use `Back to dashboard` from a rendered state.

**Expected result:** Valid detail survives direct access and refresh. Missing or
malformed values show `Vulnerability not found` or a safe framework result. Back
to dashboard returns to `/`.<br>
**Actual result:** ______________________________<br>
**Status:** Not Run<br>
**Evidence:** ______________________________<br>
**Defect ID:** ______________________________<br>
**Notes:** Do not enumerate identifiers outside the local dataset.

### P6-04-MT-032 — Verify vulnerability loading and controlled failure

**Area:** Vulnerability detail<br>
**Priority:** Medium<br>
**Regression Smoke:** No<br>
**Preconditions:** Valid detail link; request can be delayed and backend safely stopped.<br>
**Test data:** `<VULNERABILITY_PUBLIC_ID>`.<br>
**Steps:**
1. Delay the local request and confirm `Loading vulnerability details`.
2. Restore networking and confirm the detail loads.
3. Stop the backend, refresh, and confirm `Vulnerability unavailable`.

**Expected result:** Loading and error states are distinct and announced. The
error retains safe navigation and reveals no raw exception, payload, SQL, or
private path.<br>
**Actual result:** ______________________________<br>
**Status:** Not Run<br>
**Evidence:** ______________________________<br>
**Defect ID:** ______________________________<br>
**Notes:** Restart the backend and remove throttling afterward.

### P6-04-MT-033 — Enforce safe and unsafe external-link rules

**Area:** Safe rendering and external links<br>
**Priority:** High<br>
**Regression Smoke:** Yes<br>
**Preconditions:** Approved disposable fixtures provide safe and unsafe source URL variants.<br>
**Test data:** `<SAFE_HTTPS_URL>`, `<SAFE_HTTP_URL>`, `javascript:alert(1)`, `data:text/plain,blocked`, `//example.test/path`, a credential-bearing example URL, and malformed text.<br>
**Steps:**
1. Inspect `Open source` for ordinary absolute HTTPS and HTTP fixture URLs.
2. Inspect the same label for each unsafe or malformed fixture.
3. Do not paste any value into the browser address bar or shared system.

**Expected result:** Absolute HTTP/HTTPS values render as anchors. Unsafe,
protocol-relative, credential-bearing, and malformed values render as
non-clickable text with an unavailable/disabled semantic; no unsafe navigation
occurs.<br>
**Actual result:** ______________________________<br>
**Status:** Not Run<br>
**Evidence:** ______________________________<br>
**Defect ID:** ______________________________<br>
**Notes:** Mark Blocked if approved fixture variants are unavailable.

### P6-04-MT-034 — Render markup-like intelligence fields as text

**Area:** Safe rendering and external links<br>
**Priority:** High<br>
**Regression Smoke:** No<br>
**Preconditions:** Approved disposable fixture contains `<MARKUP_LIKE_TEXT>` in title, summary, affected-system, or link-label fields.<br>
**Test data:** `<MARKUP_LIKE_TEXT>`.<br>
**Steps:**
1. Open the relevant list and detail views.
2. Confirm the angle-bracket text is visible literally.
3. Inspect the Elements panel and console for injected elements or script execution.

**Expected result:** The string remains an ordinary text node. No image, script,
SVG, frame, event handler, dialog, redirect, or console side effect is created
from it.<br>
**Actual result:** ______________________________<br>
**Status:** Not Run<br>
**Evidence:** ______________________________<br>
**Defect ID:** ______________________________<br>
**Notes:** Never create this fixture in production or a shared database.

### P6-04-MT-035 — Verify protected behavior of a clickable external source

**Area:** Safe rendering and external links<br>
**Priority:** High<br>
**Regression Smoke:** No<br>
**Preconditions:** A safe synthetic source link is visible.<br>
**Test data:** `<SAFE_HTTPS_URL>`.<br>
**Steps:**
1. Inspect the link element in developer tools without sending credentials.
2. Confirm `target="_blank"` and `rel="noopener noreferrer"`.
3. Activate it only when the example destination is safe and locally approved.

**Expected result:** The link has the current new-tab and opener/referrer
protections. The dashboard tab remains on its existing route and no tracking or
credential data is added to the URL.<br>
**Actual result:** ______________________________<br>
**Status:** Not Run<br>
**Evidence:** ______________________________<br>
**Defect ID:** ______________________________<br>
**Notes:** Do not follow unknown or non-example destinations during this test.

### P6-04-MT-036 — Verify browser Back, direct detail, refresh, and unknown route behavior

**Area:** Navigation and browser behavior<br>
**Priority:** Medium<br>
**Regression Smoke:** No<br>
**Preconditions:** Valid article and vulnerability detail routes are available.<br>
**Test data:** Both public-ID placeholders and `/route-that-does-not-exist`.<br>
**Steps:**
1. Navigate dashboard → article detail → browser Back.
2. Navigate dashboard → vulnerability detail → browser Back.
3. Open each detail URL directly and refresh it.
4. Open the unknown route.

**Expected result:** Back returns to the prior dashboard history entry; direct and
refreshed valid routes load; the unknown route shows the framework not-found
page; no route causes an unexpected full-page external redirect.<br>
**Actual result:** ______________________________<br>
**Status:** Not Run<br>
**Evidence:** ______________________________<br>
**Defect ID:** ______________________________<br>
**Notes:** Record unexpected history duplication or redirect loops.

### P6-04-MT-037 — Verify mobile navigation focus and close behavior

**Area:** Navigation and browser behavior<br>
**Priority:** Medium<br>
**Regression Smoke:** No<br>
**Preconditions:** Browser viewport is narrow enough to show `Open navigation`.<br>
**Test data:** Approximately 375 px width.<br>
**Steps:**
1. Activate `Open navigation` with the keyboard.
2. Confirm focus moves to `Close navigation`.
3. Press Escape; reopen and activate `Close navigation overlay`.

**Expected result:** The modal navigation opens without page scroll behind it;
Escape/close dismisses it; focus returns to `Open navigation`; remaining page
controls stay usable.<br>
**Actual result:** ______________________________<br>
**Status:** Not Run<br>
**Evidence:** ______________________________<br>
**Defect ID:** ______________________________<br>
**Notes:** This is a basic focus check, not full assistive-technology certification.

### P6-04-MT-038 — Check representative responsive widths

**Area:** Responsive layout<br>
**Priority:** High<br>
**Regression Smoke:** Yes<br>
**Preconditions:** Dashboard has representative loaded data.<br>
**Test data:** Viewports approximately 1440, 1024, 768, and 375 CSS pixels wide.<br>
**Steps:**
1. At each width, review the hero, summary cards, trends, vulnerability table, article filters/cards, and navigation.
2. Scroll vertically and horizontally where controls intentionally provide it.
3. Open one article and one vulnerability detail page at the narrow width.

**Expected result:** No critical content overlaps or becomes unreadable; navigation
remains accessible; buttons and filters remain reachable; detail metadata remains
understandable. This does not certify specific devices.<br>
**Actual result:** ______________________________<br>
**Status:** Not Run<br>
**Evidence:** ______________________________<br>
**Defect ID:** ______________________________<br>
**Notes:** Record browser zoom and device-emulation mode.

### P6-04-MT-039 — Verify table and filters at laptop, tablet, and narrow widths

**Area:** Responsive layout<br>
**Priority:** Medium<br>
**Regression Smoke:** No<br>
**Preconditions:** Article and vulnerability panels are loaded.<br>
**Test data:** 1024, 768, and 375 CSS pixels.<br>
**Steps:**
1. Use every article filter and action at each representative width.
2. Use every vulnerability filter, row-limit selector, and pagination button.
3. Inspect the vulnerability table's overflow behavior.

**Expected result:** Labels remain associated with controls; actions are not hidden
or clipped; the table remains understandable or horizontally scrollable without
covering adjacent content.<br>
**Actual result:** ______________________________<br>
**Status:** Not Run<br>
**Evidence:** ______________________________<br>
**Defect ID:** ______________________________<br>
**Notes:** Minor reflow differences are acceptable if content stays usable.

### P6-04-MT-040 — Navigate and activate controls by keyboard

**Area:** Basic accessibility<br>
**Priority:** High<br>
**Regression Smoke:** No<br>
**Preconditions:** Dashboard is loaded; mouse is not used during the steps.<br>
**Test data:** None.<br>
**Steps:**
1. Tab through navigation, article and vulnerability filters, Apply/Clear, pagination, and links.
2. Confirm visible focus at each interactive control.
3. Activate buttons/links with Enter or Space as appropriate.

**Expected result:** Focus order follows the visible workflow; focus never becomes
lost or trapped; every enabled control has a visible indicator and works with its
native keyboard action.<br>
**Actual result:** ______________________________<br>
**Status:** Not Run<br>
**Evidence:** ______________________________<br>
**Defect ID:** ______________________________<br>
**Notes:** Disabled preview navigation is not expected to activate.

### P6-04-MT-041 — Verify labels, names, table semantics, and status announcements

**Area:** Basic accessibility<br>
**Priority:** Medium<br>
**Regression Smoke:** No<br>
**Preconditions:** Browser accessibility tree or a screen reader is available.<br>
**Test data:** Loaded, loading, empty, and error states.<br>
**Steps:**
1. Confirm filters expose `Search articles`, `Category`, `Geographic scope`, `UAE relevance`, `Search CVEs`, `Severity`, and `Rows`.
2. Confirm buttons and links expose meaningful names such as `Apply`, `Clear`, `Previous`, `Next`, `View details`, and `Back to dashboard`.
3. Confirm vulnerability columns are headers and loading/status states are announced where implemented.
4. Confirm badges include text so color is not the only severity/status indicator.

**Expected result:** Controls, links, headings, table columns, and supported status
regions have understandable accessible names/roles. Text accompanies color-coded
states.<br>
**Actual result:** ______________________________<br>
**Status:** Not Run<br>
**Evidence:** ______________________________<br>
**Defect ID:** ______________________________<br>
**Notes:** Do not claim WCAG conformance from this case.

### P6-04-MT-042 — Verify usability at 200% browser zoom

**Area:** Basic accessibility<br>
**Priority:** Medium<br>
**Regression Smoke:** No<br>
**Preconditions:** Desktop browser at approximately 1280 CSS pixels or wider before zoom.<br>
**Test data:** 200% browser zoom.<br>
**Steps:**
1. Set browser zoom to 200%.
2. Navigate the dashboard, use filters/pagination, and open both detail types.
3. Check focus visibility, text clipping, and reachable actions.

**Expected result:** Primary content and actions remain readable and reachable;
horizontal scrolling, if needed for the data table, does not hide unrelated page
controls.<br>
**Actual result:** ______________________________<br>
**Status:** Not Run<br>
**Evidence:** ______________________________<br>
**Defect ID:** ______________________________<br>
**Notes:** Reset zoom after execution.

### P6-04-MT-043 — Verify backend-unavailable privacy and recovery

**Area:** Error and privacy regression<br>
**Priority:** High<br>
**Regression Smoke:** Yes<br>
**Preconditions:** Frontend can remain running while the local backend is stopped and restarted.<br>
**Test data:** Dashboard and valid detail route.<br>
**Steps:**
1. Stop the local backend and refresh the dashboard and a detail route.
2. Inspect UI, console, and the application's own failed local requests.
3. Restart the backend and refresh again.

**Expected result:** UI shows controlled unavailable states without stack traces,
SQL, connection details, raw payloads, private paths, or secret/header values.
After restart, normal data loads without clearing browser or database state.<br>
**Actual result:** ______________________________<br>
**Status:** Not Run<br>
**Evidence:** ______________________________<br>
**Defect ID:** ______________________________<br>
**Notes:** Redact network screenshots.

### P6-04-MT-044 — Inspect safe local 404 and validation 422 responses

**Area:** Error and privacy regression<br>
**Priority:** High<br>
**Regression Smoke:** No<br>
**Preconditions:** Local backend is running; developer tools inspect only localhost.<br>
**Test data:** Missing valid UUID and a harmless invalid local query such as `limit=0`.<br>
**Steps:**
1. Request a local article or vulnerability detail using `<MISSING_PUBLIC_ID>` and inspect the 404 response.
2. Request a local list endpoint with an invalid bounded parameter and inspect the 422 response.
3. Check response body and headers without copying sensitive request data.

**Expected result:** Status codes are 404 and 422 respectively; bodies are
allow-listed and user-safe; no stack trace, SQL, database detail, raw source
payload, or local path is exposed.<br>
**Actual result:** ______________________________<br>
**Status:** Not Run<br>
**Evidence:** ______________________________<br>
**Defect ID:** ______________________________<br>
**Notes:** Use only documented local API routes; do not fuzz or scan.

### P6-04-MT-045 — Inspect handled and unexpected local 500 responses

**Area:** Error and privacy regression<br>
**Priority:** High<br>
**Regression Smoke:** No<br>
**Preconditions:** A developer provides an approved local-only fault fixture for one handled and one unexpected server error.<br>
**Test data:** Disposable fault fixture; no production records.<br>
**Steps:**
1. Trigger the approved handled-error fixture once and inspect its response/UI.
2. Trigger the approved unexpected-error fixture once and inspect its response/UI.
3. Review only sanitized local logs and capture redacted evidence.

**Expected result:** Both responses use HTTP 500 with controlled generic content,
retain applicable request/security headers, and expose no raw exception, SQL,
connection string, secret, payload, or private path.<br>
**Actual result:** ______________________________<br>
**Status:** Not Run<br>
**Evidence:** ______________________________<br>
**Defect ID:** ______________________________<br>
**Notes:** Mark Blocked if no approved fault fixture exists; do not change production code to execute this case.

### P6-04-MT-046 — Verify request ID, CORS, and security headers

**Area:** Error and privacy regression<br>
**Priority:** High<br>
**Regression Smoke:** No<br>
**Preconditions:** Local backend is running, PowerShell is available, and the tester has obtained `<ALLOWED_FRONTEND_ORIGIN>` from approved, non-secret development configuration.<br>
**Test data:** Local `/api/health`, one successful API request, one 404, one 422, `<ALLOWED_FRONTEND_ORIGIN>`, and `<UNAPPROVED_ORIGIN>`.<br>
**Steps:**
1. Send or inspect the normal successful request, 404, and 422 against the local backend.
2. For each response, confirm a non-empty opaque `X-Request-ID` and the applicable `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`, `Permissions-Policy`, and API `Content-Security-Policy` headers are present.
3. Send an `OPTIONS` request to `http://127.0.0.1:8000/api/health` with `Origin: <ALLOWED_FRONTEND_ORIGIN>` and `Access-Control-Request-Method: GET`. In PowerShell, use `Invoke-WebRequest -Method Options -Uri "http://127.0.0.1:8000/api/health" -Headers @{ Origin = "<ALLOWED_FRONTEND_ORIGIN>"; "Access-Control-Request-Method" = "GET" }`.
4. Confirm `Access-Control-Allow-Origin` exactly equals `<ALLOWED_FRONTEND_ORIGIN>`.
5. Repeat the same local `OPTIONS` request with `Origin: <UNAPPROVED_ORIGIN>`.
6. Confirm the response does not contain an `Access-Control-Allow-Origin` value that authorizes `<UNAPPROVED_ORIGIN>`.
7. Inspect both preflight responses and confirm credentials are never enabled together with `Access-Control-Allow-Origin: *`.

**Expected result:** The success, 404, and 422 responses each contain a non-empty
opaque request ID and the applicable security headers. The approved-origin
preflight returns `Access-Control-Allow-Origin` with exactly
`<ALLOWED_FRONTEND_ORIGIN>`; the unapproved-origin preflight does not authorize
`<UNAPPROVED_ORIGIN>`; and no response combines credential-enabled CORS with a
wildcard allowed origin. Response bodies and visible logs contain no sensitive
values.<br>
**Actual result:** ______________________________<br>
**Status:** Not Run<br>
**Evidence:** ______________________________<br>
**Defect ID:** ______________________________<br>
**Notes:** Local development may intentionally omit transport-security headers that require HTTPS.

## 11. Regression-smoke subset

Execute these 12 cases for a bounded release smoke test. A smoke run does not
replace the remaining manual suite.

| Test ID | Smoke objective |
| --- | --- |
| P6-04-MT-003 | Start the local application |
| P6-04-MT-007 | Render the dashboard composition |
| P6-04-MT-009 | Verify health states |
| P6-04-MT-015 | Render the article list |
| P6-04-MT-016 | Apply article search |
| P6-04-MT-020 | Navigate to article detail |
| P6-04-MT-024 | Render the vulnerability table |
| P6-04-MT-025 | Apply vulnerability search/severity |
| P6-04-MT-029 | Navigate to vulnerability detail |
| P6-04-MT-033 | Enforce external-link rules |
| P6-04-MT-038 | Check responsive widths |
| P6-04-MT-043 | Verify backend-unavailable privacy |

## 12. Traceability matrix

Manual cases complement automated evidence; a linked automated suite does not
mark any manual case executed.

| Project item | Manual coverage | Complementary automated evidence |
| --- | --- | --- |
| P3-06 vulnerability detail behavior | P6-04-MT-029–P6-04-MT-032 | P6-01 API detail tests; P6-03 vulnerability detail tests |
| P4-03 filters and pagination | P6-04-MT-016–P6-04-MT-019; P6-04-MT-025–P6-04-MT-028 | P6-01 API filter tests; P6-03 component tests |
| P5-01 input validation | P6-04-MT-022; P6-04-MT-031; P6-04-MT-044 | P6-01 API validation tests |
| P5-02 CORS and security headers | P6-04-MT-046 | P6-01 middleware/API tests |
| P5-03 safe rendering | P6-04-MT-033–P6-04-MT-035 | Standalone safe-rendering validation; P6-03 link/content tests |
| P5-04 safe logging and error handling | P6-04-MT-005; P6-04-MT-023; P6-04-MT-032; P6-04-MT-043–P6-04-MT-046 | P6-01 error tests; P6-02 fetcher error tests; P6-03 UI error tests |
| P6-01 backend automated tests | P6-04-MT-002; P6-04-MT-044–P6-04-MT-046 | Backend pytest suite |
| P6-02 fetcher automated tests | P6-04-MT-002; P6-04-MT-003 | Backend fetcher/client/collector pytest suites; manual UI cases do not re-execute source-specific malformed-response or idempotency behavior |
| P6-03 frontend automated tests | P6-04-MT-007–P6-04-MT-042 | 66 Vitest component/page tests |

## 13. Manual execution summary template

| Metric | Value |
| --- | --- |
| Total cases | |
| Passed | |
| Failed | |
| Blocked | |
| Not run | |
| Critical defects | |
| High defects | |
| Test date | |
| Tester | |
| Build/commit | |

### Sign-off

| Role/decision | Name or value | Date |
| --- | --- | --- |
| Tester | | |
| Developer | | |
| Mentor/reviewer | | |
| Decision | Accepted / Accepted with limitations / Rejected | |

## 14. Known limitations

- The repository has no CI workflow.
- These cases are manual procedures, not browser automation.
- P6-03 uses jsdom rather than a real browser.
- Public source availability may vary, but live-source certification is outside scope.
- Live ingestion remains explicitly manual-only.
- Results depend on the selected disposable local dataset and fixture availability.
- The representative responsive widths do not certify browsers, devices, or operating systems.
- Basic accessibility cases do not constitute WCAG or assistive-technology certification.
