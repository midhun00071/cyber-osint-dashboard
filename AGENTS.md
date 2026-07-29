# AGENTS.md — Alpha Data / Cyber OSINT Dashboard

## 1. Project purpose

- **Project:** Alpha Data / Cyber OSINT Dashboard
- **Purpose:** Build a full-stack defensive cybersecurity OSINT platform.
- **Goal:** Collect, normalise, store, search, correlate, visualise, and report approved public cybersecurity intelligence.
- **Audience:** Cybersecurity internship mentors, senior analysts, and technical reviewers.
- **Release target:** Mentor-accessible staging deployment by **11 August 2026**.
- Keep explanations beginner-friendly, but make code, tests, documentation, commits, reports, and deployment evidence workplace-ready.

## 2. Security and authorisation scope

Work only on authorised, defensive, educational, lab-safe, and approved production tasks.

Do not implement or assist:

- exploit execution;
- unauthorised scanning or probing;
- credential theft;
- phishing;
- malware retrieval or delivery;
- persistence;
- stealth or evasion;
- control bypass;
- attacks against real systems.

Use approved public intelligence sources and respect:

- API licences and terms;
- applicable `robots.txt` requirements;
- rate limits and quotas;
- approved outbound domains and paths;
- data-retention requirements.

Never expose:

- secrets;
- passwords;
- API keys or tokens;
- database URLs;
- cookies or authorisation headers;
- raw vendor payloads;
- stack traces;
- SQL statements;
- environment values;
- private configuration.

Do not place sensitive data in source code, logs, APIs, frontend UI, reports, tests, screenshots, commits, or summaries.

## 3. Branch and Git workflow

- `main` is the stable submission branch.
- `dev` is the active development branch.
- Perform new implementation work on `dev` unless explicitly instructed otherwise.

Before meaningful work, inspect:

```powershell
git branch --show-current
git status --short
git fetch origin
git log --oneline -5
git rev-parse HEAD
git rev-parse origin/dev
```

Confirm:

- official task ID;
- implementation goal;
- expected branch;
- clean working tree;
- recent commits;
- local `HEAD`;
- `origin/dev`;
- approved checkpoint.

Stop if the repository state differs from the expected checkpoint.

Do not perform any of these actions without explicit user approval:

- stage;
- commit;
- push;
- reset;
- restore;
- clean;
- delete;
- switch branches;
- rewrite history.

Use exact-file staging commands only.

Never use:

```powershell
git add .
```

Do not include review ZIPs, temporary files, secrets, caches, build output, or local databases in commits.

After a commit, verify:

```powershell
git status --short
git log -1 --oneline
git show --stat --oneline --summary HEAD
git diff --check HEAD^ HEAD
git rev-parse HEAD
git rev-parse origin/dev
```

Confirm the push when required and verify `HEAD` equals `origin/dev`.

## 4. Acceptance freeze

Before implementation, freeze a written acceptance contract containing:

- official task ID;
- repository checkpoint;
- goal;
- files and components to inspect;
- in-scope behaviour;
- explicit out-of-scope behaviour;
- security requirements;
- data-integrity requirements;
- required tests;
- validation commands;
- documentation changes;
- definition of done;
- accepted limitations.

Do not expand the task after implementation starts merely because additional improvements are possible.

Acceptance criteria may change only for a demonstrated:

- Critical or High security defect;
- data-integrity defect;
- regression;
- missed frozen requirement;
- unsafe or unusable assumption.

Optional enhancements, style preferences, future architecture ideas, and speculative risks must become follow-up tasks.

## 5. Technology stack

- **Frontend:** Next.js, React, TypeScript
- **Backend:** Python, FastAPI
- **Database:** PostgreSQL
- **ORM and migrations:** SQLAlchemy, Alembic
- **HTTP client:** httpx
- **RSS parsing:** feedparser
- **Testing:** pytest, Vitest, TypeScript checks, production builds
- **Containers:** Docker, Docker Compose
- **Orchestration:** self-hosted Prefect for development and staging
- **Reverse proxy:** deployment-specific approved proxy
- **Secrets:** environment-based locally; production provider must be configurable

Do not introduce a second scheduler such as APScheduler unless an approved task explicitly requires it.

## 6. Codex and agent task sizing

Use bounded tasks that complete one meaningful unit, for example:

- backend service plus tests;
- API group plus schemas and tests;
- models plus migration and tests;
- frontend page or component group;
- source adapter plus fixtures, tests, and documentation;
- Prefect flow or deployment unit;
- authentication or authorisation boundary;
- deployment or recovery unit.

Avoid tiny prompts unless debugging a demonstrated defect.

Avoid combining unrelated layers such as ingestion, authentication, frontend, reporting, and deployment in one task.

Codex prompts must include:

- task ID;
- repository checkpoint;
- current state;
- goal;
- files to inspect fully;
- implementation requirements;
- security and integrity requirements;
- strict out-of-scope rules;
- tests to add or update;
- validation commands;
- documentation changes;
- final summary requirements;
- prohibition on Git writes.

Ask Codex to:

1. inspect the relevant implementation;
2. implement the bounded task;
3. add or update tests;
4. run focused validation;
5. fix failures introduced by its work;
6. self-review against frozen acceptance criteria;
7. report exact files, tests, warnings, limitations, and Git state.

Do not ask Codex to stage, commit, push, reset, restore, clean, or delete files.

## 7. Review and anti-loop process

Normal workflow:

```text
Acceptance frozen
→ Codex implementation
→ Complete-file review
→ One consolidated hardening pass when required
→ Final confirmation
→ Exact-file staging and commit
```

Normally allow:

- one implementation pass;
- one independent review;
- one consolidated hardening pass;
- one final confirmation review.

A second hardening pass requires explicit user approval unless a newly demonstrated Critical or High defect, corruption risk, or regression exists.

Classify review findings as follows.

### BLOCKER

A demonstrated issue involving:

- Critical or High security exposure;
- authentication or authorisation bypass;
- secret exposure;
- unsafe external access;
- data corruption;
- transaction failure;
- broken required functionality;
- failed frozen acceptance criterion.

### MUST FIX

A demonstrated Medium-risk production or reliability defect that materially affects safe use.

### FOLLOW-UP

A useful improvement outside the frozen task.

### ACCEPTED LIMITATION

A known, bounded, documented limitation that is safe for the current release.

Only Blockers and approved Must Fix findings trigger hardening.

Every blocking finding must include evidence such as:

- exact file and location;
- failing test;
- reproducible behaviour;
- unsafe data flow;
- violated requirement;
- clear security or integrity impact.

Do not block work based only on hypothetical possibilities.

Consolidate all valid findings into one hardening prompt. Once frozen requirements are met and no Blocker remains, stop adding requirements and proceed to completion.

## 8. Independent file review

Do not rely only on Codex summaries or test totals.

Request complete changed files or a focused review ZIP for meaningful changes involving:

- backend services;
- database models;
- migrations;
- APIs;
- authentication;
- authorisation;
- external requests;
- ingestion;
- Prefect;
- frontend;
- production configuration;
- tests;
- security boundaries;
- documentation.

Review ZIPs must exclude:

- `.env`;
- secrets and credentials;
- `.git`;
- `.venv`;
- `node_modules`;
- `.next`;
- `__pycache__`;
- `.pytest_cache`;
- databases;
- build output;
- old ZIPs;
- review folders;
- caches;
- temporary files.

Do not approve staging or commit based only on generated summaries.

## 9. Secure coding standards

Use:

- secure defaults;
- clear structure;
- readable names;
- bounded inputs;
- explicit validation;
- deterministic behaviour;
- safe error handling;
- structured and sanitised logging;
- idempotency;
- transaction safety;
- auditability.

Never hardcode:

- passwords;
- API keys;
- tokens;
- database URLs;
- private keys;
- cookies;
- authorisation headers;
- secret values;
- default administrator credentials.

Use environment variables, `.env.example`, configuration objects, or an approved secret-management provider.

## 10. Backend and API requirements

- Keep FastAPI routes modular.
- Use Pydantic schemas for request and response validation.
- Allow-list all public API fields.
- Enforce type, length, count, page, object, depth, and byte limits.
- Use bounded pagination.
- Use sanitised errors.
- Do not expose raw exceptions, SQL, stack traces, or environment values.
- Enforce authentication and backend authorisation.
- Frontend hiding is not authorisation.
- Prevent BOLA, BFLA, and mass assignment.
- Apply rate limits where appropriate.
- Keep ingestion logic outside route handlers.
- Do not perform uncontrolled ingestion during application startup.
- Manual ingestion endpoints must use the same approved source policies and audit controls as scheduled flows.

## 11. Database requirements

- Use SQLAlchemy ORM or parameterised queries.
- Never construct SQL using untrusted string concatenation.
- Preserve committed migration history.
- Never edit previously committed migrations.
- Use named constraints, indexes, and uniqueness rules.
- Use deterministic idempotency keys.
- Validate lifecycle transitions.
- Use explicit transaction boundaries.
- Advance checkpoints only after successful persistence and commit.
- Protect provenance and source relationships.
- Add rollback, concurrency, duplicate, and recovery tests where relevant.
- Validate Alembic heads and history.
- Do not store unrestricted raw external payloads unless explicitly approved.

## 12. Frontend requirements

- Use the Next.js App Router and TypeScript.
- Safely render all external OSINT content.
- Avoid `dangerouslySetInnerHTML` with untrusted data.
- Validate and safely render external URLs.
- Prevent DOM-based XSS.
- Avoid unnecessary remote scripts, CDNs, and remote fonts.
- Display sanitised errors.
- Support loading, success, empty, stale, disabled, and failure states.
- Do not expose sensitive configuration.
- Remove nonfunctional buttons and visible “Coming Soon” pages before release.

Approved visible release pages:

- Overview
- Threat Feed
- Vulnerabilities
- UAE Intelligence
- IOC Search
- Ingestion Operations
- Sources
- Run History
- Reports
- System Health
- Audit Log
- Methodology

## 13. External-source and ingestion requirements

Use fixed approved source policies.

Reject arbitrary:

- hosts;
- API roots;
- endpoints;
- collections;
- redirect targets;
- headers;
- cookies;
- callback URLs.

External clients must use:

- exact approved HTTPS hosts and paths;
- bounded connect, read, write, pool, and total timeouts;
- bounded response sizes;
- bounded pages and objects;
- redirect rejection or strict approved redirect handling;
- source-specific rate and quota controls;
- sanitised errors and logs;
- incremental checkpoints;
- idempotent persistence;
- failure isolation.

Do not perform:

- scanning;
- active probing;
- target DNS checks;
- malware retrieval;
- binary retrieval;
- file submission;
- exploit execution.

Build offline fixtures and mocked tests before live validation.

Live requests require:

- approved source policy;
- approved credentials when required;
- approval of the exact command;
- bounded staging validation before production activation.

Remove tracking parameters such as `utm_*`, `gclid`, and campaign identifiers from canonical URLs.

## 14. Prefect orchestration

Phase B uses self-hosted Prefect for development and staging.

Required model:

- one parent ingestion cycle every two hours;
- independent source flows or subflows;
- incremental retrieval;
- persistent checkpoints;
- retries and exponential backoff;
- quotas and rate limits;
- source failure isolation;
- safe run evidence;
- manual run, pause, retry, enable, and disable controls.

Each enabled source is evaluated every cycle.

A source may produce an explicit non-request state when:

- disabled;
- unchanged;
- rate-limited;
- in backoff;
- missing credentials;
- missing licence;
- quota unavailable.

Expected states include:

- `success`;
- `no_change`;
- `deferred_quota`;
- `disabled`;
- `credentials_missing`;
- `licence_required`;
- `rate_limited`;
- `partial`;
- `failed`;
- `cancelled`.

One source failure must not fail unrelated source flows.

## 15. AI-generated logic review

Treat generated code as untrusted.

Check for:

- fake-success responses;
- demo-only logic;
- production mock data;
- swallowed exceptions;
- allow-on-error behaviour;
- disabled validation;
- weakened tests;
- removed assertions;
- skipped security checks;
- bypassed authorisation;
- fabricated run states;
- misleading health responses;
- checkpoint advancement before commit;
- success after partial failure;
- broad exception handling hiding defects;
- default credentials;
- development configuration active in staging or production.

Do not accept generated code merely because it compiles or passes a happy-path test.

## 16. Security review coverage

Review relevant risks including:

- SQL injection;
- XSS;
- SSRF;
- CSRF;
- authentication weaknesses;
- authorisation failures;
- BOLA and BFLA;
- mass assignment;
- password and session security;
- secret exposure;
- unsafe logging;
- unsafe file handling;
- path traversal;
- unsafe redirects;
- CSV and PDF injection;
- dependency risk;
- container configuration;
- CORS and CSP;
- input validation;
- resource exhaustion;
- race conditions;
- replay;
- stale updates;
- idempotency;
- backup and restore;
- unsafe third-party API consumption;
- exceptional-condition handling.

Use OWASP Top 10, OWASP API Security Top 10, OWASP ASVS, and NIST SSDF where relevant.

Do not create blockers for features that do not exist.

## 17. Testing and validation

Testing is required for every meaningful task.

Run focused validation first, then appropriate regression.

General:

```powershell
git diff --check
```

Backend:

- focused pytest tests;
- full backend pytest suite when appropriate;
- SQLAlchemy mapper validation;
- negative-path and security tests.

Database:

```powershell
python -m alembic -c alembic.ini heads
python -m alembic -c alembic.ini history
```

Use `current`, upgrade, downgrade, and migration tests when a local database is involved.

Frontend:

```powershell
npm run test
npm run type-check
npm run build
```

Full project:

```powershell
.\run.cmd test
```

Report:

- exact commands;
- test totals;
- warnings;
- skipped tests;
- failures;
- known environment limitations.

Separate pre-existing issues from newly introduced failures.

Never claim an unrun test passed.

## 18. Approval-gated integrations

Commercial or restricted integrations may remain disabled only when:

- offline adapter design is complete;
- fixtures and mocked tests pass;
- Prefect integration is complete;
- secure configuration is ready;
- the remaining blocker is approval, entitlement, licence, payment, quota, or credentials.

Use explicit statuses:

- `Need Approval`
- `Licence Required`
- `Credentials Required`
- `Quota Unavailable`
- `Disabled`

Approval-gated work should be separated into:

1. offline design;
2. fixtures and mocked implementation;
3. approval gate;
4. secure credential configuration;
5. staging live validation;
6. production activation.

## 19. Completion and stopping rule

A task is complete when:

- frozen acceptance criteria are satisfied;
- all Blockers are resolved;
- approved Must Fix findings are resolved;
- required tests pass;
- changed files are independently reviewed;
- documentation is accurate;
- Git evidence is verified;
- limitations are recorded;
- the tree is clean after commit;
- push is verified when required.

Do not continue hardening after these conditions are met.

Record optional improvements as follow-up tasks or post-submission backlog items.

## 20. Documentation and reporting

For each completed task, record:

- official task ID;
- summary;
- files changed;
- tests and totals;
- commit hash;
- push status;
- deployment evidence;
- limitations;
- exact next action.

When updating Excel task sheets:

- preserve the official format;
- use official task IDs;
- make only necessary changes;
- preserve formulas and formatting;
- do not duplicate completion credit;
- mark approval-gated work as `Need Approval`;
- ask when task mapping is unclear.

Daily reports should contain:

- management summary;
- completed tasks;
- implementation details;
- security controls;
- validation evidence;
- Git evidence;
- limitations;
- approvals required;
- next actions.

## 21. Response expectations

- Be clear, direct, and professional.
- Use PowerShell for Windows repository work.
- Explain important Git and security steps.
- Do not repeat instructions unnecessarily.
- Keep progress moving.
- Do not request repeated hardening without demonstrated evidence.
- Do not claim completion without proof.
