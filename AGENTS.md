# Project Instructions

## 1. Project Overview

- **Project name:** Alpha Data / Cyber OSINT Dashboard
- **Purpose:** Build a full-stack defensive cybersecurity OSINT dashboard.
- **Goal:** Collect, normalize, store, search, visualize, and report public cybersecurity intelligence.
- **Audience:** This is a cybersecurity internship project and should be suitable for review by a senior or lead cybersecurity employee.
- **Standard:** Keep explanations beginner-friendly, but make final implementation, documentation, commits, and reports workplace-ready.

## 2. Security Scope

- Use this project only for defensive, ethical, authorized, educational, or lab-safe purposes.
- Do not implement exploit execution or automate unauthorized scanning.
- Do not download malware samples.
- Do not create phishing, credential theft, persistence, evasion, stealth, bypass, or attack tooling.
- Use only safe, public cybersecurity intelligence sources.
- Respect API terms, applicable `robots.txt` rules, and rate limits.
- Do not expose raw payloads, secrets, stack traces, database URLs, headers, environment values, or sensitive configuration in logs, API responses, frontend UI, reports, or chat output.

## 3. Branch and Git Workflow

- `main` is the stable and final submission branch.
- `dev` is the long-running development branch.
- Perform all new implementation work on `dev` unless explicitly instructed otherwise.
- Before each task, start with a clean checkpoint:
  - confirm current branch
  - check `git status --short`
  - check recent commits
  - verify latest pushed checkpoint when relevant
- Do not stage, commit, push, reset, restore, delete files, or switch branches unless the user explicitly approves.
- Use specific staging commands instead of `git add .`.
- Keep changes small enough to review, but prefer larger well-bounded implementation prompts when they save time without mixing unrelated layers.
- Remove review zips/folders before committing.
- After each commit, verify:
  - `git status --short` is clean
  - latest commit is correct
  - push to `origin/dev` succeeded when required

## 4. Technology Stack

- **Frontend:** Next.js, React, and TypeScript
- **Backend:** Python and FastAPI
- **Database:** PostgreSQL
- **ORM and migrations:** SQLAlchemy and Alembic
- **HTTP client:** httpx
- **RSS parser:** feedparser
- **Testing:** pytest for the backend; TypeScript and build checks for the frontend
- **Containerization:** Docker and Docker Compose
- **Scheduler:** APScheduler may be introduced only when explicitly approved. Current ingestion work should remain manual-only unless a task specifically requires scheduling.

## 5. Coding Standards

- Use a clear folder structure and readable names.
- Prefer simple, maintainable, testable code.
- Add useful comments where needed without over-commenting.
- Validate inputs and handle errors safely.
- Avoid string-concatenated SQL; use safe SQLAlchemy ORM/query patterns.
- Do not expose stack traces or sensitive configuration to users.
- Never log secrets.
- Avoid dangerous HTML rendering such as `dangerouslySetInnerHTML`.
- Avoid unnecessary external scripts, CDNs, remote fonts, or unsafe rendering of public OSINT text.
- Keep CORS restrictive and environment-driven.
- For API/backend work, return only allow-listed safe response fields.

## 6. Secret Handling

- Never hardcode passwords, API keys, tokens, private keys, database credentials, or sensitive configuration.
- Use environment variables, configuration files, `.env.example`, or secret-management best practices.
- Real `.env` files must remain ignored by Git.
- `.env.example` files may contain placeholder values only.
- Do not paste real secret values into chat, reports, commits, logs, or test output.

## 7. Backend Guidelines

- Keep FastAPI routes modular.
- Use Pydantic schemas for request and response validation.
- Use SQLAlchemy models for database entities.
- Keep database session logic separated from other application concerns.
- Keep ingestion logic separated from API route handlers.
- Do not trigger ingestion from application startup, scheduler, or API routes unless explicitly approved.
- Keep public APIs read-only unless a task specifically requires writes.
- Do not expose raw source payloads through public APIs.
- Add tests for new endpoints, services, database behavior, and important validation logic.

## 8. Frontend Guidelines

- Use the Next.js App Router and TypeScript.
- Keep the UI professional and suitable for a cybersecurity dashboard MVP.
- Safely render all external and public OSINT text.
- Handle loading, success, empty, and error states.
- Do not expose raw technical errors in the UI.
- Avoid unsafe HTML rendering, untrusted scripts, unnecessary CDNs, and remote dependencies unless reviewed.

## 9. Testing and Validation Expectations

- Testing is required for every meaningful implementation task.
- For backend changes, run focused pytest tests and the full backend test suite when appropriate.
- For frontend changes, run:
  - `npm run type-check`
  - `npm run build`
- For database/migration work, run Alembic checks:
  - `python -m alembic -c alembic.ini heads`
  - `python -m alembic -c alembic.ini history`
  - `python -m alembic -c alembic.ini current` when checking a live local DB
- For full project validation, prefer:
  - `git diff --check`
  - focused backend pytest tests
  - full backend pytest suite
  - frontend type-check/build
  - `.\run.cmd test`
- Clearly mention warnings, skipped checks, and known limitations.
- Do not claim tests passed unless they were actually run.

## 10. Codex / Agent Work Style

- Before large changes, summarize the goal, current state, files to inspect, implementation plan, and out-of-scope items.
- Break large implementation work into clear sub-tasks that are large enough to make efficient use of Codex, but not so large that unrelated layers are mixed together.
- A good Codex task should usually complete one meaningful project unit, such as:
  - one backend service plus tests
  - one API endpoint group plus schemas/tests
  - one frontend page/component group plus validation
  - one ingestion source layer plus tests/docs
- Avoid tiny prompts for every small line change unless debugging or hardening requires it.
- Avoid overly broad prompts that combine unrelated work such as ingestion, frontend UI, scheduler, authentication, and reporting in one task.
- Prefer prompts that ask Codex to implement, test, fix obvious failures, and summarize.
- For complex tasks, use a professional Codex prompt that includes:
  - current state
  - goal
  - files to inspect
  - strict workflow rules
  - implementation requirements
  - security requirements
  - tests to add/run
  - validation commands
  - final summary requirements
- After Codex finishes, do not rely only on Codex’s summary.
- Always upload changed files or a review zip when the task involves meaningful code, tests, database logic, API behavior, security boundaries, or documentation updates.
- Review zips should include only changed project files and should exclude:
  - `.env` files
  - secrets
  - `.venv`
  - `node_modules`
  - `.next`
  - `__pycache__`
  - `.pytest_cache`
  - old review folders/zips
  - local-only artifacts
- Changed files should be reviewed before approving staging or commit.
- Do not approve a commit based only on Codex output, test summaries, or similarity to expected work.
- If validation fails, fix clear implementation/test failures and rerun the affected tests.
- If review finds issues, create one focused hardening/fix prompt, rerun validation, and upload the updated files again.
- Stop for human review if a real blocker appears, especially schema changes, architecture changes, failing security assumptions, or unclear task mapping.

## 11. Documentation and Reporting

- Update documentation when a meaningful project behavior, command, endpoint, or security boundary changes.
- For each completed task, maintain evidence:
  - task ID
  - summary of work
  - files changed
  - tests run
  - commit hash
  - known limitations
  - next step
- When updating Excel task sheets:
  - make only necessary changes
  - preserve formatting
  - use official task IDs
  - do not mark a task complete based only on similarity to another task
  - ask if task ID mapping is unclear
- When creating daily reports, use a professional format suitable for mentor/senior review:
  - management summary
  - completed tasks
  - implementation details
  - security controls
  - validation evidence
  - Git evidence
  - limitations and next steps

## 12. Project-Specific Source Rules

- Current ingestion style favors manual-only ingestion unless automation is explicitly approved.
- Use defensive public intelligence sources.
- NVD is the current primary CVE source.
- Censys should be included later as a main external intelligence/reference source, using clean canonical URLs instead of ad-tracking URLs.
- Do not store tracking parameters such as `utm_*`, `gclid`, or ad campaign parameters in source configuration.
- Do not scrape or access dark web sources unless the task is explicitly approved, legally safe, and scoped for defensive research only.

## 13. Response Expectations

- Be clear, direct, and professional.
- Give commands in PowerShell when working on this Windows repository.
- Explain why each step is needed, especially for security, testing, or Git safety.
- If there are multiple ways to solve a problem, recommend the most secure and professional approach and briefly explain why.
- Do not claim a task is complete unless there is evidence from tests, Git output, and/or file review.