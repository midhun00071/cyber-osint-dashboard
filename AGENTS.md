# Project Instructions

## 1. Project Overview

- **Project name:** Alpha Data / Cyber OSINT Dashboard
- **Purpose:** Build a full-stack defensive cybersecurity OSINT dashboard.
- **Goal:** Collect, normalize, store, search, visualize, and report public cybersecurity intelligence.
- **Audience:** This is a cybersecurity internship project and should be suitable for review by a senior or lead cybersecurity employee.

## 2. Security Scope

- Use this project only for defensive, ethical, and authorized purposes.
- Do not implement exploit execution or automate unauthorized scanning.
- Do not download malware samples.
- Do not create phishing, credential theft, persistence, evasion, or attack tooling.
- Use only safe, public cybersecurity intelligence sources.
- Respect API terms, applicable `robots.txt` rules, and rate limits.

## 3. Branch Workflow

- `main` is the stable and final submission branch.
- `dev` is the long-running development branch.
- Perform all new implementation work on `dev` unless explicitly instructed otherwise.
- Do not commit or push unless the user explicitly asks.
- Keep changes small and reviewable.

## 4. Technology Stack

- **Frontend:** Next.js, React, and TypeScript
- **Backend:** Python and FastAPI
- **Database:** PostgreSQL
- **ORM and migrations:** SQLAlchemy and Alembic
- **MVP scheduler:** APScheduler
- **HTTP client:** httpx
- **RSS parser:** feedparser
- **Testing:** pytest for the backend; TypeScript and build checks for the frontend
- **Containerization:** Docker and Docker Compose

## 5. Coding Standards

- Use a clear folder structure and readable names.
- Prefer simple, maintainable code.
- Add useful comments where needed without over-commenting.
- Validate inputs and handle errors safely.
- Do not expose stack traces or sensitive configuration to users.
- Never log secrets.
- Avoid dangerous HTML rendering such as `dangerouslySetInnerHTML`.
- Keep CORS restrictive and environment-driven.

## 6. Secret Handling

- Never hardcode passwords, API keys, tokens, private keys, database credentials, or sensitive configuration.
- Use environment variables for configuration and secrets.
- Real `.env` files must remain ignored by Git.
- `.env.example` files may contain placeholder values only.

## 7. Backend Guidelines

- Keep FastAPI routes modular.
- Use Pydantic schemas for request and response validation.
- Use SQLAlchemy models for database entities.
- Keep database session logic separated from other application concerns.
- Keep ingestion logic separated from API route handlers.
- Add tests for new endpoints and important services.

## 8. Frontend Guidelines

- Use the Next.js App Router and TypeScript.
- Keep the UI professional and suitable for a cybersecurity dashboard MVP.
- Safely render all external and public OSINT text.
- Handle loading, success, empty, and error states.
- Do not expose raw technical errors in the UI.

## 9. Testing Expectations

- For backend changes, run `pytest` from the `backend` folder.
- For frontend changes, run `npm install` if dependencies changed, followed by `npm run type-check` and `npm run build`.
- Clearly mention warnings, skipped checks, and known limitations.

## 10. Response Expectations

- Before large changes, summarize the implementation plan.
- After changes, summarize which files changed and why.
- Mention the testing commands that were run.
- Mention relevant security considerations.
- Do not claim tests passed unless they were actually run.
