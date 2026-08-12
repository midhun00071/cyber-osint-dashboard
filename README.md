# Alpha Data / Cyber OSINT Dashboard

Alpha Data is a full-stack defensive cybersecurity OSINT platform. It collects
approved public intelligence, validates and normalizes it, stores it in
PostgreSQL, schedules approved recurring work with Prefect, exposes bounded
FastAPI query services, and presents the results in an authenticated Next.js
dashboard.

This repository is an internship release prepared for mentors, analysts, and
technical reviewers. It provides a validated local application and a
production-oriented deployment baseline. It is not proof of a complete,
public-internet-ready service or of a mentor-accessible external staging host.

This README is the primary, self-contained entry point for a zero-knowledge
mentor handover. The linked operator guide remains the detailed specialist
runbook for routine and exceptional operations.

## Start Here — Fresh Laptop Setup

This is the complete supported local path for a reader with no prior Alpha Data
knowledge. Follow the steps in order. The primary verified environment is
Windows with Windows PowerShell.

### 1. Install the required tools

The normal containerized startup requires:

- **Git**, with access to the approved repository;
- **Windows PowerShell**, which `run.cmd` invokes directly;
- **Docker Desktop** or an equivalent Docker Engine with **Docker Compose v2**;
  and
- enough local permission to build images and bind loopback ports `3000`,
  `8000`, `4200`, and `5432`.

Start Docker Desktop and wait until the Docker daemon reports that it is ready.
Verify the tools in PowerShell:

```powershell
git --version
docker --version
docker compose version
docker info --format "{{.ServerVersion}}"
```

The normal `.\run.cmd` Docker workflow does **not** require Python or Node.js on
the host. Host Python **3.13**, Node.js/npm (the container build uses Node 24),
and the Python launcher are required only for host hot reload, the full test
runner, or direct component development. Install those before using
`.\run.cmd install`, `.\run.cmd dev`, or `.\run.cmd test`.

### 2. Clone the authoritative repository and select `main`

The final mentor handover targets `main` at the authoritative repository below.
GitHub authorization may be required if repository access is restricted. Never
put a credential in the clone URL.

```powershell
git clone "https://github.com/midhun00071/cyber-osint-dashboard.git" "cyber-osint-dashboard"
Set-Location ".\cyber-osint-dashboard"
git switch main
git pull --ff-only origin main
git branch --show-current
git status --short
git log --oneline -5
```

`git branch --show-current` must print `main`. A fresh clone should have no
output from `git status --short`. Stop and ask the project owner if the expected
branch or checkpoint differs; do not reset, clean, or delete files to force a
match. The explicit switch verifies the final branch even when cloning already
selects the repository's default branch.

### 3. Create the local environment files safely

Run the non-destructive setup step from the repository root:

```powershell
.\run.cmd setup
```

It creates only missing files and never overwrites existing local configuration:

| Committed template | Local file created | Used by |
| --- | --- | --- |
| `.env.example` | `.env` | Local Docker Compose and its services |
| `backend/.env.example` | `backend/.env` | Direct host backend development |
| `frontend/.env.example` | `frontend/.env.local` | Direct host frontend development |

When root `.env` does not exist, `scripts/setup-dev.ps1` copies its structure
and replaces the three application-database password markers with three
different cryptographically random local values. It does not display them. The
three credentials belong to the runtime application role, the PostgreSQL
bootstrap role, and the migration role.

For the ordinary fresh local path, no database secret must be invented or
pasted manually. Review variable **names and comments** in `.env`, but never
print or share its values. Keep these safety settings unchanged:

- `APP_ENV` identifies a local/development environment;
- `DEBUG` remains false;
- `ENABLE_ADMIN_INGESTION` remains false;
- `BACKEND_CORS_ALLOWED_ORIGINS` and `BACKEND_TRUSTED_HOSTS` remain exact
  loopback values; and
- `NEXT_PUBLIC_API_BASE_URL` remains the browser-reachable local backend URL.

`NVD_API_KEY` may remain blank. It is used only for an explicitly approved NVD
workflow and is not required to start Alpha Data. The optional local Prefect
metadata database passwords should be set to unique values **before the first
Prefect start** if the operator chooses to manage them explicitly. Changing
only `.env` after the Prefect metadata volume exists does not rotate database
roles and can break the preserved volume.

Confirm the expected files without displaying their contents:

```powershell
Test-Path .\.env
Test-Path .\backend\.env
Test-Path .\frontend\.env.local
git status --short
```

The three `Test-Path` commands should return `True`. The real files are ignored
by Git and must never appear in `git status` or a review ZIP.

### 4. Start and initialize the complete application

Run the supported one-command workflow:

```powershell
.\run.cmd
```

The runner performs the following bounded sequence:

1. verifies Docker, Compose v2, and the Docker daemon;
2. creates only missing local environment files;
3. rejects missing database fields, committed password markers, non-local
   environment identity, debug mode, or enabled admin ingestion;
4. validates Compose without printing resolved secrets;
5. builds the backend, frontend, and pinned Prefect images;
6. starts the application PostgreSQL database, dedicated Prefect metadata
   database, Prefect server, and Prefect process worker;
7. reconciles the configured PostgreSQL roles;
8. verifies that Alembic has one known linear migration chain, then safely
   upgrades the application database to its current head;
9. reapplies least-privilege runtime grants;
10. reconciles the approved source catalog and performs the fresh-database
    offline intelligence bootstrap described below;
11. registers or updates the single Prefect deployment without changing an
    existing activation choice—a new deployment starts paused;
12. starts FastAPI and Next.js; and
13. checks backend health, frontend availability, Prefect server/worker/pool,
    and deployment integrity.

The command does **not** launch a manual flow and does not contact an external
intelligence source merely because the application started.

### 5. Verify successful startup

The runner should end with `[PASS]` messages and a readiness summary. Verify the
services and public local endpoints:

```powershell
docker compose ps
Invoke-WebRequest -Uri "http://localhost:8000/api/health" -UseBasicParsing
Invoke-WebRequest -Uri "http://localhost:3000/" -UseBasicParsing
```

Expected local URLs are:

| URL | Expected use |
| --- | --- |
| `http://localhost:3000/` | Alpha Data sign-in and dashboard |
| `http://localhost:8000/api/health` | Sanitized backend health; expect HTTP 200 |
| `http://localhost:4200/` | Loopback-only Prefect operations UI |

`docker compose ps` should show the application database, backend, frontend,
Prefect metadata database, Prefect server, and Prefect worker running; services
with health checks should be healthy.

### 6. Create the first application administrator

The intelligence bootstrap creates **no user**, there is no default password,
and public self-registration does not exist. On a truly fresh application
database, create exactly one first administrator with the reviewed CLI in the
already configured backend container:

```powershell
docker compose exec backend python -m app.security.bootstrap_admin_cli `
    --username "approved-local-username" `
    --display-name "Approved Display Name"
```

Replace both identity placeholders. The username must begin with a lowercase
letter, contain 3–64 lowercase letters, digits, underscores, periods, or
hyphens, and be unique. The command securely prompts for the password and its
confirmation; it accepts no password argument or password environment variable.
Use a unique password of 12–128 characters and do not record it in source,
terminal commands, tickets, screenshots, or documentation.

The CLI runs only while the application user table is empty. It creates the
local Administrator and its security-audit event in one transaction. If any
user already exists, it refuses instead of replacing or elevating an account.
An Administrator can create later users and assign supported roles through
**User Access** in the dashboard.

### 7. Sign in and make the first review

1. Open `http://localhost:3000/`.
2. Enter the approved username and password on **Secure sign in**.
3. Confirm that **Overview** loads and that the left navigation matches your
   role.
4. Open **Vulnerabilities** and **Threat Feed** to confirm stored intelligence
   is available.
5. Open **System Health** and **Sources** to review truthful runtime and source
   state.
6. If you are the Administrator, open **User Access** to create distinct mentor,
   analyst, or operator accounts; do not share the bootstrap account.

Frontend route protection is a usability boundary. Backend authentication and
permission checks remain authoritative even when a button or navigation item is
hidden.

### 8. Verify Prefect without starting ingestion

Prefect is Alpha Data's scheduler and workflow coordinator. These checks do not
start a source flow:

```powershell
docker compose ps prefect-server prefect-worker
docker compose exec -T prefect-worker python -m app.orchestration.deployments --verify-registration
docker compose exec -T prefect-worker prefect deployment inspect alpha-data-parent-ingestion-cycle/alpha-data-ingestion-cycle
docker compose exec -T prefect-worker prefect deployment schedule ls alpha-data-parent-ingestion-cycle/alpha-data-ingestion-cycle
docker compose exec -T prefect-worker prefect work-pool inspect alpha-data-process
docker compose exec -T prefect-worker prefect work-queue ls --pool alpha-data-process
docker compose exec -T prefect-worker prefect work-pool preview alpha-data-process --hours 6
```

A newly created deployment is deliberately **PAUSED**. Leave it paused for a
mentor UI review or whenever recurring external requests are not explicitly
authorized. The previously preserved local release deployment was approved and
verified ACTIVE/READY on 11 August 2026; a fresh Prefect metadata database has
its own deployment ID and does not inherit that approval automatically.

Only an authorized operator recreating the approved fixed recurring deployment
may resume its schedule, after all verification above succeeds and the six
source approvals remain current:

```powershell
docker compose exec -T prefect-worker prefect deployment schedule resume alpha-data-parent-ingestion-cycle/alpha-data-ingestion-cycle --all
docker compose exec -T prefect-worker prefect deployment inspect alpha-data-parent-ingestion-cycle/alpha-data-ingestion-cycle
docker compose exec -T prefect-worker prefect deployment schedule ls alpha-data-parent-ingestion-cycle/alpha-data-ingestion-cycle
```

After an authorized resume, inspection should show `paused: False`, deployment
status `READY`, and one active schedule. Do not use `prefect deployment run` to
test activation; resuming a schedule authorizes future scheduled runs and does
not require a manual run.

### 9. Stop and restart safely

Stop the local stack while preserving application data and Prefect metadata:

```powershell
docker compose down
```

Restart with `.\run.cmd`. Existing users, intelligence, operational history,
checkpoints, source state, and Prefect activation state are preserved in named
volumes.

> **Data-destruction warning:** `docker compose down -v` deletes the named
> application and Prefect volumes. It is not routine cleanup, password reset,
> migration rollback, or troubleshooting. Do not use it without explicit
> approval to destroy the local persisted environment.

## Final Release and Handover State

This evidence snapshot is dated **12 August 2026**. Final handover policy makes
`main` the authoritative mentor, operator, and future-development branch.
Release preparation and validation were performed on `dev` before controlled
promotion of the exact reviewed release to `main`.

| Handover item | Reviewed state |
| --- | --- |
| Authoritative repository | `https://github.com/midhun00071/cyber-osint-dashboard.git` |
| Authoritative handover branch | `main` |
| Mentor/developer working branch | `main` |
| Historical release-preparation branch | `dev`; preparation and validation context only, not a mentor checkout instruction |
| Final release commit hash | Recorded during controlled release promotion; this document does not invent or predeclare it |
| Mentor-accessible external staging | Not claimed; local and production-oriented configuration evidence is not an external deployment |

The reviewed Prefect deployment state is:

| Prefect item | Reviewed state |
| --- | --- |
| Deployment | `alpha-data-parent-ingestion-cycle/alpha-data-ingestion-cycle` |
| Deployment ID | `8e584852-6ffc-4806-9cc9-22b758767bf3` |
| Work pool | `alpha-data-process` |
| Working directory | `/opt/alpha-data/backend` |
| Schedule | `17 */2 * * *` in `Asia/Dubai` |
| Concurrency/collision policy | `1` / `CANCEL_NEW` |
| Existing reviewed deployment | `paused=False`, `READY`, one active schedule |
| Newly created deployment | **PAUSED** until separately authorized |

The final recurring-cycle runtime proof is internally consistent: expected
sources = **6**, started = **6**, completed = **6**, successful = **6**,
non-successful = **0**, manual-only recurring rows = **0**, and parent status =
`success`. This proves the reviewed bounded cycle, not future availability of an
external source or an external staging host.

The fresh offline bootstrap proof is **112** real public-intelligence records,
not synthetic or demo data:
100 NVD vulnerabilities, 4 CERT-EU advisories, 4 Google Threat Intelligence
publications, and 4 Mandiant publications. It produces 0 ingestion cycles, 0
ingestion runs, 0 checkpoints, 0 watermarks, and 0 users; it makes no live
source request, skips a populated database, and a second startup imports 0
duplicates.

## Environment Configuration and Secret Handling

Alpha Data has no module literally named `secrets`. Configuration and secret
boundaries are implemented by the actual components below:

- `scripts/setup-dev.ps1` creates missing local files and generates three local
  application-database credentials;
- `run.ps1` validates the local environment before Compose starts;
- `docker-compose.yml` interpolates root `.env` and passes only the settings
  required by each local service;
- `backend/app/core/config.py` defines the Pydantic `Settings` model, loads and
  validates backend/runtime environment values, and wraps sensitive fields in
  `SecretStr`;
- `backend/app/db/session.py` builds the bounded SQLAlchemy engine without
  logging parameters;
- `frontend/src/config/publicEnvironment.ts` permits only approved public
  browser configuration and rejects secret-like `NEXT_PUBLIC_*` names; and
- `compose.prod.yml` plus `.env.production.example` define the separate
  protected deployment and secret-file-reference boundary.

### Configuration files and precedence

The committed files are templates and source code. They are safe to review and
commit:

- `.env.example` — root local Compose template;
- `backend/.env.example` — direct host backend template;
- `frontend/.env.example` — direct host frontend template; and
- `.env.production.example` — staging/production structure, copied to a
  protected location outside the repository rather than used as a completed
  file in Git.

Real `.env`, `backend/.env`, `frontend/.env.local`, completed production
environment files, and secret files are operator-managed and ignored or kept
outside Git. In short:

```text
SOURCE CODE / EXAMPLE TEMPLATES       -> committed to Git
REAL ENVIRONMENT VALUES / CREDENTIALS -> local or protected; never committed
```

For local containers, Docker Compose automatically reads root `.env` and
interpolates `docker-compose.yml`. The backend, migration job, application
database, and Prefect worker receive different database identities according to
their responsibility. The frontend receives only a public API base URL and
environment identity at build time. The Prefect server uses its separate
metadata database and never receives the application database credential; the
worker uses the application runtime identity but not bootstrap or migration
credentials.

Local Compose currently uses the validated backend defaults for authentication
lifetimes/throttling rather than forwarding the root template's optional
`AUTH_*` overrides. The production Compose file explicitly supplies those
bounded settings and forces secure cookies. Do not assume that editing an
unused local template field changes a running container; confirm the receiving
service in the applicable Compose definition.

For a direct host backend process, Pydantic settings read process environment
variables before `backend/.env`; invalid explicitly supplied values never fall
back silently. `get_settings()` caches the validated settings. The frontend
build validates `NEXT_PUBLIC_API_BASE_URL` and the build-generated public
environment identity before browser assets are produced.

### What belongs in environment configuration

| Category | Examples | Secret? |
| --- | --- | --- |
| Environment identity and logging | `APP_ENV`, `APP_VERSION`, `LOG_LEVEL`, `DEBUG` | No, but security-sensitive |
| Database location and role names | `POSTGRES_HOST`, `POSTGRES_PORT`, `POSTGRES_DB`, role-name fields | Normally no |
| Database credentials | runtime, bootstrap, migration, Prefect metadata passwords | **Yes** |
| Database pool controls | pool size, overflow, timeout, recycle, connect timeout | No |
| Browser/API routing | `NEXT_PUBLIC_API_BASE_URL`, exact CORS origins, exact trusted hosts | Public or security-sensitive, not secret |
| Session policy | secure-cookie flag, idle/absolute lifetime, session count, login-throttle bounds | No, but security-sensitive |
| External source credentials | optional `NVD_API_KEY` and any future approved source credential | **Yes** |
| Prefect platform | local UI port; fixed pool, schedule, and worker settings live in reviewed code | Port is public configuration |

Browser sessions require no signing secret. The server generates opaque session
and CSRF values, sends them as cookies, and stores only their SHA-256 hashes in
PostgreSQL. A secret must never be placed in `NEXT_PUBLIC_*`, because those
values are delivered to every browser.

### Failure behavior and protected environments

Local startup fails closed when required database settings are missing, the
known template markers remain, unsafe booleans are enabled, identifiers are
malformed, database pools exceed bounds, CORS/Host lists are invalid, or the
database cannot be reached. Errors identify the setting category without
printing the value.

Staging and production add stricter rules in `backend/app/core/config.py`:

- debug and admin ingestion must be disabled;
- secure authentication cookies are required;
- the deployed commit SHA is required;
- CORS origins must be explicit non-loopback HTTPS origins;
- trusted hosts must be explicit non-loopback hosts;
- credential-bearing `DATABASE_URL` and direct database password values are
  rejected; and
- the database password must come from a readable protected secret file.

`.env.production.example` contains non-secret structure and blank references.
An operator copies it outside the repository, restricts access, supplies
separate secret files for bootstrap, runtime, migration, and backup identities,
and validates Compose with `config --quiet`. Never print resolved Compose
configuration when real values are loaded.

### Rules that always apply

- Never commit, upload, paste, screenshot, or log a real password, API key,
  token, cookie, authorization header, credential-bearing URL, private key, or
  completed environment file.
- Never pass secrets as Docker build arguments or put them in frontend source.
- Never inspect troubleshooting state by dumping full environments, container
  inspection output, or resolved Compose configuration.
- Rotate a database credential in both PostgreSQL and its protected delivery
  file; changing a file alone does not rotate the stored role.
- If exposure is suspected, report only the affected file and secret category,
  revoke/rotate the value, and preserve sanitized evidence without copying the
  value again.

## How the System Works

### Runtime services

| Service | Purpose | Important boundary |
| --- | --- | --- |
| `db` | PostgreSQL system of record for intelligence, users, sessions, source state, and operational evidence | Local port is loopback-only; runtime and migration roles are separated |
| `backend` | FastAPI authentication, authorization, bounded queries, reports, health, source operations, and audit APIs | Only allow-listed schemas leave the API; no raw database/source payloads |
| `frontend` | Next.js authenticated analyst and operator interface | No database or source access; browser calls FastAPI |
| `prefect-db` | Dedicated local PostgreSQL store for Prefect metadata | Internal-only network; no host port |
| `prefect-server` | Self-hosted Prefect API and UI | Local administration is loopback-only |
| `prefect-worker` | Polls the fixed process pool and runs registered Alpha Data flows | Uses the application database role and fixed orchestration package |
| `migrate` | One-shot Alembic migration job used by the runner | Uses the migration identity; not a normal long-running service |

### Intelligence data path

```text
approved public source or reviewed local catalogue
  -> fixed source collector/client
  -> source-specific adapter or normalizer
  -> ingestion/publication service
  -> SQLAlchemy transaction and PostgreSQL
  -> query service
  -> allow-listed FastAPI schema
  -> validated frontend API client
  -> authenticated dashboard page
```

Collectors receive a fixed source identity and bounded request parameters, not
an arbitrary URL. Normalizers turn different NVD, EPSS, KEV, RSS, publication,
or STIX-shaped structures into the application's internal contracts. Services
apply identity, deduplication, transaction, provenance, and audit rules.
PostgreSQL stores the committed result. Query services then paginate and filter
stored data; FastAPI schemas expose only approved fields; frontend services
validate responses before React renders text and safe external links.

The browser never connects to PostgreSQL or an intelligence source. Loading a
dashboard page performs a stored-data query, not live collection.

### Scheduled ingestion path

```text
Prefect cron slot
  -> alpha-data-parent-ingestion-cycle
  -> scheduled source policies in deterministic order
  -> one source-specific flow/handler per source
  -> bounded collection and normalization
  -> committed source data and run evidence
  -> checkpoint/watermark advancement after safe persistence
  -> reconciled parent-cycle status
```

The parent cycle considers every scheduled policy and isolates each source.
One source failure does not stop unrelated sources. Source results and parent
status are reconstructed from committed evidence rather than assumed from
control flow.

## Repository and Module Map

The following map groups code by responsibility rather than listing every file.

### Backend application

- `backend/app/main.py` constructs FastAPI, validates settings at import/startup,
  installs exact Host, body-size, CORS, request-ID, safe-error, and security-header
  middleware, and registers route groups. Its lifespan logs startup/shutdown but
  does not run ingestion.
- `backend/app/api/v1/routes/` contains modular health, version, authentication,
  dashboard, articles, intelligence, analyst, source/operations, report, system,
  audit, and Administrator user routes.
- `backend/app/api/v1/schemas/` contains Pydantic request/response allow-lists.
  Query validation rejects unknown/repeated parameters and applies pagination,
  date, count, and body bounds.
- `backend/app/services/` owns authentication, user administration, dashboard,
  article/intelligence/analyst queries, source operations, audit search, reports,
  system health, metrics, and retention planning. Routes remain thin and do not
  build SQL from user strings.
- `backend/app/core/` owns environment validation, structured sanitized logging,
  request correlation, and security headers.
- `backend/app/db/` owns the SQLAlchemy declarative base, lazy engine, bounded
  pool, and request-scoped sessions.

### Authentication, authorization, sessions, and audit

- `backend/app/security/identity.py` canonicalizes local usernames and resolves
  the fixed local identity provider.
- `backend/app/security/passwords.py` enforces the bounded password policy and
  Argon2id hashing/verification.
- `backend/app/security/sessions.py` creates opaque session/CSRF values, stores
  hashes, applies idle and absolute expiry, limits active sessions, rotates or
  revokes sessions, and sets Strict cookies.
- `backend/app/security/contracts.py` defines the closed roles and permissions;
  `authorization.py` maps a role to permissions; `dependencies.py` enforces
  authentication, permission, Origin, CSRF, and JSON requirements in FastAPI.
- `backend/app/services/authentication_service.py` owns login, throttling,
  refresh, logout, and password-change transactions.
- `backend/app/services/user_admin_service.py` owns bounded user lifecycle,
  roles, expiry, and session-revocation rules.
- `backend/app/services/security_audit_service.py` appends allow-listed security
  actions and safe details. ORM/database controls prevent routine update,
  deletion, or truncation of audit evidence.

Roles are:

| Role | Intended capability |
| --- | --- |
| Viewer | Read approved content and source information |
| Analyst | Viewer access plus stored IOC analysis and report read/export |
| Ingestion operator | Viewer access plus ingestion read/run/retry/pause controls |
| Administrator | All permissions, including user lifecycle, source management, session revocation, and audit search |

The backend is authoritative. Source-control and user-management requests are
also protected by exact Origin and double-submit CSRF checks. Login failures use
a generic response and bounded throttling rather than revealing whether a user
exists.

### Ingestion and processing

- `backend/app/ingestion/source_registry.py` is the immutable approved-source
  registry: canonical slug, vendor, content family, access method, exact host,
  fixed HTTPS base URL, implementation/enabled state, and progress contract.
- `backend/app/ingestion/collectors/` contains fixed-policy HTTP/RSS clients for
  NVD, EPSS, CISA KEV, official RSS, Google threat research, Censys publication
  metadata, Anomali publication metadata, and disabled DESC metadata.
- `backend/app/ingestion/normalizers/` turns NVD, EPSS, KEV, and RSS input into
  bounded normalized values.
- `backend/app/ingestion/adapters/` maps publication-family inputs into the
  common `PublicationCandidate` contract.
- `backend/app/ingestion/services/` owns source-specific persistence and
  operational evidence. `publication_pipeline.py` applies common publication
  identity and safe-metadata rules but uses its caller's transaction.
- `backend/app/ingestion/stix_taxii/` contains a strict offline/fixed-policy
  STIX/TAXII foundation. Its production registry is empty unless a separately
  approved integration is configured.
- `backend/app/processing/` provides offline UAE relevance classification and
  IOC extraction from already normalized text. It performs no network lookup,
  scanning, active validation, malware retrieval, or exploit activity.
- source CLIs under `backend/app/ingestion/` are explicit manual workflows;
  they are not backend startup hooks or public arbitrary-source APIs.

### Orchestration

- `backend/app/orchestration/contracts.py` defines closed statuses, eligibility,
  retries, quota observation, progress proposals, handler protocols, and the
  immutable policies generated from enabled sources.
- `backend/app/orchestration/source_handlers/` binds the six recurring sources
  to their reviewed collectors, normalizers, and persistence services.
- `backend/app/orchestration/persistence.py` owns short application-role
  transactions and advisory-lock-backed cycle/run/progress changes.
- `backend/app/orchestration/flows.py` implements the parent flow and per-source
  flow, bounded retry/backoff, deterministic staggering, timeout, failure
  isolation, truthful result recording, and progress recovery.
- `backend/app/orchestration/deployments.py` defines and verifies the single
  deployment, work pool, cron, timezone, working directory, concurrency, and
  paused/active registration behavior.

### Bootstrap

- `backend/app/runtime_bootstrap.py` validates the Alembic graph and live
  revision, reconciles approved source identities, and owns one transaction for
  application reference state.
- `backend/app/bootstrap_data/snapshot.json` is the fixed bounded offline public
  snapshot.
- `backend/app/bootstrap_data/service.py` validates size, depth, schema, source
  ownership, counts, and duplicate identities before passing records through
  the normal NVD and publication persistence paths.

### Database

- `backend/app/models/` defines intelligence, provenance, vulnerability,
  indicator, threat-knowledge, ingestion-operation, authentication, session,
  role, and audit tables.
- `backend/alembic/versions/` is the preserved forward migration history;
  `backend/alembic.ini` and `backend/alembic/env.py` configure Alembic.
- `database/init/` and the reconciliation/grant scripts provision distinct
  bootstrap, migration, runtime, read-only, backup, and retention boundaries.
- `backend/app/db/session.py` supplies SQLAlchemy sessions. Runtime SQL hides
  parameters and translates initial connection detail into a sanitized error.

### Frontend

- `frontend/src/app/` uses the Next.js App Router for login, the protected
  dashboard layout, release pages, and article/vulnerability detail routes.
- `frontend/src/components/auth/` bootstraps `/auth/me`, redirects anonymous
  users, renders access-denied/recoverable states, and checks permissions for
  usability.
- `frontend/src/services/` builds bounded credential-included API requests and
  validates response shapes. It does not store session tokens in browser
  storage.
- `frontend/src/components/dashboard/` and `components/analyst/` present KPI,
  trends, feeds, vulnerabilities, IOC, provenance, and operational state.
- `frontend/src/components/SafeExternalLink.tsx` and URL utilities reject unsafe
  external links. React renders external text as text; untrusted raw HTML is not
  inserted.
- `frontend/src/config/publicEnvironment.ts` is the public configuration
  allow-list and protected-environment URL validator.

### Operations and tests

- `docker-compose.yml` is the local loopback-only stack; `compose.prod.yml` is
  the separate production-oriented baseline.
- `run.cmd`, `run.ps1`, and `scripts/setup-dev.ps1` are the supported Windows
  setup/start/test/development entry points.
- `prefect/Dockerfile` pins Prefect 3.8.1 on Python 3.13 and runs as a fixed
  non-root user.
- `backend/tests/` contains pytest coverage for models, migrations, services,
  APIs, ingestion, orchestration, security, Compose, scripts, and documentation.
- frontend `*.test.ts`/`*.test.tsx` files use Vitest, jsdom, React Testing
  Library, response validation, and security-focused rendering tests.

## Ingestion: Detailed Lifecycle and Safety Model

### 1. Source registry and policy

The registry accepts only developer-controlled `SourceDefinition` objects. Each
enabled source has a canonical slug and exact HTTPS host/base URL. Runtime users
cannot supply a new API root, host, redirect destination, cookie, header, or
callback URL. Registry inclusion describes implementation state; it does not by
itself grant licensing, collection, storage, redistribution, or scheduling
approval.

Exactly six handlers belong to the recurring parent cycle:

- `nvd` — vulnerability records from the NIST NVD API;
- `first-epss` — EPSS enrichment for CVEs already stored locally;
- `cisa-kev` — Known Exploited Vulnerability enrichment/reconciliation;
- `cert-eu-security-advisories` — CERT-EU advisory publication metadata;
- `google-threat-intelligence-public-research` — public Google TI research
  publication metadata; and
- `mandiant-public-threat-research` — public Mandiant research publication
  metadata.

Exactly five registered sources are manual or approval-gated and remain outside
the automatic recurring parent cycle:

- `anomali-cyber-watch`;
- `censys-arc-research`;
- `censys-rapid-response-advisories`;
- `ibm-x-force-public-osint-advisories`; and
- `ibm-x-force-public-research`.

Registered does not mean scheduled. MITRE/CERT-FR/UK NCSC, DESC, UAE source
proposals, other commercial sources, and production STIX/TAXII collection
remain disabled, approval-gated, unbound, or otherwise outside the recurring
schedule.

### 2. Collection/client layer

Source clients use exact approved HTTPS locations and source-specific methods.
They enforce bounded connect/read/write/pool behavior, response bytes, pages,
objects, and record counts; validate status and content type; reject environment
proxy surprises where required; and reject redirects or validate each redirect
against the fixed policy. NVD pacing changes only when an approved optional key
is present. Upstream errors are converted to sanitized categories rather than
logging raw bodies, headers, cookies, URLs containing secrets, or exceptions.

Collectors retrieve vulnerability/feed/publication **data only**. They do not
scan targets, probe hosts, submit files, download malware or arbitrary binaries,
execute exploits, or follow user-supplied endpoints.

### 3. Adapter and normalizer layer

NVD, EPSS, KEV, and RSS normalizers validate identifiers, timestamps, scores,
text, URLs, shapes, and bounded source evidence. Publication adapters emit a
`PublicationCandidate`; the common pipeline then derives the item type from the
registered content family, removes fragments and tracking parameters such as
`utm_*`, validates canonical hosts/paths, and snapshots only shallow safe
metadata. Sensitive key aliases, signed/credential-like URLs, control
characters, oversized identities, and conflicting ownership fail closed.

### 4. Persistence, identity, and deduplication

`IntelligenceItem` is the normalized analyst-facing record. A
`Vulnerability` adds CVSS, severity, affected-product, EPSS, and KEV fields.
`IntelligenceItemIdentifier` supplies stable global identities such as CVE.
`IntelligenceSource` records the approved source, while `SourceRecord` preserves
the source-owned external ID, URL/hash, timestamps, processing status, safe
content hash, and link to the normalized item.

NVD creates or updates vulnerability items through CVE and source identity.
EPSS and KEV only enrich matching existing CVEs; they do not create arbitrary
vulnerabilities. Publication records deduplicate within a source by external ID
or canonical URL hash. Global URL/title fingerprints can link compatible items,
while conflicts fail safely or require analyst review. A stable content hash
produces `unchanged`; changed validated content produces an update; a new stable
identity produces a create.

Transaction ownership is explicit. Source-specific services or invoking CLIs
commit/rollback; the common publication pipeline never secretly commits.
Database failure rolls back the owning transaction. The operational service
uses advisory locks and idempotency identities to prevent duplicate scheduled
cycles/runs and unsafe concurrent progress changes.

### 5. Operational state and progress

`IngestionCycle` represents a parent scheduled or manual cycle.
`IngestionRun` represents one source attempt and stores truthful bounded
counters and status. `IngestionRunRecord`, `IngestionRunEvent`, and
`IngestionError` preserve per-record and safe operational evidence.
`SourceCheckpoint` and `SourceWatermark` store versioned progress; quota and
rate-limit tables store defer/backoff state.

NVD, FIRST EPSS, CERT-EU, Google TI, and Mandiant use watermark progress; CISA
KEV uses a checkpoint. Progress never advances merely because a request
returned. Source data and terminal run evidence must commit first. If data has
committed but progress finalization fails, the run remains `checkpoint_pending`
and the next attempt reconstructs progress from committed evidence rather than
re-fetching blindly or claiming success.

### 6. Failure, retry, and source isolation

Each scheduled source has concurrency one, a maximum of three attempts with
30- and 60-second backoff, deterministic staggering, quota checks, and a
900-second execution timeout. Rate-limit responses are recorded truthfully and
are not retried through the ordinary transient path. Expected states include
`success`, `no_change`, `deferred_quota`, `disabled`, `credentials_missing`,
`licence_required`, `rate_limited`, `partial`, `failed`, and `cancelled`.

The parent continues after one source exception, reads committed evidence, and
finishes as success, partial, failed, or cancelled according to the reconciled
source outcomes. It never converts incomplete work into fake success.

### 7. Example scheduled lifecycle

```text
minute 17 of an eligible two-hour slot arrives
  -> Prefect creates the parent flow run
  -> the parent acquires one idempotent scheduled cycle
  -> the six approved scheduled policies are considered in slug order
  -> each source flow checks operator state, handler, quota, and prior progress
  -> the fixed client obtains bounded public data
  -> the source normalizer/adapter validates and canonicalizes it
  -> the source service persists records idempotently in PostgreSQL
  -> committed run evidence is recorded
  -> checkpoint/watermark progress advances safely
  -> the parent reconciles cycle status from stored evidence
  -> query APIs expose stored intelligence
  -> authenticated dashboard pages display it
```

## Fresh Database Bootstrap

A completely empty database would otherwise show an empty dashboard and make a
first-time mentor unable to evaluate the product. Alpha Data therefore bundles a
bounded offline snapshot of real public intelligence:

- **100** NVD vulnerabilities;
- **4** CERT-EU security advisories;
- **4** Google Threat Intelligence public research publications; and
- **4** Mandiant public threat research publications.

The total is exactly **112** records. The snapshot is size-, depth-, schema-,
source-, count-, duplicate-, URL-, and payload-validated. It passes through the
normal NVD and publication persistence services, so later live/scheduled
collection can identify an unchanged record or safely update it.

The bootstrap runs only when all core intelligence tables are genuinely empty.
If any intelligence/source-record/identifier/vulnerability state already
exists, it preserves that state and does not mix in the snapshot. It creates no
default user, no `IngestionCycle`, no `IngestionRun`, no checkpoint, no
watermark, and no fabricated collection history. The runner output states
whether 112 records were created or existing intelligence was preserved.

This distinction is essential:

- **Application initialization** migrates the schema, reconciles fixed source
  reference data, and may load the offline snapshot into a fresh database.
- **Live/scheduled ingestion** makes approved external requests through source
  handlers and records real operational cycles/runs. It is controlled by
  Prefect activation, source policy, quotas, and operator state—not FastAPI
  startup.

## Prefect for First-Time Operators

Prefect is the orchestration system that schedules and observes ingestion work.
It is separate from the FastAPI web server.

- A **flow** is Python code describing a unit of work. Alpha Data has one parent
  ingestion flow and source-specific child flows.
- A **deployment** is the registered runnable configuration for a flow: its
  name, schedule, parameters, pool, working directory, and concurrency.
- A **work pool** is the queueing boundary. `alpha-data-process` is a fixed
  process pool.
- A **worker** polls that pool and starts eligible flow runs in the pinned Alpha
  Data environment.
- The cron expression `17 */2 * * *` in `Asia/Dubai` means **every two hours at
  minute 17 in Dubai time**.
- Deployment concurrency `1` with `CANCEL_NEW` prevents overlapping parent
  cycles; source policies also limit each source to one concurrent run.

`.\run.cmd` starts the Prefect infrastructure and registers/verifies the
deployment. Registration preserves an existing pause/active choice and creates
a missing deployment paused. **Schedule activation** is a separate approval
decision. **Scheduled ingestion** occurs later at a cron slot while the server
and worker are online. A **manual source request** or legacy source CLI is a
separate, explicit action and cannot bypass a missing handler, disabled state,
credential/licence/quota requirement, or endpoint policy.

`ACTIVE`/`paused=False` means the schedule may create future work. `READY` means
the registered deployment/pool state is available; it is not proof that every
source request succeeded or that data is fresh. Use the Prefect UI at
`http://localhost:4200/`, **Ingestion Operations**, and **Run History** together
for operational evidence.

The authenticated manual-run and retry endpoints durably accept and audit an
approved operation request; acceptance does not mean an upstream request ran or
succeeded. The current recurring executor is the Prefect deployment. Legacy
manual CLIs remain separate explicit workflows and require their own source
approval and bounds.

The local PC, Docker daemon, Prefect server, and worker must remain running for
the schedule to fire. A browser window need not remain open. Continuous 24/7
collection requires an always-on staging host, which is not demonstrated by
this local setup.

## Database for First-Time Operators

PostgreSQL is Alpha Data's system of record. It stores normalized intelligence,
source provenance, identifiers, vulnerabilities, indicators, threat metadata,
users, credentials hashes, sessions, roles, audit events, source state,
ingestion cycles/runs/events/errors, checkpoints, watermarks, quota state, and
report-relevant operational evidence.

SQLAlchemy models express tables and relationships as Python objects. Alembic
migrations are the ordered, committed history that changes the schema safely.
`.\run.cmd` verifies one known linear migration head before upgrading. Existing
migrations are preserved because rewriting history makes deployed databases
ambiguous and risks corruption.

For any future schema change, create a **new** Alembic migration; never edit a
committed migration. Define named foreign keys, constraints, uniqueness rules,
and indexes deliberately, preserve idempotent identities, and test upgrade and
downgrade behavior where applicable. Mapper validation and Alembic validation
must finish with exactly one linear head before the change can be accepted.

Database responsibilities are separated:

- the **bootstrap role** initializes and reconciles database roles;
- the **migration role** owns/manages schema objects and applies Alembic;
- the **runtime role** used by FastAPI and the Prefect worker has required DML
  and sequence access but no schema ownership, role administration, truncate,
  or routine delete privilege;
- read-only, backup, and retention groups have narrower reviewed access.

Least privilege limits the damage of a compromised service or coding error.
The source catalog is reference data; the 112-record snapshot is optional
fresh-database intelligence; scheduled ingestion adds real cycle/run/progress
evidence. These are different layers and should not be conflated.

Do not repair migration, login, or ingestion problems by deleting volumes or
editing database rows. A destructive reset destroys users, intelligence,
history, and Prefect metadata and is not routine troubleshooting.

## Authentication and Authorization

Alpha Data currently uses local single-factor identities. Passwords are
Argon2id hashes; submitted passwords are never stored. Browser sessions use
random opaque values with only token/CSRF hashes persisted. The session cookie
is HttpOnly, both cookies are `SameSite=Strict`, staging/production requires
`Secure`, and unsafe requests require exact Origin plus CSRF cookie/header
agreement.

The default idle session lifetime is 60 minutes, the absolute lifetime is eight
hours, and a user has at most five active sessions. Refresh rotates the previous
session. Logout, password change, account disablement, role changes, and
Administrator revocation invalidate applicable sessions. Login throttling is
bounded and does not reveal whether an identity exists.

After the one-time first-admin procedure, Administrators use **User Access** to
create unique accounts, assign one closed role, set account expiry/status, and
revoke sessions. Security-sensitive actions produce append-only audit events
with public identifiers, correlation IDs, outcomes, and safe details—not
usernames submitted to login, passwords, cookies, request bodies, SQL, or raw
exceptions.

## Dashboard User Guide

Visible navigation is permission-aware. A user may see fewer pages than an
Administrator.

| Page | What it is for |
| --- | --- |
| **Overview** | Stored intelligence totals, trends, recent vulnerabilities/publications, freshness, and backend health |
| **Threat Feed** | Normalized publication metadata and validated stored threat-entity information; opening it performs no live collection |
| **Vulnerabilities** | Search and inspect stored CVEs with CVSS, EPSS, KEV, provenance, freshness, and UAE relevance |
| **UAE Intelligence** | Distinguish direct UAE evidence, potential relevance, global context, and no demonstrated UAE relevance |
| **IOC Search** | Search normalized indicators already stored; it never probes a domain/IP or fetches external content |
| **Sources** | Review registry policy, effective operator state, readiness, credential boolean, quota/backoff, progress fingerprint, freshness, and allowed actions |
| **Ingestion Operations** | Review committed cycle/run summaries and request supported audited operations; acceptance is not proof of successful collection |
| **Run History** | Inspect attempts, counters, source-safe messages, ordered events, and deterministic retry lineage |
| **Reports** | Generate authorized UAE Intelligence or Source Operations CSV/PDF exports from allow-listed fields, at most 100 rows and 2 MiB |
| **System Health** | Review truthful service, database, Prefect, source, storage, and deployment state; unknown/stale/degraded is not healthy |
| **Audit Log** | Administrator-only bounded search of safe security and operator events |
| **Methodology** | Understand evidence wording, attribution, relevance, freshness, normalization, and limitations |
| **User Access** | Administrator-only account creation, role/status/expiry changes, and session revocation |

Article and vulnerability detail pages show stored normalized fields and
provenance. Treat all OSINT text and outbound links as untrusted. Use only links
accepted by the safe URL renderer and follow organizational browsing policy.

## How It All Fits Together

1. The operator runs `.\run.cmd`; local configuration is created or validated.
2. Docker starts the two PostgreSQL services and Prefect server/worker.
3. Database roles are reconciled and Alembic confirms/advances the schema.
4. Runtime bootstrap reconciles the approved source catalog.
5. On a genuinely fresh intelligence database, the 112-record offline snapshot
   loads through normal persistence; existing databases are preserved.
6. The Prefect deployment is registered while preserving its activation state;
   a new deployment remains paused.
7. FastAPI becomes healthy and Next.js becomes available.
8. A fresh operator uses the one-time CLI to create the first Administrator,
   then signs in and creates least-privilege users.
9. When the fixed schedule is explicitly authorized and active, Prefect
   considers the six recurring sources every two hours at minute 17.
10. Each source independently collects, validates, normalizes, persists, and
    records progress/evidence; one source failure is isolated.
11. FastAPI query services read committed PostgreSQL data and return allow-listed
    schemas to authenticated browsers.
12. The Next.js pages present stored intelligence, while Sources, Operations,
    Run History, Audit Log, and System Health provide operational evidence.

## Routine Operation

Daily local start:

```powershell
.\run.cmd
```

Development hot reload, after installing host dependencies:

```powershell
.\run.cmd install
.\run.cmd dev
```

The `dev` argument in `.\run.cmd dev` selects the hot-reload runner; it is not a
Git branch instruction. It keeps PostgreSQL and Prefect in Docker and runs
Uvicorn/Next.js on the host. Press Ctrl+C to stop the host applications, then
use `docker compose down` when the infrastructure should also stop.

Use bounded logs only when necessary:

```powershell
docker compose logs --tail 100 backend
docker compose logs --tail 100 frontend
docker compose logs --tail 100 prefect-server prefect-worker
```

Do not run live/manual collectors simply to make the dashboard look populated.
Do not edit source state, checkpoints, users, or migration rows directly in the
database.

## Adding a New Ingestion Source

Treat a new source as a bounded security and data-integrity change, not as an
extra URL. Freeze its approval, source identity, collection mode, persistence
contract, operational evidence, tests, and documentation before implementation.
The steps below describe the existing Alpha Data pattern.

### 1. Approve and freeze the source policy

Record the source owner, official task, public-data purpose, terms/licence,
`robots.txt` decision where applicable, storage and redistribution rights,
credential class, quota, retention, and whether the source is scheduled or
manual/approval-gated. Assign a stable canonical slug and stable vendor/content
metadata. Fix the exact HTTPS hosts and paths, acceptable redirect behavior,
authentication method, connect/read/write/pool and total timeouts, response-byte
limit, pagination/object bounds, rate limits, quota handling, retry/backoff,
incremental cursor, checkpoint contract, and source-failure isolation.

Never accept a runtime-supplied API root, arbitrary host or endpoint, callback
URL, redirect target, header, or cookie. A collector must never scan or probe a
target, submit a file, retrieve malware or arbitrary binaries, execute an
exploit, or perform another harmful activity. Commercial or restricted sources
remain disabled until the exact licence, payment, entitlement, quota, credential,
and activation approvals are recorded.

### 2. Register identity without implying scheduling

Add the immutable source definition to
`backend/app/ingestion/source_registry.py` and keep its canonical slug and
metadata aligned with the source catalogue reconciliation in
`backend/app/runtime_bootstrap.py`. When orchestration is approved, generate or
validate its closed policy contract through
`backend/app/orchestration/contracts.py`. **Registered does not mean scheduled**:
registry membership records a reviewed identity, while the parent-cycle handler
set separately grants recurring execution.

### 3. Configure credentials and limits safely

Add only necessary typed settings through `backend/app/core/config.py` and the
applicable committed environment templates. Never add a real secret value.
Secret fields must stay server-side, use protected delivery in staging or
production, never enter `NEXT_PUBLIC_*`, and fail closed when missing or invalid.
Logs, errors, reports, fixtures, screenshots, and tests must not expose tokens,
authorization headers, cookies, credential-bearing URLs, raw vendor payloads,
environment values, SQL, or stack traces.

### 4. Implement the fixed-policy client

Place HTTP/RSS clients under `backend/app/ingestion/collectors/`. Follow the NVD,
EPSS, KEV, or publication collectors according to the source family. The client
must enforce the frozen HTTPS host/path policy, reject or strictly validate
redirects, distrust ambient proxy behavior where required, validate status and
content type, and bound timeouts, bytes, pages, objects, retries, pacing, rate,
and quota. Convert failures into sanitized source-safe categories. An HTTP 200
alone is never evidence of correct collection or persistence.

### 5. Normalize into canonical data

Put source-specific translation in `backend/app/ingestion/normalizers/` or
`backend/app/ingestion/adapters/`. Validate canonical identifiers, timestamps,
URLs, scores, types, text, nesting, and bounded metadata. Strip fragments and
tracking parameters, reject credential-like URLs and control characters, and
preserve source attribution. Prefer the common `PublicationCandidate` contract
for publication metadata; do not store an unrestricted raw vendor response.

### 6. Reuse the canonical database model

A new source does **not** automatically justify a new table. Reuse the existing
`IntelligenceSource`, `SourceRecord`, `IntelligenceItem`, identifier,
vulnerability, publication, operational, and progress models whenever their
semantics fit. If genuinely new semantics require schema work, add new ORM
definitions and a **new** Alembic migration. Never edit a committed migration.
Specify named foreign keys/constraints, uniqueness, indexes, lifecycle rules,
idempotency keys, and transaction ownership; add mapper and migration tests and
retain exactly one linear Alembic head.

### 7. Persist idempotently through the service layer

Implement the source service or pipeline under
`backend/app/ingestion/services/`. Use `PublicationPipeline` for compatible
publication inputs and the existing NVD/vulnerability enrichment pattern for
vulnerability data. Define create, update, unchanged, and conflict outcomes;
preserve the source record, canonical identifiers, normalized item, provenance,
and safe content hash in one explicit transaction. Deduplicate by stable
source-owned identity and canonical identity, roll back on failure, and report
truthful counters. A common pipeline must not secretly commit for its caller.

### 8. Define incremental progress safely

Specify how the source reads and resumes its cursor, checkpoint, watermark, or
other progress proposal. Retried pages and restarts must not duplicate records.
Never advance progress because a request merely returned or before all related
records and run evidence are durably committed. A failure must retain the last
safe progress value. Offline bootstrap/reference reconciliation must not invent
cycles, runs, checkpoints, watermarks, or successful collection history.

### 9. Bind the handler and Prefect flow

Create the reviewed source handler under
`backend/app/orchestration/source_handlers/` and connect the fixed chain:
eligibility, quota/backoff, client, adapter/normalizer, service transaction,
truthful counters, committed run evidence, and progress proposal. The source
flow must use bounded retry/backoff and timeout rules. One source exception must
remain isolated so unrelated source flows can finish and the parent can
reconcile its status from committed evidence.

### 10. Decide scheduled versus manual explicitly

For a scheduled source, update the approved scheduled policy/handler set, the
expected source count, orchestration tests, deployment assumptions, and runtime
proof. Re-prove that every intended scheduled slug runs and that every manual
slug produces zero recurring rows. For a manual or approval-gated source, keep
it outside the parent cycle, expose only an authorized bounded entry point, and
document the exact approval gate. Never auto-enable a commercial source.

### 11. Preserve the deployment model

Alpha Data uses one self-hosted Prefect parent deployment; do not add a second
scheduler. Source registration normally does not require another deployment.
Unless an approved task changes them, preserve the fixed work pool, working
directory, Dubai cron, deployment concurrency `1`, and `CANCEL_NEW`. A new
deployment starts paused and activation remains an operator approval.

### 12. Validate offline before any live request

Use this order:

1. source-policy and registry tests;
2. malicious/invalid configuration tests;
3. bounded HTTP fixtures with redirects, wrong hosts, wrong content types,
   oversize bodies, pagination caps, timeout, retry, rate, and quota cases;
4. adapter/normalizer fixture tests;
5. canonical URL, timestamp, identifier, and metadata-boundary tests;
6. persistence create/update/unchanged/conflict and rollback tests;
7. idempotency, duplicate, replay, and concurrency tests;
8. checkpoint/watermark commit-order and recovery tests;
9. handler status, retry, timeout, and failure-isolation tests;
10. scheduled-versus-manual membership tests;
11. source-catalog/bootstrap reconciliation tests;
12. SQLAlchemy mapper validation;
13. Alembic heads/history and migration tests when schema changed;
14. focused API/frontend tests if the source becomes visible; and
15. the appropriate backend regression, frontend Vitest, type-check, production
    build, and `git diff --check` gates.

Mocked fixtures must be bounded, deterministic, non-secret, and representative;
they must not weaken validation just to make the happy path pass.

### 13. Gate and record live validation

A live check requires prior approval for the exact command, host/path, source,
credential class, limits, environment, and expected storage. Perform it only in
the approved bounded staging context. Evidence must include source slug, action,
request/page/object limits, created/updated/unchanged/error counts, checkpoint
before and after, run/cycle identifiers and statuses, committed database proof,
Prefect proof when scheduled, and proof that manual-only sources stayed outside
the recurring cycle. Sanitize all evidence. Do not present HTTP 200 as success,
and do not infer external staging from a local run.

### 14. Update the operator and product documentation

Update this README's exact recurring/manual inventories and count, plus
`docs/data-sources.md`, architecture/security/testing material, environment
templates, operator procedures, UI/methodology text, and the task evidence that
the approved change actually affects. Clearly label licence, credential, quota,
coverage, freshness, and storage limitations.

### 15. Source completion checklist

- [ ] Official task, frozen acceptance contract, defensive public purpose, and source owner are recorded.
- [ ] Terms, licence, robots, storage, redistribution, retention, and approval are recorded.
- [ ] Stable canonical slug, vendor, and content family are fixed.
- [ ] Exact HTTPS hosts, paths, and redirect policy are allow-listed.
- [ ] Arbitrary hosts, endpoints, callbacks, headers, and cookies are rejected.
- [ ] Authentication uses typed secure configuration with no committed secret.
- [ ] Timeouts, response bytes, pages, objects, rate, quota, and retries are bounded.
- [ ] Collector failures and logs are sanitized.
- [ ] Harmful retrieval, probing, scanning, submission, and execution are impossible.
- [ ] Adapter/normalizer validates canonical identifiers, timestamps, URLs, and bounds.
- [ ] Provenance and safe source metadata are preserved.
- [ ] Existing canonical models are reused unless new semantics are demonstrated.
- [ ] Any schema change uses a new migration with one linear head.
- [ ] Persistence has explicit transaction ownership and rollback.
- [ ] Create/update/unchanged/conflict behavior and truthful counters are tested.
- [ ] Idempotency, deduplication, replay, and concurrency are tested.
- [ ] Progress advances only after durable commit and resumes safely.
- [ ] No fabricated cycle, run, checkpoint, watermark, or success is created.
- [ ] Handler retry, backoff, timeout, and source-failure isolation are tested.
- [ ] Scheduled or manual/approval-gated status is an explicit reviewed decision.
- [ ] Scheduled count and manual-only exclusion tests are updated when applicable.
- [ ] Prefect's single-scheduler, pool, cron, concurrency, and pause rules are preserved.
- [ ] Offline, regression, mapper, migration, frontend, and diff checks are recorded.
- [ ] Exact live approval and sanitized end-to-end evidence exist before activation.
- [ ] README, source catalogue, operator, security, test, and limitation docs are current.

## Testing and Validation

Install host dependencies once before the full local test runner:

```powershell
.\run.cmd install
.\run.cmd test
```

The test command runs, in order:

1. all backend pytest tests;
2. frontend Vitest in non-watch mode;
3. Next/TypeScript type generation and `tsc --noEmit`; and
4. the frontend production build.

Useful direct checks are:

```powershell
Set-Location .\backend
.\.venv\Scripts\python.exe -m pytest
.\.venv\Scripts\python.exe -m alembic -c alembic.ini heads
.\.venv\Scripts\python.exe -m alembic -c alembic.ini history
Set-Location ..\frontend
npm run test:run
npm run type-check
npm run build
Set-Location ..
git diff --check
```

The primary final regression evidence is dated **12 August 2026**:

| Validation gate | Literal result |
| --- | --- |
| Full backend pytest | **5,225 passed, 258 skipped, 56 failed, 12 warnings**; nonzero, therefore not a PASS |
| SQLAlchemy mapper validation | **PASS** |
| Alembic graph | **PASS**; exactly one linear head |
| Frontend Vitest | **PASS**; 38 files and 237 tests |
| Frontend type-check | **PASS** |
| Frontend production build | **PASS** |
| `git diff --check` | **PASS**, with Windows LF/CRLF advisories |
| `.\run.cmd test` | Nonzero because the same backend environment/historical limitations stop the aggregate runner |

The 56 backend failures have two distinct classifications and must not be
reported as 56 hash failures:

1. **54 failures** are in `tests/test_c08_pre02_reconciliation.py` because the
   test environment has no `pwsh` executable. PowerShell 7 is unavailable;
   Windows PowerShell 5.1 does not satisfy that test contract.
2. The remaining **2 raw-byte/hash failures** are:
   `tests/test_c08_pre02_reconciliation.py::test_reviewed_sql_hashes_match_final_files`
   (LF/CRLF raw-byte hash) and
   `tests/test_ioc_relationship_migration.py::test_previous_migration_files_are_byte_for_byte_unchanged`
   (historical migration raw-byte hash).

These are accepted environment/historical limitations at this checkpoint, not
a newly demonstrated release regression. They are also not a green backend
suite: report the nonzero result literally. `.\run.cmd test` therefore did not
pass, even though the separately executed mapper, migration, frontend, and diff
gates above passed.

Automated tests do not prove live-source availability, licensing, public TLS,
staging uptime, external load capacity, alert delivery, backup recovery, or
manual accessibility/analyst acceptance.

## Troubleshooting

### Docker or Compose is unavailable

Start Docker Desktop, wait for the daemon, and rerun `.\run.cmd`. If
`docker compose version` fails, install/enable Compose v2. Do not change the
project to an unreviewed container runtime command.

### Missing or invalid environment values

Run `.\run.cmd setup`. It will not overwrite an existing `.env`. If startup
names a missing/unsafe field, edit only that field locally using `.env.example`
as the structural reference. Never paste the value into chat or print the file.
If existing credentials and a named database volume disagree, do not delete the
volume; coordinate role reconciliation or credential rotation.

### A port is occupied

Find the local owner of ports `3000`, `8000`, `4200`, or `5432`:

```powershell
Get-NetTCPConnection -State Listen | Where-Object LocalPort -In 3000,8000,4200,5432
```

Stop the conflicting approved process or configure a reviewed alternative host
port in root `.env`. Do not widen loopback bindings to `0.0.0.0` as a shortcut.

### Database or migration validation fails

Read the sanitized runner message and at most the last 100 database/migration
log lines. The runner blocks unknown revisions, multiple heads, unversioned
application tables, conflicting source identities, and unsafe grants. Preserve
the database, record the current commit/revision, and escalate. Do not edit an
old migration, stamp a revision, drop tables, or delete the volume.

### Backend or frontend is unhealthy

Check `docker compose ps`, then the backend health URL and bounded service logs.
Confirm exact local CORS/Host/API-base configuration. Do not expose stack traces,
environment dumps, cookies, or resolved configuration in an issue.

### First administrator or login fails

Run the bootstrap command only after `.\run.cmd` succeeds. It refuses when a
user already exists. For an existing environment, use **User Access** with an
authorized Administrator to check status, expiry, role, or revoke sessions; do
not rerun bootstrap, modify password hashes, or reset the database. After five
failed logins in the default 15-minute window, the default block is 15 minutes;
the public response remains generic.

### Prefect is unavailable, paused, or not scheduling

Run the read-only verification commands from the fresh setup. Confirm the
server/worker are healthy, the `alpha-data-process` pool and default queue are
ready, the exact deployment exists, and the schedule is active only when
authorized. A paused fresh deployment is expected, not a startup failure.
Closing the browser does not stop Prefect; stopping Docker or the worker does.

### Tests stop at the PowerShell/checkout boundary

At the 12 August 2026 checkpoint, 54 reconciliation tests fail because `pwsh`
(PowerShell 7) is unavailable; Windows PowerShell 5.1 is not a substitute for
that executable contract. Two additional tests fail on reviewed raw bytes: one
LF/CRLF SQL hash and one historical migration hash. Record exact node IDs and
environment evidence, and do not classify a different failure as known without
proof. Run separately labeled complementary validation; never weaken or skip an
assertion merely to obtain a green total.

## Defensive, Ethical, and Security Boundary

Use Alpha Data only for defensive, ethical, authorized, educational, or
lab-safe work. It must not be used for exploit execution, unauthorized scanning
or probing, credential theft, phishing, malware retrieval/delivery,
persistence, stealth/evasion, control bypass, or attacks against real systems.

External OSINT is untrusted data. Fixed developer-controlled sources, bounded
clients, schemas, normalizers, transaction controls, response allow-lists, and
safe rendering reduce risk. Registry inclusion does not grant collection
authorization, licensing permission, API access, storage rights, or
redistribution rights. Any new source requires current terms/robots/rate review,
explicit approval, fixed endpoint policy, offline fixtures/tests, secure
configuration, independent review, and bounded staging validation.

## Production and Staging Boundary

Local startup is not production deployment. The production-oriented package
adds Caddy edge policy, private networks, non-root containers, capability drops,
secret-file references, bounded logs, monitoring configuration, encrypted
backup, and isolated restore/rehearsal tooling. Deployment still requires an
approved external host, protected credentials, DNS/TLS, firewall/routing,
deployed migration evidence, mentor accounts, UAT, monitoring/alert ownership,
off-host backup storage, and recovery evidence.

Do not improvise a public deployment from the local commands in this README.
Use the protected production procedure and task-specific approval.

## Known Limitations

- The local schedule stops when the PC, Docker, Prefect server, or worker stops.
- No mentor-accessible external staging environment, public DNS/certificate
  evidence, or always-on uptime is claimed.
- External alert delivery, centralized off-host logs, approved off-host backup
  transfer, staging recovery measurements, and staging UAT remain external
  operator dependencies.
- Production load, capacity, failover, high availability, autoscaling,
  zero-downtime deployment, and public-internet operation are not validated.
- Prefect is a single local server/worker baseline, not a high-availability
  control plane; the local UI has no separate login and is protected by
  loopback binding.
- Authentication is local single-factor; rate limiting is process-local.
- Manual/commercial and approval-gated sources may require explicit approval,
  credentials, licence, payment, entitlement, or quota. Until those gates are
  satisfied they do not provide comprehensive coverage or freshness. Bounded
  runs may truthfully be partial, capped, deferred, or failed.
- Publication ingestion stores selected metadata, not complete article bodies,
  PDFs, attachments, malware, scan results, or arbitrary binaries.
- The final backend run has 54 accepted environment failures because PowerShell
  7 (`pwsh`) is unavailable; Windows PowerShell 5.1 does not satisfy those
  reconciliation tests.
- Two additional accepted historical raw-byte/hash failures remain: the
  reviewed SQL LF/CRLF hash and the byte-for-byte historical IOC relationship
  migration hash. They are separate from the 54 `pwsh` failures.
- Strict cron-slot validation is intentional. A manually launched parent flow
  outside minute 17 of an eligible Dubai two-hour slot can correctly fail slot
  validation, so an off-cron parent run is not the normal validation method.
- Manual QA and formal assistive-technology testing require separately recorded
  human evidence.

## Deeper Reference Documents

This README is sufficient for first setup and product understanding. Use these
documents for exact specialist contracts and historical evidence:

| Topic | Reference |
| --- | --- |
| Full operator procedures and handover checklist | [Operator guide](docs/operator-guide.md) |
| Variable-by-variable configuration and secret rules | [Environment and secrets](docs/environment-and-secrets.md) |
| Source endpoints, bounds, status, and limitations | [Data sources](docs/data-sources.md) |
| Detailed components, flows, and trust boundaries | [Architecture](docs/architecture.md) |
| Security controls and accepted limitations | [Security notes](docs/security-notes.md) |
| Automated validation strategy | [Testing plan](docs/testing-plan.md) |
| Human-executed validation cases | [Manual test cases](docs/manual-test-cases.md) |
| Protected deployment procedure | [Production Docker deployment](docs/production-docker-deployment.md) |
| Recovery safety gates | [C09 recovery runbook](docs/c09-recovery-runbook.md) |
| Backend CLI/development details | [Backend README](backend/README.md) |
| Frontend development details | [Frontend README](frontend/README.md) |
| Current external deployment status | [Deployment notes](docs/deployment-notes.md) |
| Historical release test evidence | [Final mentor report](docs/final-mentor-report.md) |
| Historical architecture handover snapshot | [Final architecture package](docs/final-architecture-package.md) |

Historical documents are checkpoint-scoped. Earlier PAUSED or unbound-handler
statements describe their recorded checkpoint and are not current operating
instructions. Current operation must be reconciled with the code, this README,
and the approved change record.
