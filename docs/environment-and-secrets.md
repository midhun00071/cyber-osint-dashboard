# B1-01 Environment and Secret-Management Boundaries

## Purpose and scope

Environment configuration is kept separate from source code. Committed example
files contain only safe local values, blank secret fields, or unmistakably
non-operational placeholders. Real values must never be committed, copied into
documentation, uploaded for review, or exposed in logs and chat output.

This document is the authoritative reference for environment-variable names,
classification, lifecycle, storage, and rotation. The project remains defensive
and manual-ingestion focused. FastAPI startup does not run ingestion, and the
repository has no active scheduler, background ingestion job, or public
ingestion endpoint. C01 defines a paused-by-default Prefect deployment, but no
schedule was activated and the production source-handler registry is empty.

APR-10 is a team-owned decision and does not require separate mentor approval.
B1-01 selects no secret-management provider, implements no provider-specific
delivery mechanism, requests no credentials, and makes no staging or production
deployment claim. Team ownership is not implementation or deployment evidence:
a selected provider or delivery baseline still requires task-specific secure
implementation, validation, deployment, and activation evidence. Until that
work exists, credential-dependent integrations remain disabled and make no
external request. No secret value may be committed or documented.

## Configuration file hierarchy

| File | Intended use | Consumer |
| --- | --- | --- |
| `.env.example` | Template for a repository-root `.env` used by the development `docker-compose.yml` workflow. | Docker Compose interpolation; values are passed to PostgreSQL, backend, and frontend containers. |
| `backend/.env.example` | Template for `backend/.env` when the backend or a manual backend CLI runs from `backend`. | Pydantic `Settings`, Alembic, database sessions, and approved manual ingestion commands. |
| `frontend/.env.example` | Template for `frontend/.env.local` during local Next.js work. | Next.js development and build processes. |
| `.env.production.example` | Placeholder-only template for an external production environment file. Do not complete it inside the repository. | `compose.prod.yml` through an explicit `--env-file` argument. |

Real root `.env`, `backend/.env`, and `frontend/.env.local` files are ignored by
Git. A completed production file must live outside the repository with access
limited to the deployment operator or service account. Process environment
values take precedence when the configuration library or Compose provides an
override.

`run.cmd dev` starts PostgreSQL through development Compose, then starts the
backend from `backend` and the frontend from `frontend`. The backend therefore
loads `backend/.env`; the runner also accepts a process-level `DATABASE_URL` and
temporarily rewrites only the Compose host name `db` to `localhost` for the host
backend without printing the URL.

## Environment matrix

`APP_ENV` accepts exactly `local`, `test`, `staging`, or `production`, after
trimming surrounding whitespace and normalizing case. `development` is retained
only as a documented compatibility alias for `local`; all security decisions
use the effective `local` identity. Blank and unknown values are rejected and
never fall through to a convenience environment.

| Boundary | Database | CORS and trusted hosts | Debug/admin behavior | Frontend public configuration |
| --- | --- | --- | --- | --- |
| `local` | Complete `POSTGRES_*` components or a valid PostgreSQL `DATABASE_URL` are required before backend availability. A direct `POSTGRES_PASSWORD` remains supported. | Bounded loopback defaults are allowed. `testserver` is included only for the in-process FastAPI test client. | `DEBUG` may be selected for local diagnosis; `ENABLE_ADMIN_INGESTION` does not create or activate a route. Committed defaults are `false`. Reload exists only in `run.cmd dev`. | `APP_ENV=local` is the build identity and `NEXT_PUBLIC_API_BASE_URL` may fall back to `http://localhost:8000`. |
| `test` | Synthetic complete database settings are required for application startup; unit settings tests may validate individual fields without starting the application. | The same bounded loopback/test defaults are allowed. | Test-only behavior is allowed; no fake-success fallback is permitted. | The documented loopback fallback is allowed. Tests use synthetic values only. |
| `staging` | Explicit component database configuration and `POSTGRES_PASSWORD_FILE` are required. Direct `DATABASE_URL` and `POSTGRES_PASSWORD` values are rejected. | Explicit non-loopback HTTPS CORS origins and explicit non-wildcard, non-loopback trusted hosts are required. | `DEBUG=false` and `ENABLE_ADMIN_INGESTION=false` are mandatory. Invalid configuration stops startup. | Explicit `APP_ENV=staging` and a credential-free, non-loopback HTTPS `NEXT_PUBLIC_API_BASE_URL` are required at build time. |
| `production` | Same file-referenced, fail-closed database contract as staging; local/test direct-secret values are rejected. | Same explicit HTTPS CORS and trusted-host contract as staging. | `DEBUG=false`, `ENABLE_ADMIN_INGESTION=false`, no reload, and no development error page. | Explicit `APP_ENV=production` and the same non-loopback HTTPS build-time contract as staging. |

Backend settings are validated when FastAPI is imported, before the application
can report availability. This eager startup validation constructs the
SQLAlchemy URL without connecting to the database. Validation failures name
only the affected setting or category and never include a rejected value,
credential-bearing URL, secret value, raw settings object, or raw exception.

## Variable reference

Required and conditional status is contextual: production Compose requirements
are stricter than local defaults. “Sensitive configuration” is not itself a
credential, but it can reveal topology or weaken a security boundary and should
still be shared only when needed.

| Variable | Component | Requirement | Exposure | Evaluation | Purpose and safe placeholder | Validation notes |
| --- | --- | --- | --- | --- | --- | --- |
| `APP_NAME` | Backend, production Compose | Optional | Public configuration | Runtime | Service display name, for example `Cyber OSINT Dashboard`. | Trimmed; blank values are rejected by settings normalization. |
| `APP_VERSION` | Backend, production Compose | Optional | Public configuration | Runtime | Public version metadata, for example `0.1.0`. | Length must be 1–64 characters. |
| `APP_ENV` | Backend and frontend build | Defaults to `local`; fixed in production Compose | Non-secret operational configuration | Runtime for backend; build time for frontend | One of `local`, `test`, `staging`, or `production`; `development` is a compatibility alias for `local`. | Blank/unknown input is rejected. The frontend build injects the canonical identity as `NEXT_PUBLIC_APP_ENV` so browser validation uses the same boundary. The backend health response remains `not-disclosed`. |
| `DEBUG` | Backend | Optional locally; fixed `false` in production Compose | Backend-only sensitive configuration | Runtime | Framework debug control; safe example is `false`. | `true` is rejected in staging and production. |
| `LOG_LEVEL` | Backend, migration workflow | Optional | Sensitive configuration | Runtime | Logging threshold; safe example is `INFO`. | Allowed values are `DEBUG`, `INFO`, `WARNING`, `ERROR`, and `CRITICAL`; invalid input is rejected without echoing it. |
| `BACKEND_HOST` | Backend settings | Optional | Local development value | Runtime | Bind address accepted by settings, for example `0.0.0.0`. | Current repository launch commands set their own host explicitly. |
| `BACKEND_PORT` | Backend settings, Docker Compose | Optional | Local/deployment configuration | Runtime | Backend host-port override, for example `8000`. | The current settings field accepts an integer; Compose and the server still require a valid available TCP port. Production maps the selected host port to container port 8000. |
| `FRONTEND_PORT` | Docker Compose | Optional | Local/deployment configuration | Runtime | Frontend host-port override, for example `3000`. | Production maps it to container port 3000. |
| `PREFECT_PORT` | Development Compose | Optional | Local development configuration | Runtime | Loopback host port for local Prefect administration; default `4200`. | The bind address is fixed to `127.0.0.1`. Production publishes no Prefect host port and does not consume this variable. |
| `PREFECT_METADATA_ADMIN_PASSWORD` | Development Compose `prefect-db` | Optional local override | Secret value | Initialization | Local-only bootstrap/administration credential for the dedicated Prefect metadata database. Use a unique generated value in an ignored root `.env` when the local metadata volume is not disposable. | Compose passes it only as the fixed `prefect_bootstrap` role's `POSTGRES_PASSWORD`. The committed fallback is a local-development placeholder, is not supplied to the Prefect server or worker, and must never be reused in staging or production. Changing the environment value after database initialization does not rotate the stored role password. |
| `PREFECT_POSTGRES_PASSWORD` | Development Compose `prefect-db` and `prefect-server` | Optional local override | Secret value | Initialization and runtime | Local-only credential for the dedicated non-superuser Prefect metadata runtime role. Use a unique generated value distinct from the bootstrap credential in an ignored root `.env` when the local metadata volume is not disposable. | Compose maps the same value to the initializer's `PREFECT_RUNTIME_PASSWORD` and the server's `PREFECT_SERVER_DATABASE_PASSWORD`; the worker does not receive it. The committed fallback is a local-development placeholder and must never be reused in staging or production. |
| `PREFECT_RUNTIME_USER` | Development Compose `prefect-db` | Fixed internal container configuration | Non-secret local platform configuration | Initialization and health check | Fixed `prefect_runtime` login provisioned for the local Prefect server. | It is a literal Compose value, not an independent operator override. The initialization script validates it as a PostgreSQL identifier and requires it to differ from the fixed bootstrap identity. |
| `PREFECT_RUNTIME_PASSWORD` | Development Compose `prefect-db` | Fixed internal secret mapping | Secret value | Initialization and health check | Container-internal name that receives `PREFECT_POSTGRES_PASSWORD` for runtime-role provisioning and metadata-database health checks. | It is not an independent operator input. The initialization script requires 1–4096 bytes with no line feed or carriage return, and the health check uses the same mapping without printing it. |
| `PREFECT_RUNTIME_DB` | Development Compose `prefect-db` | Fixed internal container configuration | Non-secret local platform configuration | Initialization and health check | Fixed `prefect` database owned by the local `prefect_runtime` role. | It is a literal Compose value, not an independent operator override, and the initialization script validates it as a PostgreSQL identifier. |
| `BACKEND_BIND_ADDRESS` | Production Compose | Optional | Sensitive configuration | Runtime | Host interface for publishing the backend; safe default is `127.0.0.1`. | Keep loopback-bound when an approved TLS terminator fronts the service. |
| `FRONTEND_BIND_ADDRESS` | Production Compose | Optional | Sensitive configuration | Runtime | Host interface for publishing the frontend; safe default is `127.0.0.1`. | Review before widening the bind address. |
| `POSTGRES_HOST` | Backend, development Compose | Conditional | Sensitive configuration | Runtime | Database host; local host example is `localhost`, while containers use the service name `db`. | Must be a bare DNS name, canonical IP address, or documented bracketed IPv6 representation. Schemes, credentials, paths, ports, control characters, and ambiguous numeric forms are rejected. |
| `POSTGRES_PORT` | Backend, development Compose | Conditional | Sensitive configuration | Runtime | Database port, normally `5432`. | Must be 1–65535; production Compose fixes the container value to 5432. |
| `POSTGRES_DB` | PostgreSQL, backend, migration workflow | Required by production Compose; otherwise conditional | Sensitive configuration | Runtime | Database name, for example `cyber_osint`. | Must be a 1–63 character unquoted PostgreSQL identifier using letters, digits, and underscores, beginning with a letter or underscore. |
| `POSTGRES_USER` | Backend, Prefect worker, and local development | Conditional | Sensitive configuration | Runtime | Runtime application login for local/backend/worker execution. | Uses strict PostgreSQL identifier syntax. Production Compose maps `POSTGRES_APP_USER` into this application setting. |
| `POSTGRES_BOOTSTRAP_USER` | PostgreSQL image | Required by production Compose; local placeholder available | Sensitive configuration | Initialization/administration | Bootstrap identity used only by the PostgreSQL container to initialize and administer roles. | Must differ from application and migration identities. The official image may give this identity administrative privileges; backend and migration never receive its credential. |
| `POSTGRES_APP_USER` | PostgreSQL role provisioning, production backend, and Prefect worker | Required by production Compose | Sensitive configuration | Runtime | Least-privilege runtime application identity. | Non-superuser with schema `USAGE`, required DML only, no DDL, no schema creation, no truncate, no role administration, and no deletion. |
| `POSTGRES_MIGRATION_USER` | Role provisioning and migration service | Required by production Compose | Sensitive configuration | Manual migration | Separate non-superuser migration identity that owns/manages application schema objects. | Never supplied to the runtime backend. |
| `POSTGRES_PASSWORD` | Backend and development Compose | Local/test application credential only | Secret value; backend-only | Runtime | Generate a unique random local or isolated-test application credential. | Held as `SecretStr`. It is rejected in staging and production, and cannot be combined with `POSTGRES_PASSWORD_FILE`. |
| `POSTGRES_BOOTSTRAP_PASSWORD` | Local development PostgreSQL | Local development placeholder only | Secret value | Initialization | Development-only bootstrap credential. | Never use the committed placeholder in staging or production. |
| `POSTGRES_MIGRATION_PASSWORD` | Local migration workflow | Local development placeholder only | Secret value | Manual migration | Development-only migration credential. | Never use the committed placeholder in staging or production. |
| `POSTGRES_PASSWORD_FILE` | Backend, Prefect worker, or migration process | Required in staging/production | Non-secret file reference | Runtime | Container path to that process's mounted role-specific password file. | Must reference a readable regular file of 1–4096 bytes after terminal CR/LF removal. Empty, NUL-containing, oversized, missing, and non-file inputs fail closed without exposing path or content. |
| `POSTGRES_BOOTSTRAP_PASSWORD_SECRET_FILE` | Production Compose host | Required | Non-secret host file reference | Compose deployment | Protected bootstrap-password file mounted only to PostgreSQL. | No checked-in default; absence fails Compose interpolation. |
| `POSTGRES_APP_PASSWORD_SECRET_FILE` | Production Compose host | Required | Non-secret host file reference | Compose deployment | Protected application-password file mounted to PostgreSQL provisioning, backend, and Prefect worker only. | No checked-in default; not mounted to migration or Prefect server. |
| `POSTGRES_MIGRATION_PASSWORD_SECRET_FILE` | Production Compose host | Required | Non-secret host file reference | Compose deployment | Protected migration-password file mounted to PostgreSQL provisioning and migration only. | No checked-in default; not mounted to backend. |
| `DATABASE_URL` | Repository runner, backend, Alembic | Optional local/test alternative to component fields | Secret value; backend-only | Runtime | Do not place a credential-bearing example in documentation. | Local/test only. It has explicit precedence over component fields and accepts only complete PostgreSQL/psycopg URLs. It is rejected in staging and production. |
| `DATABASE_POOL_SIZE` | Backend, Prefect worker, and migration settings | Optional | Non-secret operational configuration | Runtime | SQLAlchemy persistent pool size; default `5`. | Strict integer `1..20`; booleans, floats and unsafe string coercion are rejected. |
| `DATABASE_MAX_OVERFLOW` | Backend, Prefect worker, and migration settings | Optional | Non-secret operational configuration | Runtime | Temporary connections above pool size; default `5`. | Strict integer `0..20`; combined pool plus overflow cannot exceed `30`. |
| `DATABASE_POOL_TIMEOUT_SECONDS` | Backend, Prefect worker, and migration settings | Optional | Non-secret operational configuration | Runtime | Maximum pool checkout wait; default `30`. | Strict integer `1..60`; exhaustion fails instead of waiting indefinitely. |
| `DATABASE_POOL_RECYCLE_SECONDS` | Backend, Prefect worker, and migration settings | Optional | Non-secret operational configuration | Runtime | Connection recycle age; default `1800`. | Strict integer `60..3600`. |
| `DATABASE_CONNECT_TIMEOUT_SECONDS` | Backend, Prefect worker, and migration settings | Optional | Non-secret operational configuration | Runtime | PostgreSQL connection establishment timeout; default `10`. | Strict integer `1..30`. |
| `BACKEND_CORS_ALLOWED_ORIGINS` | Backend, Prefect worker, production Compose | Explicit in staging/production; bounded default locally/test | Backend-only sensitive configuration | Runtime | Comma-separated exact origins, for example `https://dashboard.example.invalid`. | No wildcard, path, query, fragment, credentials, control character, or empty entry. Staging/production require non-loopback HTTPS. The worker supplies this only for the shared protected settings model; it exposes no HTTP API. |
| `BACKEND_TRUSTED_HOSTS` | Backend, Prefect worker, production Compose | Explicit in staging/production; bounded default locally/test | Backend-only sensitive configuration | Runtime | Exact comma-separated hostnames such as `api.example.invalid`. | Configuration rejects wildcards, schemes, ports, paths, credentials, malformed/empty entries, ambiguous numeric forms, and protected-environment loopback or unspecified hosts without DNS resolution. Runtime requires exactly one Host header, accepts case-insensitive DNS or canonical IP with an optional valid decimal port, compares the normalized host exactly, and returns a fixed `400` without redirecting or echoing rejected input. The worker supplies this only for shared settings validation. |
| `NEXT_PUBLIC_API_BASE_URL` | Frontend, Docker Compose | Required for staging/production builds; bounded fallback locally/test | Public configuration | Build time | Browser-visible backend base URL, for example `https://api.example.invalid`. | Credential-bearing URLs, non-HTTP(S), query/fragment values, and protected-environment HTTP, loopback, or unspecified hosts are rejected; trailing slashes are normalized. |
| `NVD_API_KEY` | Approved manual NVD ingestion and smoke test | Conditional | Secret | Runtime | Leave blank when unused; provide only for an explicitly approved manual NVD command. | Masked by backend settings. It is not supplied by production Compose and does not activate ingestion. |
| `FETCH_INTERVAL_MINUTES` | Backend settings | Optional | Non-secret operational configuration | Runtime | Operational interval placeholder, currently `30`. | The settings model accepts an integer. The current application has no scheduler and does not consume this field to start recurring work. |
| `ENABLE_ADMIN_INGESTION` | Backend settings, Compose | Optional locally/test; mandatory `false` in staging/production | Backend-only sensitive security control | Runtime | Safe value is `false`. | The current API exposes no ingestion route. This flag neither schedules nor starts ingestion; staging/production reject `true`. |
| `IMAGE_TAG` | Production Compose | Optional | Non-secret deployment configuration | Compose build and startup | Reviewable image tag, for example `p7-01`. | Used only in backend/frontend image names. |

### B2-01/C01 Prefect configuration boundary

The self-hosted Prefect 3.8.1 image, server API address, state location, worker
health server, process work-pool type, and `alpha-data-process` pool name are
fixed platform configuration rather than operator environment inputs. Among
non-secret Prefect platform controls, local Compose exposes only `PREFECT_PORT`;
it changes the loopback host port without widening the fixed `127.0.0.1` bind.
The two local metadata-database secret overrides are documented below.
Production exposes no Prefect host port and consumes none of these local Prefect
database variables.

Development Compose defines two local-only PostgreSQL secret overrides for its
dedicated Prefect metadata database. `PREFECT_METADATA_ADMIN_PASSWORD` supplies
the fixed bootstrap role, while `PREFECT_POSTGRES_PASSWORD` supplies the fixed
non-superuser runtime role and the Prefect server's component-form database
setting. Compose also passes the fixed internal names `PREFECT_RUNTIME_USER`,
`PREFECT_RUNTIME_PASSWORD`, and `PREFECT_RUNTIME_DB` to the metadata container;
they are not three additional operator inputs. No Prefect UI username/password,
API key, or Cloud API URL is defined. These local PostgreSQL credentials do not
provide Prefect UI authentication. Local administration therefore remains
loopback-bound, and the production administration surface must not be published
or routed publicly.

In development, the server stores metadata in the internal-only `prefect-db`
PostgreSQL service and `prefect_postgres_data` volume. It still mounts
`prefect_data` at its explicit `PREFECT_HOME` for writable Prefect state and UI
assets; the earlier SQLite file is retained but is not migrated. The worker
uses the internal self-hosted API, has no metadata-database credential or
network, and does not mount either state volume. Production retains the
separately reviewed SQLite baseline: its server alone mounts `prefect_data`,
joins only `orchestration`, and the worker joins only `orchestration` and
`database`. Do not add a Prefect UI credential, Cloud workspace setting,
database URL, arbitrary API root, or worker-accessible state mount as an
environment override.

C01's worker adds no new database credential. It reuses only the
application-role database configuration already used by the backend. Local
Compose passes the local application role, while production mounts only
`postgres_app_password` and sets `POSTGRES_PASSWORD_FILE`. The server receives
no application, migration, or
bootstrap database setting. The worker receives no migration or bootstrap
identity. `APP_ENV=production`, protected-environment CORS/trusted-host values,
and bounded pool settings are supplied because the worker imports the same
validated application settings boundary.

Flow, deployment, work-pool, cron, timezone, concurrency, retry, stagger, quota,
and progress identities are fixed in application code. They are not environment
overrides. Registration is an explicit command and paused by default; activation
is staging-only and additionally requires complete scheduled handler bindings
and an explicit controlled-evidence confirmation. No environment value alone
activates source execution.

Developer validation commands may temporarily set `TEMP` and `TMP` to a fresh
directory outside the repository and clear `PYTEST_ADDOPTS` so local user
options cannot change the requested test gate. `TEMP`, `TMP`, `PYTEST_ADDOPTS`,
`NODE_PATH`, and `CD` are tooling or operating-system controls, not application
configuration and do not belong in project `.env` files.

Only `NEXT_PUBLIC_API_BASE_URL` and the build-generated
`NEXT_PUBLIC_APP_ENV` identity are approved public frontend configuration.
`NEXT_PUBLIC_DATABASE_URL`, password, API-key, token, authorization, cookie,
session, secret-reference, Prefect-credential, and other unapproved
`NEXT_PUBLIC_*` names fail the build boundary. Backend-only environment
variables may exist in the build process but are never copied into the returned
public configuration object. A public frontend variable must never contain a secret.

The Dockerfiles also set image-internal runtime controls such as `NODE_ENV`,
`HOSTNAME`, `PORT`, `NEXT_TELEMETRY_DISABLED`, `PYTHONUNBUFFERED`, and
`PYTHONDONTWRITEBYTECODE`. They are maintained by the images rather than exposed
as operator inputs, so they are intentionally absent from the example files.

### B1-05 database role separation

B1-05 separates six responsibilities. The bootstrap identity remains inside the
PostgreSQL administration boundary. A distinct migration identity owns or
manages application schema objects. The runtime application identity receives
schema `USAGE`, required table DML and sequence use only: no DDL, no schema
creation, no truncate, no role administration, no ownership and no deletion.
Read-only and logical backup roles receive `SELECT` only. The retention role
receives `SELECT` only on operational evidence used by the dry-run planner and
has no destructive privilege. All non-administrative roles are non-superuser,
cannot create databases or roles, have no replication or RLS-bypass privilege,
and receive no grant option.

The provisioning scripts support fresh initialization and an existing database
at the B1-04 head, revoke public schema creation, transfer application-object
ownership only to the migration identity, and define future-object default
privileges. Running or documenting B1-05 does not mean production roles have
been provisioned. APR-09 is team-owned and requires no separate mentor
approval, but staging/production administration still requires task-specific
implementation, validation, deployment, and activation evidence. Destructive
retention remains disabled until its required safety and recovery evidence
exists.

## Secret ownership, references, and storage

A secret reference is a non-secret identifier that an approved future delivery
mechanism may resolve for an authorized service. A secret value is the
credential itself. References may be recorded only when they reveal no value or
private topology; values must remain outside Git, documentation, frontend
assets, tests (except unmistakable synthetic canaries), screenshots, reports,
and review evidence. Database credentials belong to the database/deployment
owner; source credentials belong to the approved source owner. Each credential
must be scoped to its consuming service and rotated or revoked by its owner.

### Local development

- Copy only the relevant example and replace placeholders in the ignored local
  file. Do not maintain multiple unnecessary copies of the same credential.
- Restrict file access to the developer account and approved local tooling.
- Prefer component database fields over a credential-bearing `DATABASE_URL`.
- Local/test may use one direct password or one password-file reference, never
  both. Staging/production require the file reference and reject direct values.
- Do not paste secrets directly into commands when that would retain them in
  PowerShell history, process listings, terminal capture, or screenshots.

### Docker Compose validation

- Use synthetic validation credentials and a dedicated environment file outside
  the repository and review package.
- Restrict the file to the validation session and isolated Compose project.
- Never print `docker compose config` without controlling whether interpolation
  could expose a resolved value; use `config --quiet` for structural checks.

### Staging, production, and CI/CD

- Prefer the deployment platform’s protected secret store or CI/CD secret
  settings, using a least-privilege service identity and the smallest authorized
  audience.
- If an external production environment file is unavoidable, store it outside
  source control, restrict filesystem permissions, back it up only through an
  approved encrypted process, and exclude it from review artifacts.
- Store bootstrap, application, and migration passwords in separate protected
  regular files and put only their paths in
  `POSTGRES_BOOTSTRAP_PASSWORD_SECRET_FILE`,
  `POSTGRES_APP_PASSWORD_SECRET_FILE`, and
  `POSTGRES_MIGRATION_PASSWORD_SECRET_FILE`. Production Compose mounts each
  file only into its authorized consumers. The application password is shared
  only with the backend and Prefect worker; this is reuse of the existing
  application role, not a new credential.
- APR-10 is team-owned; no secret-management provider or credential-delivery
  mechanism has yet been selected or implemented. Any selection must still meet
  the project security controls and receive task-specific validation,
  deployment, and activation evidence; no secret value may be committed or
  documented.
- The repository does not integrate with a cloud secret manager, Vault product,
  CI/CD injector, or automated rotation service.
- Never pass secrets as Docker build arguments. Build arguments and image layers
  are not secret stores.

## Prohibited handling

Never:

- commit a real `.env`, `.env.local`, or completed production environment file;
- hardcode credentials, tokens, private keys, cookies, or authorization headers
  in source code, tests, Compose, Dockerfiles, or package scripts;
- put a secret in `NEXT_PUBLIC_*`, frontend source, browser storage, or a
  frontend bundle;
- pass secrets through Docker build arguments or bake them into image layers;
- place credential-bearing URLs in documentation, examples, task sheets, daily
  reports, screenshots, review comments, or chat;
- print full environment listings or resolved production Compose output;
- log passwords, API keys, bearer tokens, authorization headers, session
  cookies, complete database URLs, or raw exception data;
- upload a secret-bearing review ZIP or include a real environment file in an
  evidence package; or
- commit a default production password or configure wildcard production CORS.

If a possible real secret is discovered, preserve the evidence, stop normal
work, report only the affected file and secret category, and begin revocation.
Do not copy the value into an issue, report, or chat message.

## Rotation and incident response

For a database password, NVD key, or future approved credential:

1. Generate a unique replacement using an approved secure generator.
2. Update the authorized secret store or protected external environment file.
3. Restart or redeploy only the affected service so it loads the replacement.
4. Verify service health and the required operation without printing either
   credential.
5. Revoke the old credential after the replacement is confirmed.
6. Review sanitized logs and repository history for exposure indicators without
   searching by printing the credential.
7. Record the time, affected component, response, and validation result without
   recording the secret itself.

The current Compose deployment does not automate PostgreSQL role-password
rotation. Rotate one identity at a time: change the database role password
through the privileged initialization role, replace only that identity's
protected password file, restart or redeploy only its consumer, verify service
health or migration access, revoke the old credential, and review sanitized
evidence. Updating a file alone does not change the role stored in the database.
Coordinate every database-administration password change with the secret
update, service restart or redeployment, health verification, and
old-credential revocation. Do not delete the database volume as a rotation
method.

Changing `NEXT_PUBLIC_API_BASE_URL` is configuration replacement, not secret
rotation. Rebuild and redeploy the frontend because the public value is embedded
in browser-delivered assets.

## Safe validation procedures

Confirm the committed templates exist:

```powershell
Test-Path .\.env.example
Test-Path .\.env.production.example
Test-Path .\backend\.env.example
Test-Path .\frontend\.env.example
```

Run the offline documentation and configuration contracts with a fresh external
`TEMP`/`TMP` directory:

```powershell
$ValidationTemp = Join-Path $env:USERPROFILE "pytest-temp-p7-02"
New-Item -ItemType Directory -Path $ValidationTemp -Force | Out-Null
$env:TEMP = $ValidationTemp
$env:TMP = $ValidationTemp
Remove-Item Env:PYTEST_ADDOPTS -ErrorAction SilentlyContinue

.\backend\.venv\Scripts\python.exe -m pytest `
    backend\tests\test_environment_documentation.py `
    backend\tests\test_production_compose.py `
    backend\tests\test_database_config.py `
    backend\tests\test_cors_config.py `
    backend\tests\test_run_script.py `
    -q -p no:cacheprovider
```

Check Git structure without opening real environment files:

```powershell
git diff --check
git status --short
git ls-files | Where-Object {
    $_ -match '(^|[\\/])\.env($|\.)' -and $_ -notmatch '\.example$'
}
```

The last command should return no path. For production Compose, use a controlled
synthetic file outside the repository and validate structure without rendering
resolved configuration:

```powershell
docker compose -f .\compose.prod.yml --env-file $ValidationEnv config --quiet
```

Do not replace `--quiet` with unrestricted resolved output when real values are
loaded.

## Environment lifecycle

- Example templates are committed, reviewed, and changed with the corresponding
  implementation contract.
- Real development files remain local and ignored; production and validation
  values remain external or in an authorized secret store.
- Development, isolated validation, and production must use different
  credentials and may use different non-secret endpoints and ports.
- Backend runtime changes generally require a backend or migration-service
  restart. PostgreSQL credential rotation also requires an approved database
  role change.
- Frontend public build variables require a rebuild and redeployment.
- Completed environment files must never be included in review ZIPs, task
  sheets, reports, screenshots, or uploaded artifacts.

## C09 edge, monitoring, and backup references

Production now requires explicit `EDGE_HOST`, edge bind/ports, same-origin
frontend API URL, exact backend HTTPS origin/Host, and `APP_COMMIT_SHA`. An
optional trustworthy `STORAGE_CAPACITY_BYTES` enables capacity classification;
blank means unknown.

The explicit edge variables are `EDGE_BIND_ADDRESS`, `EDGE_HTTP_PORT`,
`EDGE_HTTPS_PORT`, and `EDGE_TLS_MODE`. Backup policy is configured with
`BACKUP_DESTINATION_ROOT`, `BACKUP_RETENTION_DAILY`,
`BACKUP_RETENTION_WEEKLY`, and `BACKUP_RETENTION_MONTHLY`.

Backup uses separate `POSTGRES_BACKUP_*` and `POSTGRES_RESTORE_*` components,
never `DATABASE_URL`. Passwords, age recipient, and age identity are regular
bounded non-symlink file references. The backup LOGIN is externally provisioned
and must not reuse runtime, migration, bootstrap, or the NOLOGIN backup role.
The corresponding operator references are `POSTGRES_BACKUP_USER`,
`POSTGRES_BACKUP_PASSWORD_SECRET_FILE`, `AGE_RECIPIENT_FILE`, and
`AGE_IDENTITY_FILE`.
The backup destination must exist outside the repository. Alert recipient
credentials are intentionally absent pending owner/provider approval. Follow
the rotation sequence in `c09-production-operations-recovery.md`.
