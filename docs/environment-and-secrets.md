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
ingestion endpoint.

APR-10 remains **Need Approval**. B1-01 selects no secret-management provider,
implements no provider-specific delivery mechanism, requests no credentials,
and makes no staging or production deployment claim. Until a later approved
task defines delivery, credential-dependent approval-gated integrations remain
disabled and make no external request.

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
| `BACKEND_BIND_ADDRESS` | Production Compose | Optional | Sensitive configuration | Runtime | Host interface for publishing the backend; safe default is `127.0.0.1`. | Keep loopback-bound when an approved TLS terminator fronts the service. |
| `FRONTEND_BIND_ADDRESS` | Production Compose | Optional | Sensitive configuration | Runtime | Host interface for publishing the frontend; safe default is `127.0.0.1`. | Review before widening the bind address. |
| `POSTGRES_HOST` | Backend, development Compose | Conditional | Sensitive configuration | Runtime | Database host; local host example is `localhost`, while containers use the service name `db`. | Must be a bare DNS name, canonical IP address, or documented bracketed IPv6 representation. Schemes, credentials, paths, ports, control characters, and ambiguous numeric forms are rejected. |
| `POSTGRES_PORT` | Backend, development Compose | Conditional | Sensitive configuration | Runtime | Database port, normally `5432`. | Must be 1–65535; production Compose fixes the container value to 5432. |
| `POSTGRES_DB` | PostgreSQL, backend, migration workflow | Required by production Compose; otherwise conditional | Sensitive configuration | Runtime | Database name, for example `cyber_osint`. | Must be a 1–63 character unquoted PostgreSQL identifier using letters, digits, and underscores, beginning with a letter or underscore. |
| `POSTGRES_USER` | PostgreSQL, backend, migration workflow | Required by production Compose; otherwise conditional | Sensitive configuration | Runtime | PostgreSQL initialization role name. The official image grants this role superuser privileges, and current Compose reuses it for backend and migration access. | Uses the same strict identifier syntax as `POSTGRES_DB`; tightly restrict access to its credential. |
| `POSTGRES_PASSWORD` | Backend and development Compose | Local/test component configuration only | Secret value; backend-only | Runtime | Generate a unique random local or isolated-test credential. | Held as `SecretStr`. It is rejected in staging and production, and cannot be combined with `POSTGRES_PASSWORD_FILE`. |
| `POSTGRES_PASSWORD_FILE` | PostgreSQL image, backend, migration workflow | Required in staging/production | Non-secret file reference | Runtime | Container path to the mounted password file; production Compose fixes it to `/run/secrets/postgres_password`. | Must reference a readable regular file of 1–4096 bytes after terminal CR/LF removal. Empty, NUL-containing, oversized, missing, and non-file inputs fail closed without exposing path or content. |
| `POSTGRES_PASSWORD_SECRET_FILE` | Production Compose host | Required by production Compose | Non-secret host file reference | Compose deployment | Absolute path to the protected host password file. | Compose mounts the same secret read-only into PostgreSQL, backend, and migration containers; the password value is never placed in their environment metadata. |
| `DATABASE_URL` | Repository runner, backend, Alembic | Optional local/test alternative to component fields | Secret value; backend-only | Runtime | Do not place a credential-bearing example in documentation. | Local/test only. It has explicit precedence over component fields and accepts only complete PostgreSQL/psycopg URLs. It is rejected in staging and production. |
| `BACKEND_CORS_ALLOWED_ORIGINS` | Backend, production Compose | Explicit in staging/production; bounded default locally/test | Backend-only sensitive configuration | Runtime | Comma-separated exact origins, for example `https://dashboard.example.invalid`. | No wildcard, path, query, fragment, credentials, control character, or empty entry. Staging/production require non-loopback HTTPS. |
| `BACKEND_TRUSTED_HOSTS` | Backend, production Compose | Explicit in staging/production; bounded default locally/test | Backend-only sensitive configuration | Runtime | Exact comma-separated hostnames such as `api.example.invalid`. | Configuration rejects wildcards, schemes, ports, paths, credentials, malformed/empty entries, ambiguous numeric forms, and protected-environment loopback or unspecified hosts without DNS resolution. Runtime requires exactly one Host header, accepts case-insensitive DNS or canonical IP with an optional valid decimal port, compares the normalized host exactly, and returns a fixed `400` without redirecting or echoing rejected input. |
| `NEXT_PUBLIC_API_BASE_URL` | Frontend, Docker Compose | Required for staging/production builds; bounded fallback locally/test | Public configuration | Build time | Browser-visible backend base URL, for example `https://api.example.invalid`. | Credential-bearing URLs, non-HTTP(S), query/fragment values, and protected-environment HTTP, loopback, or unspecified hosts are rejected; trailing slashes are normalized. |
| `NVD_API_KEY` | Approved manual NVD ingestion and smoke test | Conditional | Secret | Runtime | Leave blank when unused; provide only for an explicitly approved manual NVD command. | Masked by backend settings. It is not supplied by production Compose and does not activate ingestion. |
| `FETCH_INTERVAL_MINUTES` | Backend settings | Optional | Non-secret operational configuration | Runtime | Operational interval placeholder, currently `30`. | The settings model accepts an integer. The current application has no scheduler and does not consume this field to start recurring work. |
| `ENABLE_ADMIN_INGESTION` | Backend settings, Compose | Optional locally/test; mandatory `false` in staging/production | Backend-only sensitive security control | Runtime | Safe value is `false`. | The current API exposes no ingestion route. This flag neither schedules nor starts ingestion; staging/production reject `true`. |
| `IMAGE_TAG` | Production Compose | Optional | Non-secret deployment configuration | Compose build and startup | Reviewable image tag, for example `p7-01`. | Used only in backend/frontend image names. |

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

### Current database-role limitation

The official PostgreSQL image creates the configured `POSTGRES_USER`
initialization role with superuser privileges. Current production Compose reuses
that privileged role for PostgreSQL initialization, normal backend access, and
the migration workflow; it does not provision a separate restricted application
role. Provisioning a non-superuser application role with only the required
permissions is future work and requires a separately reviewed database and
deployment change outside P7-02. This documentation does not implement or
automate that change.

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
- Store the database password itself in a separate protected regular file and
  put only its path in `POSTGRES_PASSWORD_SECRET_FILE`. Production Compose
  mounts that file into each authorized consumer.
- APR-10 remains `Need Approval`; no secret-management provider or credential
  delivery mechanism has been selected or approved.
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
rotation. Its password-file secret protects the privileged initialization role
that is also used by the backend and migration workflow. Updating the value in
an environment file does not change an existing role stored in the persistent
database volume. Coordinate an approved database-administration password change
with the secret update, service restart or redeployment, health verification,
and old-credential revocation. Do not delete the database volume as a rotation
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
