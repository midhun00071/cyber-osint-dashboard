# P7-02 Environment and Secret Handling

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

## Variable reference

Required and conditional status is contextual: production Compose requirements
are stricter than local defaults. “Sensitive configuration” is not itself a
credential, but it can reveal topology or weaken a security boundary and should
still be shared only when needed.

| Variable | Component | Requirement | Exposure | Evaluation | Purpose and safe placeholder | Validation notes |
| --- | --- | --- | --- | --- | --- | --- |
| `APP_NAME` | Backend, production Compose | Optional | Public configuration | Runtime | Service display name, for example `Cyber OSINT Dashboard`. | Trimmed; blank values are rejected by settings normalization. |
| `APP_VERSION` | Backend, production Compose | Optional | Public configuration | Runtime | Public version metadata, for example `0.1.0`. | Length must be 1–64 characters. |
| `APP_ENV` | Backend | Optional locally; fixed in production Compose | Public configuration | Runtime | Environment label such as `development` or `production`. | The health response exposes this label. Production activates stricter CORS and debug validation. |
| `DEBUG` | Backend | Optional locally; fixed `false` in production Compose | Sensitive configuration | Runtime | Framework debug control; safe example is `false`. | `true` is rejected when `APP_ENV=production`. |
| `LOG_LEVEL` | Backend, migration workflow | Optional | Sensitive configuration | Runtime | Logging threshold; safe example is `INFO`. | Allowed values are `DEBUG`, `INFO`, `WARNING`, `ERROR`, and `CRITICAL`; invalid input is rejected without echoing it. |
| `BACKEND_HOST` | Backend settings | Optional | Local development value | Runtime | Bind address accepted by settings, for example `0.0.0.0`. | Current repository launch commands set their own host explicitly. |
| `BACKEND_PORT` | Backend settings, Docker Compose | Optional | Local/deployment configuration | Runtime | Backend host-port override, for example `8000`. | The current settings field accepts an integer; Compose and the server still require a valid available TCP port. Production maps the selected host port to container port 8000. |
| `FRONTEND_PORT` | Docker Compose | Optional | Local/deployment configuration | Runtime | Frontend host-port override, for example `3000`. | Production maps it to container port 3000. |
| `BACKEND_BIND_ADDRESS` | Production Compose | Optional | Sensitive configuration | Runtime | Host interface for publishing the backend; safe default is `127.0.0.1`. | Keep loopback-bound when an approved TLS terminator fronts the service. |
| `FRONTEND_BIND_ADDRESS` | Production Compose | Optional | Sensitive configuration | Runtime | Host interface for publishing the frontend; safe default is `127.0.0.1`. | Review before widening the bind address. |
| `POSTGRES_HOST` | Backend, development Compose | Conditional | Sensitive configuration | Runtime | Database host; local host example is `localhost`, while containers use the service name `db`. | Required with the other component fields when `DATABASE_URL` is absent; production Compose fixes it to `db`. |
| `POSTGRES_PORT` | Backend, development Compose | Conditional | Sensitive configuration | Runtime | Database port, normally `5432`. | Must be 1–65535; production Compose fixes the container value to 5432. |
| `POSTGRES_DB` | PostgreSQL, backend, migration workflow | Required by production Compose; otherwise conditional | Sensitive configuration | Runtime | Database name, for example `cyber_osint`. | Required with component fields when `DATABASE_URL` is absent. |
| `POSTGRES_USER` | PostgreSQL, backend, migration workflow | Required by production Compose; otherwise conditional | Sensitive configuration | Runtime | PostgreSQL initialization role name. The official image grants this role superuser privileges, and current Compose reuses it for backend and migration access. | Treat the username as sensitive and tightly restrict access to its credential. |
| `POSTGRES_PASSWORD` | PostgreSQL, backend, migration workflow | Required by production Compose; otherwise conditional | Secret | Runtime | Generate a unique random credential; examples use blank or `replace_with_local_secret`. | Protects the privileged initialization and runtime role in current Compose. Production Compose has no default and rejects missing or empty input. Never log or place it in a URL in documentation. |
| `DATABASE_URL` | Repository runner, backend, Alembic | Optional alternative to component fields | Secret | Runtime | Structural format only: `postgresql+psycopg://<user>:<password>@<host>:<port>/<database>`. | Takes precedence over all `POSTGRES_*` fields. Only `postgresql` and `postgresql+psycopg` schemes are accepted. It is a credential secret; when it uses the current Compose role, it carries privileged database access, although other deployments may use a restricted role. Prefer component fields where practical. |
| `BACKEND_CORS_ALLOWED_ORIGINS` | Backend, production Compose | Required by production Compose; optional with safe local defaults in development | Sensitive configuration | Runtime | Comma-separated exact origins, for example `https://dashboard.example.com`. | No wildcard, path, query, fragment, user information, control character, empty entry, or port 0. Production requires non-loopback HTTPS origins. |
| `NEXT_PUBLIC_API_BASE_URL` | Frontend, Docker Compose | Required for the production image build; optional locally | Public configuration | Build time in production; development-server startup locally | Browser-visible backend base URL, for example `https://api.example.com`. | Every `NEXT_PUBLIC_*` value is delivered to browser code and must never contain a secret. Rebuild the frontend image after changing it. |
| `NVD_API_KEY` | Approved manual NVD ingestion and smoke test | Conditional | Secret | Runtime | Leave blank when unused; provide only for an explicitly approved manual NVD command. | Masked by backend settings. It is not supplied by production Compose and does not activate ingestion. |
| `FETCH_INTERVAL_MINUTES` | Backend settings | Optional | Non-secret operational configuration | Runtime | Operational interval placeholder, currently `30`. | The settings model accepts an integer. The current application has no scheduler and does not consume this field to start recurring work. |
| `ENABLE_ADMIN_INGESTION` | Backend settings, Compose | Optional | Sensitive security control | Runtime | Safe value is `false`. | The current API exposes no ingestion route. This flag neither schedules nor starts ingestion; the committed examples and production Compose use `false`. Development Compose has an inert local default of `true` when no root `.env` override is supplied. |
| `IMAGE_TAG` | Production Compose | Optional | Non-secret deployment configuration | Compose build and startup | Reviewable image tag, for example `p7-01`. | Used only in backend/frontend image names. |

Developer validation commands may temporarily set `TEMP` and `TMP` to a fresh
directory outside the repository and clear `PYTEST_ADDOPTS` so local user
options cannot change the requested test gate. `TEMP`, `TMP`, `PYTEST_ADDOPTS`,
`NODE_PATH`, and `CD` are tooling or operating-system controls, not application
configuration and do not belong in project `.env` files.

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

## Secret storage

### Local development

- Copy only the relevant example and replace placeholders in the ignored local
  file. Do not maintain multiple unnecessary copies of the same credential.
- Restrict file access to the developer account and approved local tooling.
- Prefer component database fields over a credential-bearing `DATABASE_URL`.
- Do not paste secrets directly into commands when that would retain them in
  PowerShell history, process listings, terminal capture, or screenshots.

### Docker Compose validation

- Use synthetic validation credentials and a dedicated environment file outside
  the repository and review package.
- Restrict the file to the validation session and isolated Compose project.
- Never print `docker compose config` without controlling whether interpolation
  could expose a resolved value; use `config --quiet` for structural checks.

### Production and CI/CD

- Prefer the deployment platform’s protected secret store or CI/CD secret
  settings, using a least-privilege service identity and the smallest authorized
  audience.
- If an external production environment file is unavoidable, store it outside
  source control, restrict filesystem permissions, back it up only through an
  approved encrypted process, and exclude it from review artifacts.
- The repository does not currently integrate with a specific cloud secret
  manager, Vault product, CI/CD injector, or automated rotation service.
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
rotation. Its `POSTGRES_PASSWORD` protects the privileged initialization role
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
