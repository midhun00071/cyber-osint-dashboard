# P7-03 Production Docker Deployment Guide

## Purpose and audience

This is the production-oriented Docker deployment guide for the Alpha Data
defensive cybersecurity OSINT dashboard. It is written for a developer or
deployment operator who must safely validate, deploy, update, troubleshoot,
stop, or roll back the currently implemented Docker Compose stack.

The guide documents the repository's existing local production-style baseline
and the B1-01 fail-closed configuration boundary.
It does not claim to provide cloud orchestration, TLS termination, automated
backups, monitoring, or enterprise secret management. A real production
deployment must supply those controls outside this repository.

## Deployment modes and boundaries

| Mode | Entry point | Intended use |
| --- | --- | --- |
| Local development | `docker-compose.yml` and `.\run.cmd dev` | PostgreSQL in Docker with reload-enabled backend and frontend processes on the host. |
| Local production-style validation | `compose.prod.yml` | Build and exercise the hardened production images and manual migration workflow on a controlled host. |
| Real production deployment | `compose.prod.yml` plus deployment-environment controls | Operate the same services behind approved TLS, secret management, backup, monitoring, and host-security controls. |
| Destructive maintenance | Separate approved recovery procedure | Any database-volume deletion or destructive schema/data recovery requires verified backups and explicit authorization. |

Do not use `.\run.cmd dev`, `.\run.cmd docker`, the development Compose file,
reload servers, or development environment values as production procedures.

## Architecture summary

The production entry point is `compose.prod.yml`. It is standalone because the
development Compose file intentionally contains local-only defaults, fixed
container names, a published PostgreSQL port, and a single shared network.
Keeping the production definition separate prevents those development settings
from being inherited accidentally and leaves `.\run.cmd dev` unchanged.

The stack contains four services:

- `db`: PostgreSQL 17 with persistent data in the named `postgres_data` volume;
- `backend`: the FastAPI application on container port `8000`;
- `frontend`: the standalone Next.js server on container port `3000`; and
- `migrate`: a manual, one-shot Alembic service enabled only through the
  `migration` profile.

```text
approved TLS proxy / local operator
                 |
       frontend (application network)
                 |
        backend (application + internal database networks)
                 |
     PostgreSQL (internal database network, no host port)

     migrate (manual profile) --------^ database network only
```

Frontend and backend share the `application` network. Backend and PostgreSQL
share the internal `database` network. Frontend cannot join the database
network, and production PostgreSQL is not published to the host. Backend
outbound access exists for separately approved manual operations, but startup
does not collect intelligence or contact external sources.

## Prerequisites

- A reviewed repository checkout at the intended Git commit, with no unexpected
  local changes.
- Git and PowerShell for the documented Windows workflow.
- A running Docker Engine and the Docker Compose v2 plugin (`docker compose`).
  On Windows, confirm Docker Desktop is running and using Linux containers.
- Sufficient host CPU, memory, and disk for PostgreSQL plus two application
  images. Exact minimum resources have not been measured; monitor the controlled
  validation host rather than treating an invented minimum as a guarantee.
- Available loopback host ports `8000` and `3000`, unless reviewed
  `BACKEND_PORT` and `FRONTEND_PORT` overrides are used.
- A protected production environment file outside the repository.

## Environment preparation

The authoritative variable classifications, placeholder rules, storage
requirements, and rotation procedure are documented in
[Environment and secret handling](environment-and-secrets.md). This deployment
guide retains only the variables and commands needed to operate P7-01.

Create the deployment environment file outside the repository. Start from
`.env.production.example`, restrict access to the completed file, and never add
it to Git. The required variables are:

- `POSTGRES_DB`
- `POSTGRES_USER`
- `POSTGRES_PASSWORD_SECRET_FILE`
- `BACKEND_CORS_ALLOWED_ORIGINS`
- `BACKEND_TRUSTED_HOSTS`
- `NEXT_PUBLIC_API_BASE_URL`

`POSTGRES_PASSWORD_SECRET_FILE` contains only the absolute path to a protected
regular file holding the strong deployment password. Compose mounts that file
as `/run/secrets/postgres_password` for PostgreSQL, backend, and migration; it
does not place the password value in container environment metadata. The secret
protects the current privileged initialization and runtime database role; the
security section records that role's known least-privilege limitation.
Direct `POSTGRES_PASSWORD` and credential-bearing `DATABASE_URL` values are not
production inputs and are rejected by the protected backend boundary.
`BACKEND_CORS_ALLOWED_ORIGINS` must contain explicit trusted HTTPS origins; a
wildcard is invalid. `BACKEND_TRUSTED_HOSTS` must contain exact non-loopback
hostnames with no wildcard, scheme, port, path, or credentials.
At runtime the backend requires exactly one Host header. DNS names are compared
case-insensitively; canonical IPv4 and bracketed canonical IPv6 are supported;
and an optional decimal port from 1 through 65535 is validated and then removed
before exact comparison. Missing, duplicate, malformed, ambiguous-numeric, or
unlisted Host values receive a fixed HTTP `400`. The boundary performs no DNS
lookup, suffix or wildcard match, rejected-value echo, or implicit `www.`
redirect.
`NEXT_PUBLIC_API_BASE_URL` is public configuration, not a secret. It is never a secret.
Next.js embeds it in browser-delivered assets during the image
build. Changing it requires a frontend rebuild and redeployment.
The same build receives explicit `APP_ENV=production`; the validated canonical
identity is embedded as `NEXT_PUBLIC_APP_ENV` so browser and build checks agree.

Production Compose fixes `APP_ENV=production`, `DEBUG=false`, and
`ENABLE_ADMIN_INGESTION=false`; do not weaken those controls. The production
stack does not receive `NVD_API_KEY` and does not expose an ingestion route.

The template also lists optional image tag, application metadata, log level,
loopback bind address, and host-port overrides. Do not place API keys, tokens,
complete database URLs, or other credentials in source-controlled files.

Backend configuration is validated eagerly before FastAPI reports availability.
Missing database components, unreadable or invalid password files,
unsafe CORS/trusted-host entries, `DEBUG=true`, or
`ENABLE_ADMIN_INGESTION=true` stop staging and production startup. The public
health response does not disclose the configured environment identity.

APR-10 remains `Need Approval`. No secret-management provider or
provider-specific credential-delivery mechanism is selected by B1-01. Keep
credential-dependent approval-gated integrations disabled until both approval
and valid configuration exist.

In the examples below, set `$ProdEnv` to the absolute path of the completed
external file:

```powershell
$ProdEnv = "C:\secure-config\alpha-data-production.env"
$ComposeFile = ".\compose.prod.yml"
```

Create the external file once, then edit it through an approved secret-handling
workflow without displaying its completed contents:

```powershell
Copy-Item -LiteralPath .\.env.production.example -Destination $ProdEnv
```

Do not commit, upload, screenshot, or include the completed file in deployment
evidence. Do not place a credential-bearing database URL in the guide or shell
history. Follow the canonical environment classification, storage, validation,
and rotation requirements before continuing.

## Pre-deployment validation

Run these checks from the reviewed repository root:

```powershell
git status --short
git rev-parse HEAD
docker version
docker compose version
docker compose -f $ComposeFile --env-file $ProdEnv config --quiet
docker compose -f $ComposeFile --env-file $ProdEnv config --services

docker compose `
    -f $ComposeFile `
    --env-file $ProdEnv `
    --profile migration `
    config --quiet

docker compose `
    -f $ComposeFile `
    --env-file $ProdEnv `
    --profile migration `
    config --services
```

Normal runtime validation excludes profiled services. Its expected service set
is `db`, `backend`, and `frontend`. With the `migration` profile enabled, the
service set additionally includes `migrate`.

`migrate` is intentionally excluded from normal runtime configuration and
normal startup. It appears only when the `migration` profile is enabled or when
the `migrate` service is explicitly targeted. This preserves manual-only
migration behavior. Its absence from the normal runtime service list is
expected, not a deployment failure.

Both `config --quiet` commands validate interpolation and structure without
printing resolved configuration. Do not replace them with unrestricted `docker
compose config` when real secrets are loaded.

Check the default Windows host ports without opening or printing configuration:

```powershell
Get-NetTCPConnection -State Listen -LocalPort 3000,8000 -ErrorAction SilentlyContinue
```

No output means neither default port currently has a listener. If a port is in
use, identify the owning approved process or select a reviewed host-port
override; do not stop an unrelated service blindly. PostgreSQL needs no host
port in production.

## Image build

Normally build the two application images from the repository root with the
reviewed environment file:

```powershell
docker compose -f $ComposeFile --env-file $ProdEnv build backend frontend
```

Use a no-cache build only when validating all layers from scratch, investigating
a suspected stale layer, or following an approved release procedure:

```powershell
docker compose -f $ComposeFile --env-file $ProdEnv build --no-cache backend frontend
```

`APP_ENV=production` and `NEXT_PUBLIC_API_BASE_URL` are the frontend build
arguments. Both are non-secret; changing the public API URL requires a frontend
rebuild.
Never supply passwords, tokens, keys, database URLs, or other secrets as build
arguments. Review build logs for accidental disclosure, then identify and record
the resulting image tags and IDs without recording environment values:

```powershell
docker compose -f $ComposeFile --env-file $ProdEnv images
```

## Manual database migration

Migrations do not run automatically during normal startup. Start PostgreSQL,
wait for its health check, inspect the packaged Alembic head, run the one-shot
migration service, and verify the current database revision:

```powershell
docker compose -f $ComposeFile --env-file $ProdEnv up -d db
docker compose -f $ComposeFile --env-file $ProdEnv --profile migration run --rm migrate alembic -c /app/alembic.ini heads
docker compose -f $ComposeFile --env-file $ProdEnv --profile migration run --rm migrate
docker compose -f $ComposeFile --env-file $ProdEnv --profile migration run --rm migrate alembic -c /app/alembic.ini current
```

The migration service uses the backend image, waits for the database health
check, and runs `alembic upgrade head`. It is excluded from normal startup and
does not run ingestion. `heads` reports the revision packaged in the image;
`current` confirms the live database revision. Both must agree at the expected
head before application startup. Do not generate a migration during deployment,
and do not print credentials or resolved environment configuration while
troubleshooting migration output.

## Production startup

Start the normal production services after the migration succeeds:

```powershell
docker compose -f $ComposeFile --env-file $ProdEnv up -d db backend frontend
docker compose -f $ComposeFile --env-file $ProdEnv ps
```

PostgreSQL starts first. Backend waits for healthy PostgreSQL, and frontend waits
for a healthy backend. The `migrate` service is not part of normal startup. The
default host bindings are loopback-only: frontend port `3000` and backend port
`8000`; PostgreSQL has no host binding. Do not use the development runner for
production startup.

Container health checks use `pg_isready` for PostgreSQL, `/api/health` for
FastAPI, and `/` for the production Next.js server. Wait until `docker compose
ps` reports all three runtime services healthy before continuing.

## Health and functional smoke validation

The backend health route and frontend root are availability checks. The version,
dashboard, article, and intelligence routes are functional smoke checks. With
the database migrated, each request below should return HTTP `200`; assignment
to a variable avoids printing response bodies unnecessarily. Set
`$BackendHostHeader` to the first exact approved host in
`BACKEND_TRUSTED_HOSTS`; direct loopback requests must carry that Host header so
they exercise the same TrustedHost boundary as deployed traffic:

```powershell
$BackendHostHeader = "api.example.invalid"
$BackendSmokeChecks = @(
    "http://127.0.0.1:8000/api/health",
    "http://127.0.0.1:8000/api/version",
    "http://127.0.0.1:8000/api/v1/dashboard/summary",
    "http://127.0.0.1:8000/api/v1/articles",
    "http://127.0.0.1:8000/api/v1/intelligence/items"
)

foreach ($Uri in $BackendSmokeChecks) {
    $Response = Invoke-WebRequest `
        -UseBasicParsing `
        -Uri $Uri `
        -Headers @{ Host = $BackendHostHeader } `
        -TimeoutSec 10
    if ($Response.StatusCode -ne 200) {
        throw "Deployment smoke check failed for $Uri."
    }
}

$FrontendResponse = Invoke-WebRequest `
    -UseBasicParsing `
    -Uri "http://127.0.0.1:3000/" `
    -TimeoutSec 10
if ($FrontendResponse.StatusCode -ne 200) {
    throw "Deployment smoke check failed for the frontend."
}
```

Do not call ingestion commands or external intelligence sources during these
checks. A database-backed smoke route returning `500` is a deployment failure,
not evidence that the service is healthy.

## CORS validation

Set `$ApprovedOrigin` to the exact trusted HTTPS frontend origin already stored
in `BACKEND_CORS_ALLOWED_ORIGINS`. Reuse the exact approved
`$BackendHostHeader` defined above. Send both checks only to the local backend:

```powershell
$ApprovedOrigin = "https://dashboard.example.invalid"
$ApprovedPreflight = Invoke-WebRequest `
    -UseBasicParsing `
    -Method Options `
    -Uri "http://127.0.0.1:8000/api/health" `
    -Headers @{
        Host = $BackendHostHeader
        Origin = $ApprovedOrigin
        "Access-Control-Request-Method" = "GET"
    }

if ($ApprovedPreflight.Headers["Access-Control-Allow-Origin"] -ne $ApprovedOrigin) {
    throw "The approved CORS origin was not returned exactly."
}
if ($ApprovedPreflight.Headers["Access-Control-Allow-Origin"] -eq "*") {
    throw "Wildcard production CORS is prohibited."
}
if ($ApprovedPreflight.Headers["Access-Control-Allow-Credentials"]) {
    throw "Browser credentials were unexpectedly enabled."
}

$UnapprovedResponse = Invoke-WebRequest `
    -UseBasicParsing `
    -Uri "http://127.0.0.1:8000/api/health" `
    -Headers @{
        Host = $BackendHostHeader
        Origin = "https://unapproved.invalid"
    }

if ($UnapprovedResponse.Headers["Access-Control-Allow-Origin"]) {
    throw "An unapproved CORS origin received browser permission."
}
```

An unapproved-origin GET may still return HTTP `200` to a non-browser client;
rejection at the CORS boundary means the response omits
`Access-Control-Allow-Origin`, so browser JavaScript cannot read it. Do not test
by contacting the unapproved domain.

## Security and persistence design

- Backend and frontend run as dedicated non-root users.
- Application containers are non-privileged, enable `no-new-privileges`, drop
  all Linux capabilities, and use an init process for signal handling.
- PostgreSQL runs as its image's `postgres` user and is reachable only on the
  internal database network.
- Frontend joins only the application network and has no database-network path.
- Backend joins both networks so it can serve the frontend, reach PostgreSQL,
  and retain outbound access for separately approved manual operations.
- No application source, Docker socket, environment file, or host directory is
  mounted into a production container.
- PostgreSQL data is stored in the named `postgres_data` volume.
- The database password is mounted as the same read-only Compose secret into
  PostgreSQL, backend, and the manual migration service; it is not an
  environment value or image build argument.
- Runtime services use `restart: unless-stopped`.
- The local Docker log driver is bounded to three 10 MB files per service.
- Backend and frontend images define local health checks and contain no reload
  server, Next.js development server, or startup ingestion command.
- Production requires exact HTTPS CORS origins; wildcard origins and browser
  credentials are disabled.
- Runtime Host enforcement requires one syntactically valid header and compares
  its normalized host exactly against `BACKEND_TRUSTED_HOSTS`; ports do not
  widen the allow-list and unlisted hosts are never redirected.
- Normal startup does not run Alembic migrations.

The FastAPI startup path performs no ingestion. P7-01 does not add a scheduler,
ingestion service, ingestion startup hook, or public ingestion trigger.

The official PostgreSQL image grants the configured `POSTGRES_USER`
initialization role superuser privileges, and current Compose reuses that
privileged role for backend and migration access. It does not provision a
separate restricted application role. A mature production deployment should
separately provision a non-superuser application role with only the required
permissions, but that database and deployment change is future, separately
reviewed work and is not implemented or automated by P7-02. Do not publish
PostgreSQL, mount the Docker socket, enable privileged containers, or run the
application images as root to compensate for a deployment problem.

## Logging and troubleshooting

Review bounded, service-scoped logs. Never print the resolved Compose
configuration, container environment, credentials, headers, cookies, complete
database URLs, or raw external payloads:

```powershell
docker compose -f $ComposeFile --env-file $ProdEnv ps
docker compose -f $ComposeFile --env-file $ProdEnv logs --tail 200 backend frontend db
docker compose -f $ComposeFile --env-file $ProdEnv logs --tail 200 backend
```

The local Docker logging driver retains at most three 10 MB files per service.
Check only safe container state and restart counts when investigating an
unhealthy or looping service:

```powershell
$BackendId = docker compose -f $ComposeFile --env-file $ProdEnv ps -q backend
docker inspect --format '{{.State.Status}} {{if .State.Health}}{{.State.Health.Status}}{{end}} {{.RestartCount}}' $BackendId
```

Do not use unrestricted `docker inspect` because its configuration can include
environment values. A restart loop requires investigation rather than repeated
restarts.

| Symptom | Safe checks and likely cause |
| --- | --- |
| Missing required environment value | Recheck the six required variable names in the protected file and confirm `POSTGRES_PASSWORD_SECRET_FILE` names a readable protected regular file; use `config --quiet`, never resolved output. |
| Windows command cannot reach Docker | Confirm Docker Desktop is running, the engine answers `docker version`, and Linux containers are enabled. |
| Port conflict | Use `Get-NetTCPConnection` to identify the listener; stop only an approved process or use a reviewed host-port override. |
| Production build fails | Review the bounded build error, disk capacity, dependency retrieval, and checked-out source; do not add secrets as build arguments. |
| Frontend calls the wrong backend | Confirm `NEXT_PUBLIC_API_BASE_URL`, rebuild the frontend image, and redeploy it; restarting a stale image is insufficient. |
| CORS mismatch | Compare the browser origin exactly with `BACKEND_CORS_ALLOWED_ORIGINS`; do not add a wildcard or enable credentials. |
| PostgreSQL is unhealthy | Review `ps` and bounded `db` logs, then check storage availability and protected database settings without printing values. |
| Backend cannot resolve the database | Confirm the service is attached to the `database` network and uses service hostname `db`; do not publish PostgreSQL or replace the internal boundary. |
| Migration not applied | Run the manual `heads` and `current` checks, then the approved `migrate` service; do not generate or casually downgrade migrations. |
| Database volume permission or corruption indicators | Stop repeated writes, preserve the volume, collect sanitized evidence, and invoke the deployment recovery plan; do not delete the volume, run the application as root, or change permissions blindly. |

## Controlled restart

Restart only the affected application service when its image and configuration
are unchanged:

```powershell
docker compose -f $ComposeFile --env-file $ProdEnv restart backend
docker compose -f $ComposeFile --env-file $ProdEnv restart frontend
docker compose -f $ComposeFile --env-file $ProdEnv ps
```

These commands do not recreate the database volume. Re-run the health and
functional smoke checks and confirm migrations remain at head:

```powershell
docker compose -f $ComposeFile --env-file $ProdEnv --profile migration run --rm migrate alembic -c /app/alembic.ini current
```

Restart PostgreSQL only during approved database maintenance, then verify the
database, backend, and frontend in dependency order. If an image or Compose
environment value changed, `restart` is insufficient; use a reviewed recreate:

```powershell
docker compose -f $ComposeFile --env-file $ProdEnv up -d --no-deps backend frontend
```

## Update and redeployment workflow

1. Confirm a clean deployment checkout and record `git rev-parse HEAD`.
2. Review the approved release notes, source diff, configuration changes,
   migration compatibility, and known issues.
3. Create and verify the required database backup through the deployment
   environment's approved procedure.
4. Fetch and select the approved source commit through the organization's
   controlled release process; do not deploy an unreviewed moving branch.
5. Rebuild the application images and record their tags and IDs.
6. Run `heads`, the manual migration service, and `current`.
7. Recreate backend and frontend, leaving the named database volume intact.
8. Verify service health, functional routes, CORS, and bounded logs.
9. Record the deployed Git commit, image identifiers, migration revision,
   operator, timestamp, and rollback reference.

The corresponding production commands after the reviewed source update are:

```powershell
git status --short
git rev-parse HEAD
docker compose -f $ComposeFile --env-file $ProdEnv build --pull backend frontend
docker compose -f $ComposeFile --env-file $ProdEnv --profile migration run --rm migrate
docker compose -f $ComposeFile --env-file $ProdEnv up -d backend frontend
docker compose -f $ComposeFile --env-file $ProdEnv ps
docker compose -f $ComposeFile --env-file $ProdEnv images
```

This workflow does not provide zero-downtime deployment.

## Rollback

A safe application rollback requires the recorded prior Git commit, image tags
or IDs, compatible protected configuration, a verified database backup, and a
reviewed schema-compatibility decision.

If continued application activity could worsen the incident, stop only the
application services while retaining PostgreSQL and its named volume:

```powershell
docker compose -f $ComposeFile --env-file $ProdEnv stop frontend backend
```

1. Stop backend and frontend if continued writes could worsen the incident.
2. Confirm whether the previous application version is compatible with the
   database's current Alembic revision.
3. Restore or select the previously recorded application images and reviewed
   configuration through the deployment's release process.
4. Recreate backend and frontend without deleting the database volume.
5. Run health, functional, CORS, migration-revision, and log checks.
6. Record the rollback result and any remaining recovery action.

Application rollback does not automatically reverse database migrations.
Alembic downgrade must not be run casually. A destructive database rollback or
restore requires a separately validated recovery plan, verified backup, exact
target identification, maintenance window, and explicit approval.

## Controlled shutdown and destructive cleanup

Routine shutdown should retain containers, networks, and the database volume:

```powershell
docker compose -f $ComposeFile --env-file $ProdEnv stop
```

`stop` stops services but retains their containers, networks, and volume state.
When removal of service containers and project networks is intentionally
required, use `down` without the volume flag:

```powershell
docker compose -f $ComposeFile --env-file $ProdEnv down
```

`down` removes the Compose service containers and networks but retains named
volumes by default.

> **Destructive warning:** `docker compose down -v` deletes the named
> `postgres_data` volume and its persistent database data. It is not routine
> cleanup. Do not run it without a verified backup, exact project and volume
> identification, a separately validated recovery plan, and explicit approval.

## Backup and recovery responsibility

Automated PostgreSQL backup and restore are not implemented by this repository.
A real production deployment must define backup frequency, retention,
encryption, access control, integrity verification, restore testing, recovery
objectives, and incident ownership. Protect backup credentials and contents as
sensitive production data.

The existence of the `postgres_data` volume is not a backup. The volume can be
lost, corrupted, deleted, or become incompatible with a failed change. Do not
claim recoverability until a representative restore has been tested through the
deployment environment's approved process.

## Deployment evidence checklist

Record the following without copying secrets, completed environment files,
resolved Compose output, response bodies, or sensitive logs:

- task, change, or release ID;
- deployed Git commit;
- backend and frontend image tags and immutable IDs;
- deployment environment identifier;
- expected and current Alembic migration revision;
- `db`, `backend`, and `frontend` health result;
- functional and CORS validation result;
- validation timestamp and operator;
- backup and rollback reference;
- known limitations, warnings, and approved exceptions; and
- final outcome and next action.

## Known limitations and future infrastructure work

- TLS termination and HSTS trust are not included.
- No reverse proxy or load balancer is included.
- Automated database backup and restore are not included.
- No monitoring or alerting platform is integrated.
- Logs are bounded locally but there is no centralized logging platform.
- No CI/CD deployment workflow is implemented.
- No orchestration platform, autoscaling, or zero-downtime deployment exists.
- Enterprise secret management and automated secret rotation are not
  integrated; APR-10 remains `Need Approval` and no provider is selected.
- No separate restricted PostgreSQL application role is provisioned; backend
  and migration reuse the privileged initialization role.
- The backend production image installs the shared `requirements.txt`, which
  currently includes development/test dependencies as well as runtime packages.
- Production load, capacity, failover, and disaster-recovery testing have not
  been completed.
- No public internet deployment has been validated.

This Compose file is a hardened production-oriented baseline, not a complete
internet-facing platform. TLS, trusted proxy configuration, backups, restore
testing, monitoring, centralized logging, orchestration, host hardening,
dependency remediation, restricted database-role provisioning, and production
capacity engineering are future, separately reviewed infrastructure work.
Production API and frontend ports should normally remain loopback-bound behind
the deployment's approved TLS terminator.
