# P7-01 Production Docker Deployment

## Scope and architecture

P7-01 adds a production-oriented local orchestration entry point for the
existing FastAPI backend, Next.js frontend, and PostgreSQL database. It does not
add a reverse proxy, TLS automation, cloud infrastructure, scheduling,
monitoring, backups, or automatic ingestion.

The production entry point is `compose.prod.yml`. It is standalone because the
development Compose file intentionally contains local-only defaults, fixed
container names, a published PostgreSQL port, and a single shared network.
Keeping the production definition separate prevents those development settings
from being inherited accidentally and leaves `.\run.cmd dev` unchanged.

## Required configuration

Create the deployment environment file outside the repository. Start from
`.env.production.example`, restrict access to the completed file, and never add
it to Git. The required variables are:

- `POSTGRES_DB`
- `POSTGRES_USER`
- `POSTGRES_PASSWORD`
- `BACKEND_CORS_ALLOWED_ORIGINS`
- `NEXT_PUBLIC_API_BASE_URL`

`POSTGRES_PASSWORD` has no committed default. Use a strong deployment secret.
`BACKEND_CORS_ALLOWED_ORIGINS` must contain explicit trusted HTTPS origins; a
wildcard is invalid. `NEXT_PUBLIC_API_BASE_URL` is public browser configuration,
not a secret. Next.js embeds it during the image build, so changing it requires
rebuilding the frontend image.

The template also lists optional image tag, application metadata, log level,
loopback bind address, and host-port overrides. Do not place API keys, tokens,
complete database URLs, or other credentials in source-controlled files.

In the examples below, set `$ProdEnv` to the absolute path of the completed
external file:

```powershell
$ProdEnv = "C:\secure-config\alpha-data-production.env"
$ComposeFile = ".\compose.prod.yml"
```

## Build and controlled migration

Build the two application images deterministically from the repository root:

```powershell
docker compose -f $ComposeFile --env-file $ProdEnv build
```

Database migrations are manual-only. Start the database, wait for its health
check, and then run the one-shot migration profile:

```powershell
docker compose -f $ComposeFile --env-file $ProdEnv up -d db
docker compose -f $ComposeFile --env-file $ProdEnv --profile migration run --rm migrate
```

The migration service uses the backend image, waits for the database health
check, and runs `alembic upgrade head`. It is excluded from normal startup and
does not run ingestion.

## Start, inspect, and verify

Start the normal production services after the migration succeeds:

```powershell
docker compose -f $ComposeFile --env-file $ProdEnv up -d db backend frontend
docker compose -f $ComposeFile --env-file $ProdEnv ps
```

The default host bindings are loopback-only: frontend port `3000` and backend
port `8000`. PostgreSQL does not publish a host port. Verify local service health
with:

```powershell
Invoke-WebRequest -UseBasicParsing http://127.0.0.1:8000/api/health
Invoke-WebRequest -UseBasicParsing http://127.0.0.1:3000/
```

Review bounded service logs without printing environment configuration:

```powershell
docker compose -f $ComposeFile --env-file $ProdEnv logs --tail 200 backend frontend db
```

Container health checks use only local service endpoints: `pg_isready` for
PostgreSQL, `/api/health` for FastAPI, and `/` for the production Next.js server.
Frontend startup waits for a healthy backend; backend and the manual migration
service wait for a healthy database.

## Security and persistence design

- Backend and frontend run as dedicated non-root users.
- Application containers enable `no-new-privileges`, drop Linux capabilities,
  and use an init process for signal handling.
- PostgreSQL runs as its image's `postgres` user and is reachable only on the
  internal database network.
- Frontend joins only the application network and has no database-network path.
- Backend joins both networks so it can serve the frontend, reach PostgreSQL,
  and retain outbound access for separately approved manual operations.
- No application source, Docker socket, environment file, or host directory is
  mounted into a production container.
- PostgreSQL data is stored in the named `postgres_data` volume.
- Runtime services use `restart: unless-stopped`.
- The local Docker log driver is bounded to three 10 MB files per service.
- Backend and frontend images define local health checks and contain no reload
  server, Next.js development server, or startup ingestion command.

The FastAPI startup path performs no ingestion. P7-01 does not add a scheduler,
ingestion service, ingestion startup hook, or public ingestion trigger.

## Update and rollback

For a controlled update, review the new source checkpoint, back up the database
using deployment-approved procedures, rebuild, rerun the manual migration, and
recreate only the application services:

```powershell
docker compose -f $ComposeFile --env-file $ProdEnv build --pull
docker compose -f $ComposeFile --env-file $ProdEnv --profile migration run --rm migrate
docker compose -f $ComposeFile --env-file $ProdEnv up -d backend frontend
```

For application rollback, restore a reviewed compatible source/image tag and
recreate backend and frontend. Confirm migration compatibility before rolling
back application code; P7-01 does not implement automatic database downgrade.
Keep the named database volume intact.

Stop the stack without deleting retained data:

```powershell
docker compose -f $ComposeFile --env-file $ProdEnv stop
```

Do not use `docker compose down -v` as routine cleanup. Removing the named
volume permanently deletes PostgreSQL data. Any destructive cleanup requires an
explicit backup, an exact project/volume check, and separate approval.

## Deployment-environment responsibilities

This Compose file is a hardened production-oriented baseline, not a complete
internet-facing platform. The deployment environment remains responsible for
TLS termination, trusted reverse-proxy or load-balancer configuration, secret
management, database backups and restore testing, monitoring and alerting,
orchestration, capacity planning, dependency remediation, and host security.
Production API and frontend ports should normally remain loopback-bound behind
the deployment's approved TLS terminator.
