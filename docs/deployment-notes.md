# Deployment Notes

## Purpose

This concise status note distinguishes the implemented runtime architecture
from local development and the remaining external staging work. Start with the
primary self-contained [`README.md`](../README.md); use the
[operator guide](operator-guide.md) for detailed specialist operation and
[production Docker deployment](production-docker-deployment.md) for the
protected deployment procedure.

## Implemented Runtime Architecture

The repository implements FastAPI, Next.js, PostgreSQL, self-hosted Prefect,
Docker images, development Compose, and a separate production-oriented Compose
baseline. The production package also includes Caddy edge policy, private
monitoring, secret-file references, and encrypted backup/isolated-restore
tooling. This is implemented architecture, not proof that an external staging
environment is currently available.

Exactly six approved scheduled source handlers are code-bound to the Prefect
deployment. Its fixed schedule is `17 */2 * * *` in `Asia/Dubai`, using the
`alpha-data-process` process work pool and backend working directory
`/opt/alpha-data/backend`. Ordinary bootstrap creates a missing deployment
**PAUSED** and preserves the activation state of an existing deployment while
updating it. It does not run ingestion or contact a live source.

The current local release deployment was explicitly approved and activated on
11 August 2026. Deployment
`alpha-data-parent-ingestion-cycle/alpha-data-ingestion-cycle` (ID
`8e584852-6ffc-4806-9cc9-22b758767bf3`) is verified with `paused=False`, status
`READY`, its single schedule active, working directory
`/opt/alpha-data/backend`, concurrency `1`, and collision strategy `CANCEL_NEW`.
No manual Prefect flow run was used to activate it.

## Local Development

This concise status note does not repeat every local setup, URL, activation,
restart, or shutdown step. Use the primary [README](../README.md) for the
complete mentor entry path and the [operator guide](operator-guide.md) for
specialist operational detail. At the deployment boundary, local application
and Prefect administration ports remain loopback-only, the dedicated Prefect
metadata database has no host port, and named volumes provide persistence.

Current release validation also confirmed local runtime health and successful
authentication after the PostgreSQL authentication row-lock scope correction;
auth identity immutability and least privilege remain preserved.

## Environment Boundary

`.env.example` is the local structural template, while
`.env.production.example` is the separate staging/production reference. Secret
classification, generation, ownership, and handling belong exclusively in
[environment and secrets](environment-and-secrets.md).

## External Staging Status

No mentor-accessible external staging deployment is claimed by this document.
Public staging/DNS/certificate evidence, external alert delivery, an approved
off-host backup destination, protected production credential provisioning and
rotation, staging UAT, and measured staging RPO/RTO remain operator/approval
dependencies. Production Prefect metadata remains on the separately documented
production baseline until a reviewed production migration task changes it.

The current local recurring Prefect deployment is ACTIVE, but it runs only while
the local Docker/Prefect infrastructure is running. A successful local startup,
login, activation, build, or health check is not external staging evidence.
