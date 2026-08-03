# B2-01 Self-hosted Prefect Platform

## Frozen acceptance contract

| Control | Frozen value |
| --- | --- |
| Bundle and official task | E01 / B2-01 — Add self-hosted Prefect services to Docker Compose |
| Starting checkpoint | `6089aaa188f453284a00cfe2f00e80bc9fe70bd4` on `dev`, equal to `origin/dev` before implementation |
| Goal | Add one reproducible self-hosted Prefect server and one process worker for local development and staging readiness. |
| Prefect version | `prefecthq/prefect:3.8.1-python3.13` |
| Work pool | Fixed name `alpha-data-process`, type `process` |
| State | One `prefect_data` volume, SQLite inside server `PREFECT_HOME`, server-only mount |
| Local administration | `127.0.0.1:${PREFECT_PORT:-4200}:4200`; no worker host port |
| Production administration | No Prefect host ports; internal `orchestration` network only |
| Definition of done | Static/Compose/focused/runtime/restart/regression evidence is collected, complete authorized files are reviewed, limitations are recorded, and an external review package is prepared. This does not itself approve or complete B2-01. |

The initial implementation freeze authorized 13 files: `prefect/Dockerfile`,
both Compose files, the two root environment examples,
`backend/requirements.txt`, the Compose and Prefect platform tests, this
document, the production Docker guide, the environment guide, and the root
README. An approved amendment added `docs/architecture.md` and
`backend/tests/test_architecture_documentation.py` after regression exposed a
stale four-service topology contract. A later amendment added
`backend/tests/test_environment_documentation.py` and
`backend/tests/test_readme_documentation.py` after regression exposed stale
APR-10 ownership and database-role documentation contracts. The final approved
implementation and review boundary is therefore 17 files. These evidence-backed
contract corrections did not expand B2-01 into flows, schedules, source
integration, authentication, monitoring, backup, or staging deployment.
Relevant existing Dockerfiles, runner behavior, tests, health/logging
conventions, and repository search results were inspected read-only.

In scope is the pinned project image, non-root identity, server/worker services,
fixed idempotent process-pool registration, health checks, one persistent state
volume, restart persistence, local loopback exposure, private production
networking, production container hardening, removal of unused APScheduler,
focused tests, and accurate operator documentation.

Out of scope is every flow, deployment, schedule, parent cycle, retry/quota or
no-overlap contract, source checkpoint integration, operator-control API/UI,
source conversion, authentication/RBAC, reverse proxy/TLS, monitoring/alerting,
backup automation, staging deployment, Prefect Cloud, Prefect PostgreSQL, Redis,
high availability, Docker workers, Docker socket access, and application schema
change. These remain separate tasks even if they would be useful.

Security and integrity acceptance requires exact immutable image use, no
credentials or Prefect Cloud settings, no shell-built input, no public
production administration, non-root execution, dropped capabilities,
`no-new-privileges`, bounded local logs, actual endpoint health checks, no
Docker socket, no privileged/host networking, no source or broad host mounts,
server-only SQLite ownership, idempotent pool reuse, and preservation of the
existing application/PostgreSQL network and role boundaries.

Required validation is `git diff --check`, local and production `config
--quiet`, and the final expanded focused suite of six relevant test modules:
`backend/tests/test_docker_compose_config.py`,
`backend/tests/test_production_compose.py`,
`backend/tests/test_prefect_platform.py`,
`backend/tests/test_architecture_documentation.py`,
`backend/tests/test_environment_documentation.py`, and
`backend/tests/test_readme_documentation.py`. The acceptance evidence also
includes live server/worker health and non-root checks,
work-pool identity/restart/recreate persistence checks, the full backend suite
with a unique external `--basetemp`, and `run.cmd test`. Validation uses no live
OSINT source. A known Windows protected-temp `WinError 5` may stop the wrapper
before frontend validation; it must be reported rather than hidden.

## Architecture

Both services use the same project image. Its Dockerfile inherits only from the
exact pinned upstream image, creates group/user `10001:10001`, creates
`/var/lib/prefect` with mode `0750`, sets `PREFECT_HOME`, and switches to the
fixed unprivileged identity. It installs no package and copies no application
source or environment material.

```text
local operator -> 127.0.0.1:4200 -> prefect-server -> prefect_data (SQLite)
                                           ^
                                           |
                               prefect-worker (process)
                               alpha-data-process
                               health: 127.0.0.1:8080/health
```

The server starts with `prefect server start --host 0.0.0.0 --port 4200` inside
its isolated container. Local Compose publishes that container port only on the
host loopback address. Production publishes none. The server health check calls
`http://127.0.0.1:4200/api/health` from inside the container and fails when that
request fails.

The worker receives only the internal self-hosted API URL. Its argument-vector
command starts the `process` worker for `alpha-data-process`, enables Prefect's
supported health server, and uses `--create-pool-if-not-found`. Prefect creates
the pool when absent and reuses it when present; no shell or external input is
used. The worker waits for a healthy server and its Docker health check calls
`http://127.0.0.1:8080/health`. The worker does not mount `prefect_data` and
therefore cannot directly open the server's SQLite file.

Production attaches both services only to the dedicated internal
`orchestration` bridge. It preserves the separate `application` and internal
`database` networks. Both Prefect services run as `10001:10001`, use an init
process, set `no-new-privileges`, drop all capabilities, restart unless stopped,
and use three bounded 10 MiB local log files. There is no Docker socket,
privileged mode, host networking, source bind mount, default credential, Cloud
API URL/key, or arbitrary Prefect setting.

## Local operation and health

Start only the new services:

```powershell
docker compose up --build -d prefect-server prefect-worker
docker compose ps prefect-server prefect-worker
```

Verify the server from the host with a bounded request:

```powershell
$Response = Invoke-WebRequest `
    -Uri "http://127.0.0.1:4200/api/health" `
    -UseBasicParsing `
    -TimeoutSec 10
if ($Response.StatusCode -ne 200) { throw "Prefect server is unhealthy." }
```

Verify the container identities and fixed pool without printing configuration:

```powershell
docker compose exec -T prefect-server id
docker compose exec -T prefect-worker id
docker compose exec -T prefect-worker prefect work-pool inspect alpha-data-process
```

Do not use unrestricted resolved Compose output, full container-environment
inspection, or unbounded logs as evidence. Use `config --quiet`, `docker compose
ps`, and service-scoped `logs --tail 200` when troubleshooting.

## Restart-persistence procedure

1. Wait for both services to be healthy.
2. Inspect `alpha-data-process` and record only its pool ID, name, and type.
3. Restart `prefect-server` and `prefect-worker` without removing storage.
4. Wait for both health checks, inspect the pool, and confirm the same ID and
   exactly one matching pool.
5. Recreate both containers with `docker compose up -d --force-recreate
   prefect-server prefect-worker`; do not remove volumes.
6. Wait for health and confirm the same pool ID and one matching pool again.

Never run `docker compose down -v`, `docker volume rm`, or Docker system prune
for this procedure. A successful restart/recreate proves bounded state
persistence only. It is not a backup, restore, RPO, or RTO test.

## Current truthful state and accepted limitations

The platform exists, but no production source flow or schedule exists. There is
one server, one process worker, SQLite state, and an idle worker apart from pool
registration and polling. There is no high availability, Redis,
Prefect-specific PostgreSQL, Prefect authentication, flow, deployment, schedule,
staging deployment, backup/restore proof, RPO/RTO claim, or application-health
integration. Protection currently depends on loopback-only local administration
and private production networking.

Later tasks own flow contracts, the two-hour parent schedule, retry/quota and
no-overlap controls, source checkpoints and conversion, operator actions,
authentication/RBAC, monitoring, backup/recovery, and deployment. APScheduler
has been removed so Prefect remains the sole planned workflow orchestrator.
