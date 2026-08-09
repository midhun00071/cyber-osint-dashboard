# P6-05 Deployment Build Validation

## Acceptance status

**Passed — clean isolated build and startup verified**

This document records local deployment-build validation evidence. It does not
claim production readiness.

## Validation scope and checkpoint

| Item | Result |
| --- | --- |
| Project | Alpha Data / Cyber OSINT Dashboard |
| Task | P6-05 — Run deployment build tests |
| Prepared by | Pending |
| Technical reviewer | Pending |
| Review status | Pending mentor review |
| Validation date | 2026-07-21 (Asia/Dubai) |
| Branch | `dev` |
| Starting commit | `6e64169421c1a5e44a511180bc92491d35a16594` |
| Remote checkpoint | `HEAD == origin/dev` |
| Starting worktree | Clean |
| Docker Engine | 28.5.1, Linux/amd64 |
| Docker Desktop | 4.49.0 |
| Docker Compose | v2.40.3-desktop.1 |
| Isolated project | `alpha-p605-final-20260721-102953` |

The Compose configuration validated successfully and resolved the expected
`db`, `backend`, and `frontend` services. The normal healthy database already
occupied host port 5432. A new external override, stored outside the repository,
mapped only the isolated database to host port 15435 while preserving container
port 5432 and internal Compose networking. Ports 3000 and 8000 were available.

| Service | Host mapping | Initial state | Initial restart count |
| --- | --- | --- | --- |
| PostgreSQL | `15435:5432` | Running and healthy | 0 |
| Backend | `8000:8000` | Running | 0 |
| Frontend | `3000:3000` | Running | 0 |

## No-cache build

All buildable services were built through the isolated Compose project with
`build --no-cache`. The PostgreSQL service used its declared upstream image.
The backend dependency installation and image assembly
completed, and the packaged image contained `alembic.ini` and the Alembic
directory. The frontend production build completed inside its builder image.
The Dockerfiles use no build arguments, and the backend and frontend
`.dockerignore` files exclude environment files from their build contexts. No
OSINT ingestion or live intelligence-source request occurred during the build.

| Image | Image ID | Size |
| --- | --- | --- |
| Backend | `sha256:0623165054c93f58d4d6eaea7b3d45028e8d688579cc0179dc6d8cb8d7ba1655` | 76.1 MB (76,063,682 bytes) |
| Frontend | `sha256:e8c77fa19dab4d8d887551c21cecd4db97f6646246f417f3bdbb88eb4aa31da7` | 252 MB (251,855,194 bytes) |
| PostgreSQL 17 Alpine | `sha256:dc17045ccfd343b49600570ea734b9c4991cf1c3f3302e67df51e3b402dd55c4` | 117 MB (117,165,924 bytes) |

## Fresh startup and migration evidence

Compose created the fresh volume
`alpha-p605-final-20260721-102953_postgres_data` and network
`alpha-p605-final-20260721-102953_alpha_data_network`. PostgreSQL became
healthy within the bounded readiness period. Backend and frontend remained
running without restart loops, and every restart count stayed at zero.

Alembic validation ran inside the packaged backend container:

| Check | Result |
| --- | --- |
| `alembic heads` | `f8d739439ed0 (head)` |
| First `alembic upgrade head` | Passed; created the initial schema |
| `alembic current` | `f8d739439ed0 (head)` |
| Second `alembic upgrade head` | Passed; no additional migration ran |
| Required equality | `current == heads == f8d739439ed0` |

No migration file was edited or generated.

## HTTP and security verification

### Backend

| Request | Result |
| --- | --- |
| `GET /api/health` | HTTP 200; safe `ok` development health response |
| `GET /api/version` | HTTP 200; service version `0.1.0` |
| `GET /api/v1/dashboard/summary` | HTTP 200; safe read-only response with zero fresh-database counts and no last-ingestion value |

The responses contained allow-listed fields and did not expose a database URL,
token, stack trace, filesystem path, raw SQL, or raw exception. The health
response included a generated `X-Request-ID`. Verified response headers were:

- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: DENY`
- `Referrer-Policy: no-referrer`
- `Permissions-Policy: camera=(), microphone=(), geolocation=()`
- `Content-Security-Policy: default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'`

### Frontend

The frontend root returned HTTP 200 with `text/html; charset=utf-8` and contained
the `Cyber OSINT Dashboard` heading. A representative generated stylesheet at
`/_next/static/chunks/0zrx6yognzvkx.css` returned HTTP 200 as CSS (19,594
bytes). Runtime logs showed no frontend crash.

### CORS

An OPTIONS preflight using the approved `http://localhost:3000` origin returned
HTTP 200, echoed that exact origin, allowed GET, did not enable credentials, and
retained request-ID and security headers. The same local request carrying
`Origin: https://unapproved.example` returned HTTP 400 and no
`Access-Control-Allow-Origin`, so the unapproved origin was not authorized. No
request was sent to that domain.

## Log safety and ingestion isolation

Only logs belonging to the new isolated Compose project were scanned in memory.
Possible matching lines were not copied into this report.

| Scan category | Matches |
| --- | ---: |
| Sensitive values | 0 |
| Unhandled/raw exceptions | 0 |
| Retry or backoff activity | 0 |
| Raw SQL | 0 |
| Unexpected ingestion or live-source contact | 0 |

No automatic ingestion ran at startup or restart. No ingestion endpoint was
called, and there was no contact with a configured live intelligence source.

## Restart recovery and controlled shutdown

Only the isolated backend and frontend were restarted. Both HTTP services
recovered in 6.4 seconds. Their start timestamps changed, the PostgreSQL start
timestamp did not change, PostgreSQL remained healthy, restart counts remained
zero, and `alembic current` still returned `f8d739439ed0 (head)`. The repeated
log-safety scan remained at zero for every category.

The project was stopped with `docker compose stop`, not `down`. The backend and
database exited with code 0; the frontend exited with code 143 during the
requested Compose stop. All new containers, images, network, and volume remain
available for review.

## Retained Docker resources

New P6-05 resources retained:

- Containers: `alpha-p605-final-20260721-102953-db`,
  `alpha-p605-final-20260721-102953-backend`, and
  `alpha-p605-final-20260721-102953-frontend`
- Images: `alpha-p605-final-20260721-102953-backend:latest` and
  `alpha-p605-final-20260721-102953-frontend:latest`
- Network: `alpha-p605-final-20260721-102953_alpha_data_network`
- Volume: `alpha-p605-final-20260721-102953_postgres_data`

Previously retained resources were not reused or modified:

- `alpha-p605-20260721-092803-db`,
  `alpha-p605-20260721-092803-backend`, and
  `alpha-p605-20260721-092803-frontend`
- `alpha-p605-20260721-092803_alpha_data_network`
- `alpha-p605-20260721-092803_postgres_data`
- `alpha-p605-fix-20260721-094726-db` and
  `alpha-p605-fix-20260721-094726-backend`
- `alpha-p605-fix-20260721-094726_alpha_data_network`
- `alpha-p605-fix-20260721-094726_postgres_data`
- Diagnostic image `alpha-p605-backend-retry:20260721-102305`
  (`sha256:664d307ae050d04cd8ecdb40b6c67bf94f2227ae7757e605b84505dd5af84a73`)

The failed `alpha-p605-rerun-20260721-101401` project still has no runtime
resources. The normal `alpha-data-db` container remained running and healthy on
host port 5432 throughout validation.

## Full regression

The full regression ran through `run.cmd test` with fresh external TEMP and TMP
directory `pytest-temp-p6-05-final-20260721-104545`.

| Gate | Exact result |
| --- | --- |
| Backend pytest | 2,646 passed, 5 skipped, 1 warning in 27.39 seconds |
| Frontend Vitest | 9 files passed; 66 tests passed |
| Frontend type-check | Passed |
| Frontend production build | Passed |
| `run.cmd test` | Exit code 0 |

## Known warnings

- The no-cache backend build experienced a transient package-download timeout;
  pip resumed the same download and the single build completed successfully.
- pip emitted its standard root-user warning in the disposable image build
  stage; the final backend image runs as the non-root `appuser`.
- npm audit reported three dependency findings (two moderate and one high), and
  npm printed allow-scripts warnings for `sharp` and `unrs-resolver`. These
  existing dependency warnings were not changed in this validation task.
- Backend pytest emitted one `StarletteDeprecationWarning` concerning the
  TestClient/httpx compatibility path.

## Limitations

- HTTP checks are not full browser end-to-end testing.
- No CI workflow validation was performed.
- No production orchestration validation was performed.
- No load or stress testing was performed.
- Live ingestion was intentionally not exercised.
- Isolated stopped Docker resources remain pending explicit cleanup approval.

## Conclusion

P6-05 passed every required local gate from the verified clean checkpoint: a
new isolated no-cache Compose build, fresh database startup, packaged Alembic
migration, backend and frontend HTTP checks, restrictive CORS, sanitized logs,
restart recovery, controlled shutdown, and full regression. This evidence
supports the stated local deployment-build result only and is not a production
readiness claim.

## C09 isolated production-operations validation (2026-08-09)

C09 used project `alpha-data-c09-rehearsal`, reserved hostname `c09-validation.example.invalid`, loopback-only ports 9080/9443, and synthetic secrets/data. Exact pinned project images built successfully. A fresh database migrated to `c07a01b02c03`; all eight long-running services became healthy and the one-shot ninth `migrate` service completed; only Caddy published ports. Caddy, Prometheus (nine rules), and Alertmanager configuration validators passed. Prometheus privately scraped the backend with `up=1`.

Backend runtime ran as `appuser`, frontend as `nextjs`, Prefect and Caddy as UID/GID 10001. Backend runtime had no pytest and `pip check` passed. Synthetic-canary checks found no value in six local images' config, labels, history, or recorded layer commands. Docker Scout v1.21.0 was UNRUN because no Docker ID session was available. Production npm audit reported 0 Critical and 4 High packages; applicability review and the C10 follow-up are recorded in `c09-local-rehearsal-evidence.md`.

Encrypted PostgreSQL backup/restore passed with matching SHA-256, Alembic head, and safe row counts. Encrypted Prefect backup/restore passed after quiescence, archive safety validation, and source/restore manifest comparison. All eight fixed offline recovery scenarios passed. These results do not demonstrate public staging, external alert delivery, off-host retention, or RPO/RTO.

The consolidated C09 hardening validation used the separate isolated project
`alpha-data-rehearsal-c09hard02`. Five operational Docker scenarios passed:
application rollback, failed deployment, migration failure, worker outage, and
synthetic credential failure. Source outage, partial-ingestion checkpoint, and
the combined backup/restore harness scenario remained `UNRUN` because no safe
runtime fault-injection boundary was available. A separate encrypted PostgreSQL
backup (158,065 bytes) restored to `alpha_data_restore_hardening01`; the distinct
runtime login verified Alembic head `c07a01b02c03`, expected data evidence, and
least-privilege readability. A new Prefect restore-readability run was `UNRUN`
because approval for exposing the host Docker socket to the validation container
was refused; no workaround was attempted. Prometheus validated 10 alert rules.
