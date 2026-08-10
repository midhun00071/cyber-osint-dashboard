# Deployment Notes

## Purpose

This document tracks deployment preparation notes for the Cyber OSINT Dashboard / Alpha Data project.

## Planned Deployment Approach

The MVP will be prepared for Docker-based deployment with:

- FastAPI backend service
- Next.js frontend service
- PostgreSQL database service
- Docker Compose for local deployment-style testing

## Local Development Targets

Expected local URLs:

- Frontend: http://localhost:3000
- Backend: http://localhost:8000
- PostgreSQL: localhost:5432
- Prefect UI/API: http://127.0.0.1:4200

Local Prefect metadata uses a separate internal-only PostgreSQL service with no
host port and persistent `prefect_postgres_data`. The non-root Prefect server
serves its real UI from the writable `/var/lib/prefect/ui` path in the preserved
`prefect_data` volume. The old local SQLite file is preserved separately and is
not represented as migrated.

## Environment Requirements

Deployment environments must provide:

- Database credentials through environment variables.
- Backend configuration through environment variables.
- Frontend public API base URL.
- Approved data-source API keys only when required.

## Production Considerations

Before production-style deployment:

- Disable or protect admin ingestion endpoints.
- Restrict CORS to trusted frontend domains.
- Use HTTPS.
- Use stronger database credentials.
- Avoid exposing database ports publicly.
- Configure logging and monitoring.
- Run tests before deployment.
- Review dependencies for known vulnerabilities.

## Docker Notes

The development Compose workflow remains available for local work. P7-01 adds a
separate production-oriented Compose entry point with non-root application
images, private PostgreSQL networking, manual-only migrations, health checks,
bounded logging, and restart controls. See
[Production Docker deployment](production-docker-deployment.md) for the
approved commands and limitations.

## Current Status

The C09 package includes Caddy TLS termination, Prefect, private monitoring,
Docker secret-file references, and encrypted backup/isolated-restore tooling.
Only Caddy is host-published. Public staging/DNS/certificate evidence, external
alert delivery, an approved off-host destination, production credential
rotation, and measured RPO/RTO evidence remain B9-03/operator responsibilities.
The post-C11 PF-01/PF-02 correction is local-development evidence only;
production Prefect metadata remains on the documented SQLite baseline.
