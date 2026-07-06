# Backend - Cyber OSINT Dashboard

## Purpose

The backend provides the API, database access, ingestion services, processing logic, and scheduled data-fetching foundation for the Cyber OSINT Dashboard.

## Planned Responsibilities

- Run the FastAPI backend server.
- Connect securely to PostgreSQL.
- Expose dashboard and threat intelligence API endpoints.
- Store normalized threat and vulnerability records.
- Fetch approved open-source cybersecurity data.
- Process, normalize, deduplicate, and classify records.
- Provide safe logging and error handling.
- Support backend tests.

## Planned Backend Structure

- app/main.py - FastAPI application entry point
- app/api/ - API route definitions
- app/core/ - configuration and logging
- app/db/ - database session and base setup
- app/models/ - SQLAlchemy database models
- app/schemas/ - Pydantic request/response schemas
- app/services/ - business logic services
- app/ingestion/ - external source collectors and jobs
- app/processing/ - normalization, severity mapping, tagging, and deduplication
- tests/ - backend automated tests
- alembic/ - database migration files

## Environment Variables

Use backend/.env.example as the template.

Never commit real backend/.env files.

## Dependencies

Initial dependencies are listed in requirements.txt.

## Current Status

Phase 1 setup only. Application logic will be added in a later phase.

## Synthetic Development Seed Data

P1-12 adds an explicitly invoked synthetic dataset for local development and
frontend testing. It inserts fictional sources, tags, intelligence items,
identifiers, source records, and vulnerability extension rows into the existing
schema. The data is not real threat intelligence and must not be used for
security decisions.

Safety boundaries:

- Runs only when `APP_ENV` is `development` or `test`.
- Performs no network requests.
- Does not reset, truncate, or delete database data.
- Does not run automatically during application startup.
- Uses only `example.com`, `example.org`, and `example.net` URLs.

Prerequisites:

1. Configure a local or disposable PostgreSQL database through the existing
   environment variables in `backend/.env.example`.
2. Apply the existing Alembic migration.
3. Run the seed command from the `backend` directory.

The database host must be reachable from where the command runs. The hostname
`db` is intended for commands running inside the Docker Compose network. Commands
run directly from Windows PowerShell normally need the host-mapped PostgreSQL
address, such as `localhost` with the configured PostgreSQL port.

Commands:

```powershell
python -m alembic -c alembic.ini upgrade head
$env:APP_ENV = "development"
python -m app.dev_data.cli
python -m app.dev_data.cli
```

Expected first run: creates the synthetic dataset and prints created counts.
Expected second run: creates no duplicate logical records and prints existing
counts. If an existing seed-keyed record conflicts with the expected synthetic
data, the command stops with a safe conflict message.

Example verification queries:

```sql
select count(*) from intelligence_sources where slug like 'alpha-synthetic-%';
select count(*) from intelligence_item_identifiers where namespace = 'alpha-seed';
select count(*) from vulnerabilities;
select count(*) from source_records where source_external_id like 'ALPHA-SEED-%';
```

If the command fails, verify that `APP_ENV` is `development` or `test`, the
database settings are present for the current execution environment, and the
migration has been applied. Do not paste real database URLs, passwords, tokens,
or stack traces into issues or reports.
