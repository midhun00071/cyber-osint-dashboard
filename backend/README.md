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
