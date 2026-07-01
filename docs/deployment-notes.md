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

The current Docker setup is prepared for later use, but full container execution should wait until backend and frontend application skeletons are implemented.

## Current Status

Phase 1 setup only. Deployment run steps will be added after the application can start successfully.
