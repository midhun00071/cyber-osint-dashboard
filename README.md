# Cyber OSINT Dashboard / Alpha Data

## Project Overview

Cyber OSINT Dashboard / Alpha Data is a full-stack cybersecurity dashboard designed to collect, process, store, and display open-source cybersecurity intelligence for defensive awareness.

The project focuses on vulnerabilities, known exploited vulnerabilities, threat intelligence reports, cyberattack updates, and UAE/global cybersecurity context.

## Project Goal

Build a deployment-ready full-stack cybersecurity OSINT dashboard with:

- Backend API
- Frontend dashboard
- PostgreSQL database
- Automated open-source intelligence ingestion
- Threat and vulnerability detail pages
- Search, filtering, and summary views
- Testing and deployment documentation

## Ethical Use Statement

This project is intended only for defensive cybersecurity awareness, vulnerability tracking, educational analysis, and authorized open-source intelligence review.

The application must not provide exploit instructions, weaponized proof-of-concept content, unauthorized attack guidance, malware downloads, or steps to compromise real systems.

## Recommended Stack

- Frontend: Next.js with TypeScript
- Backend: Python FastAPI
- Database: PostgreSQL
- Background scheduling: APScheduler for MVP
- Deployment: Docker and Docker Compose
- Testing: pytest for backend and frontend tests later

## Repository Structure

- backend/ - FastAPI backend application
- frontend/ - Next.js frontend dashboard
- database/ - PostgreSQL initialization and database notes
- docs/ - architecture, security, testing, deployment, and data-source documentation
- scripts/ - developer setup scripts

## Current Phase

Phase 1: Project setup and repository structure.

Current focus:

- Folder structure
- Environment variable examples
- Docker setup
- README skeletons
- Dependency lists
- Git hygiene

## Setup Status

This project is still in setup phase. Backend and frontend application logic will be added in later phases.

## Security Principles

- Do not commit real .env files.
- Do not hardcode API keys, passwords, tokens, or private configuration.
- Keep external data collection limited to approved public sources.
- Do not fetch dangerous files or malware samples.
- Validate backend inputs.
- Render external text safely in the frontend.
- Log errors without exposing secrets.

## Running the Project

Run these commands from the repository root:

```powershell
.\run.cmd install
.\run.cmd test
.\run.cmd docker
.\run.cmd dev
```

`install` prepares the backend and frontend dependencies, while `test` runs the
backend tests plus the frontend type check and production build. `docker` builds,
starts, and verifies the complete Docker Compose application.

For day-to-day development, `dev` starts only PostgreSQL in Docker, then runs the
FastAPI backend and Next.js frontend locally with reload support. Press Ctrl+C to
stop the local backend and frontend processes. The database container remains
running so it can be reused; stop it manually with Docker Compose when needed.

## Documentation

See the docs/ folder for:

- architecture.md
- data-sources.md
- security-notes.md
- testing-plan.md
- deployment-notes.md
