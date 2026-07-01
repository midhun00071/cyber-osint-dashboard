# Security Notes

## Purpose

This document tracks security decisions and safeguards for the Cyber OSINT Dashboard / Alpha Data project.

## Core Security Principles

- Do not commit real .env files.
- Do not hardcode API keys, passwords, tokens, or credentials.
- Use environment variables for configuration.
- Validate backend query parameters.
- Use safe database access through ORM or parameterized queries.
- Render external text safely in the frontend.
- Log errors without exposing secrets.
- Use approved public data sources only.
- Do not download malware samples or unsafe files.
- Keep the project defensive and educational.

## Environment Variable Handling

Example files:

- .env.example
- backend/.env.example
- frontend/.env.example

Real local environment files must remain untracked by Git.

## Docker Security

Dockerfiles should:

- Avoid copying real .env files.
- Use .dockerignore files.
- Run application services as non-root users where practical.
- Avoid embedding secrets into images.

## Backend Security

Planned backend controls:

- Pydantic validation.
- Controlled error responses.
- Safe logging.
- CORS restricted to trusted frontend origins.
- Request timeouts for external sources.
- Admin ingestion endpoint protected or disabled in production.

## Frontend Security

Planned frontend controls:

- Do not store secrets in frontend variables.
- Only use NEXT_PUBLIC_ variables for safe public values.
- Escape or safely render external source content.
- Avoid rendering untrusted HTML.

## Current Status

Phase 1 setup only. Security checks will expand during implementation and testing.
