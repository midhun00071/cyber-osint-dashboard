# Architecture Notes

## Purpose

This document explains the planned architecture for the Cyber OSINT Dashboard / Alpha Data project.

## High-Level Architecture

The application will follow a modular full-stack architecture:

Open-source cybersecurity sources
-> Backend ingestion layer
-> Processing and enrichment layer
-> PostgreSQL database
-> FastAPI backend API
-> Next.js frontend dashboard

## Planned Main Modules

1. Backend API and Database
2. Data Ingestion
3. Data Processing and Enrichment
4. Frontend Dashboard

## UAE Relevance Classification

The backend includes an offline processing component for P4-01 UAE relevance
classification. It runs only when manually invoked for existing records or when
new NVD/CERT-EU RSS records are persisted through the existing manual ingestion
commands. It uses normalized title, summary, controlled source identity, and
existing safe geographic metadata. It does not use raw payloads, network calls,
machine learning, an LLM, schedulers, startup hooks, or public mutation routes.

Manual and source-declared classifications are treated as analyst-owned and are
not overwritten by automatic rules.

## Backend Responsibilities

- Provide API endpoints for dashboard data.
- Connect to PostgreSQL.
- Store normalized threat and vulnerability records.
- Run or trigger ingestion jobs.
- Validate query parameters.
- Handle errors safely.

## Frontend Responsibilities

- Display summary cards.
- Display threat and vulnerability records.
- Support search and filters.
- Display detail pages.
- Show loading, empty, and error states.
- Safely render external text.

## Database Responsibilities

- Store normalized intelligence records.
- Preserve source traceability.
- Support filtering and future historical analysis.

## Current Status

Phase 1 setup only. Architecture will be refined as implementation progresses.
