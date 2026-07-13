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
classification and P4-02 rule-strength confidence. It runs only when manually
invoked for existing records or when new NVD/CERT-EU RSS records are persisted
through the existing manual ingestion commands. It uses normalized title,
summary, controlled source identity, and existing safe geographic metadata. It
does not use raw payloads, network calls, machine learning, an LLM, schedulers,
startup hooks, or public mutation routes.

Automatic confidence is a fixed deterministic mapping from the winning
classification rule to a nullable `numeric(4,3)` value. It is not exploit
probability, threat attribution, attacker intent, targeting certainty, source
reliability in general, or business impact. Records with no direct UAE evidence
retain `null` confidence rather than a misleading zero score.

The frontend presents that canonical numeric confidence as a label for review
clarity: High for `0.900`-`1.000`, Medium for `0.750`-`0.899`, Low for
`0.000`-`0.749`, and no label for `null`. These labels are UI presentation
levels only. They are not severity, exploit likelihood, statistical
calibration, or attribution certainty, and P4-02 does not add confidence
filters.

P4-03 adds backend-driven frontend controls for geographic scope and UAE
relevance status on the dashboard latest-articles feed and vulnerability table.
Those controls send the existing read-only backend query parameters, combine
with search and pagination, and reset the current offset when changed. UAE
relevance status remains a classification field; it is not threat attribution,
attacker intent, or targeting certainty.

Manual and source-declared classifications are treated as analyst-owned and are
not overwritten by automatic rules, including their existing confidence values.

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
