# Database - Cyber OSINT Dashboard

## Purpose

The database folder stores PostgreSQL setup notes and optional initialization files for local Docker-based development.

## Planned Database

The MVP will use PostgreSQL.

The first planned main table is expected to store normalized cybersecurity intelligence records such as vulnerabilities, advisories, and threat reports.

## Planned Data Areas

Future database schema may include:

- Threat records
- Source metadata
- Source health status
- Indicators of compromise metadata
- MITRE ATT&CK mappings
- Analyst notes
- Audit logs

## init/ Folder

The init/ folder is mounted into the PostgreSQL container at:

/docker-entrypoint-initdb.d

Only safe initialization scripts should be placed here.

Do not place secrets, credentials, database dumps with sensitive data, or production data in this folder.

## Current Status

Phase 1 setup only. No schema has been added yet.
