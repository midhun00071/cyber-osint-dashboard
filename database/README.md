# Database - Cyber OSINT Dashboard

## Purpose

The database folder stores PostgreSQL setup notes and optional initialization files for local Docker-based development.

## Implemented database

The application uses PostgreSQL 17, SQLAlchemy models, and a linear Alembic
migration history. The current metadata contains 21 application tables for
normalized intelligence, provenance, ingestion operations, progress state,
quarantine, and audit evidence.

## Data areas

- normalized intelligence and vulnerability records;
- approved-source metadata and provenance;
- indicator metadata and publication relationships;
- ingestion cycles, runs, records, errors, and append-only run events;
- versioned checkpoints and watermarks;
- bounded quarantine and audit evidence; and
- provider-neutral credential-reference metadata without secret values.

## init/ folder

Compose mounts only the role-provisioning shell script into PostgreSQL's
automatic initialization directory at:

`/docker-entrypoint-initdb.d/10-provision-database-roles.sh`

The grants SQL is mounted separately at the fixed non-automatic path
`/opt/alpha-data/database/11-apply-database-grants.sql`. The shell validates
that exact regular, readable, non-symlink path and invokes it once. PostgreSQL's
entrypoint therefore cannot also auto-execute the SQL.

Do not place secrets, credentials, database dumps with sensitive data, or production data in this folder.

`10-provision-database-roles.sh` and `11-apply-database-grants.sql` implement
idempotent B1-05 role separation. Fresh PostgreSQL initialization runs them
in that single shell-controlled order before Alembic. Existing databases at or
beyond `b103a71d2e4f` require an
authorized operator to invoke the provisioning script explicitly. Role and
schema identifiers are strictly validated; application and migration passwords
come from protected inputs and are never stored in SQL.

All six managed identities must have pairwise-distinct names. Existing or
inbound role memberships at any managed boundary fail provisioning before role
normalization or password rotation. Future objects receive no automatic access
for runtime, read-only, backup, or retention roles; rerunning provisioning
grants access only to the recognized current tables and owned sequences.

The bootstrap identity administers initialization only. Migration owns/manages
schema objects. Runtime receives required DML but no DDL, truncate, role
administration, ownership, or deletion. Read-only and logical-backup roles can
select only. Retention can read only the operational evidence needed for dry-run
planning and has no destructive privilege.

## Backup metadata

`backup-metadata.schema.json` is a strict, versioned, non-secret metadata
contract for future B9-05 evidence. It does not create a backup and does not
prove restore, recoverability, RPO, or RTO. APR-11 remains pending.

## Current status

B1-05 implementation is dry-run and review-oriented. No staging or production
role provisioning, retention deletion, backup, or restore is claimed. APR-09,
APR-10, and APR-11 remain approval dependencies.
