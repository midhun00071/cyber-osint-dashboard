# B1-06 Database Security Audit

## Frozen scope and checkpoint

B1-06 audits database queries and persistence at checkpoint
`7ebdbb957fb18cb921067c746624e1a444382a97` on `dev`. It covers SQL injection,
fixed identifiers, mass assignment, write scope, public data projection,
active-record lifecycle enforcement, exception sanitization, transaction cleanup,
and the unchanged five-revision migration chain. It does not implement
authentication, authorization, tenancy, RBAC, BOLA/BFLA controls, API mutation
routes, schema changes, database roles, Prefect, deployment, or penetration
testing.

## Query and persistence inventory

The public read inventory comprises:

- `IntelligenceQueryService`: active intelligence list and direct public-ID
  detail, fixed item type and validated severity, source, CVE, year, geography,
  UAE relevance, pagination, and text filters.
- `ArticleQueryService`: active article list and direct public-ID detail, fixed
  article categories, validated source/tag/date/geography/UAE filters, literal
  escaped text search, fixed newest-first ordering, and bounded pagination.
- `DashboardSummaryService`: active-item and vulnerability aggregates, bounded
  latest articles, latest successful source fetch timestamp, and one latest
  ingestion run with fixed ordering.

The write inventory includes the approved source adapters and normalization
pipeline, source-specific Anomali and Censys transaction owners, RSS caller-owned
transactions, enrichment services, offline STIX persistence, and the B1-05
operational persistence service. Model construction assigns explicit fields.
There is no public API mutation route, generic model update endpoint, request
dictionary expansion into model constructors, dynamic ORM attribute assignment,
or unbounded production `UPDATE`/`DELETE`.

All production and migration uses of ORM `execute()`, `text()`,
`literal_column()`, `getattr()`, `setattr()`, model construction, and update/delete
were reviewed. Production has no `exec_driver_sql()` and passes no raw SQL string
directly to ORM `execute()`.

## Findings and resolved defects

### BLOCKER — PostgreSQL acceptance URL query overrides

The B1-03, B1-04, B1-05, and B1-06 PostgreSQL acceptance guards validated the
authority host and path database but previously allowed URL query parameters to
reach the driver. PostgreSQL connection parameters such as `host`, `hostaddr`,
`dbname`, `database`, `service`, and `servicefile` can select a different target;
other query fields can override the authority user, password, port, options, or
TLS mode. That created a corruption risk because acceptance setup can drop a
schema, remove test roles, run migrations, or bulk-delete test rows.

All four guards now reject every non-empty URL query before engine creation or
any destructive setup. They accept only PostgreSQL, normalize the accepted URL
to `postgresql+psycopg`, require their exact `b103_test_`, `b104_test_`,
`b105_test_`, or `b106_test_` prefix, reject database names containing
`staging`, `production`, or `prod`, and permit only `127.0.0.1`, `::1`, or
`localhost`. When `localhost` is used, every resolved address must be loopback.
Failure messages are fixed and do not contain the submitted URL, password, query
name, or query value. Guard-only tests run without database environment variables
and prove rejected URLs never invoke engine creation.

### MUST FIX — order-dependent rollback log assertions

The Anomali and Censys rollback tests used `caplog.text` even though the
application logger is intentionally non-propagating, making their result depend
on unrelated logging initialization order. Each affected test now monkeypatches
the exact service module `_LOGGER` with a deterministic recorder and asserts the
complete call list is exactly one `.error()` invocation containing only the
fixed rollback event and no keyword arguments. This proves no `exc_info`, raw
exception, SQL, URL, password, or traceback value is supplied without changing
production logger propagation or handlers.

### BLOCKER — SEC-0020 rollback failure suppression

The Anomali and Censys source-owned transaction helpers silently ignored ordinary
rollback failures. Both now emit exactly one fixed event:

```text
event=ingestion_rollback_failed source=<fixed-source> error_category=transaction_cleanup_failed
```

The event contains no exception object, exception text, SQL, parameters, URL,
credential, payload, or traceback. On rollback failure, the uncertain SQLAlchemy
session is marked with one fixed internal poison attribute before either logging
or invalidation is attempted. Logging and invalidation are independent
best-effort operations that catch `BaseException`; neither can replace the
primary exception or clear the marker. Missing or non-callable invalidation is
handled the same way. The caller must discard a poisoned session.

Every Anomali and Censys `ingest()` call checks the session-owned poison marker as
its first action. Reuse through the existing service or a newly constructed
service fails with a fixed sanitized database exception before input validation,
pipeline creation, model creation, queries, flush, rollback, or commit. An
ordinary primary failure plus any rollback failure, including rollback
`MemoryError`, raises the existing fixed transaction-cleanup exception. When
`MemoryError`, `KeyboardInterrupt`, `SystemExit`, or `GeneratorExit` is already
active, the exact original object remains primary even if both logging and
invalidation fail. Successful rollback does not poison the session. These
services do not own operational checkpoints or watermarks; failure occurs before
any durable progress advance, and no commit follows rollback failure.

### BLOCKER — inactive intelligence exposure

The intelligence list previously lacked a database-level active predicate and
detail loaded the entire result set before scanning in Python. Both paths now
require `IntelligenceItem.status == "active"`; detail also binds the requested
public UUID in its SQL statement. Archived, merged, superseded, and nonexistent
IDs return the same public 404 response.

### MUST FIX — RSS database exception classification

RSS previously grouped `SQLAlchemyError` with domain exceptions and inspected its
string for `conflicts`. SQLAlchemy errors now have a separate branch and their
text is never inspected. Only exact reviewed domain messages are allow-listed;
all other source/persistence/database failures become
`RSS persistence failed safely.` without exception chaining. Tests use database
URL, SQL, password, conflict-word, and traceback canaries and prove non-disclosure.

### MUST FIX — over-broad public ORM loads

Article, intelligence, and dashboard entity queries now use explicit
`load_only(..., raiseload=True)` column projections, recursive relationship
`raiseload("*")`, and relationship-specific projections. Count queries select
counts rather than full entity subqueries. Captured PostgreSQL SQL omits:

- `SourceRecord.raw_payload`, content/canonical URL hashes, processing state, and
  diagnostic summaries;
- `Vulnerability.affected_products_json`, KEV processing timestamps, and internal
  required action;
- analyst-review state and internal UAE reason/method;
- source checkpoint data and credential relationships;
- ingestion-run checkpoints, safe summaries, and unrelated operational metadata.

Serializers retain their existing response fields and ordering. Direct access to
prohibited deferred fields raises instead of silently issuing a lazy query.

## Injection, identifiers, filters, and ordering

Negative tests cover quotes, SQL comments, `UNION SELECT`, `DROP TABLE`,
`pg_sleep`, literal `%`, `_`, and backslash, plus existing long numeric,
identifier, CVE, slug, UUID, unknown-parameter, and repeated-parameter tests.
Article search escapes backslash first and then `%` and `_`, supplies an explicit
escape character, and sends the resulting pattern as a bound parameter. The
disposable PostgreSQL test proves literal wildcard matching, unchanged row counts,
and table survival after every payload.

Public routes expose no sort-field or order selector. Ordering columns and table
identifiers are fixed in code. Validation rejects invalid CVE, slug, UUID,
unknown, and repeated parameters before database execution where those inputs
exist. User input cannot choose an ORM attribute, column, table, or ordering
expression.

## Static SQL allow-list

`test_b1_06_database_security.py` parses all Python files under `backend/app` and
`backend/alembic`. Every allow-list entry records an exact file, call type,
fragment, and safety reason. The reviewed constant fragments are:

- fixed ordering: `source_published_at DESC`, `started_at DESC`,
  `occurred_at DESC`, `last_seen_at DESC`, and `id DESC`;
- fixed null/boolean predicates: `source_external_id IS NOT NULL`,
  `canonical_url_hash IS NOT NULL`, `source_record_id IS [NOT] NULL`,
  `source_id IS [NOT] NULL`, `is_primary IS TRUE`,
  `is_primary_reference IS TRUE AND intelligence_item_id IS NOT NULL`, and
  `correlation_id IS NOT NULL`;
- fixed operational predicates: `scope_kind = 'source' AND partition_key IS
  NULL`, `scope_kind = 'partition' AND partition_key IS NOT NULL`, and
  `state <> 'available'`;
- fixed optimistic-version expression:
  `ingestion_run_events.xmin::text::xid8`.

The audit fails on nonconstant `text()`/`literal_column()`, production
`exec_driver_sql()`, raw string ORM execution, unreviewed dynamic attributes,
model `**mapping`, unbounded migration updates/deletes, or new API mutation
decorators. Whole-file exclusions are not used.

## Mass assignment and write scope

Current persistence code explicitly names model fields. The two dynamic CLI
`setattr()` calls target bounded `argparse.Namespace` destinations rather than ORM
objects; logging configuration targets a handler marker; development seed
comparison reads a fixed local field manifest. These exact non-ORM calls are
listed in the AST audit. The existing migration updates all contain explicit
`WHERE` clauses. Operational checkpoints are advanced only in the caller-owned
transaction after persistence validation; the source-owned publication services
do not advance them and cannot fabricate success after transaction cleanup fails.
This is evidence for the current code snapshot, not a guarantee about future
changes.

## Migration review

No migration changed and no revision was created. Git-aware regression checks
preserve the accepted Windows CRLF normalization behavior while proving all five
historical migration paths are unchanged. Alembic remains one linear chain:

```text
f8d739439ed0 -> a6c9d4e2f107 -> c4e8b2a91d30 -> b103a71d2e4f -> d7a9e51c2f40
```

The head is `d7a9e51c2f40`; SQLAlchemy registers 21 tables.

## PostgreSQL 17 acceptance

The four dedicated suites read only their task-specific B103/B104/B105/B106
environment variables. Each URL must be query-free, use one approved loopback
authority, and name a database with the exact disposable task prefix. Validation
completes before engine creation, schema drops, role cleanup, migrations, or bulk
row deletion. No rejected URL is connected to.

The B1-06 suite additionally verifies PostgreSQL major version 17, rebuilds only
the disposable database's `public` schema, migrates to the frozen head, exercises
bound malicious searches, active-only access, public SQL projections,
deferred-field `raiseload`, dashboard canary isolation, table survival, and exact
row preservation, then removes test data and resets the disposable schema.

Configured acceptance used a temporary isolated PostgreSQL 17 container bound
only to `127.0.0.1:55439`, with four query-free databases named
`b103_test_hardening`, `b104_test_hardening`, `b105_test_hardening`, and
`b106_test_hardening`. Results were 19, 176, 46, and 21 passed respectively: 262
passed and zero skipped in total. The temporary container was stopped and
auto-removed afterward. The normal project database was not used, and there was
no staging, production, or external database access.

## Validation commands and evidence

Run from `backend`:

```powershell
.\.venv\Scripts\python.exe -m pytest tests/test_intelligence_api.py tests/test_articles_api.py tests/test_dashboard_summary_api.py tests/test_rss_ingestion_service.py tests/test_anomali_publications_ingestion_service.py tests/test_censys_publications_ingestion_service.py tests/test_b1_06_database_security.py -q
$env:B106_POSTGRESQL_TEST_DATABASE_URL = "<dedicated-loopback-b106-test-url>"
.\.venv\Scripts\python.exe -m pytest tests/test_b1_06_database_security_postgresql.py -q
```

The focused and full regression totals, wrapper result, mapper check, Alembic
commands, Git state, and review-package hashes are reported with the independent
review handoff. Hardening validation produced these exact results:

- query guards with all four database variables unset: 53 passed, 209
  deselected;
- Anomali and Censys ingestion-service suites: 118 passed;
- combined B1-06 focused suite in the required file order: 369 passed, one
  warning in the first hardening pass and 395 passed, one warning after the
  session-poisoning hardening;
- configured B1-03 through B1-06 PostgreSQL 17 suites: 262 passed, zero skipped;
- full backend with external writable `--basetemp`: 4,238 passed, 215 skipped,
  one warning;
- `run.cmd test`: backend collected 4,453; 4,170 passed, 209 skipped, 74 setup
  errors, and one warning before the wrapper stopped, so frontend validation was
  not reached. Every error was the existing protected default Windows pytest
  temporary-directory `WinError 5` condition.

The warning is the pre-existing Starlette `httpx` TestClient deprecation. The
successful full backend run uses the documented external writable `--basetemp`
to avoid that Windows environment limitation. Mapper registration remains 21
tables; Alembic reports one head, `d7a9e51c2f40`, and the unchanged five-revision
linear history.

## Classification, limitations, and ownership

- **BLOCKER:** SEC-0020, unsafe session reuse after failed rollback/invalidation,
  and inactive intelligence exposure were demonstrated and resolved with
  regression evidence. The PostgreSQL acceptance URL override was also a
  demonstrated destructive-test corruption risk and is resolved across all four
  suites.
- **MUST FIX:** RSS exception classification, broad public ORM entity loading,
  and order-dependent rollback log assertions were demonstrated and resolved.
- **FOLLOW-UP:** B7 owns authentication, authorization, tenancy, RBAC, BOLA, and
  BFLA. B10-02 owns release penetration testing.
- **ACCEPTED LIMITATION:** This is an offline/static and disposable-loopback
  PostgreSQL 17 assessment of the current snapshot. It is not production database
  testing, staging penetration testing, external certification, deployment
  evidence, or a claim of complete future SQL-injection immunity.
