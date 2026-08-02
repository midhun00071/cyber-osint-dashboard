\set ON_ERROR_STOP on

BEGIN;

SET LOCAL search_path = pg_catalog;

SELECT set_config('b105.app_schema', :'app_schema', false);
SELECT set_config('b105.bootstrap_role', :'bootstrap_role', false);
SELECT set_config('b105.app_login', :'app_login', false);
SELECT set_config('b105.migration_login', :'migration_login', false);
SELECT set_config('b105.readonly_role', :'readonly_role', false);
SELECT set_config('b105.backup_role', :'backup_role', false);
SELECT set_config('b105.retention_role', :'retention_role', false);

DO $b105$
DECLARE
    identifier text;
    identifiers text[] := ARRAY[
        current_setting('b105.bootstrap_role'),
        current_setting('b105.app_login'),
        current_setting('b105.migration_login'),
        current_setting('b105.readonly_role'),
        current_setting('b105.backup_role'),
        current_setting('b105.retention_role')
    ];
    distinct_identifier_count integer;
BEGIN
    FOREACH identifier IN ARRAY array_prepend(
        current_setting('b105.app_schema'), identifiers
    )
    LOOP
        IF identifier !~ '^[A-Za-z_][A-Za-z0-9_]{0,62}$' THEN
            RAISE EXCEPTION 'database role provisioning identifier is invalid';
        END IF;
    END LOOP;

    SELECT count(DISTINCT managed_identifier)
    INTO distinct_identifier_count
    FROM unnest(identifiers) AS managed_identifier;
    IF distinct_identifier_count <> cardinality(identifiers) THEN
        RAISE EXCEPTION 'managed database role identifiers must be pairwise distinct';
    END IF;
END
$b105$;

DO $b105$
DECLARE
    schema_name text := current_setting('b105.app_schema');
    app_login text := current_setting('b105.app_login');
    migration_login text := current_setting('b105.migration_login');
    readonly_role text := current_setting('b105.readonly_role');
    backup_role text := current_setting('b105.backup_role');
    retention_role text := current_setting('b105.retention_role');
    object_record record;
    managed_role text;
    table_name text;
    managed_nonowner_roles text[] := ARRAY[
        app_login, readonly_role, backup_role, retention_role
    ];
    application_tables constant text[] := ARRAY[
        'audit_events', 'indicator_provenances', 'indicators',
        'ingestion_cycles', 'ingestion_errors', 'ingestion_run_records',
        'ingestion_run_events', 'ingestion_runs',
        'intelligence_item_identifiers', 'intelligence_item_indicators',
        'intelligence_item_tags', 'intelligence_items', 'intelligence_sources',
        'quarantined_records', 'source_checkpoints',
        'source_credential_references', 'source_rate_limit_states',
        'source_records', 'source_watermarks', 'tags', 'vulnerabilities'
    ];
    runtime_update_tables constant text[] := ARRAY[
        'indicators', 'ingestion_cycles', 'ingestion_runs',
        'intelligence_items', 'intelligence_sources', 'quarantined_records',
        'source_credential_references', 'source_rate_limit_states',
        'source_records', 'vulnerabilities'
    ];
    retention_read_tables constant text[] := ARRAY[
        'audit_events', 'ingestion_errors', 'ingestion_run_records',
        'ingestion_run_events', 'ingestion_runs', 'quarantined_records',
        'source_checkpoints', 'source_watermarks'
    ];
BEGIN
    EXECUTE format('REVOKE CREATE ON SCHEMA %I FROM PUBLIC', schema_name);
    EXECUTE format('GRANT USAGE, CREATE ON SCHEMA %I TO %I', schema_name, migration_login);
    EXECUTE format('GRANT USAGE ON SCHEMA %I TO %I', schema_name, app_login);
    EXECUTE format('GRANT USAGE ON SCHEMA %I TO %I', schema_name, readonly_role);
    EXECUTE format('GRANT USAGE ON SCHEMA %I TO %I', schema_name, backup_role);
    EXECUTE format('GRANT USAGE ON SCHEMA %I TO %I', schema_name, retention_role);
    EXECUTE format('REVOKE CREATE ON SCHEMA %I FROM %I', schema_name, app_login);
    EXECUTE format('REVOKE CREATE ON SCHEMA %I FROM %I', schema_name, readonly_role);
    EXECUTE format('REVOKE CREATE ON SCHEMA %I FROM %I', schema_name, backup_role);
    EXECUTE format('REVOKE CREATE ON SCHEMA %I FROM %I', schema_name, retention_role);

    FOR object_record IN
        SELECT c.relname, c.relkind
        FROM pg_class AS c
        JOIN pg_namespace AS n ON n.oid = c.relnamespace
        WHERE n.nspname = schema_name
          AND c.relkind IN ('r', 'p', 'S')
          AND (
              c.relkind <> 'S'
              OR NOT EXISTS (
                  SELECT 1
                  FROM pg_depend AS d
                  WHERE d.objid = c.oid
                    AND d.deptype IN ('a', 'i')
              )
          )
        ORDER BY CASE WHEN c.relkind = 'S' THEN 1 ELSE 0 END, c.relname
    LOOP
        IF object_record.relkind = 'S' THEN
            EXECUTE format(
                'ALTER SEQUENCE %I.%I OWNER TO %I',
                schema_name, object_record.relname, migration_login
            );
        ELSE
            EXECUTE format(
                'ALTER TABLE %I.%I OWNER TO %I',
                schema_name, object_record.relname, migration_login
            );
        END IF;
    END LOOP;

    EXECUTE format('REVOKE ALL ON ALL TABLES IN SCHEMA %I FROM PUBLIC', schema_name);
    EXECUTE format('REVOKE ALL ON ALL SEQUENCES IN SCHEMA %I FROM PUBLIC', schema_name);
    EXECUTE format('REVOKE ALL ON ALL TABLES IN SCHEMA %I FROM %I', schema_name, app_login);
    EXECUTE format('REVOKE ALL ON ALL TABLES IN SCHEMA %I FROM %I', schema_name, readonly_role);
    EXECUTE format('REVOKE ALL ON ALL TABLES IN SCHEMA %I FROM %I', schema_name, backup_role);
    EXECUTE format('REVOKE ALL ON ALL TABLES IN SCHEMA %I FROM %I', schema_name, retention_role);
    EXECUTE format('REVOKE ALL ON ALL SEQUENCES IN SCHEMA %I FROM %I', schema_name, app_login);
    EXECUTE format('REVOKE ALL ON ALL SEQUENCES IN SCHEMA %I FROM %I', schema_name, readonly_role);
    EXECUTE format('REVOKE ALL ON ALL SEQUENCES IN SCHEMA %I FROM %I', schema_name, backup_role);
    EXECUTE format('REVOKE ALL ON ALL SEQUENCES IN SCHEMA %I FROM %I', schema_name, retention_role);

    FOREACH table_name IN ARRAY application_tables
    LOOP
        IF to_regclass(format('%I.%I', schema_name, table_name)) IS NOT NULL THEN
            EXECUTE format(
                'GRANT SELECT, INSERT ON TABLE %I.%I TO %I',
                schema_name, table_name, app_login
            );
            EXECUTE format(
                'GRANT SELECT ON TABLE %I.%I TO %I',
                schema_name, table_name, readonly_role
            );
            EXECUTE format(
                'GRANT SELECT ON TABLE %I.%I TO %I',
                schema_name, table_name, backup_role
            );
        END IF;
    END LOOP;

    FOREACH table_name IN ARRAY runtime_update_tables
    LOOP
        IF to_regclass(format('%I.%I', schema_name, table_name)) IS NOT NULL THEN
            EXECUTE format(
                'GRANT UPDATE ON TABLE %I.%I TO %I',
                schema_name, table_name, app_login
            );
        END IF;
    END LOOP;

    FOREACH table_name IN ARRAY retention_read_tables
    LOOP
        IF to_regclass(format('%I.%I', schema_name, table_name)) IS NOT NULL THEN
            EXECUTE format(
                'GRANT SELECT ON TABLE %I.%I TO %I',
                schema_name, table_name, retention_role
            );
        END IF;
    END LOOP;

    FOR object_record IN
        SELECT DISTINCT sequence_class.relname
        FROM pg_class AS table_class
        JOIN pg_namespace AS table_namespace
          ON table_namespace.oid = table_class.relnamespace
        JOIN pg_depend AS dependency
          ON dependency.refobjid = table_class.oid
         AND dependency.deptype IN ('a', 'i')
        JOIN pg_class AS sequence_class
          ON sequence_class.oid = dependency.objid
         AND sequence_class.relkind = 'S'
        WHERE table_namespace.nspname = schema_name
          AND table_class.relkind IN ('r', 'p')
          AND table_class.relname = ANY(application_tables)
        ORDER BY sequence_class.relname
    LOOP
        EXECUTE format(
            'GRANT USAGE, SELECT ON SEQUENCE %I.%I TO %I',
            schema_name, object_record.relname, app_login
        );
    END LOOP;

    EXECUTE format(
        'ALTER DEFAULT PRIVILEGES FOR ROLE %I IN SCHEMA %I REVOKE ALL ON TABLES FROM PUBLIC',
        migration_login, schema_name
    );
    EXECUTE format(
        'ALTER DEFAULT PRIVILEGES FOR ROLE %I IN SCHEMA %I REVOKE ALL ON SEQUENCES FROM PUBLIC',
        migration_login, schema_name
    );
    FOREACH managed_role IN ARRAY managed_nonowner_roles
    LOOP
        EXECUTE format(
            'ALTER DEFAULT PRIVILEGES FOR ROLE %I IN SCHEMA %I REVOKE ALL ON TABLES FROM %I',
            migration_login, schema_name, managed_role
        );
        EXECUTE format(
            'ALTER DEFAULT PRIVILEGES FOR ROLE %I IN SCHEMA %I REVOKE ALL ON SEQUENCES FROM %I',
            migration_login, schema_name, managed_role
        );
    END LOOP;
END
$b105$;

COMMIT;
