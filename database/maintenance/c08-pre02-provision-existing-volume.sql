\set ON_ERROR_STOP on

\if :{?c08_phase}
\else
\set c08_phase invalid
\endif

SELECT 1 / CASE WHEN :'c08_phase' IN ('prepare', 'normalize') THEN 1 ELSE 0 END;
SELECT (:'c08_phase' = 'prepare')::integer AS prepare,
       (:'c08_phase' = 'normalize')::integer AS normalize
\gset c08_

\if :c08_prepare

BEGIN ISOLATION LEVEL SERIALIZABLE;

SET LOCAL search_path = pg_catalog;
SET LOCAL lock_timeout = '5s';
SET LOCAL statement_timeout = '60s';

DO $c08_pre02_prepare_guard$
DECLARE
    expected_tables constant text[] := ARRAY[
        'alembic_version', 'ingestion_errors', 'ingestion_run_records',
        'ingestion_runs', 'intelligence_item_identifiers',
        'intelligence_item_tags', 'intelligence_items',
        'intelligence_sources', 'source_records', 'tags', 'vulnerabilities'
    ];
    expected_sequences constant text[] := ARRAY[
        'ingestion_errors_id_seq', 'ingestion_run_records_id_seq',
        'ingestion_runs_id_seq', 'intelligence_item_identifiers_id_seq',
        'intelligence_items_id_seq', 'intelligence_sources_id_seq',
        'source_records_id_seq', 'tags_id_seq', 'vulnerabilities_id_seq'
    ];
    database_owner_name text;
    schema_owner_name text;
    app_owned_table_count integer;
    app_owned_sequence_count integer;
    managed_role_count integer;
    managed_membership_count integer;
    unexpected_owner_count integer;
    unexpected_object_name_count integer;
    unexpected_database_connect_grant_count integer;
BEGIN
    IF current_database() <> 'alpha_data_db' THEN
        RAISE EXCEPTION 'C08-PRE-02 unexpected database';
    END IF;
    IF current_user <> 'alpha_data_user' THEN
        RAISE EXCEPTION 'C08-PRE-02 unexpected maintenance identity';
    END IF;

    SELECT pg_get_userbyid(datdba)
    INTO database_owner_name
    FROM pg_database
    WHERE datname = current_database();

    SELECT pg_get_userbyid(nspowner)
    INTO schema_owner_name
    FROM pg_namespace
    WHERE nspname = 'public';

    IF database_owner_name <> 'alpha_data_user'
       OR schema_owner_name <> 'pg_database_owner' THEN
        RAISE EXCEPTION 'C08-PRE-02 legacy database/schema owner precondition failed';
    END IF;

    IF NOT EXISTS (
        SELECT 1
        FROM pg_roles AS role
        WHERE role.rolname = 'alpha_data_user'
          AND role.rolcanlogin
          AND role.rolsuper
          AND role.rolcreatedb
          AND role.rolcreaterole
          AND NOT role.rolreplication
          AND role.rolbypassrls
    ) THEN
        RAISE EXCEPTION 'C08-PRE-02 legacy application-role precondition failed';
    END IF;

    SELECT count(*)
    INTO managed_role_count
    FROM pg_roles
    WHERE rolname IN (
        'alpha_data_bootstrap', 'alpha_data_migration',
        'alpha_data_readonly', 'alpha_data_backup', 'alpha_data_retention'
    );

    IF managed_role_count <> 0 THEN
        RAISE EXCEPTION 'C08-PRE-02 legacy managed-role absence precondition failed';
    END IF;

    SELECT
        count(*) FILTER (
            WHERE object.relkind IN ('r', 'p')
              AND owner_role.rolname = 'alpha_data_user'
        ),
        count(*) FILTER (
            WHERE object.relkind = 'S'
              AND owner_role.rolname = 'alpha_data_user'
        ),
        count(*) FILTER (WHERE owner_role.rolname <> 'alpha_data_user'),
        count(*) FILTER (
            WHERE (object.relkind IN ('r', 'p') AND object.relname <> ALL(expected_tables))
               OR (object.relkind = 'S' AND object.relname <> ALL(expected_sequences))
        )
    INTO app_owned_table_count, app_owned_sequence_count, unexpected_owner_count,
         unexpected_object_name_count
    FROM pg_class AS object
    JOIN pg_namespace AS namespace ON namespace.oid = object.relnamespace
    JOIN pg_roles AS owner_role ON owner_role.oid = object.relowner
    WHERE namespace.nspname = 'public'
      AND object.relkind IN ('r', 'p', 'S');

    IF app_owned_table_count <> 11 OR app_owned_sequence_count <> 9 THEN
        RAISE EXCEPTION 'C08-PRE-02 exact legacy ownership precondition failed';
    END IF;
    IF unexpected_owner_count <> 0 THEN
        RAISE EXCEPTION 'C08-PRE-02 unexpected public object owner';
    END IF;
    IF unexpected_object_name_count <> 0 THEN
        RAISE EXCEPTION 'C08-PRE-02 unexpected public object name';
    END IF;

    SELECT count(*)
    INTO unexpected_database_connect_grant_count
    FROM pg_database AS database_record
    CROSS JOIN LATERAL aclexplode(
        coalesce(database_record.datacl, acldefault('d', database_record.datdba))
    ) AS privilege_record
    WHERE database_record.datname = current_database()
      AND privilege_record.privilege_type = 'CONNECT'
      AND privilege_record.grantee <> 0
      AND privilege_record.grantee <> (
          SELECT oid FROM pg_roles WHERE rolname = 'alpha_data_user'
      );
    IF unexpected_database_connect_grant_count <> 0 THEN
        RAISE EXCEPTION 'C08-PRE-02 unexpected legacy database CONNECT grant';
    END IF;

    SELECT count(*)
    INTO managed_membership_count
    FROM pg_auth_members AS membership
    JOIN pg_roles AS granted_role ON granted_role.oid = membership.roleid
    JOIN pg_roles AS member_role ON member_role.oid = membership.member
    WHERE granted_role.rolname LIKE 'alpha_data_%'
       OR member_role.rolname LIKE 'alpha_data_%';

    IF managed_membership_count <> 0 THEN
        RAISE EXCEPTION 'C08-PRE-02 unexpected managed-role membership';
    END IF;
END
$c08_pre02_prepare_guard$;

CREATE ROLE alpha_data_bootstrap
    LOGIN INHERIT SUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION BYPASSRLS;
CREATE ROLE alpha_data_migration
    LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
CREATE ROLE alpha_data_readonly
    NOLOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
CREATE ROLE alpha_data_backup
    NOLOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
CREATE ROLE alpha_data_retention
    NOLOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;

GRANT CONNECT ON DATABASE alpha_data_db TO alpha_data_bootstrap;
GRANT CONNECT ON DATABASE alpha_data_db TO alpha_data_migration;
GRANT CONNECT ON DATABASE alpha_data_db TO alpha_data_readonly;
GRANT CONNECT ON DATABASE alpha_data_db TO alpha_data_backup;
GRANT CONNECT ON DATABASE alpha_data_db TO alpha_data_retention;
GRANT USAGE, CREATE ON SCHEMA public TO alpha_data_migration;
GRANT USAGE ON SCHEMA public TO alpha_data_readonly;
GRANT USAGE ON SCHEMA public TO alpha_data_backup;
GRANT USAGE ON SCHEMA public TO alpha_data_retention;

DO $c08_pre02_verify_prepared$
DECLARE
    prepared_role_count integer;
    app_owned_table_count integer;
    app_owned_sequence_count integer;
    auxiliary_database_connect_count integer;
    auxiliary_schema_usage_count integer;
    auxiliary_schema_create_count integer;
    prepared_table_privilege_count integer;
    prepared_sequence_privilege_count integer;
    migration_default_acl_count integer;
BEGIN
    IF pg_get_userbyid((SELECT datdba FROM pg_database WHERE datname = current_database()))
        <> 'alpha_data_user'
       OR pg_get_userbyid((SELECT nspowner FROM pg_namespace WHERE nspname = 'public'))
        <> 'pg_database_owner' THEN
        RAISE EXCEPTION 'C08-PRE-02 Prepare changed an ownership boundary';
    END IF;

    SELECT count(*)
    INTO prepared_role_count
    FROM pg_roles AS role
    WHERE (
        role.rolname = 'alpha_data_bootstrap'
        AND role.rolcanlogin AND role.rolsuper
        AND NOT role.rolcreatedb AND NOT role.rolcreaterole
        AND NOT role.rolreplication AND role.rolbypassrls
    ) OR (
        role.rolname = 'alpha_data_migration'
        AND role.rolcanlogin AND NOT role.rolsuper
        AND NOT role.rolcreatedb AND NOT role.rolcreaterole
        AND NOT role.rolreplication AND NOT role.rolbypassrls
    ) OR (
        role.rolname IN ('alpha_data_readonly', 'alpha_data_backup', 'alpha_data_retention')
        AND NOT role.rolcanlogin AND NOT role.rolsuper
        AND NOT role.rolcreatedb AND NOT role.rolcreaterole
        AND NOT role.rolreplication AND NOT role.rolbypassrls
    );

    IF prepared_role_count <> 5 THEN
        RAISE EXCEPTION 'C08-PRE-02 prepared managed-role verification failed';
    END IF;

    SELECT
        count(*) FILTER (WHERE object.relkind IN ('r', 'p')),
        count(*) FILTER (WHERE object.relkind = 'S')
    INTO app_owned_table_count, app_owned_sequence_count
    FROM pg_class AS object
    JOIN pg_namespace AS namespace ON namespace.oid = object.relnamespace
    JOIN pg_roles AS owner_role ON owner_role.oid = object.relowner
    WHERE namespace.nspname = 'public'
      AND object.relkind IN ('r', 'p', 'S')
      AND owner_role.rolname = 'alpha_data_user';

    IF app_owned_table_count <> 11 OR app_owned_sequence_count <> 9 THEN
        RAISE EXCEPTION 'C08-PRE-02 Prepare changed application ownership';
    END IF;
    IF NOT has_database_privilege('alpha_data_migration', current_database(), 'CONNECT')
       OR NOT has_schema_privilege('alpha_data_migration', 'public', 'USAGE')
       OR NOT has_schema_privilege('alpha_data_migration', 'public', 'CREATE') THEN
        RAISE EXCEPTION 'C08-PRE-02 prepared migration capability verification failed';
    END IF;

    SELECT
        count(*) FILTER (
            WHERE has_database_privilege(role.rolname, current_database(), 'CONNECT')
        ),
        count(*) FILTER (WHERE has_schema_privilege(role.rolname, 'public', 'USAGE')),
        count(*) FILTER (WHERE has_schema_privilege(role.rolname, 'public', 'CREATE'))
    INTO auxiliary_database_connect_count, auxiliary_schema_usage_count,
         auxiliary_schema_create_count
    FROM pg_roles AS role
    WHERE role.rolname IN (
        'alpha_data_readonly', 'alpha_data_backup', 'alpha_data_retention'
    );
    IF auxiliary_database_connect_count <> 3
       OR auxiliary_schema_usage_count <> 3
       OR auxiliary_schema_create_count <> 0 THEN
        RAISE EXCEPTION 'C08-PRE-02 prepared auxiliary capability verification failed';
    END IF;

    SELECT count(*)
    INTO prepared_table_privilege_count
    FROM pg_roles AS role
    CROSS JOIN pg_class AS object
    JOIN pg_namespace AS namespace ON namespace.oid = object.relnamespace
    WHERE role.rolname IN (
        'alpha_data_migration', 'alpha_data_readonly',
        'alpha_data_backup', 'alpha_data_retention'
    )
      AND namespace.nspname = 'public'
      AND object.relkind IN ('r', 'p')
      AND (
          has_table_privilege(role.rolname, object.oid, 'SELECT')
          OR has_table_privilege(role.rolname, object.oid, 'INSERT')
          OR has_table_privilege(role.rolname, object.oid, 'UPDATE')
          OR has_table_privilege(role.rolname, object.oid, 'DELETE')
          OR has_table_privilege(role.rolname, object.oid, 'TRUNCATE')
          OR has_table_privilege(role.rolname, object.oid, 'REFERENCES')
          OR has_table_privilege(role.rolname, object.oid, 'TRIGGER')
      );
    SELECT count(*)
    INTO prepared_sequence_privilege_count
    FROM pg_roles AS role
    CROSS JOIN pg_class AS object
    JOIN pg_namespace AS namespace ON namespace.oid = object.relnamespace
    WHERE role.rolname IN (
        'alpha_data_migration', 'alpha_data_readonly',
        'alpha_data_backup', 'alpha_data_retention'
    )
      AND namespace.nspname = 'public'
      AND object.relkind = 'S'
      AND (
          has_sequence_privilege(role.rolname, object.oid, 'USAGE')
          OR has_sequence_privilege(role.rolname, object.oid, 'SELECT')
          OR has_sequence_privilege(role.rolname, object.oid, 'UPDATE')
      );
    IF prepared_table_privilege_count <> 0
       OR prepared_sequence_privilege_count <> 0 THEN
        RAISE EXCEPTION 'C08-PRE-02 Prepare added an object privilege';
    END IF;

    SELECT count(*)
    INTO migration_default_acl_count
    FROM pg_default_acl AS default_acl
    JOIN pg_roles AS role ON role.oid = default_acl.defaclrole
    WHERE role.rolname = 'alpha_data_migration';
    IF migration_default_acl_count <> 0 THEN
        RAISE EXCEPTION 'C08-PRE-02 unexpected prepared migration default privilege';
    END IF;
END
$c08_pre02_verify_prepared$;

COMMIT;

\elif :c08_normalize

BEGIN ISOLATION LEVEL SERIALIZABLE;

SET LOCAL search_path = pg_catalog;
SET LOCAL lock_timeout = '5s';
SET LOCAL statement_timeout = '60s';

DO $c08_pre02_normalize_guard$
DECLARE
    expected_tables constant text[] := ARRAY[
        'alembic_version', 'ingestion_errors', 'ingestion_run_records',
        'ingestion_runs', 'intelligence_item_identifiers',
        'intelligence_item_tags', 'intelligence_items',
        'intelligence_sources', 'source_records', 'tags', 'vulnerabilities'
    ];
    expected_sequences constant text[] := ARRAY[
        'ingestion_errors_id_seq', 'ingestion_run_records_id_seq',
        'ingestion_runs_id_seq', 'intelligence_item_identifiers_id_seq',
        'intelligence_items_id_seq', 'intelligence_sources_id_seq',
        'source_records_id_seq', 'tags_id_seq', 'vulnerabilities_id_seq'
    ];
    managed_role_count integer;
    managed_membership_count integer;
    app_owned_table_count integer;
    app_owned_sequence_count integer;
    unexpected_owner_count integer;
    unexpected_object_name_count integer;
    auxiliary_database_connect_count integer;
    auxiliary_schema_usage_count integer;
    auxiliary_schema_create_count integer;
    prepared_table_privilege_count integer;
    prepared_sequence_privilege_count integer;
    migration_default_acl_count integer;
    unexpected_database_connect_grant_count integer;
BEGIN
    IF current_database() <> 'alpha_data_db' OR current_user <> 'alpha_data_user' THEN
        RAISE EXCEPTION 'C08-PRE-02 Normalize execution identity precondition failed';
    END IF;
    IF pg_get_userbyid((SELECT datdba FROM pg_database WHERE datname = current_database()))
        <> 'alpha_data_user'
       OR pg_get_userbyid((SELECT nspowner FROM pg_namespace WHERE nspname = 'public'))
        <> 'pg_database_owner' THEN
        RAISE EXCEPTION 'C08-PRE-02 prepared database/schema owner precondition failed';
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM pg_roles AS role
        WHERE role.rolname = 'alpha_data_user'
          AND role.rolcanlogin AND role.rolsuper AND role.rolcreatedb
          AND role.rolcreaterole AND NOT role.rolreplication AND role.rolbypassrls
    ) THEN
        RAISE EXCEPTION 'C08-PRE-02 prepared application-role precondition failed';
    END IF;

    SELECT count(*)
    INTO managed_role_count
    FROM pg_roles AS role
    WHERE (
        role.rolname = 'alpha_data_bootstrap'
        AND role.rolcanlogin AND role.rolsuper
        AND NOT role.rolcreatedb AND NOT role.rolcreaterole
        AND NOT role.rolreplication AND role.rolbypassrls
    ) OR (
        role.rolname = 'alpha_data_migration'
        AND role.rolcanlogin AND NOT role.rolsuper
        AND NOT role.rolcreatedb AND NOT role.rolcreaterole
        AND NOT role.rolreplication AND NOT role.rolbypassrls
    ) OR (
        role.rolname IN ('alpha_data_readonly', 'alpha_data_backup', 'alpha_data_retention')
        AND NOT role.rolcanlogin AND NOT role.rolsuper
        AND NOT role.rolcreatedb AND NOT role.rolcreaterole
        AND NOT role.rolreplication AND NOT role.rolbypassrls
    );
    IF managed_role_count <> 5 THEN
        RAISE EXCEPTION 'C08-PRE-02 prepared managed-role precondition failed';
    END IF;

    SELECT
        count(*) FILTER (
            WHERE object.relkind IN ('r', 'p')
              AND owner_role.rolname = 'alpha_data_user'
        ),
        count(*) FILTER (
            WHERE object.relkind = 'S'
              AND owner_role.rolname = 'alpha_data_user'
        ),
        count(*) FILTER (WHERE owner_role.rolname <> 'alpha_data_user'),
        count(*) FILTER (
            WHERE (object.relkind IN ('r', 'p') AND object.relname <> ALL(expected_tables))
               OR (object.relkind = 'S' AND object.relname <> ALL(expected_sequences))
        )
    INTO app_owned_table_count, app_owned_sequence_count, unexpected_owner_count,
         unexpected_object_name_count
    FROM pg_class AS object
    JOIN pg_namespace AS namespace ON namespace.oid = object.relnamespace
    JOIN pg_roles AS owner_role ON owner_role.oid = object.relowner
    WHERE namespace.nspname = 'public'
      AND object.relkind IN ('r', 'p', 'S');
    IF app_owned_table_count <> 11 OR app_owned_sequence_count <> 9
       OR unexpected_owner_count <> 0 OR unexpected_object_name_count <> 0 THEN
        RAISE EXCEPTION 'C08-PRE-02 prepared ownership precondition failed';
    END IF;

    SELECT count(*)
    INTO managed_membership_count
    FROM pg_auth_members AS membership
    JOIN pg_roles AS granted_role ON granted_role.oid = membership.roleid
    JOIN pg_roles AS member_role ON member_role.oid = membership.member
    WHERE granted_role.rolname LIKE 'alpha_data_%'
       OR member_role.rolname LIKE 'alpha_data_%';
    IF managed_membership_count <> 0 THEN
        RAISE EXCEPTION 'C08-PRE-02 unexpected managed-role membership';
    END IF;
    IF NOT has_database_privilege('alpha_data_migration', current_database(), 'CONNECT')
       OR NOT has_schema_privilege('alpha_data_migration', 'public', 'USAGE')
       OR NOT has_schema_privilege('alpha_data_migration', 'public', 'CREATE') THEN
        RAISE EXCEPTION 'C08-PRE-02 prepared migration capability precondition failed';
    END IF;

    SELECT
        count(*) FILTER (
            WHERE has_database_privilege(role.rolname, current_database(), 'CONNECT')
        ),
        count(*) FILTER (WHERE has_schema_privilege(role.rolname, 'public', 'USAGE')),
        count(*) FILTER (WHERE has_schema_privilege(role.rolname, 'public', 'CREATE'))
    INTO auxiliary_database_connect_count, auxiliary_schema_usage_count,
         auxiliary_schema_create_count
    FROM pg_roles AS role
    WHERE role.rolname IN (
        'alpha_data_readonly', 'alpha_data_backup', 'alpha_data_retention'
    );
    IF auxiliary_database_connect_count <> 3
       OR auxiliary_schema_usage_count <> 3
       OR auxiliary_schema_create_count <> 0 THEN
        RAISE EXCEPTION 'C08-PRE-02 prepared auxiliary capability precondition failed';
    END IF;

    SELECT count(*)
    INTO prepared_table_privilege_count
    FROM pg_roles AS role
    CROSS JOIN pg_class AS object
    JOIN pg_namespace AS namespace ON namespace.oid = object.relnamespace
    WHERE role.rolname IN (
        'alpha_data_migration', 'alpha_data_readonly',
        'alpha_data_backup', 'alpha_data_retention'
    )
      AND namespace.nspname = 'public'
      AND object.relkind IN ('r', 'p')
      AND (
          has_table_privilege(role.rolname, object.oid, 'SELECT')
          OR has_table_privilege(role.rolname, object.oid, 'INSERT')
          OR has_table_privilege(role.rolname, object.oid, 'UPDATE')
          OR has_table_privilege(role.rolname, object.oid, 'DELETE')
          OR has_table_privilege(role.rolname, object.oid, 'TRUNCATE')
          OR has_table_privilege(role.rolname, object.oid, 'REFERENCES')
          OR has_table_privilege(role.rolname, object.oid, 'TRIGGER')
      );
    SELECT count(*)
    INTO prepared_sequence_privilege_count
    FROM pg_roles AS role
    CROSS JOIN pg_class AS object
    JOIN pg_namespace AS namespace ON namespace.oid = object.relnamespace
    WHERE role.rolname IN (
        'alpha_data_migration', 'alpha_data_readonly',
        'alpha_data_backup', 'alpha_data_retention'
    )
      AND namespace.nspname = 'public'
      AND object.relkind = 'S'
      AND (
          has_sequence_privilege(role.rolname, object.oid, 'USAGE')
          OR has_sequence_privilege(role.rolname, object.oid, 'SELECT')
          OR has_sequence_privilege(role.rolname, object.oid, 'UPDATE')
      );
    IF prepared_table_privilege_count <> 0
       OR prepared_sequence_privilege_count <> 0 THEN
        RAISE EXCEPTION 'C08-PRE-02 prepared object-privilege precondition failed';
    END IF;

    SELECT count(*)
    INTO migration_default_acl_count
    FROM pg_default_acl AS default_acl
    JOIN pg_roles AS role ON role.oid = default_acl.defaclrole
    WHERE role.rolname = 'alpha_data_migration';
    IF migration_default_acl_count <> 0 THEN
        RAISE EXCEPTION 'C08-PRE-02 unexpected prepared migration default privilege';
    END IF;

    SELECT count(*)
    INTO unexpected_database_connect_grant_count
    FROM pg_database AS database_record
    CROSS JOIN LATERAL aclexplode(
        coalesce(database_record.datacl, acldefault('d', database_record.datdba))
    ) AS privilege_record
    LEFT JOIN pg_roles AS grantee_role ON grantee_role.oid = privilege_record.grantee
    WHERE database_record.datname = current_database()
      AND privilege_record.privilege_type = 'CONNECT'
      AND privilege_record.grantee <> 0
      AND grantee_role.rolname NOT IN (
          'alpha_data_user', 'alpha_data_bootstrap', 'alpha_data_migration',
          'alpha_data_readonly', 'alpha_data_backup', 'alpha_data_retention'
      );
    IF unexpected_database_connect_grant_count <> 0 THEN
        RAISE EXCEPTION 'C08-PRE-02 unexpected prepared database CONNECT grant';
    END IF;
END
$c08_pre02_normalize_guard$;

ALTER DATABASE alpha_data_db OWNER TO alpha_data_bootstrap;
ALTER SCHEMA public OWNER TO alpha_data_bootstrap;

DO $c08_pre02_transfer_exact_ownership$
DECLARE
    expected_tables constant text[] := ARRAY[
        'alembic_version', 'ingestion_errors', 'ingestion_run_records',
        'ingestion_runs', 'intelligence_item_identifiers',
        'intelligence_item_tags', 'intelligence_items',
        'intelligence_sources', 'source_records', 'tags', 'vulnerabilities'
    ];
    expected_sequences constant text[] := ARRAY[
        'ingestion_errors_id_seq', 'ingestion_run_records_id_seq',
        'ingestion_runs_id_seq', 'intelligence_item_identifiers_id_seq',
        'intelligence_items_id_seq', 'intelligence_sources_id_seq',
        'source_records_id_seq', 'tags_id_seq', 'vulnerabilities_id_seq'
    ];
    object_record record;
    transferred_table_count integer := 0;
    transferred_sequence_count integer := 0;
BEGIN
    FOR object_record IN
        SELECT object.relname, object.relkind
        FROM pg_class AS object
        JOIN pg_namespace AS namespace ON namespace.oid = object.relnamespace
        JOIN pg_roles AS owner_role ON owner_role.oid = object.relowner
        WHERE namespace.nspname = 'public'
          AND object.relkind IN ('r', 'p', 'S')
          AND owner_role.rolname = 'alpha_data_user'
          AND (
              (object.relkind IN ('r', 'p') AND object.relname = ANY(expected_tables))
              OR (object.relkind = 'S' AND object.relname = ANY(expected_sequences))
          )
        ORDER BY CASE WHEN object.relkind = 'S' THEN 1 ELSE 0 END, object.relname
    LOOP
        IF object_record.relkind = 'S' THEN
            EXECUTE format(
                'ALTER SEQUENCE %I.%I OWNER TO alpha_data_migration',
                'public', object_record.relname
            );
            transferred_sequence_count := transferred_sequence_count + 1;
        ELSE
            EXECUTE format(
                'ALTER TABLE %I.%I OWNER TO alpha_data_migration',
                'public', object_record.relname
            );
            transferred_table_count := transferred_table_count + 1;
        END IF;
    END LOOP;

    IF transferred_table_count <> 11 OR transferred_sequence_count <> 9 THEN
        RAISE EXCEPTION 'C08-PRE-02 exact ownership transfer failed';
    END IF;
END
$c08_pre02_transfer_exact_ownership$;

REVOKE CONNECT ON DATABASE alpha_data_db FROM PUBLIC;
GRANT CONNECT ON DATABASE alpha_data_db TO alpha_data_user;
GRANT CONNECT ON DATABASE alpha_data_db TO alpha_data_bootstrap;
GRANT CONNECT ON DATABASE alpha_data_db TO alpha_data_migration;
GRANT CONNECT ON DATABASE alpha_data_db TO alpha_data_readonly;
GRANT CONNECT ON DATABASE alpha_data_db TO alpha_data_backup;
GRANT CONNECT ON DATABASE alpha_data_db TO alpha_data_retention;

REVOKE CREATE ON SCHEMA public FROM PUBLIC;
REVOKE ALL ON ALL TABLES IN SCHEMA public FROM PUBLIC;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM PUBLIC;
GRANT USAGE, CREATE ON SCHEMA public TO alpha_data_migration;
GRANT USAGE ON SCHEMA public TO alpha_data_readonly;
GRANT USAGE ON SCHEMA public TO alpha_data_backup;
GRANT USAGE ON SCHEMA public TO alpha_data_retention;

DO $c08_pre02_apply_non_application_allow_lists$
DECLARE
    table_name text;
    application_tables constant text[] := ARRAY[
        'ingestion_errors', 'ingestion_run_records', 'ingestion_runs',
        'intelligence_item_identifiers', 'intelligence_item_tags',
        'intelligence_items', 'intelligence_sources', 'source_records',
        'tags', 'vulnerabilities'
    ];
    retention_read_tables constant text[] := ARRAY[
        'ingestion_errors', 'ingestion_run_records', 'ingestion_runs'
    ];
BEGIN
    REVOKE ALL ON ALL TABLES IN SCHEMA public FROM alpha_data_readonly;
    REVOKE ALL ON ALL TABLES IN SCHEMA public FROM alpha_data_backup;
    REVOKE ALL ON ALL TABLES IN SCHEMA public FROM alpha_data_retention;
    REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM alpha_data_readonly;
    REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM alpha_data_backup;
    REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM alpha_data_retention;

    FOREACH table_name IN ARRAY application_tables LOOP
        IF to_regclass(format('%I.%I', 'public', table_name)) IS NULL THEN
            RAISE EXCEPTION 'C08-PRE-02 expected application table missing';
        END IF;
        EXECUTE format('GRANT SELECT ON TABLE %I.%I TO alpha_data_readonly', 'public', table_name);
        EXECUTE format('GRANT SELECT ON TABLE %I.%I TO alpha_data_backup', 'public', table_name);
    END LOOP;
    FOREACH table_name IN ARRAY retention_read_tables LOOP
        EXECUTE format('GRANT SELECT ON TABLE %I.%I TO alpha_data_retention', 'public', table_name);
    END LOOP;
END
$c08_pre02_apply_non_application_allow_lists$;

ALTER DEFAULT PRIVILEGES FOR ROLE alpha_data_migration IN SCHEMA public
    REVOKE ALL ON TABLES FROM PUBLIC;
ALTER DEFAULT PRIVILEGES FOR ROLE alpha_data_migration IN SCHEMA public
    REVOKE ALL ON SEQUENCES FROM PUBLIC;
ALTER DEFAULT PRIVILEGES FOR ROLE alpha_data_migration IN SCHEMA public
    REVOKE ALL ON TABLES FROM alpha_data_user;
ALTER DEFAULT PRIVILEGES FOR ROLE alpha_data_migration IN SCHEMA public
    REVOKE ALL ON SEQUENCES FROM alpha_data_user;
ALTER DEFAULT PRIVILEGES FOR ROLE alpha_data_migration IN SCHEMA public
    REVOKE ALL ON TABLES FROM alpha_data_readonly;
ALTER DEFAULT PRIVILEGES FOR ROLE alpha_data_migration IN SCHEMA public
    REVOKE ALL ON SEQUENCES FROM alpha_data_readonly;
ALTER DEFAULT PRIVILEGES FOR ROLE alpha_data_migration IN SCHEMA public
    REVOKE ALL ON TABLES FROM alpha_data_backup;
ALTER DEFAULT PRIVILEGES FOR ROLE alpha_data_migration IN SCHEMA public
    REVOKE ALL ON SEQUENCES FROM alpha_data_backup;
ALTER DEFAULT PRIVILEGES FOR ROLE alpha_data_migration IN SCHEMA public
    REVOKE ALL ON TABLES FROM alpha_data_retention;
ALTER DEFAULT PRIVILEGES FOR ROLE alpha_data_migration IN SCHEMA public
    REVOKE ALL ON SEQUENCES FROM alpha_data_retention;

DO $c08_pre02_verify_paths_before_application_restriction$
DECLARE
    migration_owned_table_count integer;
    migration_owned_sequence_count integer;
BEGIN
    IF pg_get_userbyid((SELECT datdba FROM pg_database WHERE datname = current_database()))
        <> 'alpha_data_bootstrap'
       OR pg_get_userbyid((SELECT nspowner FROM pg_namespace WHERE nspname = 'public'))
        <> 'alpha_data_bootstrap' THEN
        RAISE EXCEPTION 'C08-PRE-02 bootstrap ownership verification failed';
    END IF;
    IF NOT has_database_privilege('alpha_data_migration', current_database(), 'CONNECT')
       OR NOT has_schema_privilege('alpha_data_migration', 'public', 'USAGE')
       OR NOT has_schema_privilege('alpha_data_migration', 'public', 'CREATE') THEN
        RAISE EXCEPTION 'C08-PRE-02 migration path verification failed';
    END IF;

    SELECT
        count(*) FILTER (WHERE object.relkind IN ('r', 'p')),
        count(*) FILTER (WHERE object.relkind = 'S')
    INTO migration_owned_table_count, migration_owned_sequence_count
    FROM pg_class AS object
    JOIN pg_namespace AS namespace ON namespace.oid = object.relnamespace
    JOIN pg_roles AS owner_role ON owner_role.oid = object.relowner
    WHERE namespace.nspname = 'public'
      AND object.relkind IN ('r', 'p', 'S')
      AND owner_role.rolname = 'alpha_data_migration';
    IF migration_owned_table_count <> 11 OR migration_owned_sequence_count <> 9 THEN
        RAISE EXCEPTION 'C08-PRE-02 normalized ownership verification failed';
    END IF;
END
$c08_pre02_verify_paths_before_application_restriction$;

SET LOCAL ROLE alpha_data_migration;
DO $c08_pre02_effective_migration_role$
BEGIN
    IF current_user <> 'alpha_data_migration'
       OR NOT has_schema_privilege(current_user, 'public', 'USAGE')
       OR NOT has_schema_privilege(current_user, 'public', 'CREATE') THEN
        RAISE EXCEPTION 'C08-PRE-02 effective migration-role verification failed';
    END IF;
END
$c08_pre02_effective_migration_role$;
RESET ROLE;

REVOKE CREATE ON SCHEMA public FROM alpha_data_user;
REVOKE ALL ON ALL TABLES IN SCHEMA public FROM alpha_data_user;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM alpha_data_user;

DO $c08_pre02_apply_application_allow_list$
DECLARE
    object_record record;
    table_name text;
    application_tables constant text[] := ARRAY[
        'ingestion_errors', 'ingestion_run_records', 'ingestion_runs',
        'intelligence_item_identifiers', 'intelligence_item_tags',
        'intelligence_items', 'intelligence_sources', 'source_records',
        'tags', 'vulnerabilities'
    ];
    runtime_update_tables constant text[] := ARRAY[
        'ingestion_runs', 'intelligence_items', 'intelligence_sources',
        'source_records', 'vulnerabilities'
    ];
BEGIN
    IF to_regclass('public.alembic_version') IS NULL THEN
        RAISE EXCEPTION 'C08-PRE-02 expected revision table missing';
    END IF;
    GRANT SELECT ON TABLE public.alembic_version TO alpha_data_user;

    FOREACH table_name IN ARRAY application_tables LOOP
        EXECUTE format(
            'GRANT SELECT, INSERT ON TABLE %I.%I TO alpha_data_user',
            'public', table_name
        );
    END LOOP;
    FOREACH table_name IN ARRAY runtime_update_tables LOOP
        EXECUTE format('GRANT UPDATE ON TABLE %I.%I TO alpha_data_user', 'public', table_name);
    END LOOP;
    FOR object_record IN
        SELECT DISTINCT sequence_class.relname
        FROM pg_class AS table_class
        JOIN pg_namespace AS table_namespace ON table_namespace.oid = table_class.relnamespace
        JOIN pg_depend AS dependency
          ON dependency.refobjid = table_class.oid AND dependency.deptype IN ('a', 'i')
        JOIN pg_class AS sequence_class
          ON sequence_class.oid = dependency.objid AND sequence_class.relkind = 'S'
        WHERE table_namespace.nspname = 'public'
          AND table_class.relkind IN ('r', 'p')
          AND table_class.relname = ANY(application_tables)
        ORDER BY sequence_class.relname
    LOOP
        EXECUTE format(
            'GRANT USAGE, SELECT ON SEQUENCE %I.%I TO alpha_data_user',
            'public', object_record.relname
        );
    END LOOP;
END
$c08_pre02_apply_application_allow_list$;

ALTER ROLE alpha_data_user WITH
    LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;

DO $c08_pre02_final_guard$
DECLARE
    runtime_owned_object_count integer;
    unexpected_owner_count integer;
    public_database_connect_count integer;
    unexpected_database_connect_grant_count integer;
    migration_default_acl_count integer;
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_roles AS role
        WHERE role.rolname = 'alpha_data_bootstrap'
          AND role.rolcanlogin AND role.rolsuper
          AND NOT role.rolcreatedb AND NOT role.rolcreaterole
          AND NOT role.rolreplication AND role.rolbypassrls
    ) THEN
        RAISE EXCEPTION 'C08-PRE-02 final administrative path verification failed';
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM pg_roles AS role
        WHERE role.rolname = 'alpha_data_migration'
          AND role.rolcanlogin AND NOT role.rolsuper
          AND NOT role.rolcreatedb AND NOT role.rolcreaterole
          AND NOT role.rolreplication AND NOT role.rolbypassrls
    )
       OR NOT has_database_privilege('alpha_data_migration', current_database(), 'CONNECT')
       OR NOT has_schema_privilege('alpha_data_migration', 'public', 'USAGE')
       OR NOT has_schema_privilege('alpha_data_migration', 'public', 'CREATE') THEN
        RAISE EXCEPTION 'C08-PRE-02 final migration path verification failed';
    END IF;
    IF EXISTS (
        SELECT 1 FROM pg_roles AS role
        WHERE role.rolname = 'alpha_data_user'
          AND (
              NOT role.rolcanlogin OR role.rolsuper OR role.rolcreatedb
              OR role.rolcreaterole OR role.rolreplication OR role.rolbypassrls
          )
    ) THEN
        RAISE EXCEPTION 'C08-PRE-02 runtime attribute normalization failed';
    END IF;
    IF has_schema_privilege('alpha_data_user', 'public', 'CREATE')
       OR has_table_privilege('alpha_data_user', 'public.intelligence_sources', 'DELETE')
       OR has_sequence_privilege(
           'alpha_data_user', 'public.intelligence_sources_id_seq', 'UPDATE'
       ) THEN
        RAISE EXCEPTION 'C08-PRE-02 runtime destructive privilege remains';
    END IF;
    IF NOT has_database_privilege('alpha_data_user', current_database(), 'CONNECT')
       OR NOT has_database_privilege('alpha_data_bootstrap', current_database(), 'CONNECT')
       OR NOT has_database_privilege('alpha_data_migration', current_database(), 'CONNECT')
       OR NOT has_database_privilege('alpha_data_readonly', current_database(), 'CONNECT')
       OR NOT has_database_privilege('alpha_data_backup', current_database(), 'CONNECT')
       OR NOT has_database_privilege('alpha_data_retention', current_database(), 'CONNECT') THEN
        RAISE EXCEPTION 'C08-PRE-02 managed database CONNECT path missing';
    END IF;

    SELECT
        count(*) FILTER (WHERE privilege_record.grantee = 0),
        count(*) FILTER (
            WHERE privilege_record.grantee <> 0
              AND grantee_role.rolname NOT IN (
                  'alpha_data_user', 'alpha_data_bootstrap', 'alpha_data_migration',
                  'alpha_data_readonly', 'alpha_data_backup', 'alpha_data_retention'
              )
        )
    INTO public_database_connect_count, unexpected_database_connect_grant_count
    FROM pg_database AS database_record
    CROSS JOIN LATERAL aclexplode(
        coalesce(database_record.datacl, acldefault('d', database_record.datdba))
    ) AS privilege_record
    LEFT JOIN pg_roles AS grantee_role ON grantee_role.oid = privilege_record.grantee
    WHERE database_record.datname = current_database()
      AND privilege_record.privilege_type = 'CONNECT';
    IF public_database_connect_count <> 0
       OR unexpected_database_connect_grant_count <> 0 THEN
        RAISE EXCEPTION 'C08-PRE-02 database CONNECT allow-list verification failed';
    END IF;

    SELECT count(*)
    INTO migration_default_acl_count
    FROM pg_default_acl AS default_acl
    JOIN pg_roles AS role ON role.oid = default_acl.defaclrole
    WHERE role.rolname = 'alpha_data_migration';
    IF migration_default_acl_count <> 0 THEN
        RAISE EXCEPTION 'C08-PRE-02 migration default privilege verification failed';
    END IF;

    SELECT
        count(*) FILTER (WHERE owner_role.rolname = 'alpha_data_user'),
        count(*) FILTER (WHERE owner_role.rolname <> 'alpha_data_migration')
    INTO runtime_owned_object_count, unexpected_owner_count
    FROM pg_class AS object
    JOIN pg_namespace AS namespace ON namespace.oid = object.relnamespace
    JOIN pg_roles AS owner_role ON owner_role.oid = object.relowner
    WHERE namespace.nspname = 'public'
      AND object.relkind IN ('r', 'p', 'S');
    IF runtime_owned_object_count <> 0 OR unexpected_owner_count <> 0 THEN
        RAISE EXCEPTION 'C08-PRE-02 final ownership normalization failed';
    END IF;
END
$c08_pre02_final_guard$;

COMMIT;

\endif
