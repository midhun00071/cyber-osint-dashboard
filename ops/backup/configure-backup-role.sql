\set ON_ERROR_STOP on

BEGIN;

DO $c09$
DECLARE
    role_record record;
BEGIN
    SELECT rolcanlogin, rolsuper, rolcreatedb, rolcreaterole, rolreplication, rolbypassrls
    INTO role_record
    FROM pg_roles
    WHERE rolname = 'alpha_data_backup';

    IF NOT FOUND
       OR role_record.rolcanlogin
       OR role_record.rolsuper
       OR role_record.rolcreatedb
       OR role_record.rolcreaterole
       OR role_record.rolreplication
       OR role_record.rolbypassrls THEN
        RAISE EXCEPTION 'the fixed backup group role is absent or unsafe';
    END IF;
END
$c09$;

DO $c09$
BEGIN
    IF NOT has_schema_privilege('alpha_data_backup', 'public', 'USAGE') THEN
        RAISE EXCEPTION 'the fixed backup group lacks required schema usage';
    END IF;
END
$c09$;
GRANT SELECT ON ALL TABLES IN SCHEMA public TO alpha_data_backup;
GRANT SELECT ON ALL SEQUENCES IN SCHEMA public TO alpha_data_backup;

ALTER DEFAULT PRIVILEGES IN SCHEMA public
    GRANT SELECT ON TABLES TO alpha_data_backup;
ALTER DEFAULT PRIVILEGES IN SCHEMA public
    GRANT SELECT ON SEQUENCES TO alpha_data_backup;

COMMIT;
