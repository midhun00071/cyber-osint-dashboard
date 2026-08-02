#!/bin/sh

set -eu
umask 077

readonly IDENTIFIER_PATTERN='^[A-Za-z_][A-Za-z0-9_]{0,62}$'
readonly MAX_SECRET_BYTES=4096

fail() {
    printf '%s\n' 'Database role provisioning failed.' >&2
    exit 1
}

require_identifier() {
    value=$1
    [ -n "$value" ] || fail
    printf '%s' "$value" | LC_ALL=C grep -Eq "$IDENTIFIER_PATTERN" || fail
}

require_distinct_roles() {
    checked_roles=
    for managed_role in "$@"
    do
        for checked_role in $checked_roles
        do
            [ "$managed_role" != "$checked_role" ] || fail
        done
        checked_roles="${checked_roles:+$checked_roles }$managed_role"
    done
}

read_role_secret() {
    direct_value=$1
    file_reference=$2

    if [ -n "$direct_value" ] && [ -n "$file_reference" ]; then
        fail
    fi
    if [ -n "$file_reference" ]; then
        [ -f "$file_reference" ] && [ ! -L "$file_reference" ] || fail
        byte_count=$(wc -c < "$file_reference" | tr -d ' ')
        [ "$byte_count" -ge 1 ] && [ "$byte_count" -le "$MAX_SECRET_BYTES" ] || fail
        secret_value=$(sed -e ':a' -e 'N' -e '$!ba' -e 's/[\r\n]*$//' "$file_reference")
    else
        secret_value=$direct_value
    fi
    [ -n "$secret_value" ] || fail
    [ "$(printf '%s' "$secret_value" | wc -l | tr -d ' ')" -eq 0 ] || fail
    carriage_return=$(printf '\r')
    case "$secret_value" in
        *"$carriage_return"*) fail ;;
    esac
    ROLE_SECRET=$secret_value
}

set_role_password() {
    role_name=$1
    role_secret=$2
    {
        printf '%s\n' "$role_secret"
        printf '%s\n' "$role_secret"
    } | psql \
        --no-psqlrc \
        --set=ON_ERROR_STOP=1 \
        --username "$POSTGRES_USER" \
        --dbname "$POSTGRES_DB" \
        --command "\\password $role_name" >/dev/null
}

: "${POSTGRES_DB:?}"
: "${POSTGRES_USER:?}"
: "${POSTGRES_APP_USER:?}"
: "${POSTGRES_MIGRATION_USER:?}"

POSTGRES_APP_SCHEMA=${POSTGRES_APP_SCHEMA:-public}
POSTGRES_READONLY_ROLE=${POSTGRES_READONLY_ROLE:-alpha_data_readonly}
POSTGRES_BACKUP_ROLE=${POSTGRES_BACKUP_ROLE:-alpha_data_backup}
POSTGRES_RETENTION_ROLE=${POSTGRES_RETENTION_ROLE:-alpha_data_retention}

for identifier in \
    "$POSTGRES_DB" \
    "$POSTGRES_USER" \
    "$POSTGRES_APP_USER" \
    "$POSTGRES_MIGRATION_USER" \
    "$POSTGRES_APP_SCHEMA" \
    "$POSTGRES_READONLY_ROLE" \
    "$POSTGRES_BACKUP_ROLE" \
    "$POSTGRES_RETENTION_ROLE"
do
    require_identifier "$identifier"
done

require_distinct_roles \
    "$POSTGRES_USER" \
    "$POSTGRES_APP_USER" \
    "$POSTGRES_MIGRATION_USER" \
    "$POSTGRES_READONLY_ROLE" \
    "$POSTGRES_BACKUP_ROLE" \
    "$POSTGRES_RETENTION_ROLE"

readonly GRANTS_FILE=/opt/alpha-data/database/11-apply-database-grants.sql
[ -f "$GRANTS_FILE" ] && [ -r "$GRANTS_FILE" ] && [ ! -L "$GRANTS_FILE" ] || fail
resolved_grants_file=$(readlink -f "$GRANTS_FILE") || fail
[ "$resolved_grants_file" = "$GRANTS_FILE" ] || fail

if ! psql \
    --no-psqlrc \
    --set=ON_ERROR_STOP=1 \
    --username "$POSTGRES_USER" \
    --dbname "$POSTGRES_DB" \
    --set=bootstrap_role="$POSTGRES_USER" \
    --set=app_login="$POSTGRES_APP_USER" \
    --set=migration_login="$POSTGRES_MIGRATION_USER" \
    --set=readonly_role="$POSTGRES_READONLY_ROLE" \
    --set=backup_role="$POSTGRES_BACKUP_ROLE" \
    --set=retention_role="$POSTGRES_RETENTION_ROLE" >/dev/null 2>&1 <<'SQL'
BEGIN;

SELECT format(
    'CREATE ROLE %I LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS',
    :'app_login'
) WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = :'app_login') \gexec
SELECT format(
    'CREATE ROLE %I LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS',
    :'migration_login'
) WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = :'migration_login') \gexec
SELECT format(
    'CREATE ROLE %I NOLOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS',
    role_name
) FROM (VALUES (:'readonly_role'), (:'backup_role'), (:'retention_role')) AS roles(role_name)
WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = role_name) \gexec

SELECT set_config('b105.bootstrap_role', :'bootstrap_role', false);
SELECT set_config('b105.app_login', :'app_login', false);
SELECT set_config('b105.migration_login', :'migration_login', false);
SELECT set_config('b105.readonly_role', :'readonly_role', false);
SELECT set_config('b105.backup_role', :'backup_role', false);
SELECT set_config('b105.retention_role', :'retention_role', false);

DO $b105$
DECLARE
    managed_roles text[] := ARRAY[
        current_setting('b105.bootstrap_role'),
        current_setting('b105.app_login'),
        current_setting('b105.migration_login'),
        current_setting('b105.readonly_role'),
        current_setting('b105.backup_role'),
        current_setting('b105.retention_role')
    ];
    unsafe_managed_role text;
BEGIN
    SELECT CASE
        WHEN member_role.rolname = ANY(managed_roles) THEN member_role.rolname
        ELSE granted_role.rolname
    END
    INTO unsafe_managed_role
    FROM pg_auth_members AS membership
    JOIN pg_roles AS granted_role ON granted_role.oid = membership.roleid
    JOIN pg_roles AS member_role ON member_role.oid = membership.member
    WHERE member_role.rolname = ANY(managed_roles)
       OR granted_role.rolname = ANY(managed_roles)
    LIMIT 1;

    IF unsafe_managed_role IS NOT NULL THEN
        RAISE EXCEPTION 'managed database role % has an unsafe membership',
            unsafe_managed_role;
    END IF;
END
$b105$;

SELECT format(
    'ALTER ROLE %I WITH LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS',
    role_name
) FROM (VALUES (:'app_login'), (:'migration_login')) AS roles(role_name) \gexec
SELECT format(
    'ALTER ROLE %I WITH NOLOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS',
    role_name
) FROM (VALUES (:'readonly_role'), (:'backup_role'), (:'retention_role')) AS roles(role_name) \gexec

COMMIT;
SQL
then
    fail
fi

read_role_secret \
    "${POSTGRES_APP_PASSWORD:-}" \
    "${POSTGRES_APP_PASSWORD_FILE:-}"
set_role_password "$POSTGRES_APP_USER" "$ROLE_SECRET"
unset ROLE_SECRET secret_value

read_role_secret \
    "${POSTGRES_MIGRATION_PASSWORD:-}" \
    "${POSTGRES_MIGRATION_PASSWORD_FILE:-}"
set_role_password "$POSTGRES_MIGRATION_USER" "$ROLE_SECRET"
unset ROLE_SECRET secret_value

psql \
    --no-psqlrc \
    --set=ON_ERROR_STOP=1 \
    --username "$POSTGRES_USER" \
    --dbname "$POSTGRES_DB" \
    --set=app_schema="$POSTGRES_APP_SCHEMA" \
    --set=bootstrap_role="$POSTGRES_USER" \
    --set=app_login="$POSTGRES_APP_USER" \
    --set=migration_login="$POSTGRES_MIGRATION_USER" \
    --set=readonly_role="$POSTGRES_READONLY_ROLE" \
    --set=backup_role="$POSTGRES_BACKUP_ROLE" \
    --set=retention_role="$POSTGRES_RETENTION_ROLE" \
    --file "$GRANTS_FILE"

printf '%s\n' 'Database roles and grants provisioned.'
