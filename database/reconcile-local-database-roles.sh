#!/bin/sh

set -eu
umask 077

fail() {
    printf '%s\n' 'Local database role reconciliation failed.' >&2
    exit 1
}

require_identifier() {
    value=$1
    [ -n "$value" ] || fail
    printf '%s' "$value" | LC_ALL=C grep -Eq '^[A-Za-z_][A-Za-z0-9_]{0,62}$' || fail
}

set_role_password() {
    admin_role=$1
    target_role=$2
    role_secret=$3
    {
        printf '%s\n' "$role_secret"
        printf '%s\n' "$role_secret"
    } | psql \
        --no-psqlrc \
        --set=ON_ERROR_STOP=1 \
        --username "$admin_role" \
        --dbname "$POSTGRES_DB" \
        --command "\\password $target_role" >/dev/null 2>&1 || fail
}

: "${POSTGRES_DB:?}"
: "${POSTGRES_USER:?}"
: "${POSTGRES_PASSWORD:?}"
: "${POSTGRES_APP_USER:?}"

POSTGRES_LEGACY_USER=${POSTGRES_LEGACY_USER:-}
POSTGRES_MIGRATION_USER=${POSTGRES_MIGRATION_USER:-alpha_data_migration}
POSTGRES_READONLY_ROLE=${POSTGRES_READONLY_ROLE:-alpha_data_readonly}
POSTGRES_BACKUP_ROLE=${POSTGRES_BACKUP_ROLE:-alpha_data_backup}
POSTGRES_RETENTION_ROLE=${POSTGRES_RETENTION_ROLE:-alpha_data_retention}

require_identifier "$POSTGRES_DB"
require_identifier "$POSTGRES_USER"
require_identifier "$POSTGRES_APP_USER"
if [ -n "$POSTGRES_LEGACY_USER" ]; then
    require_identifier "$POSTGRES_LEGACY_USER"
fi
require_identifier "$POSTGRES_MIGRATION_USER"
require_identifier "$POSTGRES_READONLY_ROLE"
require_identifier "$POSTGRES_BACKUP_ROLE"
require_identifier "$POSTGRES_RETENTION_ROLE"

checked_roles=
for managed_role in \
    "$POSTGRES_USER" \
    "$POSTGRES_APP_USER" \
    "$POSTGRES_MIGRATION_USER" \
    "$POSTGRES_READONLY_ROLE" \
    "$POSTGRES_BACKUP_ROLE" \
    "$POSTGRES_RETENTION_ROLE"
do
    for checked_role in $checked_roles
    do
        [ "$managed_role" != "$checked_role" ] || fail
    done
    checked_roles="${checked_roles:+$checked_roles }$managed_role"
done

admin_role=
for candidate in \
    "$POSTGRES_USER" \
    "$POSTGRES_LEGACY_USER" \
    alpha_data_user \
    "$POSTGRES_APP_USER"
do
    [ -n "$candidate" ] || continue
    is_superuser=$(psql \
        --no-psqlrc \
        --username "$candidate" \
        --dbname "$POSTGRES_DB" \
        --tuples-only \
        --no-align \
        --command "SELECT CASE WHEN rolsuper THEN 'yes' ELSE 'no' END FROM pg_roles WHERE rolname = current_user" \
        2>/dev/null) || continue
    if [ "$is_superuser" = yes ]; then
        admin_role=$candidate
        break
    fi
done
[ -n "$admin_role" ] || fail

if [ "$admin_role" != "$POSTGRES_USER" ]; then
    psql \
        --no-psqlrc \
        --set=ON_ERROR_STOP=1 \
        --username "$admin_role" \
        --dbname "$POSTGRES_DB" \
        --set=bootstrap_role="$POSTGRES_USER" >/dev/null 2>&1 <<'SQL' || fail
SELECT format(
    'CREATE ROLE %I LOGIN INHERIT SUPERUSER CREATEDB CREATEROLE NOREPLICATION NOBYPASSRLS',
    :'bootstrap_role'
) WHERE NOT EXISTS (
    SELECT 1 FROM pg_roles WHERE rolname = :'bootstrap_role'
) \gexec
SELECT format(
    'ALTER ROLE %I WITH LOGIN INHERIT SUPERUSER CREATEDB CREATEROLE NOREPLICATION NOBYPASSRLS',
    :'bootstrap_role'
) \gexec
SQL
fi
set_role_password "$POSTGRES_USER" "$POSTGRES_USER" "$POSTGRES_PASSWORD"

membership_count=$(psql \
    --no-psqlrc \
    --set=ON_ERROR_STOP=1 \
    --username "$POSTGRES_USER" \
    --dbname "$POSTGRES_DB" \
    --tuples-only \
    --no-align \
    --set=bootstrap_role="$POSTGRES_USER" \
    --set=app_login="$POSTGRES_APP_USER" \
    --set=migration_login="$POSTGRES_MIGRATION_USER" \
    --set=readonly_role="$POSTGRES_READONLY_ROLE" \
    --set=backup_role="$POSTGRES_BACKUP_ROLE" \
    --set=retention_role="$POSTGRES_RETENTION_ROLE" <<'SQL'
SELECT count(*)
FROM pg_auth_members AS membership
JOIN pg_roles AS granted_role ON granted_role.oid = membership.roleid
JOIN pg_roles AS member_role ON member_role.oid = membership.member
WHERE member_role.rolname IN (
    :'bootstrap_role', :'app_login', :'migration_login',
    :'readonly_role', :'backup_role', :'retention_role'
)
   OR granted_role.rolname IN (
    :'bootstrap_role', :'app_login', :'migration_login',
    :'readonly_role', :'backup_role', :'retention_role'
);
SQL
) || fail
if [ "$membership_count" -ne 0 ]; then
    printf '%s\n' 'Local database role reconciliation found conflicting role memberships.' >&2
    exit 1
fi

printf '%s\n' 'PASS Local database administrator and role topology are valid.'

ensure_login_role() {
    role_name=$1
    role_category=$2
    psql \
        --no-psqlrc \
        --set=ON_ERROR_STOP=1 \
        --username "$POSTGRES_USER" \
        --dbname "$POSTGRES_DB" \
        --set=managed_role="$role_name" >/dev/null 2>&1 <<'SQL' || {
SELECT format(
    'CREATE ROLE %I LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS',
    :'managed_role'
) WHERE NOT EXISTS (
    SELECT 1 FROM pg_roles WHERE rolname = :'managed_role'
) \gexec
SELECT format(
    'ALTER ROLE %I WITH LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS',
    :'managed_role'
) \gexec
SQL
        printf '%s\n' "Local database $role_category role transition failed." >&2
        exit 1
    }
}

ensure_group_role() {
    role_name=$1
    role_category=$2
    psql \
        --no-psqlrc \
        --set=ON_ERROR_STOP=1 \
        --username "$POSTGRES_USER" \
        --dbname "$POSTGRES_DB" \
        --set=managed_role="$role_name" >/dev/null 2>&1 <<'SQL' || {
SELECT format(
    'CREATE ROLE %I NOLOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS',
    :'managed_role'
) WHERE NOT EXISTS (
    SELECT 1 FROM pg_roles WHERE rolname = :'managed_role'
) \gexec
SELECT format(
    'ALTER ROLE %I WITH NOLOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS',
    :'managed_role'
) \gexec
SQL
        printf '%s\n' "Local database $role_category group transition failed." >&2
        exit 1
    }
}

ensure_login_role "$POSTGRES_APP_USER" application
ensure_login_role "$POSTGRES_MIGRATION_USER" migration
ensure_group_role "$POSTGRES_READONLY_ROLE" read-only
ensure_group_role "$POSTGRES_BACKUP_ROLE" backup
ensure_group_role "$POSTGRES_RETENTION_ROLE" retention

printf '%s\n' 'PASS Legacy database roles now match the separated local topology.'

tr -d '\r' < /opt/alpha-data/database/10-provision-database-roles.sh | sh
