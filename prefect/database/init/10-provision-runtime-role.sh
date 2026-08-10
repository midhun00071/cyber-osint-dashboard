#!/bin/sh

set -eu
umask 077

readonly IDENTIFIER_PATTERN='^[A-Za-z_][A-Za-z0-9_]{0,62}$'
readonly MAX_SECRET_BYTES=4096

fail() {
    printf '%s\n' 'Prefect database provisioning failed.' >&2
    exit 1
}

require_identifier() {
    value=$1
    [ -n "$value" ] || fail
    printf '%s' "$value" | LC_ALL=C grep -Eq "$IDENTIFIER_PATTERN" || fail
}

: "${POSTGRES_USER:?}"
: "${PREFECT_RUNTIME_USER:?}"
: "${PREFECT_RUNTIME_PASSWORD:?}"
: "${PREFECT_RUNTIME_DB:?}"

require_identifier "$POSTGRES_USER"
require_identifier "$PREFECT_RUNTIME_USER"
require_identifier "$PREFECT_RUNTIME_DB"
[ "$POSTGRES_USER" != "$PREFECT_RUNTIME_USER" ] || fail

secret_bytes=$(printf '%s' "$PREFECT_RUNTIME_PASSWORD" | wc -c | tr -d ' ')
[ "$secret_bytes" -ge 1 ] && [ "$secret_bytes" -le "$MAX_SECRET_BYTES" ] || fail
[ "$(printf '%s' "$PREFECT_RUNTIME_PASSWORD" | wc -l | tr -d ' ')" -eq 0 ] || fail
carriage_return=$(printf '\r')
case "$PREFECT_RUNTIME_PASSWORD" in
    *"$carriage_return"*) fail ;;
esac

psql \
    --no-psqlrc \
    --set=ON_ERROR_STOP=1 \
    --username "$POSTGRES_USER" \
    --dbname postgres \
    --set=runtime_user="$PREFECT_RUNTIME_USER" >/dev/null <<'SQL'
SELECT format(
    'CREATE ROLE %I LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS',
    :'runtime_user'
) WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = :'runtime_user') \gexec
SELECT format(
    'ALTER ROLE %I WITH LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS',
    :'runtime_user'
) \gexec
SQL

{
    printf '%s\n' "$PREFECT_RUNTIME_PASSWORD"
    printf '%s\n' "$PREFECT_RUNTIME_PASSWORD"
} | psql \
    --no-psqlrc \
    --set=ON_ERROR_STOP=1 \
    --username "$POSTGRES_USER" \
    --dbname postgres \
    --command "\\password $PREFECT_RUNTIME_USER" >/dev/null

unset PREFECT_RUNTIME_PASSWORD

psql \
    --no-psqlrc \
    --set=ON_ERROR_STOP=1 \
    --username "$POSTGRES_USER" \
    --dbname postgres \
    --set=runtime_user="$PREFECT_RUNTIME_USER" \
    --set=runtime_db="$PREFECT_RUNTIME_DB" >/dev/null <<'SQL'
SELECT format(
    'CREATE DATABASE %I OWNER %I',
    :'runtime_db',
    :'runtime_user'
) WHERE NOT EXISTS (SELECT 1 FROM pg_database WHERE datname = :'runtime_db') \gexec
SELECT format('REVOKE ALL ON DATABASE %I FROM PUBLIC', :'runtime_db') \gexec
SELECT format(
    'GRANT CONNECT, TEMPORARY ON DATABASE %I TO %I',
    :'runtime_db',
    :'runtime_user'
) \gexec
SQL

privileges=$(psql \
    --no-psqlrc \
    --tuples-only \
    --no-align \
    --field-separator='|' \
    --set=ON_ERROR_STOP=1 \
    --username "$POSTGRES_USER" \
    --dbname postgres \
    --set=runtime_user="$PREFECT_RUNTIME_USER" <<'SQL'
SELECT rolsuper, rolcreatedb, rolcreaterole, rolreplication, rolbypassrls
FROM pg_roles
WHERE rolname = :'runtime_user';
SQL
)
[ "$privileges" = 'f|f|f|f|f' ] || fail

ownership=$(psql \
    --no-psqlrc \
    --tuples-only \
    --no-align \
    --set=ON_ERROR_STOP=1 \
    --username "$POSTGRES_USER" \
    --dbname postgres \
    --set=runtime_db="$PREFECT_RUNTIME_DB" <<'SQL'
SELECT pg_get_userbyid(datdba)
FROM pg_database
WHERE datname = :'runtime_db';
SQL
)
[ "$ownership" = "$PREFECT_RUNTIME_USER" ] || fail

printf '%s\n' 'Prefect database runtime role provisioned.'
