#!/bin/sh

set -eu

fail() {
    printf '%s\n' 'Application database grants could not be reconciled.' >&2
    exit 1
}

require_identifier() {
    value=$1
    [ -n "$value" ] || fail
    printf '%s' "$value" | LC_ALL=C grep -Eq '^[A-Za-z_][A-Za-z0-9_]{0,62}$' || fail
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

readonly GRANTS_FILE=/opt/alpha-data/database/11-apply-database-grants.sql
[ -f "$GRANTS_FILE" ] && [ -r "$GRANTS_FILE" ] && [ ! -L "$GRANTS_FILE" ] || fail
[ "$(readlink -f "$GRANTS_FILE")" = "$GRANTS_FILE" ] || fail

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
    --file "$GRANTS_FILE" >/dev/null || fail

printf '%s\n' 'PASS Application database grants are current.'
