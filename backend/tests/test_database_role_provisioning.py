from pathlib import Path
import re


REPO_ROOT = Path(__file__).resolve().parents[2]
PROVISION_SCRIPT = REPO_ROOT / "database" / "init" / "10-provision-database-roles.sh"
GRANTS_SCRIPT = REPO_ROOT / "database" / "init" / "11-apply-database-grants.sql"


def source(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def test_provisioning_is_fail_fast_and_validates_every_dynamic_identifier() -> None:
    script = source(PROVISION_SCRIPT)

    assert "set -eu" in script
    assert "umask 077" in script
    assert "^[A-Za-z_][A-Za-z0-9_]{0,62}$" in script
    for variable in (
        "POSTGRES_DB",
        "POSTGRES_USER",
        "POSTGRES_APP_USER",
        "POSTGRES_MIGRATION_USER",
        "POSTGRES_APP_SCHEMA",
        "POSTGRES_READONLY_ROLE",
        "POSTGRES_BACKUP_ROLE",
        "POSTGRES_RETENTION_ROLE",
    ):
        assert f'"${variable}"' in script


def test_non_administrative_roles_have_exact_safe_attributes() -> None:
    combined = source(PROVISION_SCRIPT) + source(GRANTS_SCRIPT)

    assert combined.count(
        "NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS"
    ) >= 5
    assert "SUPERUSER" not in combined.replace("NOSUPERUSER", "")
    assert "CREATEDB" not in combined.replace("NOCREATEDB", "")
    assert "CREATEROLE" not in combined.replace("NOCREATEROLE", "")
    assert "REPLICATION" not in combined.replace("NOREPLICATION", "")
    assert "BYPASSRLS" not in combined.replace("NOBYPASSRLS", "")
    assert combined.count("INHERIT NOSUPERUSER") >= 5


def test_role_passwords_are_never_stored_in_sql_or_command_arguments() -> None:
    shell = source(PROVISION_SCRIPT)
    sql = source(GRANTS_SCRIPT).lower()

    assert "password" not in sql
    assert "--password" not in shell
    assert "--set=app_password" not in shell
    assert "--set=migration_password" not in shell
    assert "\\password $role_name" in shell
    assert "set -x" not in shell


def test_grants_are_explicit_and_never_broad_or_security_definer() -> None:
    sql = source(GRANTS_SCRIPT)
    lowered = sql.lower()

    assert not re.search(r"(?i)grant\s+all", sql)
    assert "security definer" not in lowered
    assert "SET LOCAL search_path = pg_catalog" in sql
    assert "REVOKE CREATE ON SCHEMA %I FROM PUBLIC" in sql
    assert "GRANT USAGE, CREATE ON SCHEMA %I TO %I" in sql
    assert "ALTER DEFAULT PRIVILEGES" in sql
    assert "REVOKE ALL ON TABLES FROM PUBLIC" in sql
    assert "REVOKE ALL ON SEQUENCES FROM PUBLIC" in sql
    assert not re.search(
        r"(?i)ALTER DEFAULT PRIVILEGES[^\n]*GRANT", sql
    )
    assert "GRANT USAGE, SELECT ON ALL SEQUENCES" not in sql


def test_provisioning_uses_one_fixed_non_automatic_grants_file() -> None:
    shell = source(PROVISION_SCRIPT)

    fixed_path = "/opt/alpha-data/database/11-apply-database-grants.sql"
    assert shell.count(f"GRANTS_FILE={fixed_path}") == 1
    assert shell.count('--file "$GRANTS_FILE"') == 1
    assert '[ -f "$GRANTS_FILE" ]' in shell
    assert '[ -r "$GRANTS_FILE" ]' in shell
    assert '[ ! -L "$GRANTS_FILE" ]' in shell
    assert 'readlink -f "$GRANTS_FILE"' in shell
    assert '"$resolved_grants_file" = "$GRANTS_FILE"' in shell
    assert shell.index('[ -f "$GRANTS_FILE" ]') < shell.index("if ! psql")
    assert "/docker-entrypoint-initdb.d/11-apply-database-grants.sql" not in shell


def test_every_managed_role_name_is_pairwise_distinct_before_psql() -> None:
    shell = source(PROVISION_SCRIPT)
    distinct_block = shell.split("require_distinct_roles \\\n", 1)[1].split(
        "\n\nif ! psql", 1
    )[0]

    for variable in (
        "POSTGRES_USER",
        "POSTGRES_APP_USER",
        "POSTGRES_MIGRATION_USER",
        "POSTGRES_READONLY_ROLE",
        "POSTGRES_BACKUP_ROLE",
        "POSTGRES_RETENTION_ROLE",
    ):
        assert distinct_block.count(f'"${variable}"') == 1
    assert '[ "$managed_role" != "$checked_role" ] || fail' in shell


def test_managed_role_memberships_are_rejected_before_normalization() -> None:
    shell = source(PROVISION_SCRIPT)

    membership_guard = shell.index("FROM pg_auth_members AS membership")
    normalization = shell.index("ALTER ROLE %I WITH LOGIN INHERIT")
    assert membership_guard < normalization
    assert "member_role.rolname = ANY(managed_roles)" in shell
    assert "granted_role.rolname = ANY(managed_roles)" in shell
    assert ">/dev/null 2>&1 <<'SQL'" in shell
    assert "Database role provisioning failed." in shell


def test_runtime_role_has_no_delete_truncate_ddl_or_append_only_update() -> None:
    sql = source(GRANTS_SCRIPT)
    update_block = sql.split("runtime_update_tables constant text[] := ARRAY[", 1)[1].split(
        "];", 1
    )[0]

    for table_name in (
        "ingestion_run_events",
        "source_checkpoints",
        "source_watermarks",
        "audit_events",
        "ingestion_errors",
    ):
        assert f"'{table_name}'" not in update_block
    assert "GRANT DELETE" not in sql
    assert "GRANT TRUNCATE" not in sql
    assert "GRANT CREATE ON SCHEMA %I TO %I', schema_name, app_login" not in sql


def test_readonly_backup_and_retention_roles_are_narrow() -> None:
    sql = source(GRANTS_SCRIPT)

    assert "GRANT SELECT ON TABLE %I.%I TO %I" in sql
    retention_block = sql.split(
        "retention_read_tables constant text[] := ARRAY[", 1
    )[1].split("];", 1)[0]
    assert "'intelligence_sources'" not in retention_block
    assert "GRANT SELECT, INSERT ON TABLE %I.%I TO %I" in sql
    assert "GRANT UPDATE ON TABLE %I.%I TO %I" in sql


def test_existing_objects_transfer_only_to_migration_identity() -> None:
    sql = source(GRANTS_SCRIPT)

    assert "ALTER TABLE %I.%I OWNER TO %I" in sql
    assert "ALTER SEQUENCE %I.%I OWNER TO %I" in sql
    assert "schema_name, object_record.relname, migration_login" in sql
    assert "OWNER TO %I', schema_name, object_record.relname, app_login" not in sql
