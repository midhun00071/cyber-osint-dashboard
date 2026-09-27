"""C09 streaming encrypted PostgreSQL and quiesced Prefect backup/restore CLI."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
import tarfile
import tempfile
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from secrets import token_hex
from typing import BinaryIO, Iterable, Mapping


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
ALEMBIC_HEAD = "c07a01b02c03"
MAX_SECRET_BYTES = 4096
MAX_RESTORE_ARCHIVE_BYTES = 8 * 1024 * 1024 * 1024
RESTORE_TMPFS_DIRECTORY = Path("/dev/shm")
BACKUP_ID = re.compile(r"^backup_[0-9]{8}t[0-9]{6}z_[a-f0-9]{8}$")
PREFECT_BACKUP_ID = re.compile(r"^prefect_backup_[0-9]{8}t[0-9]{6}z_[a-f0-9]{8}$")
RESTORE_DATABASE = re.compile(r"^alpha_data_restore_[a-z0-9]{8,32}$")
RESTORE_VOLUME = re.compile(r"^alpha-data-(?:rehearsal|restore)-[a-z0-9]{8,32}$")
POSTGRES_ARTIFACT = re.compile(r"^alpha-data-postgres-(backup_[0-9]{8}t[0-9]{6}z_[a-f0-9]{8})\.dump\.age$")
PREFECT_ARTIFACT = re.compile(r"^alpha-data-prefect-(prefect_backup_[0-9]{8}t[0-9]{6}z_[a-f0-9]{8})\.tar\.age$")
PREFECT_TOOL_IMAGE = "prefecthq/prefect:3.8.1-python3.13@sha256:4386a7fd80a989ab55ea98ff860f29e469f6c7b99e1a2b94eaaa7df007504ac5"
PREFECT_RUNTIME_UID = "10001:10001"
PREFECT_RESTORE_PATH = "/var/lib/prefect"
SAFE_ERROR = "The backup or restore operation could not be completed safely."
COUNT_QUERIES = {
    "intelligence_items": "SELECT count(*) FROM intelligence_items",
    "ingestion_cycles": "SELECT count(*) FROM ingestion_cycles",
    "ingestion_runs": "SELECT count(*) FROM ingestion_runs",
}
RUNTIME_APPLICATION_TABLES = (
    "audit_events", "auth_identities", "auth_local_credentials",
    "auth_login_throttles", "auth_sessions", "auth_user_roles", "auth_users",
    "indicator_provenances", "indicators", "ingestion_cycles", "ingestion_errors",
    "ingestion_run_records", "ingestion_run_events", "ingestion_runs",
    "intelligence_item_identifiers", "intelligence_item_indicators",
    "intelligence_item_tags", "intelligence_items", "intelligence_sources",
    "quarantined_records", "source_checkpoints", "source_credential_references",
    "source_rate_limit_states", "source_records", "source_watermarks", "tags",
    "threat_entities", "threat_entity_aliases", "threat_relationships",
    "vulnerabilities",
)
RUNTIME_UPDATE_TABLES = (
    "auth_local_credentials", "auth_login_throttles", "auth_sessions",
    "auth_user_roles", "auth_users", "indicators", "ingestion_cycles",
    "ingestion_runs", "intelligence_items", "intelligence_sources",
    "quarantined_records", "source_credential_references",
    "source_rate_limit_states", "source_records", "vulnerabilities",
    "threat_entities", "threat_entity_aliases", "threat_relationships",
)
POSTGRES_METADATA_KEYS = frozenset(
    {
        "metadata_format_version",
        "backup_identifier",
        "database_system",
        "logical_backup_type",
        "started_utc",
        "completed_utc",
        "alembic_revision",
        "outcome_state",
        "encryption_state",
        "checksum_algorithm",
        "checksum_value",
        "artifact_size_bytes",
        "artifact_reference",
        "row_counts",
        "safe_summary",
    }
)
PREFECT_METADATA_KEYS = frozenset(
    {
        "metadata_format_version",
        "backup_identifier",
        "state_system",
        "state_format",
        "started_utc",
        "completed_utc",
        "outcome_state",
        "encryption_state",
        "checksum_algorithm",
        "checksum_value",
        "artifact_size_bytes",
        "artifact_reference",
        "safe_summary",
    }
)


class OperationError(RuntimeError):
    """A fixed public operational failure."""


@dataclass(frozen=True, slots=True)
class PgConnection:
    host: str
    port: int
    database: str
    user: str
    password_file: Path


def utc_text(value: datetime | None = None) -> str:
    return (value or datetime.now(UTC)).astimezone(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")


def _safe_name(value: str, pattern: re.Pattern[str], category: str) -> str:
    if not isinstance(value, str) or pattern.fullmatch(value) is None:
        raise OperationError(f"The {category} is invalid.")
    return value


def read_secret_file(path: Path) -> str:
    """Read one bounded UTF-8 regular non-symlink secret without printing it."""

    try:
        if path.is_symlink():
            raise OperationError("The secret file reference is invalid.")
        metadata = path.stat()
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > MAX_SECRET_BYTES:
            raise OperationError("The secret file reference is invalid.")
        payload = path.read_bytes()
    except OperationError:
        raise
    except OSError:
        raise OperationError("The secret file reference is invalid.") from None
    if not payload or len(payload) > MAX_SECRET_BYTES or b"\x00" in payload:
        raise OperationError("The secret file content is invalid.")
    payload = payload.rstrip(b"\r\n")
    try:
        value = payload.decode("utf-8")
    except UnicodeDecodeError:
        raise OperationError("The secret file content is invalid.") from None
    if not value or any(ord(character) < 32 for character in value):
        raise OperationError("The secret file content is invalid.")
    return value


def validate_reference_file(path: Path) -> Path:
    try:
        if path.is_symlink() or not stat.S_ISREG(path.stat().st_mode) or not 1 <= path.stat().st_size <= MAX_SECRET_BYTES:
            raise OperationError("The cryptographic file reference is invalid.")
    except OSError:
        raise OperationError("The cryptographic file reference is invalid.") from None
    return path.resolve(strict=True)


def validate_backup_directory(path: Path) -> Path:
    try:
        if path.is_symlink() or not stat.S_ISDIR(path.stat().st_mode):
            raise OperationError("The backup destination is invalid.")
        resolved = path.resolve(strict=True)
    except OSError:
        raise OperationError("The backup destination is invalid.") from None
    repository = REPOSITORY_ROOT.resolve(strict=True)
    if resolved == repository or repository in resolved.parents:
        raise OperationError("The backup destination must be outside the repository.")
    return resolved


def _connection(prefix: str) -> PgConnection:
    names = {name: os.environ.get(f"{prefix}_{name}") for name in ("HOST", "PORT", "DB", "USER", "PASSWORD_FILE")}
    if any(not value for value in names.values()):
        raise OperationError("Required PostgreSQL connection references are missing.")
    try:
        port = int(str(names["PORT"]), 10)
    except ValueError:
        raise OperationError("The PostgreSQL port is invalid.") from None
    if not 1 <= port <= 65535:
        raise OperationError("The PostgreSQL port is invalid.")
    identifier = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,62}$")
    if identifier.fullmatch(str(names["DB"])) is None or identifier.fullmatch(str(names["USER"])) is None:
        raise OperationError("The PostgreSQL identity is invalid.")
    host = str(names["HOST"])
    if not host.isascii() or len(host) > 253 or any(value in host for value in ("/", "\\", "@", "?", "#", "://")):
        raise OperationError("The PostgreSQL host is invalid.")
    return PgConnection(host, port, str(names["DB"]), str(names["USER"]), Path(str(names["PASSWORD_FILE"])))


def _pg_env(connection: PgConnection) -> dict[str, str]:
    password = read_secret_file(connection.password_file)
    environment = {key: value for key, value in os.environ.items() if key not in {"DATABASE_URL", "PGPASSWORD"}}
    environment["PGPASSWORD"] = password
    return environment


def _psql(connection: PgConnection, query: str) -> str:
    command = ["psql", "--no-password", "--no-psqlrc", "--tuples-only", "--no-align", "--host", connection.host, "--port", str(connection.port), "--username", connection.user, "--dbname", connection.database, "--command", query]
    try:
        result = subprocess.run(command, env=_pg_env(connection), capture_output=True, check=False, timeout=30, text=True)
    except (OSError, subprocess.SubprocessError):
        raise OperationError(SAFE_ERROR) from None
    if result.returncode != 0:
        raise OperationError(SAFE_ERROR)
    return result.stdout.strip()


def preflight_backup_role(connection: PgConnection) -> None:
    flags = _psql(connection, "SELECT rolsuper, rolcreatedb, rolcreaterole, rolreplication, rolbypassrls FROM pg_roles WHERE rolname = current_user")
    if flags != "f|f|f|f|f":
        raise OperationError("The backup login has prohibited privileges.")


def postgres_evidence(connection: PgConnection) -> tuple[str, dict[str, int]]:
    revision = _psql(connection, "SELECT version_num FROM alembic_version")
    if re.fullmatch(r"[0-9a-f]{12}", revision) is None:
        raise OperationError("The migration revision evidence is invalid.")
    counts: dict[str, int] = {}
    for name, query in COUNT_QUERIES.items():
        value = _psql(connection, query)
        if not value.isascii() or not value.isdecimal():
            raise OperationError("The row-count evidence is invalid.")
        counts[name] = int(value)
    return revision, counts


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _metadata_path(directory: Path, backup_id: str) -> Path:
    return directory / f"alpha-data-metadata-{backup_id}.json"


def _write_metadata(path: Path, document: Mapping[str, object]) -> None:
    temporary = path.with_suffix(".json.partial")
    if temporary.exists() or temporary.is_symlink() or path.exists() or path.is_symlink():
        raise OperationError("The metadata destination already exists.")
    payload = (json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
    try:
        with temporary.open("xb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        temporary.replace(path)
    except OSError:
        temporary.unlink(missing_ok=True)
        raise OperationError(SAFE_ERROR) from None


def _pipeline(
    producer: list[str],
    consumer: list[str],
    *,
    producer_environment: Mapping[str, str] | None = None,
    consumer_environment: Mapping[str, str] | None = None,
) -> None:
    producer_process = consumer_process = None
    try:
        producer_process = subprocess.Popen(producer, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, env=producer_environment)
        assert producer_process.stdout is not None
        consumer_process = subprocess.Popen(consumer, stdin=producer_process.stdout, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=consumer_environment)
        producer_process.stdout.close()
        consumer_code = consumer_process.wait(timeout=1800)
        producer_code = producer_process.wait(timeout=1800)
    except (OSError, subprocess.SubprocessError):
        for process in (producer_process, consumer_process):
            if process is not None and process.poll() is None:
                process.kill()
        raise OperationError(SAFE_ERROR) from None
    if producer_code != 0 or consumer_code != 0:
        raise OperationError(SAFE_ERROR)


def postgres_backup(directory: Path, recipient_file: Path) -> dict[str, object]:
    destination = validate_backup_directory(directory)
    recipient = validate_reference_file(recipient_file)
    connection = _connection("POSTGRES_BACKUP")
    preflight_backup_role(connection)
    revision, counts = postgres_evidence(connection)
    started = utc_text()
    identifier = f"backup_{datetime.now(UTC).strftime('%Y%m%dt%H%M%Sz')}_{token_hex(4)}"
    artifact = destination / f"alpha-data-postgres-{identifier}.dump.age"
    partial = artifact.with_suffix(".age.partial")
    if artifact.exists() or partial.exists() or artifact.is_symlink() or partial.is_symlink():
        raise OperationError("The generated artifact destination already exists.")
    dump = ["pg_dump", "--format=custom", "--no-owner", "--no-privileges", "--host", connection.host, "--port", str(connection.port), "--username", connection.user, "--dbname", connection.database]
    encrypt = ["age", "--encrypt", "--recipients-file", str(recipient), "--output", str(partial), "-"]
    try:
        _pipeline(dump, encrypt, producer_environment=_pg_env(connection))
        if not partial.is_file() or partial.is_symlink() or partial.stat().st_size < 1:
            raise OperationError(SAFE_ERROR)
        partial.replace(artifact)
        checksum = sha256_file(artifact)
        metadata = {
            "metadata_format_version": "2.0",
            "backup_identifier": identifier,
            "database_system": "postgresql",
            "logical_backup_type": "pg_dump_custom",
            "started_utc": started,
            "completed_utc": utc_text(),
            "alembic_revision": revision,
            "outcome_state": "succeeded",
            "encryption_state": "encrypted",
            "checksum_algorithm": "sha256",
            "checksum_value": checksum,
            "artifact_size_bytes": artifact.stat().st_size,
            "artifact_reference": f"artifact_ref_{identifier}",
            "row_counts": counts,
            "safe_summary": "Encrypted logical backup completed with verified integrity metadata.",
        }
        _write_metadata(_metadata_path(destination, identifier), metadata)
        return metadata
    except Exception:
        partial.unlink(missing_ok=True)
        if artifact.exists() and not _metadata_path(destination, identifier).exists():
            artifact.unlink(missing_ok=True)
        raise


def _load_metadata(directory: Path, identifier: str, *, prefect: bool = False) -> dict[str, object]:
    pattern = PREFECT_BACKUP_ID if prefect else BACKUP_ID
    _safe_name(identifier, pattern, "backup identifier")
    path = _metadata_path(directory, identifier)
    try:
        if path.is_symlink() or not stat.S_ISREG(path.stat().st_mode) or path.stat().st_size > 65536:
            raise OperationError("The backup metadata is invalid.")
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, json.JSONDecodeError):
        raise OperationError("The backup metadata is invalid.") from None
    if not isinstance(document, dict):
        raise OperationError("The backup metadata is invalid.")
    expected_keys = PREFECT_METADATA_KEYS if prefect else POSTGRES_METADATA_KEYS
    expected_reference = f"artifact_ref_{identifier}"
    common_valid = (
        frozenset(document) == expected_keys
        and document.get("backup_identifier") == identifier
        and document.get("outcome_state") == "succeeded"
        and document.get("encryption_state") == "encrypted"
        and document.get("checksum_algorithm") == "sha256"
        and re.fullmatch(r"[0-9a-f]{64}", str(document.get("checksum_value", ""))) is not None
        and type(document.get("artifact_size_bytes")) is int
        and 1 <= int(document["artifact_size_bytes"]) <= 9_223_372_036_854_775_807
        and document.get("artifact_reference") == expected_reference
        and all(_valid_utc_text(document.get(field)) for field in ("started_utc", "completed_utc"))
        and _valid_safe_summary(document.get("safe_summary"))
    )
    if prefect:
        specific_valid = (
            document.get("metadata_format_version") == "1.0"
            and document.get("state_system") == "prefect"
            and document.get("state_format") == "prefect-3.8.1-volume-tar"
        )
    else:
        counts = document.get("row_counts")
        specific_valid = (
            document.get("metadata_format_version") == "2.0"
            and document.get("database_system") == "postgresql"
            and document.get("logical_backup_type") == "pg_dump_custom"
            and re.fullmatch(r"[0-9a-f]{12}", str(document.get("alembic_revision", ""))) is not None
            and isinstance(counts, dict)
            and frozenset(counts) == frozenset(COUNT_QUERIES)
            and all(type(value) is int and 0 <= value <= 9_223_372_036_854_775_807 for value in counts.values())
        )
    if not common_valid or not specific_valid:
        raise OperationError("The backup metadata is invalid.")
    return document


def _valid_utc_text(value: object) -> bool:
    if not isinstance(value, str) or re.fullmatch(
        r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,6})?Z",
        value,
    ) is None:
        return False
    try:
        datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return False
    return True


def _valid_safe_summary(value: object) -> bool:
    return (
        isinstance(value, str)
        and 1 <= len(value) <= 500
        and value.isascii()
        and all(32 <= ord(character) <= 126 for character in value)
    )


def postgres_restore(directory: Path, identifier: str, identity_file: Path) -> dict[str, object]:
    source = validate_backup_directory(directory)
    metadata = _load_metadata(source, identifier)
    artifact = source / f"alpha-data-postgres-{identifier}.dump.age"
    if artifact.is_symlink() or not artifact.is_file() or POSTGRES_ARTIFACT.fullmatch(artifact.name) is None:
        raise OperationError("The encrypted artifact is invalid.")
    if sha256_file(artifact) != metadata["checksum_value"] or artifact.stat().st_size != metadata.get("artifact_size_bytes"):
        raise OperationError("The encrypted artifact integrity check failed.")
    connection = _connection("POSTGRES_RESTORE")
    _safe_name(connection.database, RESTORE_DATABASE, "isolated restore database")
    if connection.database == os.environ.get("POSTGRES_PRODUCTION_DB"):
        raise OperationError("The production database cannot be a restore target.")
    identity = validate_reference_file(identity_file)
    decrypted_archive = _decrypt_archive_to_tmpfs(identity, artifact)
    restore = ["pg_restore", "--exit-on-error", "--no-owner", "--no-privileges", "--host", connection.host, "--port", str(connection.port), "--username", connection.user, "--dbname", connection.database, str(decrypted_archive)]
    try:
        try:
            result = subprocess.run(
                restore,
                env=_pg_env(connection),
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
                timeout=1800,
            )
        except (OSError, subprocess.SubprocessError):
            raise OperationError(SAFE_ERROR) from None
        if result.returncode != 0:
            raise OperationError(SAFE_ERROR)
    finally:
        decrypted_archive.unlink(missing_ok=True)
    revision, counts = postgres_evidence(connection)
    if revision != metadata.get("alembic_revision") or revision != ALEMBIC_HEAD or counts != metadata.get("row_counts"):
        raise OperationError("The isolated restore validation did not match backup evidence.")
    runtime = _connection("POSTGRES_RUNTIME")
    if (
        runtime.host != connection.host
        or runtime.port != connection.port
        or runtime.database != connection.database
        or runtime.user == connection.user
    ):
        raise OperationError("The runtime restore validation identity is invalid.")
    apply_restore_runtime_grants(connection, runtime.user)
    validate_postgres_runtime_readability(
        runtime,
        expected_revision=revision,
        expected_counts=counts,
    )
    return {
        "backup_identifier": identifier,
        "restore_state": "validated",
        "alembic_revision": revision,
        "row_counts": counts,
        "runtime_readable": True,
    }


def _validated_role_identifier(value: object, category: str) -> str:
    if not isinstance(value, str) or re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,62}", value) is None:
        raise OperationError(f"The {category} is invalid.")
    return value


def apply_restore_runtime_grants(connection: PgConnection, runtime_user: str) -> None:
    """Apply the committed least-privilege grant contract as the restore owner."""

    roles = {
        "app_schema": "public",
        "bootstrap_role": _validated_role_identifier(
            os.environ.get("POSTGRES_BOOTSTRAP_USER"), "bootstrap role"
        ),
        "app_login": _validated_role_identifier(runtime_user, "runtime role"),
        "migration_login": _validated_role_identifier(connection.user, "migration role"),
        "readonly_role": _validated_role_identifier(
            os.environ.get("POSTGRES_READONLY_ROLE", "alpha_data_readonly"),
            "read-only role",
        ),
        "backup_role": _validated_role_identifier(
            os.environ.get("POSTGRES_BACKUP_ROLE", "alpha_data_backup"),
            "backup role",
        ),
        "retention_role": _validated_role_identifier(
            os.environ.get("POSTGRES_RETENTION_ROLE", "alpha_data_retention"),
            "retention role",
        ),
    }
    managed_roles = [roles[name] for name in roles if name != "app_schema"]
    if len(set(managed_roles)) != len(managed_roles):
        raise OperationError("The restore grant role identities are invalid.")
    grant_file = REPOSITORY_ROOT / "database" / "init" / "11-apply-database-grants.sql"
    try:
        if grant_file.is_symlink() or not grant_file.is_file():
            raise OperationError("The restore grant contract is unavailable.")
        command = [
            "psql", "--no-password", "--no-psqlrc", "--host", connection.host,
            "--port", str(connection.port), "--username", connection.user,
            "--dbname", connection.database,
        ]
        for name, value in roles.items():
            command.extend(["--set", f"{name}={value}"])
        command.extend(["--file", str(grant_file.resolve(strict=True))])
        result = subprocess.run(
            command,
            env=_pg_env(connection),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
            timeout=120,
        )
    except OperationError:
        raise
    except (OSError, subprocess.SubprocessError):
        raise OperationError(SAFE_ERROR) from None
    if result.returncode != 0:
        raise OperationError(SAFE_ERROR)


def _privilege_array_query(
    tables: tuple[str, ...],
    privileges: tuple[str, ...],
    *,
    require_all: bool = True,
) -> str:
    values = ",".join(f"'{table}'" for table in tables)
    operator = " AND " if require_all else " OR "
    checks = operator.join(
        "has_table_privilege(current_user, format('public.%I', table_name), "
        f"'{privilege}')"
        for privilege in privileges
    )
    aggregate = "bool_and" if require_all else "bool_or"
    return (
        f"SELECT coalesce({aggregate}({checks}), false) "
        f"FROM unnest(ARRAY[{values}]) AS table_name"
    )


def validate_postgres_runtime_readability(
    connection: PgConnection,
    *,
    expected_revision: str,
    expected_counts: Mapping[str, int],
) -> None:
    """Prove restored state is readable through the non-owner runtime identity."""

    if _psql(connection, "SELECT current_user") != connection.user:
        raise OperationError("The runtime restore identity could not be verified.")
    role_flags = _psql(
        connection,
        "SELECT rolinherit, rolsuper, rolcreatedb, rolcreaterole, rolreplication, rolbypassrls "
        "FROM pg_roles WHERE rolname = current_user",
    )
    if role_flags != "t|f|f|f|f|f":
        raise OperationError("The runtime restore identity has unsafe privileges.")
    if _psql(
        connection,
        "SELECT has_schema_privilege(current_user, 'public', 'USAGE'), "
        "has_schema_privilege(current_user, 'public', 'CREATE')",
    ) != "t|f":
        raise OperationError("The runtime restored schema permissions are invalid.")
    if _psql(
        connection,
        _privilege_array_query(RUNTIME_APPLICATION_TABLES, ("SELECT", "INSERT")),
    ) != "t":
        raise OperationError("The runtime restored table permissions are incomplete.")
    if _psql(
        connection,
        _privilege_array_query(RUNTIME_UPDATE_TABLES, ("UPDATE",)),
    ) != "t":
        raise OperationError("The runtime restored update permissions are incomplete.")
    if _psql(
        connection,
        _privilege_array_query(
            RUNTIME_APPLICATION_TABLES,
            ("TRUNCATE", "REFERENCES", "TRIGGER"),
            require_all=False,
        ),
    ) != "f":
        raise OperationError("The runtime restored table permissions are excessive.")
    revision, counts = postgres_evidence(connection)
    if revision != expected_revision or counts != dict(expected_counts):
        raise OperationError("The runtime restored data is not readable as expected.")


def _decrypt_archive_to_tmpfs(identity: Path, artifact: Path) -> Path:
    """Decrypt a bounded archive into verified tmpfs for seekable pg_restore input."""

    if not _is_tmpfs_directory(RESTORE_TMPFS_DIRECTORY):
        raise OperationError("A verified restore tmpfs is required.")
    descriptor, raw_path = tempfile.mkstemp(
        prefix="alpha-data-restore-",
        suffix=".dump",
        dir=RESTORE_TMPFS_DIRECTORY,
    )
    output_path = Path(raw_path)
    process = None
    total = 0
    try:
        os.chmod(output_path, 0o600)
        process = subprocess.Popen(
            ["age", "--decrypt", "--identity", str(identity), str(artifact)],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        )
        assert process.stdout is not None
        with os.fdopen(descriptor, "wb") as output:
            descriptor = -1
            for chunk in iter(lambda: process.stdout.read(1024 * 1024), b""):
                total += len(chunk)
                if total > MAX_RESTORE_ARCHIVE_BYTES:
                    process.kill()
                    raise OperationError("The decrypted restore archive is too large.")
                output.write(chunk)
            output.flush()
            os.fsync(output.fileno())
        process.stdout.close()
        code = process.wait(timeout=1800)
    except OperationError:
        output_path.unlink(missing_ok=True)
        raise
    except (OSError, subprocess.SubprocessError):
        if process is not None and process.poll() is None:
            process.kill()
        output_path.unlink(missing_ok=True)
        raise OperationError(SAFE_ERROR) from None
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    if code != 0 or total < 1:
        output_path.unlink(missing_ok=True)
        raise OperationError(SAFE_ERROR)
    return output_path


def _is_tmpfs_directory(path: Path) -> bool:
    try:
        resolved = path.resolve(strict=True)
        if path.is_symlink() or not stat.S_ISDIR(resolved.stat().st_mode):
            return False
        mount_lines = Path("/proc/self/mountinfo").read_text(encoding="utf-8").splitlines()
    except OSError:
        return False
    for line in mount_lines:
        fields = line.split()
        if "-" not in fields or len(fields) < 7:
            continue
        separator = fields.index("-")
        if fields[4] == str(resolved) and fields[separator + 1] == "tmpfs":
            return True
    return False


def verify_prefect_quiesced(volume: str) -> None:
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{2,127}", volume):
        raise OperationError("The Prefect volume name is invalid.")
    try:
        result = subprocess.run(["docker", "ps", "--filter", f"volume={volume}", "--format", "{{.ID}}"], capture_output=True, text=True, timeout=30, check=False)
    except (OSError, subprocess.SubprocessError):
        raise OperationError(SAFE_ERROR) from None
    if result.returncode != 0 or result.stdout.strip():
        raise OperationError("The Prefect state volume is not quiesced.")


def prefect_backup(directory: Path, recipient_file: Path, volume: str, *, quiesced: bool) -> dict[str, object]:
    if quiesced is not True:
        raise OperationError("An explicit quiesced-state confirmation is required.")
    verify_prefect_quiesced(volume)
    destination = validate_backup_directory(directory)
    recipient = validate_reference_file(recipient_file)
    started = utc_text()
    identifier = f"prefect_backup_{datetime.now(UTC).strftime('%Y%m%dt%H%M%Sz')}_{token_hex(4)}"
    artifact = destination / f"alpha-data-prefect-{identifier}.tar.age"
    partial = artifact.with_suffix(".age.partial")
    producer = ["docker", "run", "--rm", "--read-only", "--network", "none", "--mount", f"type=volume,src={volume},dst=/source,readonly", PREFECT_TOOL_IMAGE, "tar", "-C", "/source", "-cf", "-", "."]
    consumer = ["age", "--encrypt", "--recipients-file", str(recipient), "--output", str(partial), "-"]
    try:
        _pipeline(producer, consumer)
        if not partial.is_file() or partial.is_symlink() or partial.stat().st_size < 1:
            raise OperationError(SAFE_ERROR)
        partial.replace(artifact)
        metadata = {
            "metadata_format_version": "1.0",
            "backup_identifier": identifier,
            "state_system": "prefect",
            "state_format": "prefect-3.8.1-volume-tar",
            "started_utc": started,
            "completed_utc": utc_text(),
            "outcome_state": "succeeded",
            "encryption_state": "encrypted",
            "checksum_algorithm": "sha256",
            "checksum_value": sha256_file(artifact),
            "artifact_size_bytes": artifact.stat().st_size,
            "artifact_reference": f"artifact_ref_{identifier}",
            "safe_summary": "Quiesced Prefect state backup completed with verified integrity metadata.",
        }
        _write_metadata(_metadata_path(destination, identifier), metadata)
        return metadata
    except Exception:
        partial.unlink(missing_ok=True)
        if artifact.exists() and not _metadata_path(destination, identifier).exists():
            artifact.unlink(missing_ok=True)
        raise


def validate_tar_stream(stream: BinaryIO) -> int:
    count = 0
    try:
        with tarfile.open(fileobj=stream, mode="r|") as archive:
            for member in archive:
                path = PurePosixPath(member.name)
                if path.is_absolute() or ".." in path.parts or member.issym() or member.islnk() or member.isdev():
                    raise OperationError("The Prefect archive structure is unsafe.")
                count += 1
                if count > 100_000:
                    raise OperationError("The Prefect archive contains too many entries.")
    except (tarfile.TarError, OSError):
        raise OperationError("The Prefect archive structure is invalid.") from None
    return count


def _inspect_decrypted_tar(identity: Path, artifact: Path) -> int:
    try:
        process = subprocess.Popen(["age", "--decrypt", "--identity", str(identity), str(artifact)], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        assert process.stdout is not None
        count = validate_tar_stream(process.stdout)
        process.stdout.close()
        code = process.wait(timeout=1800)
    except (OSError, subprocess.SubprocessError):
        raise OperationError(SAFE_ERROR) from None
    if code != 0 or count < 1:
        raise OperationError("The Prefect archive could not be validated.")
    return count


def prefect_restore(directory: Path, identifier: str, identity_file: Path, target_volume: str) -> dict[str, object]:
    _safe_name(target_volume, RESTORE_VOLUME, "isolated restore volume")
    if target_volume == "prefect_data" or target_volume.endswith("_prefect_data"):
        raise OperationError("The active Prefect volume cannot be a restore target.")
    source = validate_backup_directory(directory)
    metadata = _load_metadata(source, identifier, prefect=True)
    artifact = source / f"alpha-data-prefect-{identifier}.tar.age"
    if artifact.is_symlink() or not artifact.is_file() or PREFECT_ARTIFACT.fullmatch(artifact.name) is None:
        raise OperationError("The encrypted Prefect artifact is invalid.")
    if sha256_file(artifact) != metadata["checksum_value"] or artifact.stat().st_size != metadata.get("artifact_size_bytes"):
        raise OperationError("The encrypted Prefect artifact integrity check failed.")
    identity = validate_reference_file(identity_file)
    entries = _inspect_decrypted_tar(identity, artifact)
    try:
        inspect = subprocess.run(
            ["docker", "volume", "inspect", target_volume],
            capture_output=True,
            check=False,
            timeout=30,
        )
    except (OSError, subprocess.SubprocessError):
        raise OperationError(SAFE_ERROR) from None
    if inspect.returncode == 0:
        raise OperationError("The isolated restore volume already exists.")
    try:
        create = subprocess.run(
            ["docker", "volume", "create", target_volume],
            capture_output=True,
            check=False,
            timeout=30,
        )
    except (OSError, subprocess.SubprocessError):
        raise OperationError(SAFE_ERROR) from None
    if create.returncode != 0:
        raise OperationError(SAFE_ERROR)
    decrypt = ["age", "--decrypt", "--identity", str(identity), str(artifact)]
    extract = ["docker", "run", "--rm", "--read-only", "--network", "none", "--mount", f"type=volume,src={target_volume},dst=/restore", PREFECT_TOOL_IMAGE, "tar", "-C", "/restore", "-xf", "-"]
    try:
        _pipeline(decrypt, extract)
        validate_prefect_runtime_readability(target_volume)
    except Exception:
        remove_created_restore_volume(target_volume)
        raise
    return {
        "backup_identifier": identifier,
        "restore_state": "validated",
        "archive_entries": entries,
        "target_volume": target_volume,
        "runtime_readable": True,
    }


def validate_prefect_runtime_readability(target_volume: str) -> None:
    """Read the restored SQLite state through the pinned Prefect runtime identity."""

    _safe_name(target_volume, RESTORE_VOLUME, "isolated restore volume")
    validation = (
        "from pathlib import Path; import sqlite3; "
        "path=Path('/var/lib/prefect/prefect.db'); "
        "assert path.is_file(); "
        "connection=sqlite3.connect('file:/var/lib/prefect/prefect.db?mode=ro&immutable=1', uri=True); "
        "connection.execute('PRAGMA schema_version').fetchone(); "
        "connection.execute('SELECT count(*) FROM sqlite_master').fetchone(); "
        "connection.close()"
    )
    command = [
        "docker", "run", "--rm", "--read-only", "--network", "none",
        "--user", PREFECT_RUNTIME_UID,
        "--mount", f"type=volume,src={target_volume},dst={PREFECT_RESTORE_PATH},readonly",
        PREFECT_TOOL_IMAGE, "python", "-c", validation,
    ]
    try:
        result = subprocess.run(
            command,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
            timeout=60,
        )
    except (OSError, subprocess.SubprocessError):
        raise OperationError(SAFE_ERROR) from None
    if result.returncode != 0:
        raise OperationError("The restored Prefect state is not runtime-readable.")


def remove_created_restore_volume(target_volume: str) -> None:
    """Remove only a validated isolated restore volume created by this operation."""

    _safe_name(target_volume, RESTORE_VOLUME, "isolated restore volume")
    try:
        subprocess.run(
            ["docker", "volume", "rm", target_volume],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
            timeout=30,
        )
    except (OSError, subprocess.SubprocessError):
        pass


def _delete_retention_pair(
    root: Path,
    *,
    backup_class: str,
    identifier: str,
    artifact: Path,
    metadata_path: Path,
) -> None:
    """Revalidate an owned pair immediately before bounded deletion."""

    expected_artifact = (
        root / f"alpha-data-postgres-{identifier}.dump.age"
        if backup_class == "postgres"
        else root / f"alpha-data-prefect-{identifier}.tar.age"
    )
    expected_metadata = _metadata_path(root, identifier)
    if artifact != expected_artifact or metadata_path != expected_metadata:
        return
    try:
        if (
            artifact.is_symlink()
            or metadata_path.is_symlink()
            or not artifact.is_file()
            or not metadata_path.is_file()
        ):
            return
        metadata = _load_metadata(root, identifier, prefect=backup_class == "prefect")
        if (
            sha256_file(artifact) != metadata["checksum_value"]
            or artifact.stat().st_size != metadata["artifact_size_bytes"]
        ):
            return
        artifact.unlink()
        metadata_path.unlink()
    except (OSError, OperationError, KeyError):
        return


def retention_plan(directory: Path, *, apply: bool = False) -> dict[str, dict[str, list[str]]]:
    root = validate_backup_directory(directory)
    records: dict[str, list[tuple[datetime, str, Path, Path]]] = {
        "postgres": [],
        "prefect": [],
    }
    for artifact in root.iterdir():
        postgres_match = POSTGRES_ARTIFACT.fullmatch(artifact.name)
        prefect_match = PREFECT_ARTIFACT.fullmatch(artifact.name)
        match = postgres_match or prefect_match
        if match is None or artifact.is_symlink() or not artifact.is_file():
            continue
        backup_class = "postgres" if postgres_match is not None else "prefect"
        identifier = match.group(1)
        metadata_path = _metadata_path(root, identifier)
        try:
            metadata = _load_metadata(root, identifier, prefect=backup_class == "prefect")
            if (
                metadata_path.is_symlink()
                or not metadata_path.is_file()
                or sha256_file(artifact) != metadata["checksum_value"]
                or artifact.stat().st_size != metadata["artifact_size_bytes"]
            ):
                continue
            completed = datetime.fromisoformat(str(metadata["completed_utc"]).replace("Z", "+00:00"))
        except (OperationError, ValueError, KeyError):
            continue
        records[backup_class].append((completed, identifier, artifact, metadata_path))
    result: dict[str, dict[str, list[str]]] = {}
    for backup_class in ("postgres", "prefect"):
        class_records = sorted(
            records[backup_class], reverse=True, key=lambda row: (row[0], row[1])
        )
        keep: set[str] = set()
        buckets = (
            (7, lambda date: date.date().isoformat()),
            (4, lambda date: f"{date.isocalendar().year}-W{date.isocalendar().week:02d}"),
            (3, lambda date: f"{date.year}-{date.month:02d}"),
        )
        for maximum, classifier in buckets:
            seen: set[str] = set()
            for completed, identifier, _artifact, _metadata in class_records:
                bucket = classifier(completed)
                if bucket not in seen and len(seen) < maximum:
                    seen.add(bucket)
                    keep.add(identifier)
        prune = [
            identifier
            for _completed, identifier, _artifact, _metadata in class_records
            if identifier not in keep
        ]
        if apply:
            for _completed, identifier, artifact, metadata_path in class_records:
                if identifier in prune:
                    _delete_retention_pair(
                        root,
                        backup_class=backup_class,
                        identifier=identifier,
                        artifact=artifact,
                        metadata_path=metadata_path,
                    )
        result[backup_class] = {"keep": sorted(keep), "prune": prune}
    return result


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description="Cyber Sentinel encrypted backup and isolated restore tooling.")
    commands = result.add_subparsers(dest="command", required=True)
    for name in ("postgres-backup", "prefect-backup"):
        command = commands.add_parser(name)
        command.add_argument("--backup-dir", type=Path, required=True)
        command.add_argument("--recipient-file", type=Path, required=True)
        command.add_argument("--confirm-retention-delete", action="store_true")
    pg_restore = commands.add_parser("postgres-restore")
    pg_restore.add_argument("--backup-dir", type=Path, required=True)
    pg_restore.add_argument("--backup-id", required=True)
    pg_restore.add_argument("--identity-file", type=Path, required=True)
    pf_backup = commands.choices["prefect-backup"]
    pf_backup.add_argument("--volume", required=True)
    pf_backup.add_argument("--confirm-quiesced", action="store_true")
    pf_restore = commands.add_parser("prefect-restore")
    pf_restore.add_argument("--backup-dir", type=Path, required=True)
    pf_restore.add_argument("--backup-id", required=True)
    pf_restore.add_argument("--identity-file", type=Path, required=True)
    pf_restore.add_argument("--target-volume", required=True)
    return result


def main(argv: list[str] | None = None) -> int:
    arguments = parser().parse_args(argv)
    try:
        if arguments.command == "postgres-backup":
            result = postgres_backup(arguments.backup_dir, arguments.recipient_file)
            retention = retention_plan(arguments.backup_dir, apply=arguments.confirm_retention_delete)
        elif arguments.command == "postgres-restore":
            result = postgres_restore(arguments.backup_dir, arguments.backup_id, arguments.identity_file)
            retention = None
        elif arguments.command == "prefect-backup":
            result = prefect_backup(arguments.backup_dir, arguments.recipient_file, arguments.volume, quiesced=arguments.confirm_quiesced)
            retention = retention_plan(arguments.backup_dir, apply=arguments.confirm_retention_delete)
        else:
            result = prefect_restore(arguments.backup_dir, arguments.backup_id, arguments.identity_file, arguments.target_volume)
            retention = None
    except OperationError:
        print(SAFE_ERROR, file=sys.stderr)
        return 1
    except Exception:
        print(SAFE_ERROR, file=sys.stderr)
        return 1
    output = {"operation": arguments.command, "state": "succeeded", "evidence": result}
    if retention is not None:
        output["retention"] = retention
        output["retention_mode"] = "applied" if arguments.confirm_retention_delete else "dry_run"
    print(json.dumps(output, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
