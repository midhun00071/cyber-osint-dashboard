from io import BytesIO
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tarfile

import pytest


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from scripts.production import backup_restore as tool  # noqa: E402


def test_secret_file_is_bounded_and_never_accepted_as_symlink(tmp_path: Path) -> None:
    secret = tmp_path / "secret"
    secret.write_text("synthetic-password\n", encoding="utf-8")
    assert tool.read_secret_file(secret) == "synthetic-password"
    secret.write_bytes(b"x" * (tool.MAX_SECRET_BYTES + 1))
    with pytest.raises(tool.OperationError):
        tool.read_secret_file(secret)
    target = tmp_path / "target"
    target.write_text("synthetic", encoding="utf-8")
    link = tmp_path / "link"
    try:
        link.symlink_to(target)
    except OSError:
        pytest.skip("Symlink creation is unavailable in this environment.")
    with pytest.raises(tool.OperationError):
        tool.read_secret_file(link)


def test_repository_and_symlink_backup_destinations_are_rejected(tmp_path: Path) -> None:
    with pytest.raises(tool.OperationError):
        tool.validate_backup_directory(ROOT)
    target = tmp_path / "backup"
    target.mkdir()
    link = tmp_path / "backup-link"
    try:
        link.symlink_to(target, target_is_directory=True)
    except OSError:
        pytest.skip("Symlink creation is unavailable in this environment.")
    with pytest.raises(tool.OperationError):
        tool.validate_backup_directory(link)


def test_privileged_backup_roles_are_rejected(monkeypatch) -> None:
    connection = tool.PgConnection("db", 5432, "alpha", "backup", Path("secret"))
    monkeypatch.setattr(tool, "_psql", lambda *_args: "f|f|f|f|f")
    tool.preflight_backup_role(connection)
    for flags in ("t|f|f|f|f", "f|t|f|f|f", "f|f|t|f|f", "f|f|f|t|f", "f|f|f|f|t"):
        monkeypatch.setattr(tool, "_psql", lambda *_args, value=flags: value)
        with pytest.raises(tool.OperationError, match="prohibited"):
            tool.preflight_backup_role(connection)


def test_cli_has_no_database_url_or_filename_interface() -> None:
    help_text = tool.parser().format_help()
    assert "DATABASE_URL" not in help_text
    assert "filename" not in help_text.lower()
    source = (ROOT / "scripts" / "production" / "backup_restore.py").read_text(encoding="utf-8")
    assert "shell=True" not in source
    assert "PGPASSWORD" not in source.split("def _pg_env", 1)[0]


def _tar(member: tarfile.TarInfo, payload: bytes = b"") -> BytesIO:
    output = BytesIO()
    with tarfile.open(fileobj=output, mode="w") as archive:
        member.size = len(payload)
        archive.addfile(member, BytesIO(payload))
    output.seek(0)
    return output


def test_prefect_archive_validation_rejects_traversal_and_links() -> None:
    safe = tarfile.TarInfo("./prefect.db")
    assert tool.validate_tar_stream(_tar(safe, b"state")) == 1
    for name in ("../escape", "/absolute"):
        with pytest.raises(tool.OperationError):
            tool.validate_tar_stream(_tar(tarfile.TarInfo(name)))
    link = tarfile.TarInfo("link")
    link.type = tarfile.SYMTYPE
    link.linkname = "target"
    with pytest.raises(tool.OperationError):
        tool.validate_tar_stream(_tar(link))


def test_active_and_invalid_restore_targets_are_refused(tmp_path: Path) -> None:
    with pytest.raises(tool.OperationError):
        tool._safe_name("production", tool.RESTORE_DATABASE, "restore")
    with pytest.raises(tool.OperationError):
        tool.prefect_restore(tmp_path, "prefect_backup_20260809t000000z_deadbeef", tmp_path / "identity", "prefect_data")


def test_metadata_schemas_are_strict_and_secret_free() -> None:
    database = json.loads((ROOT / "database" / "backup-metadata.schema.json").read_text(encoding="utf-8"))
    prefect = json.loads((ROOT / "ops" / "backup" / "prefect-backup-metadata.schema.json").read_text(encoding="utf-8"))
    assert database["additionalProperties"] is False and database["properties"]["metadata_format_version"]["const"] == "2.0"
    assert "row_counts" in database["required"]
    assert prefect["additionalProperties"] is False
    combined = json.dumps([database, prefect]).lower()
    for prohibited in ("database_url", "authorization_header", "cookie_value"):
        assert prohibited not in combined


def test_restore_uses_bounded_verified_tmpfs_and_backup_group_policy() -> None:
    source = (ROOT / "scripts" / "production" / "backup_restore.py").read_text(encoding="utf-8")
    policy = (ROOT / "ops" / "backup" / "configure-backup-role.sql").read_text(encoding="utf-8")

    assert 'RESTORE_TMPFS_DIRECTORY = Path("/dev/shm")' in source
    assert "MAX_RESTORE_ARCHIVE_BYTES" in source
    assert "_is_tmpfs_directory(RESTORE_TMPFS_DIRECTORY)" in source
    assert "decrypted_archive.unlink(missing_ok=True)" in source
    assert "GRANT SELECT ON ALL TABLES IN SCHEMA public TO alpha_data_backup" in policy
    assert "GRANT SELECT ON ALL SEQUENCES IN SCHEMA public TO alpha_data_backup" in policy
    assert "CREATE ROLE" not in policy
    assert "PASSWORD" not in policy.upper()


def test_retention_is_dry_run_and_ignores_unowned_or_inconsistent_files(tmp_path: Path) -> None:
    unrelated = tmp_path / "do-not-delete.txt"
    unrelated.write_text("preserve", encoding="utf-8")
    result = tool.retention_plan(tmp_path)
    assert result == {
        "postgres": {"keep": [], "prune": []},
        "prefect": {"keep": [], "prune": []},
    }
    assert unrelated.exists()


def _backup_pair(
    root: Path,
    *,
    backup_class: str,
    completed: str,
    sequence: int,
    checksum_override: str | None = None,
) -> tuple[str, Path, Path]:
    stamp = completed.replace("-", "").replace(":", "").replace("T", "t").replace("Z", "z")
    identifier = (
        f"backup_{stamp}_{sequence:08x}"
        if backup_class == "postgres"
        else f"prefect_backup_{stamp}_{sequence:08x}"
    )
    artifact = root / (
        f"alpha-data-postgres-{identifier}.dump.age"
        if backup_class == "postgres"
        else f"alpha-data-prefect-{identifier}.tar.age"
    )
    payload = f"encrypted-{backup_class}-{sequence}".encode()
    artifact.write_bytes(payload)
    checksum = checksum_override or hashlib.sha256(payload).hexdigest()
    common = {
        "metadata_format_version": "2.0" if backup_class == "postgres" else "1.0",
        "backup_identifier": identifier,
        "started_utc": completed,
        "completed_utc": completed,
        "outcome_state": "succeeded",
        "encryption_state": "encrypted",
        "checksum_algorithm": "sha256",
        "checksum_value": checksum,
        "artifact_size_bytes": len(payload),
        "artifact_reference": f"artifact_ref_{identifier}",
        "safe_summary": "Synthetic encrypted retention evidence.",
    }
    if backup_class == "postgres":
        common.update(
            database_system="postgresql",
            logical_backup_type="pg_dump_custom",
            alembic_revision=tool.ALEMBIC_HEAD,
            row_counts={name: 0 for name in tool.COUNT_QUERIES},
        )
    else:
        common.update(state_system="prefect", state_format="prefect-3.8.1-volume-tar")
    metadata = tool._metadata_path(root, identifier)
    metadata.write_text(json.dumps(common), encoding="utf-8")
    return identifier, artifact, metadata


def test_retention_buckets_are_independent_per_backup_class(tmp_path: Path) -> None:
    dates = [
        "2026-08-09T00:00:00Z", "2026-08-08T00:00:00Z", "2026-08-07T00:00:00Z",
        "2026-08-06T00:00:00Z", "2026-08-05T00:00:00Z", "2026-08-04T00:00:00Z",
        "2026-08-03T00:00:00Z", "2026-08-02T00:00:00Z", "2026-07-26T00:00:00Z",
        "2026-07-19T00:00:00Z", "2026-07-12T00:00:00Z", "2026-06-01T00:00:00Z",
        "2026-05-01T00:00:00Z", "2026-04-01T00:00:00Z", "2026-03-01T00:00:00Z",
    ]
    identifiers = {"postgres": [], "prefect": []}
    for backup_class in identifiers:
        for sequence, completed in enumerate(dates, start=1):
            identifiers[backup_class].append(
                _backup_pair(
                    tmp_path,
                    backup_class=backup_class,
                    completed=completed,
                    sequence=sequence,
                )[0]
            )

    result = tool.retention_plan(tmp_path)

    for backup_class in ("postgres", "prefect"):
        kept = set(result[backup_class]["keep"])
        assert set(identifiers[backup_class][:7]) <= kept
        assert set(identifiers[backup_class][7:10]) <= kept
        assert {identifiers[backup_class][0], identifiers[backup_class][8], identifiers[backup_class][11]} <= kept
        assert identifiers[backup_class][0] in kept
    assert result["postgres"]["keep"] != result["prefect"]["keep"]
    assert all(path.exists() for path in tmp_path.iterdir())


def test_retention_apply_deletes_only_valid_class_prune_sets(tmp_path: Path) -> None:
    pairs = {"postgres": [], "prefect": []}
    for backup_class in pairs:
        for sequence in range(1, 6):
            pairs[backup_class].append(
                _backup_pair(
                    tmp_path,
                    backup_class=backup_class,
                    completed="2026-01-01T00:00:00Z",
                    sequence=sequence,
                )
            )
    unrelated = tmp_path / "unrelated.txt"
    unrelated.write_text("preserve", encoding="utf-8")
    invalid_id = "backup_20200101t000000z_aaaaaaaa"
    invalid_artifact = tmp_path / f"alpha-data-postgres-{invalid_id}.dump.age"
    invalid_artifact.write_bytes(b"invalid")
    invalid_metadata = tool._metadata_path(tmp_path, invalid_id)
    invalid_metadata.write_text("{}", encoding="utf-8")
    mismatch_id, mismatch_artifact, mismatch_metadata = _backup_pair(
        tmp_path,
        backup_class="prefect",
        completed="2020-01-01T00:00:00Z",
        sequence=99,
        checksum_override="0" * 64,
    )
    symlink = tmp_path / "alpha-data-postgres-backup_20190101t000000z_bbbbbbbb.dump.age"
    symlink_target = tmp_path / "symlink-target"
    symlink_target.write_bytes(b"preserve")
    try:
        symlink.symlink_to(symlink_target)
    except OSError:
        symlink = None

    dry_run = tool.retention_plan(tmp_path)
    assert unrelated.exists()
    for backup_class in pairs:
        assert len(dry_run[backup_class]["prune"]) == 4
        assert all(artifact.exists() and metadata.exists() for _, artifact, metadata in pairs[backup_class])

    applied = tool.retention_plan(tmp_path, apply=True)
    for backup_class in pairs:
        assert applied[backup_class]["prune"] == dry_run[backup_class]["prune"]
        remaining = [identifier for identifier, artifact, metadata in pairs[backup_class] if artifact.exists() and metadata.exists()]
        assert remaining == applied[backup_class]["keep"]
    assert unrelated.exists()
    assert invalid_artifact.exists() and invalid_metadata.exists()
    assert mismatch_id not in applied["prefect"]["prune"]
    assert mismatch_artifact.exists() and mismatch_metadata.exists()
    if symlink is not None:
        assert symlink.is_symlink() and symlink_target.exists()


def _runtime_psql(monkeypatch, *, flags="t|f|f|f|f|f", schema="t|f", tables="t", updates="t", excessive="f"):
    def response(_connection, query):
        if query == "SELECT current_user":
            return "alpha_app"
        if "rolinherit" in query:
            return flags
        if "has_schema_privilege" in query:
            return schema
        if "bool_or" in query:
            return excessive
        if "auth_local_credentials" in query and "UPDATE" in query:
            return updates
        if "bool_and" in query:
            return tables
        if "version_num" in query:
            return tool.ALEMBIC_HEAD
        if "count(*)" in query:
            return "0"
        raise AssertionError("Unexpected fixed validation query")
    monkeypatch.setattr(tool, "_psql", response)


def test_postgres_runtime_permission_evidence_is_required(monkeypatch) -> None:
    connection = tool.PgConnection("db", 5432, "alpha_data_restore_deadbeef", "alpha_app", Path("secret"))
    _runtime_psql(monkeypatch, schema="f|f")
    with pytest.raises(tool.OperationError, match="schema permissions"):
        tool.validate_postgres_runtime_readability(
            connection,
            expected_revision=tool.ALEMBIC_HEAD,
            expected_counts={name: 0 for name in tool.COUNT_QUERIES},
        )


def test_expected_postgres_runtime_identity_is_readable_and_unprivileged(monkeypatch) -> None:
    connection = tool.PgConnection("db", 5432, "alpha_data_restore_deadbeef", "alpha_app", Path("secret"))
    _runtime_psql(monkeypatch)
    tool.validate_postgres_runtime_readability(
        connection,
        expected_revision=tool.ALEMBIC_HEAD,
        expected_counts={name: 0 for name in tool.COUNT_QUERIES},
    )
    _runtime_psql(monkeypatch, flags="t|t|f|f|f|f")
    with pytest.raises(tool.OperationError, match="unsafe privileges"):
        tool.validate_postgres_runtime_readability(
            connection,
            expected_revision=tool.ALEMBIC_HEAD,
            expected_counts={name: 0 for name in tool.COUNT_QUERIES},
        )


def test_prefect_runtime_validation_uses_only_pinned_restored_volume(monkeypatch) -> None:
    commands = []
    monkeypatch.setattr(
        tool.subprocess,
        "run",
        lambda command, **_kwargs: commands.append(command) or subprocess.CompletedProcess(command, 0),
    )
    tool.validate_prefect_runtime_readability("alpha-data-rehearsal-deadbeef")
    command = commands[0]
    assert command[:6] == ["docker", "run", "--rm", "--read-only", "--network", "none"]
    assert tool.PREFECT_TOOL_IMAGE in command
    assert "--user" in command and tool.PREFECT_RUNTIME_UID in command
    assert "type=volume,src=alpha-data-rehearsal-deadbeef,dst=/var/lib/prefect,readonly" in command
    assert "prefect_data" not in command


def test_prefect_runtime_validation_failure_is_not_validated_and_cleanup_is_bounded(monkeypatch) -> None:
    commands = []
    monkeypatch.setattr(
        tool.subprocess,
        "run",
        lambda command, **_kwargs: commands.append(command) or subprocess.CompletedProcess(command, 1),
    )
    with pytest.raises(tool.OperationError, match="not runtime-readable"):
        tool.validate_prefect_runtime_readability("alpha-data-restore-deadbeef")
    with pytest.raises(tool.OperationError):
        tool.remove_created_restore_volume("prefect_data")
    tool.remove_created_restore_volume("alpha-data-restore-deadbeef")
    assert commands[-1] == ["docker", "volume", "rm", "alpha-data-restore-deadbeef"]


def test_failed_pipeline_is_sanitized_and_not_marked_success(monkeypatch, capsys) -> None:
    monkeypatch.setattr(tool, "postgres_backup", lambda *_args: (_ for _ in ()).throw(tool.OperationError("raw secret detail")))
    code = tool.main(["postgres-backup", "--backup-dir", "x", "--recipient-file", "y"])
    captured = capsys.readouterr()
    assert code == 1
    assert captured.out == ""
    assert captured.err.strip() == tool.SAFE_ERROR
    assert "raw secret detail" not in captured.err
