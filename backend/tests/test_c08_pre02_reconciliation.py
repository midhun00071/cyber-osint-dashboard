from __future__ import annotations

import base64
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess

import pytest


REPO_ROOT = Path(__file__).resolve().parents[2]
POWERSHELL_PATH = REPO_ROOT / "scripts" / "c08-pre02-reconcile-preserved-volume.ps1"
ROLE_SQL_PATH = REPO_ROOT / "database" / "maintenance" / "c08-pre02-provision-existing-volume.sql"
CORRECTION_SQL_PATH = REPO_ROOT / "database" / "maintenance" / "c08-pre02-correct-synthetic-progress.sql"
DOC_PATH = REPO_ROOT / "docs" / "c08-pre02-preserved-volume-reconciliation.md"
AUTHORIZED_FILES = {
    "scripts/c08-pre02-reconcile-preserved-volume.ps1",
    "database/maintenance/c08-pre02-provision-existing-volume.sql",
    "backend/tests/test_c08_pre02_reconciliation.py",
    "docs/c08-pre02-preserved-volume-reconciliation.md",
}
EXPECTED_CORRECTION_SQL_SHA256 = (
    "d614601fef244bb612035b6029392f207126e1de8a3cbc1bc819bb98595c0a4e"
)
OLD_PARENT_CHECKPOINT = "c6a9573d2f6dc9d519f76a1d96045b33bc21b1ba"
FUTURE_REVIEWED_CHECKPOINT = "1234567890abcdef1234567890abcdef12345678"
TARGET_SLUGS = {
    "alpha-synthetic-cve",
    "alpha-synthetic-advisories",
    "alpha-synthetic-news",
    "alpha-synthetic-uae",
}


def source(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def ps_quote(value: str | Path) -> str:
    return "'" + str(value).replace("'", "''") + "'"


def run_safe_powershell(command: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            "pwsh",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            f". {ps_quote(POWERSHELL_PATH)}; {command}",
        ],
        cwd=REPO_ROOT,
        check=False,
        capture_output=True,
        text=True,
    )


def assert_ps_fails(command: str, expected: str) -> None:
    result = run_safe_powershell(
        f"try {{ {command}; exit 0 }} catch {{ Write-Output $_.Exception.Message; exit 23 }}"
    )
    assert result.returncode == 23, result.stdout + result.stderr
    assert expected in result.stdout


def ps_fixture(fixture: dict[str, object]) -> str:
    encoded = base64.b64encode(json.dumps(fixture).encode()).decode()
    return (
        "$fixtureJson=[Text.Encoding]::UTF8.GetString("
        f"[Convert]::FromBase64String('{encoded}')); "
        "$fixture=$fixtureJson | ConvertFrom-Json -AsHashtable"
    )


def exact_timestamp(value: datetime) -> str:
    utc = value.astimezone(timezone.utc)
    return utc.strftime("%Y-%m-%dT%H:%M:%S.") + f"{utc.microsecond:06d}0+00:00"


def role_fixture(state: str) -> dict[str, object]:
    fixture: dict[str, object] = {
        "app_role_exists": True,
        "app_role_oid": 10,
        "app_role_is_oid_10": True,
        "app_role_can_login": True,
        "app_role_superuser": True,
        "app_role_createdb": True,
        "app_role_createrole": True,
        "app_role_replication": False,
        "app_role_bypassrls": True,
        "app_database_connect": True,
        "app_schema_usage": True,
        "bootstrap_role_exists": False,
        "bootstrap_role_oid": 0,
        "bootstrap_role_is_oid_10": False,
        "bootstrap_role_can_login": False,
        "bootstrap_role_superuser": False,
        "bootstrap_role_createdb": False,
        "bootstrap_role_createrole": False,
        "bootstrap_role_replication": False,
        "bootstrap_role_bypassrls": False,
        "bootstrap_database_connect": False,
        "cluster_bootstrap_role_exists": False,
        "cluster_bootstrap_role_oid": 0,
        "cluster_bootstrap_role_can_login": False,
        "cluster_bootstrap_role_superuser": False,
        "cluster_bootstrap_owned_public_object_count": 0,
        "cluster_bootstrap_explicit_connect_count": 0,
        "cluster_bootstrap_explicit_object_acl_count": 0,
        "oid_10_role_count": 1,
        "oid_10_role_name": "alpha_data_user",
        "migration_role_exists": False,
        "migration_role_can_login": False,
        "migration_role_superuser": False,
        "migration_role_createdb": False,
        "migration_role_createrole": False,
        "migration_role_replication": False,
        "migration_role_bypassrls": False,
        "auxiliary_roles_safe_count": 0,
        "auxiliary_role_count": 0,
        "managed_membership_count": 0,
        "public_table_count": 11,
        "public_sequence_count": 9,
        "expected_table_name_count": 11,
        "expected_sequence_name_count": 9,
        "database_owner": "alpha_data_user",
        "public_schema_owner": "pg_database_owner",
        "app_owned_table_count": 11,
        "app_owned_sequence_count": 9,
        "migration_owned_table_count": 0,
        "migration_owned_sequence_count": 0,
        "unexpected_owner_count": 0,
        "unexpected_database_connect_grant_count": 0,
        "public_database_connect": True,
        "migration_default_acl_count": 0,
        "migration_connect": False,
        "migration_schema_usage": False,
        "migration_schema_create": False,
        "auxiliary_database_connect_count": 0,
        "auxiliary_schema_usage_count": 0,
        "auxiliary_schema_create_count": 0,
        "auxiliary_no_sequence_privilege_count": 0,
        "app_schema_create": True,
        "app_delete": True,
        "app_sequence_update": True,
        "prepared_auxiliary_no_table_privilege_count": 0,
        "prepared_migration_no_table_privilege_count": 0,
        "prepared_migration_no_sequence_privilege_count": 0,
        "app_table_privilege_shape_count": 0,
        "app_sequence_privilege_shape_count": 0,
        "readonly_table_privilege_shape_count": 0,
        "backup_table_privilege_shape_count": 0,
        "retention_table_privilege_shape_count": 0,
    }
    if state in {"prepared_bootstrap_collision", "normalized"}:
        fixture.update(
            {
                "bootstrap_role_exists": True,
                "bootstrap_role_oid": 73_731,
                "bootstrap_role_is_oid_10": False,
                "bootstrap_role_can_login": True,
                "bootstrap_role_superuser": True,
                "bootstrap_role_createdb": False,
                "bootstrap_role_createrole": False,
                "bootstrap_role_replication": False,
                "bootstrap_role_bypassrls": True,
                "bootstrap_database_connect": True,
                "migration_role_exists": True,
                "migration_role_can_login": True,
                "migration_role_superuser": False,
                "migration_role_createdb": False,
                "migration_role_createrole": False,
                "migration_role_replication": False,
                "migration_role_bypassrls": False,
                "auxiliary_roles_safe_count": 3,
                "auxiliary_role_count": 3,
                "migration_connect": True,
                "migration_schema_usage": True,
                "migration_schema_create": True,
                "auxiliary_database_connect_count": 3,
                "auxiliary_schema_usage_count": 3,
                "auxiliary_schema_create_count": 0,
                "auxiliary_no_sequence_privilege_count": 27,
                "prepared_auxiliary_no_table_privilege_count": 33,
                "prepared_migration_no_table_privilege_count": 11,
                "prepared_migration_no_sequence_privilege_count": 9,
            }
        )
    if state == "normalized":
        fixture.update(
            {
                "app_role_oid": 80_001,
                "app_role_is_oid_10": False,
                "app_role_superuser": False,
                "app_role_createdb": False,
                "app_role_createrole": False,
                "app_role_bypassrls": False,
                "cluster_bootstrap_role_exists": True,
                "cluster_bootstrap_role_oid": 10,
                "cluster_bootstrap_role_can_login": False,
                "cluster_bootstrap_role_superuser": True,
                "oid_10_role_name": "alpha_data_cluster_bootstrap",
                "database_owner": "alpha_data_bootstrap",
                "public_schema_owner": "alpha_data_bootstrap",
                "app_owned_table_count": 0,
                "app_owned_sequence_count": 0,
                "migration_owned_table_count": 11,
                "migration_owned_sequence_count": 9,
                "app_schema_create": False,
                "app_delete": False,
                "app_sequence_update": False,
                "prepared_auxiliary_no_table_privilege_count": 0,
                "app_table_privilege_shape_count": 11,
                "app_sequence_privilege_shape_count": 9,
                "readonly_table_privilege_shape_count": 11,
                "backup_table_privilege_shape_count": 11,
                "retention_table_privilege_shape_count": 11,
                "public_database_connect": False,
            }
        )
    return fixture


def write_backup_fixture(
    tmp_path: Path,
    *,
    content: bytes = b"reviewed synthetic backup bytes",
    declared_hash: str | None = None,
    checkpoint: str = FUTURE_REVIEWED_CHECKPOINT,
    created_at: datetime | None = None,
    artifact_name: str = "preserved-volume.dump",
) -> tuple[Path, Path]:
    artifact = tmp_path / artifact_name
    artifact.write_bytes(content)
    evidence = tmp_path / "backup-evidence.json"
    document = {
        "task_id": "C08-PRE-02",
        "maintenance_session_id": "review-session-01",
        "git_checkpoint": checkpoint,
        "database_name": "alpha_data_db",
        "volume_name": "cyber-osint-dashboard_postgres_data",
        "database_revision": "f8d739439ed0",
        "created_at_utc": exact_timestamp(created_at or datetime.now(timezone.utc)),
        "backup_artifact_path": str(artifact.resolve()),
        "backup_sha256": declared_hash or hashlib.sha256(content).hexdigest(),
    }
    evidence.write_text(json.dumps(document), encoding="utf-8")
    return evidence, artifact


def backup_call(evidence: Path) -> str:
    return (
        "Read-VerifiedBackupEvidence "
        f"-EvidencePath {ps_quote(evidence)} "
        f"-ResolvedRepositoryRoot {ps_quote(REPO_ROOT)} "
        f"-ExpectedCheckpoint '{FUTURE_REVIEWED_CHECKPOINT}' "
        "-ExpectedSessionId 'review-session-01' "
        "-ExpectedRevision 'f8d739439ed0' "
        "-ExpectedVolume 'cyber-osint-dashboard_postgres_data'"
    )


@pytest.mark.parametrize(
    "checkpoint",
    ["", "abc", "A" * 40, "g" * 40, "0" * 39, "0" * 41],
)
def test_malformed_checkpoint_values_fail_functionally(checkpoint: str) -> None:
    assert_ps_fails(
        f"Assert-ReviewedGitCheckpoint -Checkpoint {ps_quote(checkpoint)}",
        "40 lowercase hexadecimal",
    )


def test_future_reviewed_checkpoint_is_accepted_functionally() -> None:
    result = run_safe_powershell(
        f"Assert-ReviewedGitCheckpoint -Checkpoint '{FUTURE_REVIEWED_CHECKPOINT}'"
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == FUTURE_REVIEWED_CHECKPOINT


def test_old_parent_checkpoint_is_not_required_by_runtime_logic() -> None:
    script = source(POWERSHELL_PATH)
    assert OLD_PARENT_CHECKPOINT not in script
    assert '$ExpectedGitCheckpoint = ""' in script
    assert "Resolve-ReviewedGitCheckpoint" in script


def test_apply_checkpoint_must_be_explicit_functionally() -> None:
    assert_ps_fails(
        "Assert-ApplyInvocation -SelectedMode 'Apply' "
        "-ModeWasExplicit $false -CheckpointWasExplicit $true",
        "Apply requires explicit Mode",
    )
    assert_ps_fails(
        "Assert-ApplyInvocation -SelectedMode 'Apply' "
        "-ModeWasExplicit $true -CheckpointWasExplicit $false",
        "Apply requires explicit ExpectedGitCheckpoint",
    )
    assert_ps_fails(
        "Resolve-ReviewedGitCheckpoint -SubmittedCheckpoint '' "
        "-ReviewedApprovalEvidencePath '' "
        f"-ResolvedRepositoryRoot {ps_quote(REPO_ROOT)} "
        "-ApplyMode $true -CheckpointWasExplicit $false",
        "Apply requires an explicit ExpectedGitCheckpoint",
    )


def test_apply_confirmation_is_exact_functionally() -> None:
    script = source(POWERSHELL_PATH)
    validator = script.split("function Assert-ApplyConfirmation", 1)[1].split(
        "function Assert-ApplyInvocation", 1
    )[0]
    backup_gate = script.split("if ($BackupEvidencePath)", 1)[1].split(
        'if ($Mode -eq "Preflight")', 1
    )[0]
    apply_gate = 'Assert-Gate "apply_mode_explicit"' + script.split(
        'Assert-Gate "apply_mode_explicit"', 1
    )[1].split("$plan = Get-RoleExecutionPlan", 1)[0]

    valid = run_safe_powershell("Assert-ApplyConfirmation -Confirmation 'APPLY C08-PRE-02'")
    assert valid.returncode == 0, valid.stderr
    assert valid.stdout.strip() == "True"
    assert '$Confirmation -ceq "APPLY C08-PRE-02"' in validator
    assert (
        'Assert-ApplyConfirmation -Confirmation (Read-Host "Type APPLY C08-PRE-02 '
        'to continue")'
    ) in apply_gate
    assert script.count("Assert-ApplyConfirmation -Confirmation") == 1
    assert "APPLYC08-PRE-02" not in script
    assert_ps_fails(
        "Assert-ApplyConfirmation -Confirmation 'apply c08-pre-02'",
        "exact interactive confirmation",
    )
    assert_ps_fails(
        "Assert-ApplyConfirmation -Confirmation 'APPLYC08-PRE-02'",
        "exact interactive confirmation",
    )
    for required_gate in (
        '"apply_mode_explicit"',
        '"apply_checkpoint_explicit"',
        '"maintenance_session_present"',
    ):
        assert required_gate in apply_gate
    assert '"backup_required_for_apply"' in backup_gate
    assert "Apply requires verified backup evidence." in backup_gate


def test_backup_artifact_and_evidence_are_verified_functionally(tmp_path: Path) -> None:
    evidence, artifact = write_backup_fixture(tmp_path)
    result = run_safe_powershell(f"{backup_call(evidence)} | ConvertTo-Json -Compress")
    assert result.returncode == 0, result.stdout + result.stderr
    verified = json.loads(result.stdout)
    assert Path(verified["BackupArtifactPath"]) == artifact.resolve()
    assert verified["BackupSha256"] == hashlib.sha256(artifact.read_bytes()).hexdigest()
    assert verified["BackupSizeBytes"] == artifact.stat().st_size
    assert verified["BackupLastWriteUtc"].endswith("+00:00")
    assert verified["GitCheckpoint"] == FUTURE_REVIEWED_CHECKPOINT


def test_missing_backup_artifact_fails_functionally(tmp_path: Path) -> None:
    evidence, artifact = write_backup_fixture(tmp_path)
    artifact.unlink()
    assert_ps_fails(backup_call(evidence), "Cannot find path")


def test_empty_backup_artifact_fails_functionally(tmp_path: Path) -> None:
    evidence, _ = write_backup_fixture(tmp_path, content=b"")
    assert_ps_fails(backup_call(evidence), "file must be non-empty")


def test_backup_hash_mismatch_fails_functionally(tmp_path: Path) -> None:
    evidence, _ = write_backup_fixture(tmp_path, declared_hash="0" * 64)
    assert_ps_fails(backup_call(evidence), "backup artifact hash mismatch")


def test_backup_git_checkpoint_mismatch_fails_functionally(tmp_path: Path) -> None:
    evidence, _ = write_backup_fixture(tmp_path, checkpoint="a" * 40)
    assert_ps_fails(backup_call(evidence), "backup Git checkpoint mismatch")


def test_stale_backup_evidence_fails_functionally(tmp_path: Path) -> None:
    evidence, _ = write_backup_fixture(
        tmp_path,
        created_at=datetime.now(timezone.utc) - timedelta(hours=3),
    )
    assert_ps_fails(backup_call(evidence), "stale or future-dated")


def test_stale_backup_artifact_fails_functionally(tmp_path: Path) -> None:
    evidence, artifact = write_backup_fixture(tmp_path)
    stale_timestamp = (datetime.now(timezone.utc) - timedelta(hours=3)).timestamp()
    os.utime(artifact, (stale_timestamp, stale_timestamp))
    assert_ps_fails(backup_call(evidence), "backup artifact is stale or future-dated")


@pytest.mark.parametrize(
    "state",
    ["legacy_bootstrap_collision", "prepared_bootstrap_collision", "normalized"],
)
def test_role_states_are_distinguished_functionally(state: str) -> None:
    command = f"{ps_fixture(role_fixture(state))}; Get-RoleBoundaryState -Snapshot $fixture"
    result = run_safe_powershell(command)
    assert result.returncode == 0, result.stdout + result.stderr
    assert result.stdout.strip() == state


@pytest.mark.parametrize(
    ("key", "value"),
    [
        ("app_role_oid", 10),
        ("app_role_is_oid_10", True),
        ("cluster_bootstrap_role_exists", False),
        ("cluster_bootstrap_role_oid", 11),
        ("cluster_bootstrap_role_can_login", True),
        ("cluster_bootstrap_role_superuser", False),
        ("bootstrap_role_is_oid_10", True),
        ("oid_10_role_count", 0),
        ("oid_10_role_name", "alpha_data_user"),
        ("cluster_bootstrap_owned_public_object_count", 1),
        ("cluster_bootstrap_explicit_connect_count", 1),
        ("cluster_bootstrap_explicit_object_acl_count", 1),
    ],
)
def test_normalized_identity_split_variants_fail_closed_functionally(
    key: str, value: object
) -> None:
    fixture = role_fixture("normalized")
    fixture[key] = value
    command = f"{ps_fixture(fixture)}; Get-RoleBoundaryState -Snapshot $fixture"
    result = run_safe_powershell(command)
    assert result.returncode == 0, result.stdout + result.stderr
    assert result.stdout.strip() == "unexpected"


def test_partial_bootstrap_rename_without_replacement_fails_closed_functionally() -> None:
    fixture = role_fixture("prepared_bootstrap_collision")
    fixture.update(
        {
            "app_role_exists": False,
            "app_role_oid": 0,
            "app_role_is_oid_10": False,
            "cluster_bootstrap_role_exists": True,
            "cluster_bootstrap_role_oid": 10,
            "cluster_bootstrap_role_can_login": False,
            "cluster_bootstrap_role_superuser": True,
            "oid_10_role_name": "alpha_data_cluster_bootstrap",
        }
    )
    command = f"{ps_fixture(fixture)}; Get-RoleBoundaryState -Snapshot $fixture"
    result = run_safe_powershell(command)
    assert result.returncode == 0, result.stdout + result.stderr
    assert result.stdout.strip() == "unexpected"


@pytest.mark.parametrize(
    ("key", "value"),
    [
        ("database_owner", "someone_else"),
        ("public_schema_owner", "someone_else"),
        ("unexpected_owner_count", 1),
        ("managed_membership_count", 1),
        ("auxiliary_role_count", 1),
        ("expected_table_name_count", 10),
        ("expected_sequence_name_count", 8),
        ("unexpected_database_connect_grant_count", 1),
    ],
)
def test_unexpected_owner_attribute_or_membership_state_fails_closed_functionally(
    key: str, value: object
) -> None:
    fixture = role_fixture("legacy_bootstrap_collision")
    fixture[key] = value
    command = f"{ps_fixture(fixture)}; Get-RoleBoundaryState -Snapshot $fixture"
    result = run_safe_powershell(command)
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "unexpected"
    assert_ps_fails(
        "Get-RoleExecutionPlan -RoleState 'unexpected'",
        "role boundary state is unexpected",
    )


def test_normalized_resume_skips_all_role_mutation_functionally() -> None:
    result = run_safe_powershell(
        "Get-RoleExecutionPlan -RoleState 'normalized' | ConvertTo-Json -Compress"
    )
    assert result.returncode == 0, result.stderr
    plan = json.loads(result.stdout)
    assert plan == {
        "Prepare": False,
        "SetCredentials": False,
        "VerifyLogins": True,
        "RequireRuntimeCredential": False,
        "Normalize": False,
        "CorrectSyntheticProgress": True,
    }


@pytest.mark.parametrize(
    ("state", "replication", "expected_state"),
    [
        ("legacy_bootstrap_collision", False, "legacy_bootstrap_collision"),
        ("legacy_bootstrap_collision", True, "legacy_bootstrap_collision"),
        ("prepared_bootstrap_collision", False, "prepared_bootstrap_collision"),
        ("prepared_bootstrap_collision", True, "prepared_bootstrap_collision"),
        ("normalized", False, "normalized"),
        ("normalized", True, "unexpected"),
    ],
)
def test_application_replication_is_bounded_by_role_state_functionally(
    state: str, replication: bool, expected_state: str
) -> None:
    fixture = role_fixture(state)
    fixture["app_role_replication"] = replication
    command = f"{ps_fixture(fixture)}; Get-RoleBoundaryState -Snapshot $fixture"
    result = run_safe_powershell(command)
    assert result.returncode == 0, result.stdout + result.stderr
    assert result.stdout.strip() == expected_state


def test_replication_tolerance_does_not_accept_mixed_legacy_attributes() -> None:
    fixture = role_fixture("legacy_bootstrap_collision")
    fixture["app_role_replication"] = True
    fixture["app_role_createrole"] = False
    command = f"{ps_fixture(fixture)}; Get-RoleBoundaryState -Snapshot $fixture"
    result = run_safe_powershell(command)
    assert result.returncode == 0, result.stdout + result.stderr
    assert result.stdout.strip() == "unexpected"


def test_prepared_resume_reconfigures_credentials_then_normalizes_functionally() -> None:
    result = run_safe_powershell(
        "Get-RoleExecutionPlan -RoleState 'prepared_bootstrap_collision' | ConvertTo-Json -Compress"
    )
    assert result.returncode == 0, result.stderr
    plan = json.loads(result.stdout)
    assert plan == {
        "Prepare": False,
        "SetCredentials": True,
        "VerifyLogins": True,
        "RequireRuntimeCredential": True,
        "Normalize": True,
        "CorrectSyntheticProgress": True,
    }


def test_sql_hash_drift_fails_functionally(tmp_path: Path) -> None:
    sql_path = tmp_path / "reviewed.sql"
    sql_path.write_text("SELECT 1;\n", encoding="utf-8")
    assert_ps_fails(
        "Get-ReviewedSqlArtifact "
        f"-SubmittedPath {ps_quote(sql_path)} -ApprovedPath {ps_quote(sql_path)} "
        f"-ExpectedSha256 '{'0' * 64}'",
        "SQL content hash drift detected",
    )


def test_reviewed_sql_text_is_retained_after_disk_change_functionally(tmp_path: Path) -> None:
    sql_path = tmp_path / "reviewed.sql"
    reviewed_bytes = b"SELECT 1;\n"
    sql_path.write_bytes(reviewed_bytes)
    expected_hash = hashlib.sha256(reviewed_bytes).hexdigest()
    result = run_safe_powershell(
        "$artifact=Get-ReviewedSqlArtifact "
        f"-SubmittedPath {ps_quote(sql_path)} -ApprovedPath {ps_quote(sql_path)} "
        f"-ExpectedSha256 '{expected_hash}'; "
        f"Set-Content -LiteralPath {ps_quote(sql_path)} -Value 'SELECT 2;' -Encoding utf8NoBOM; "
        "[pscustomobject]@{Text=$artifact.Text;Hash=$artifact.Sha256} | ConvertTo-Json -Compress"
    )
    assert result.returncode == 0, result.stdout + result.stderr
    retained = json.loads(result.stdout)
    assert retained["Text"] == reviewed_bytes.decode()
    assert retained["Hash"] == expected_hash


def test_credentials_are_non_echoing_secure_strings_functionally() -> None:
    result = run_safe_powershell(
        "$credentials=Read-ReconciliationCredentials -IncludeRuntimeCredential $true -PromptProvider { "
        "param($promptText) ConvertTo-SecureString 'synthetic-test-value' -AsPlainText -Force }; "
        "$safe=[pscustomobject]@{Runtime=$credentials.Runtime.GetType().FullName;Bootstrap=$credentials.Bootstrap.GetType().FullName;Migration=$credentials.Migration.GetType().FullName}; "
        "$credentials.Runtime.Dispose(); $credentials.Bootstrap.Dispose(); $credentials.Migration.Dispose(); $credentials=$null; "
        "$safe | ConvertTo-Json -Compress"
    )
    assert result.returncode == 0, result.stdout + result.stderr
    types = json.loads(result.stdout)
    assert types == {
        "Runtime": "System.Security.SecureString",
        "Bootstrap": "System.Security.SecureString",
        "Migration": "System.Security.SecureString",
    }
    assert "synthetic-test-value" not in result.stdout


def test_normalize_uses_bootstrap_and_runtime_credential_only_on_stdin_functionally() -> None:
    result = run_safe_powershell(
        f"$script:ResolvedRepositoryRoot={ps_quote(REPO_ROOT)}; "
        "function Invoke-SafeProcess { param($FileName,$ArgumentList,$WorkingDirectory,$StandardInputText) "
        "$script:capturedArguments=$ArgumentList -join ' '; "
        "$script:capturedInput=$StandardInputText; "
        "[pscustomobject]@{ExitCode=0;Stdout='';StderrPresent=$false} }; "
        "$credential=ConvertTo-SecureString 'synthetic-runtime-value' -AsPlainText -Force; "
        "$artifact=[pscustomobject]@{Text=\"BEGIN;`n\\password alpha_data_user`nSELECT 1;`nCOMMIT;`n\"}; "
        "Invoke-ReviewedSqlArtifact -Artifact $artifact -Phase 'normalize' -RuntimeCredential $credential; "
        "$safe=[pscustomobject]@{BootstrapIdentity=($script:capturedArguments -match '--username alpha_data_bootstrap');SecretInArguments=$script:capturedArguments.Contains('synthetic-runtime-value');SecretInputCount=([regex]::Matches($script:capturedInput,'synthetic-runtime-value')).Count;MarkerCount=([regex]::Matches($script:capturedInput,'\\\\password alpha_data_user')).Count}; "
        "$credential.Dispose(); $credential=$null; $script:capturedInput=$null; "
        "$safe | ConvertTo-Json -Compress"
    )
    assert result.returncode == 0, result.stdout + result.stderr
    evidence = json.loads(result.stdout)
    assert evidence == {
        "BootstrapIdentity": True,
        "SecretInArguments": False,
        "SecretInputCount": 2,
        "MarkerCount": 1,
    }
    assert "synthetic-runtime-value" not in result.stdout


def test_script_is_dot_source_safe_and_main_is_explicit() -> None:
    result = run_safe_powershell(
        "[pscustomobject]@{Main=(Get-Command Invoke-C08Pre02Main).Name;ResultVariable=(Test-Path variable:script:FinalResult)} | ConvertTo-Json -Compress"
    )
    assert result.returncode == 0, result.stdout + result.stderr
    evidence = json.loads(result.stdout)
    assert evidence == {"Main": "Invoke-C08Pre02Main", "ResultVariable": False}
    script = source(POWERSHELL_PATH)
    assert 'if ($MyInvocation.InvocationName -ne ".")' in script


def test_no_secret_parameter_environment_log_or_evidence_path_exists() -> None:
    script = source(POWERSHELL_PATH)
    parameter_block = script.split("param(", 1)[1].split(")\n\nSet-StrictMode", 1)[0]
    for forbidden in ("Password", "Token", "Cookie", "Authorization", "ApiKey", "Secret"):
        assert f"${forbidden}" not in parameter_block
    assert "Read-Host \"Enter alpha_data_bootstrap credential\" -AsSecureString" in script
    assert "Read-Host \"Enter alpha_data_migration credential\" -AsSecureString" in script
    assert (
        'Read-Host "Enter current alpha_data_user credential for replacement role" '
        "-AsSecureString"
    ) in script
    assert "GetEnvironmentVariable" not in script
    assert "C08_PRE02_BOOTSTRAP_CREDENTIAL_FILE" not in script
    assert "SecureStringToBSTR" in script
    assert "ZeroFreeBSTR" in script
    evidence_block = script.split("function Write-SanitizedEvidence", 1)[1].split(
        "$DatabaseSnapshotSql", 1
    )[0]
    assert "Credential" not in evidence_block


def test_script_has_no_prohibited_operational_or_git_writes() -> None:
    script = source(POWERSHELL_PATH).casefold()
    for forbidden in (
        "alembic upgrade",
        "docker compose up",
        "docker compose start",
        '"up"',
        '"start"',
        "git add",
        "git commit",
        "git push",
        "git reset",
        "git restore",
        "register handler",
        "enable source",
        "start ingestion",
    ):
        assert forbidden not in script


def test_git_checkpoint_and_clean_tree_are_rechecked_before_mutations() -> None:
    script = source(POWERSHELL_PATH)
    assert script.count("Assert-RepositoryState -ReviewedCheckpoint") >= 4
    assert '"git_head"' in script
    assert '"git_origin_head"' in script
    assert '"git_divergence"' in script
    assert '"git_staged_clean"' in script
    assert '"git_tracked_clean"' in script
    assert '"git_untracked_clean"' in script


def test_role_sql_uses_explicit_phase_and_never_infers_password_state() -> None:
    sql = source(ROLE_SQL_PATH)
    assert ":'c08_phase' IN ('prepare', 'normalize')" in sql
    assert "\\if :c08_prepare" in sql
    assert "\\elif :c08_normalize" in sql
    assert "pg_authid" not in sql
    assert "rolpassword" not in sql


def test_legacy_replication_tolerance_does_not_weaken_normalized_state() -> None:
    script = source(POWERSHELL_PATH)
    sql = source(ROLE_SQL_PATH)
    classifier = script.split("function Get-RoleBoundaryState", 1)[1].split(
        "function Get-RoleExecutionPlan", 1
    )[0]
    common = classifier.split("$common = (", 1)[1].split("$legacyApplication", 1)[0]
    safe_application = classifier.split("$safeApplication = (", 1)[1].split(
        "$dedicatedAbsent", 1
    )[0]
    prepare_guard = sql.split("$c08_pre02_prepare_guard$", 2)[1]
    prepare_app = prepare_guard.split("role.rolname = 'alpha_data_user'", 1)[1].split(
        ") THEN", 1
    )[0]
    normalize_guard = sql.split("$c08_pre02_normalize_guard$", 2)[1]
    normalize_app = normalize_guard.split("role.rolname = 'alpha_data_user'", 1)[
        1
    ].split(") THEN", 1)[0]
    final_guard = sql.split("$c08_pre02_final_guard$", 2)[1]
    normalized_runtime = final_guard.split("role.rolname = 'alpha_data_user'", 1)[
        1
    ].split(") THEN", 1)[0]

    assert "app_role_replication" not in common
    assert '(Test-EvidenceBool $Snapshot "app_role_replication" $false)' in safe_application
    assert "rolreplication" not in prepare_app
    assert "rolreplication" not in normalize_app
    assert "LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS" in sql
    assert "NOT role.rolreplication" in normalized_runtime


def test_prepare_does_not_transfer_ownership_or_demote_application_role() -> None:
    sql = source(ROLE_SQL_PATH)
    prepare = sql.split("\\if :c08_prepare", 1)[1].split("\\elif :c08_normalize", 1)[0]
    for forbidden in (
        "ALTER DATABASE alpha_data_db OWNER",
        "ALTER SCHEMA public OWNER",
        "OWNER TO alpha_data_migration",
        "ALTER ROLE alpha_data_user",
        "REVOKE CREATE ON SCHEMA public",
    ):
        assert forbidden not in prepare
    assert "app_owned_table_count <> 11" in prepare
    assert "app_owned_sequence_count <> 9" in prepare
    assert "Prepare changed an ownership boundary" in prepare


def test_normalize_transfers_exact_ownership_then_restricts_application_last() -> None:
    sql = source(ROLE_SQL_PATH)
    normalize = sql.split("\\elif :c08_normalize", 1)[1]
    rename = normalize.index(
        "ALTER ROLE alpha_data_user RENAME TO alpha_data_cluster_bootstrap"
    )
    create_runtime = normalize.index("CREATE ROLE alpha_data_user")
    transfer = normalize.index("$c08_pre02_transfer_exact_ownership$")
    path_verification = normalize.index(
        "$c08_pre02_verify_paths_before_application_restriction$"
    )
    app_revoke = normalize.index(
        "REVOKE ALL ON ALL TABLES IN SCHEMA public FROM alpha_data_user"
    )
    demotion = normalize.index("ALTER ROLE alpha_data_user WITH")
    final_guard = normalize.index("$c08_pre02_final_guard$")
    assert rename < create_runtime < transfer < path_verification < app_revoke
    assert app_revoke < demotion < final_guard
    assert "transferred_table_count <> 11" in normalize
    assert "transferred_sequence_count <> 9" in normalize
    assert "migration_owned_table_count <> 11" in normalize
    assert "migration_owned_sequence_count <> 9" in normalize


def test_role_sql_guards_complete_owner_attribute_and_membership_boundary() -> None:
    sql = source(ROLE_SQL_PATH)
    for required in (
        "database_owner_name",
        "schema_owner_name",
        "role.rolcanlogin",
        "role.rolsuper",
        "role.rolcreatedb",
        "role.rolcreaterole",
        "role.rolreplication",
        "role.rolbypassrls",
        "app_owned_table_count",
        "app_owned_sequence_count",
        "managed_membership_count",
        "unexpected_owner_count",
        "unexpected_object_name_count",
        "unexpected_database_connect_grant_count",
        "prepared_table_privilege_count",
        "prepared_sequence_privilege_count",
        "migration_default_acl_count",
    ):
        assert required in sql
    assert "unexpected public object owner" in sql
    assert "unexpected managed-role membership" in sql


def test_role_sql_has_no_credentials_or_destructive_role_database_operations() -> None:
    sql = source(ROLE_SQL_PATH)
    assert re.search(r"(?i)(?<!\\)\bPASSWORD\b", sql) is None
    assert sql.count("\\password alpha_data_user") == 1
    for forbidden_pattern in (
        r"(?i)DROP\s+ROLE",
        r"(?i)DROP\s+DATABASE",
        r"(?i)DROP\s+SCHEMA",
        r"(?i)DROP\s+OWNED",
        r"(?i)REASSIGN\s+OWNED",
        r"(?i)\bCASCADE\b",
        r"(?i)postgresql(?:\+psycopg)?://",
    ):
        assert re.search(forbidden_pattern, sql) is None


def test_normalize_splits_oid_10_from_runtime_and_runs_as_bootstrap() -> None:
    script = source(POWERSHELL_PATH)
    sql = source(ROLE_SQL_PATH)
    normalize = sql.split("\\elif :c08_normalize", 1)[1]
    final_guard = normalize.split("$c08_pre02_final_guard$", 2)[1]

    assert 'if ($Phase -eq "normalize") { "alpha_data_bootstrap" }' in script
    assert "current_user <> 'alpha_data_bootstrap'" in normalize
    assert "role.rolname = 'alpha_data_user'" in normalize
    assert "role.oid = 10" in normalize
    assert "role.rolname = 'alpha_data_bootstrap'" in normalize
    assert "role.oid <> 10" in normalize
    assert "ALTER ROLE alpha_data_user RENAME TO alpha_data_cluster_bootstrap" in normalize
    assert "ALTER ROLE alpha_data_cluster_bootstrap WITH" in normalize
    assert "NOLOGIN INHERIT SUPERUSER" in normalize
    assert "CREATE ROLE alpha_data_user" in normalize
    assert "LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS" in normalize
    assert "\\password alpha_data_user" in normalize
    assert "ALTER ROLE alpha_data_cluster_bootstrap WITH\n    NOSUPERUSER" not in normalize
    assert "role.rolname = 'alpha_data_cluster_bootstrap'" in final_guard
    assert "role.oid = 10" in final_guard
    assert "NOT role.rolcanlogin AND role.rolsuper" in final_guard
    assert "role.rolname = 'alpha_data_user'" in final_guard
    assert "role.oid <> 10" in final_guard
    assert "cluster_bootstrap_connect_grant_count <> 0" in final_guard
    assert "cluster_bootstrap_owned_object_count <> 0" in final_guard
    assert "cluster_bootstrap_explicit_object_acl_count <> 0" in final_guard


def test_role_sql_keeps_public_and_default_privileges_closed() -> None:
    sql = source(ROLE_SQL_PATH)
    assert "GRANT ALL" not in sql
    assert "REVOKE CREATE ON SCHEMA public FROM PUBLIC" in sql
    assert "REVOKE CONNECT ON DATABASE alpha_data_db FROM PUBLIC" in sql
    assert "REVOKE ALL ON ALL TABLES IN SCHEMA public FROM PUBLIC" in sql
    assert "REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM PUBLIC" in sql
    assert "ALTER DEFAULT PRIVILEGES FOR ROLE alpha_data_migration" in sql
    assert "GRANT DELETE" not in sql
    assert "GRANT UPDATE ON SEQUENCE" not in sql


def test_role_sql_pins_exact_initial_object_names_before_transfer() -> None:
    sql = source(ROLE_SQL_PATH)
    expected_tables = {
        "alembic_version",
        "ingestion_errors",
        "ingestion_run_records",
        "ingestion_runs",
        "intelligence_item_identifiers",
        "intelligence_item_tags",
        "intelligence_items",
        "intelligence_sources",
        "source_records",
        "tags",
        "vulnerabilities",
    }
    expected_sequences = {
        "ingestion_errors_id_seq",
        "ingestion_run_records_id_seq",
        "ingestion_runs_id_seq",
        "intelligence_item_identifiers_id_seq",
        "intelligence_items_id_seq",
        "intelligence_sources_id_seq",
        "source_records_id_seq",
        "tags_id_seq",
        "vulnerabilities_id_seq",
    }
    prepare_guard = sql.split("$c08_pre02_prepare_guard$", 2)[1]
    normalize_guard = sql.split("$c08_pre02_normalize_guard$", 2)[1]
    transfer = sql.split("$c08_pre02_transfer_exact_ownership$", 2)[1]
    for object_name in expected_tables | expected_sequences:
        assert object_name in prepare_guard
        assert object_name in normalize_guard
        assert object_name in transfer


def test_snapshot_dynamic_sequence_privileges_use_pg_sequence_oids() -> None:
    script = source(POWERSHELL_PATH)
    snapshot = script.split("$DatabaseSnapshotSql = @'", 1)[1].split("'@", 1)[0]
    safe_join = (
        "JOIN pg_sequence AS sequence_record "
        "ON sequence_record.seqrelid = object.oid"
    )
    assert snapshot.count(safe_join) == 3
    assert snapshot.count("sequence_record.seqrelid") == 12
    assert "has_sequence_privilege(role.rolname, object.oid" not in snapshot
    assert "has_sequence_privilege('alpha_data_migration', object.oid" not in snapshot
    assert "has_sequence_privilege('alpha_data_user', object.oid" not in snapshot
    assert re.search(
        r"has_sequence_privilege\([^)]*\bobject\.oid\b",
        snapshot,
        flags=re.DOTALL,
    ) is None


def test_snapshot_contains_sanitized_bootstrap_identity_evidence() -> None:
    script = source(POWERSHELL_PATH)
    snapshot = script.split("$DatabaseSnapshotSql = @'", 1)[1].split("'@", 1)[0]
    for evidence_key in (
        "app_role_oid",
        "app_role_is_oid_10",
        "bootstrap_role_oid",
        "bootstrap_role_is_oid_10",
        "cluster_bootstrap_role_exists",
        "cluster_bootstrap_role_oid",
        "cluster_bootstrap_role_can_login",
        "cluster_bootstrap_role_superuser",
        "oid_10_role_count",
        "oid_10_role_name",
        "cluster_bootstrap_owned_public_object_count",
        "cluster_bootstrap_explicit_connect_count",
        "cluster_bootstrap_explicit_object_acl_count",
    ):
        assert f"'{evidence_key}='" in snapshot
    assert "pg_authid" not in snapshot
    assert "rolpassword" not in snapshot


def test_explicit_cluster_bootstrap_acl_checks_use_nullable_acl_arrays() -> None:
    script = source(POWERSHELL_PATH)
    sql = source(ROLE_SQL_PATH)
    snapshot = script.split("$DatabaseSnapshotSql = @'", 1)[1].split("'@", 1)[0]
    snapshot_acl_line = next(
        line
        for line in snapshot.splitlines()
        if "cluster_bootstrap_explicit_object_acl_count=" in line
    )
    sql_acl_guard = sql.split(
        "INTO cluster_bootstrap_explicit_object_acl_count", 1
    )[1].split("IF cluster_bootstrap_explicit_object_acl_count", 1)[0]

    for acl_check in (snapshot_acl_line, sql_acl_guard):
        assert "aclexplode(object.relacl)" in acl_check
        assert "aclexplode(namespace.nspacl)" in acl_check
        assert "'{}'::aclitem[]" not in acl_check
        assert "acldefault" not in acl_check
    assert "coalesce(object.relacl" not in script
    assert "coalesce(namespace.nspacl" not in script
    assert "coalesce(object.relacl" not in sql
    assert "coalesce(namespace.nspacl" not in sql


def test_provision_dynamic_sequence_privileges_use_pg_sequence_oids() -> None:
    sql = source(ROLE_SQL_PATH)
    safe_join = (
        "JOIN pg_sequence AS sequence_record "
        "ON sequence_record.seqrelid = object.oid"
    )
    assert sql.count(safe_join) == 2
    assert sql.count("sequence_record.seqrelid") == 8
    assert re.search(
        r"has_sequence_privilege\([^)]*\bobject\.oid\b",
        sql,
        flags=re.DOTALL,
    ) is None


def test_reviewed_sql_hashes_match_final_files() -> None:
    script = source(POWERSHELL_PATH)
    provision_hash = hashlib.sha256(ROLE_SQL_PATH.read_bytes()).hexdigest()
    correction_hash = hashlib.sha256(CORRECTION_SQL_PATH.read_bytes()).hexdigest()
    provision_match = re.search(
        r'^\$ProvisionSqlSha256 = "([0-9a-f]{64})"$',
        script,
        flags=re.MULTILINE,
    )
    correction_match = re.search(
        r'^\$CorrectionSqlSha256 = "([0-9a-f]{64})"$',
        script,
        flags=re.MULTILINE,
    )
    assert provision_match is not None
    assert correction_match is not None
    assert provision_match.group(1) == provision_hash
    assert correction_match.group(1) == correction_hash
    assert correction_hash == EXPECTED_CORRECTION_SQL_SHA256


def test_sequence_counts_and_role_state_expectations_remain_frozen() -> None:
    script = source(POWERSHELL_PATH)
    sql = source(ROLE_SQL_PATH)
    for expected in (
        '(Test-EvidenceInt $Snapshot "public_sequence_count" 9)',
        '(Test-EvidenceInt $Snapshot "auxiliary_no_sequence_privilege_count" 27)',
        '(Test-EvidenceInt $Snapshot "prepared_migration_no_sequence_privilege_count" 9)',
        '(Test-EvidenceInt $Snapshot "app_sequence_privilege_shape_count" 9)',
    ):
        assert expected in script
    assert "app_owned_sequence_count <> 9" in sql
    assert "transferred_sequence_count <> 9" in sql
    assert "migration_owned_sequence_count <> 9" in sql


def test_correction_sql_uses_exact_four_slug_allow_list_without_wildcard() -> None:
    sql = source(CORRECTION_SQL_PATH)
    found = set(re.findall(r"'((?:alpha-synthetic-)[a-z-]+)'", sql))
    assert found == TARGET_SLUGS
    assert "LIKE 'alpha-synthetic-%'" not in sql
    for slug in TARGET_SLUGS:
        assert sql.count(f"('{slug}')") >= 4


def test_correction_sql_has_fixed_database_identity_revision_hash_and_row_gates() -> None:
    sql = source(CORRECTION_SQL_PATH)
    assert "current_database() <> 'alpha_data_db'" in sql
    assert "current_user <> 'alpha_data_user'" in sql
    assert "expected_revision constant text := 'f8d739439ed0'" in sql
    assert "version_row_count <> 1" in sql
    assert "target_row_count <> 4" in sql
    assert "exact_slug_count <> 4" in sql
    assert "valid_checkpoint_count <> 4" in sql
    assert "1c4f57ad3b27a40b2157dd0fade25a74363f889b8a1972702e2eb9570c2c9fa4" in sql


def test_correction_sql_preserves_exact_mutation_boundary_and_reapply_failure() -> None:
    sql = source(CORRECTION_SQL_PATH)
    update_blocks = re.findall(
        r"UPDATE\s+public\.intelligence_sources.*?;",
        sql,
        flags=re.IGNORECASE | re.DOTALL,
    )
    assert len(update_blocks) == 1
    set_clause = update_blocks[0].split("SET", 1)[1].split("FROM", 1)[0].strip()
    assert set_clause == "checkpoint_value = NULL"
    assert "associated_run_count <> 0" in sql
    assert "successful_run_count <> 0" in sql
    assert "running_run_count <> 0" in sql
    assert "matching_correlation_count <> 0" in sql
    assert "extra_shape_count <> 0" in sql
    assert "GET DIAGNOSTICS affected_row_count = ROW_COUNT" in sql
    assert "affected_row_count <> 4" in sql
    assert sql.rstrip().endswith("COMMIT;")
    assert "checkpoint_value IS NOT NULL" in sql


def test_bootstrap_identity_split_scope_policy_is_exact_and_narrow() -> None:
    expected_scope = {
        "scripts/c08-pre02-reconcile-preserved-volume.ps1",
        "database/maintenance/c08-pre02-provision-existing-volume.sql",
        "backend/tests/test_c08_pre02_reconciliation.py",
        "docs/c08-pre02-preserved-volume-reconciliation.md",
    }
    assert AUTHORIZED_FILES == expected_scope
    assert len(AUTHORIZED_FILES) == 4
    assert not any(
        path.startswith("backend/alembic/versions/") for path in AUTHORIZED_FILES
    )
    assert not any(Path(path).name.startswith(".env") for path in AUTHORIZED_FILES)
    assert not any("*" in path or "?" in path for path in AUTHORIZED_FILES)


def test_documentation_covers_bootstrap_identity_split_and_current_boundary() -> None:
    documentation = source(DOC_PATH)
    for required in (
        "Prepare completed",
        "Normalize failed transactionally",
        "C08 remains blocked",
        "post-commit Git checkpoint",
        "actual backup artifact",
        "Read-Host -AsSecureString",
        "legacy_bootstrap_collision",
        "prepared_bootstrap_collision",
        "normalized",
        "unexpected",
        "alpha_data_cluster_bootstrap",
        "OID 10",
        "never paste credentials into chat",
        "retained reviewed text",
        "functional",
    ):
        assert required in documentation
    assert "credential file" not in documentation.casefold()
    for prohibited_claim in (
        "Remediation completed successfully.",
        "Migrations pass.",
        "Administrator bootstrap succeeded.",
        "Sign-in succeeded.",
    ):
        assert prohibited_claim not in documentation
