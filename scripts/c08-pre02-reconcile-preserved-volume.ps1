<#
.SYNOPSIS
Fail-closed reconciliation orchestration for the preserved Alpha Data volume.

.DESCRIPTION
Preflight is read-only except for sanitized evidence outside the repository. Apply
requires an explicit reviewed Git checkpoint, backup evidence, maintenance session,
and interactive confirmation. Dot-sourcing exposes safe helper functions and never
runs the main workflow.
#>

[CmdletBinding()]
param(
    [ValidateSet("Preflight", "Apply")]
    [string]$Mode = "Preflight",

    [string]$RepositoryRoot = "",
    [string]$ExpectedBranch = "dev",
    [string]$ExpectedGitCheckpoint = "",
    [string]$ApprovalEvidencePath = "",
    [string]$ExpectedDatabaseRevision = "f8d739439ed0",
    [string]$ExpectedDockerVolume = "cyber-osint-dashboard_postgres_data",
    [string]$EvidenceOutputDirectory = "",
    [string]$BackupEvidencePath = "",
    [string]$MaintenanceSessionId = "",
    [string]$ProvisionSqlPath = "",
    [string]$CorrectionSqlPath = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$TaskId = "C08-PRE-02"
$FrozenBranch = "dev"
$FrozenDatabaseRevision = "f8d739439ed0"
$FrozenDockerVolume = "cyber-osint-dashboard_postgres_data"
$DatabaseContainer = "alpha-data-db"
$DatabaseService = "db"
$DatabaseName = "alpha_data_db"
$InitialDatabaseIdentity = "alpha_data_user"
$ProvisionSqlSha256 = "4e1264e5e4b1dddceedb6349885995fb324fa4fa03a04172aebef37e862c0bf5"
$CorrectionSqlSha256 = "d614601fef244bb612035b6029392f207126e1de8a3cbc1bc819bb98595c0a4e"
$MaximumBackupAge = [TimeSpan]::FromHours(2)
$AllowedBackupExtensions = @(".backup", ".dump", ".tar", ".gz")

function Assert-Condition {
    param(
        [Parameter(Mandatory = $true)][bool]$Condition,
        [Parameter(Mandatory = $true)][string]$SafeMessage
    )
    if (-not $Condition) {
        throw $SafeMessage
    }
}

function Assert-ReviewedGitCheckpoint {
    param([Parameter(Mandatory = $true)][AllowEmptyString()][string]$Checkpoint)

    Assert-Condition (
        $Checkpoint -cmatch '^[0-9a-f]{40}$'
    ) "C08-PRE-02 reviewed Git checkpoint must be exactly 40 lowercase hexadecimal characters"
    return $Checkpoint
}

function Test-PathInsideParent {
    param(
        [Parameter(Mandatory = $true)][string]$Candidate,
        [Parameter(Mandatory = $true)][string]$Parent
    )

    $separator = [System.IO.Path]::DirectorySeparatorChar
    $parentPrefix = [System.IO.Path]::GetFullPath($Parent).TrimEnd($separator) + $separator
    $candidatePath = [System.IO.Path]::GetFullPath($Candidate)
    $parentPath = [System.IO.Path]::GetFullPath($Parent).TrimEnd($separator)
    return $candidatePath.Equals(
        $parentPath,
        [System.StringComparison]::OrdinalIgnoreCase
    ) -or $candidatePath.StartsWith(
        $parentPrefix,
        [System.StringComparison]::OrdinalIgnoreCase
    )
}

function Get-CanonicalRegularFile {
    param(
        [Parameter(Mandatory = $true)][string]$PathValue,
        [Parameter(Mandatory = $true)][string[]]$AllowedExtensions,
        [switch]$RequireNonEmpty
    )

    Assert-Condition ([System.IO.Path]::IsPathRooted($PathValue)) "C08-PRE-02 path must be absolute"
    $submittedItem = Get-Item -LiteralPath $PathValue -Force -ErrorAction Stop
    Assert-Condition (
        -not ($submittedItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint)
    ) "C08-PRE-02 file must not be a link"
    Assert-Condition (
        -not ($submittedItem.Attributes -band [System.IO.FileAttributes]::Directory)
    ) "C08-PRE-02 path must identify a regular file"
    if ($RequireNonEmpty) {
        Assert-Condition ($submittedItem.Length -gt 0) "C08-PRE-02 file must be non-empty"
    }
    $resolved = [System.IO.Path]::GetFullPath((Resolve-Path -LiteralPath $PathValue).Path)
    $extension = [System.IO.Path]::GetExtension($resolved).ToLowerInvariant()
    Assert-Condition ($extension -in $AllowedExtensions) "C08-PRE-02 file extension is not approved"
    return $resolved
}

function Resolve-ReviewedGitCheckpoint {
    param(
        [string]$SubmittedCheckpoint,
        [string]$ReviewedApprovalEvidencePath,
        [Parameter(Mandatory = $true)][string]$ResolvedRepositoryRoot,
        [Parameter(Mandatory = $true)][bool]$ApplyMode,
        [Parameter(Mandatory = $true)][bool]$CheckpointWasExplicit
    )

    if ($ApplyMode) {
        Assert-Condition $CheckpointWasExplicit "C08-PRE-02 Apply requires an explicit ExpectedGitCheckpoint parameter"
    }
    if (-not [string]::IsNullOrWhiteSpace($SubmittedCheckpoint)) {
        return Assert-ReviewedGitCheckpoint -Checkpoint $SubmittedCheckpoint
    }
    Assert-Condition (-not $ApplyMode) "C08-PRE-02 Apply checkpoint cannot be inferred"
    Assert-Condition (
        -not [string]::IsNullOrWhiteSpace($ReviewedApprovalEvidencePath)
    ) "C08-PRE-02 Preflight requires an explicit checkpoint or reviewed approval evidence"

    $resolved = Get-CanonicalRegularFile -PathValue $ReviewedApprovalEvidencePath -AllowedExtensions @(".json") -RequireNonEmpty
    Assert-Condition (
        -not (Test-PathInsideParent -Candidate $resolved -Parent $ResolvedRepositoryRoot)
    ) "C08-PRE-02 approval evidence must be outside the repository"
    try {
        $document = Get-Content -LiteralPath $resolved -Raw -Encoding UTF8 | ConvertFrom-Json
    }
    catch {
        throw "C08-PRE-02 reviewed approval evidence was invalid"
    }
    Assert-Condition ([string]$document.task_id -eq $TaskId) "C08-PRE-02 approval evidence task mismatch"
    return Assert-ReviewedGitCheckpoint -Checkpoint ([string]$document.git_checkpoint)
}

function Get-ReviewedSqlArtifact {
    param(
        [Parameter(Mandatory = $true)][string]$SubmittedPath,
        [Parameter(Mandatory = $true)][string]$ApprovedPath,
        [Parameter(Mandatory = $true)][string]$ExpectedSha256
    )

    Assert-Condition ($ExpectedSha256 -cmatch '^[0-9a-f]{64}$') "C08-PRE-02 reviewed SQL hash was invalid"
    $candidate = Get-CanonicalRegularFile -PathValue $SubmittedPath -AllowedExtensions @(".sql") -RequireNonEmpty
    $approved = Get-CanonicalRegularFile -PathValue $ApprovedPath -AllowedExtensions @(".sql") -RequireNonEmpty
    Assert-Condition (
        $candidate.Equals($approved, [System.StringComparison]::OrdinalIgnoreCase)
    ) "C08-PRE-02 SQL path escaped the approved repository path"

    $bytes = [System.IO.File]::ReadAllBytes($candidate)
    $actualHash = [Convert]::ToHexString(
        [System.Security.Cryptography.SHA256]::HashData($bytes)
    ).ToLowerInvariant()
    Assert-Condition ($actualHash -ceq $ExpectedSha256) "C08-PRE-02 SQL content hash drift detected"
    $strictUtf8 = [System.Text.UTF8Encoding]::new($false, $true)
    $text = $strictUtf8.GetString($bytes)
    return [pscustomobject]@{
        Path = $candidate
        Sha256 = $actualHash
        Text = $text
    }
}

function Read-VerifiedBackupEvidence {
    param(
        [Parameter(Mandatory = $true)][string]$EvidencePath,
        [Parameter(Mandatory = $true)][string]$ResolvedRepositoryRoot,
        [Parameter(Mandatory = $true)][string]$ExpectedCheckpoint,
        [Parameter(Mandatory = $true)][string]$ExpectedSessionId,
        [Parameter(Mandatory = $true)][string]$ExpectedRevision,
        [Parameter(Mandatory = $true)][string]$ExpectedVolume,
        [DateTimeOffset]$NowUtc = [DateTimeOffset]::UtcNow
    )

    $checkpoint = Assert-ReviewedGitCheckpoint -Checkpoint $ExpectedCheckpoint
    Assert-Condition (-not [string]::IsNullOrWhiteSpace($ExpectedSessionId)) "C08-PRE-02 maintenance session is required"
    $resolvedEvidence = Get-CanonicalRegularFile -PathValue $EvidencePath -AllowedExtensions @(".json") -RequireNonEmpty
    Assert-Condition (
        -not (Test-PathInsideParent -Candidate $resolvedEvidence -Parent $ResolvedRepositoryRoot)
    ) "C08-PRE-02 backup evidence must be outside the repository"
    $jsonDocument = $null
    try {
        $rawEvidence = Get-Content -LiteralPath $resolvedEvidence -Raw -Encoding UTF8
        $document = $rawEvidence | ConvertFrom-Json
        $jsonDocument = [System.Text.Json.JsonDocument]::Parse($rawEvidence)
        $createdAtText = $jsonDocument.RootElement.GetProperty("created_at_utc").GetString()
        $createdAt = [DateTimeOffset]::ParseExact(
            $createdAtText,
            "o",
            [System.Globalization.CultureInfo]::InvariantCulture
        )
    }
    catch {
        throw "C08-PRE-02 backup evidence was invalid"
    }
    finally {
        if ($null -ne $jsonDocument) { $jsonDocument.Dispose() }
        $jsonDocument = $null
        $rawEvidence = $null
    }

    Assert-Condition ([string]$document.task_id -eq $TaskId) "C08-PRE-02 backup task mismatch"
    Assert-Condition ([string]$document.maintenance_session_id -eq $ExpectedSessionId) "C08-PRE-02 backup session mismatch"
    Assert-Condition ([string]$document.git_checkpoint -ceq $checkpoint) "C08-PRE-02 backup Git checkpoint mismatch"
    Assert-Condition ([string]$document.database_name -eq $DatabaseName) "C08-PRE-02 backup database mismatch"
    Assert-Condition ([string]$document.volume_name -eq $ExpectedVolume) "C08-PRE-02 backup volume mismatch"
    Assert-Condition ([string]$document.database_revision -eq $ExpectedRevision) "C08-PRE-02 backup revision mismatch"
    Assert-Condition ([string]$document.backup_sha256 -cmatch '^[0-9a-f]{64}$') "C08-PRE-02 backup hash format was invalid"
    Assert-Condition ($createdAt.Offset -eq [TimeSpan]::Zero) "C08-PRE-02 backup creation time must be UTC"
    $age = $NowUtc - $createdAt
    Assert-Condition (
        $age -ge [TimeSpan]::FromMinutes(-5) -and $age -le $MaximumBackupAge
    ) "C08-PRE-02 backup evidence is stale or future-dated"

    $artifactPath = Get-CanonicalRegularFile -PathValue ([string]$document.backup_artifact_path) -AllowedExtensions $AllowedBackupExtensions -RequireNonEmpty
    Assert-Condition (
        -not (Test-PathInsideParent -Candidate $artifactPath -Parent $ResolvedRepositoryRoot)
    ) "C08-PRE-02 backup artifact must be outside the repository"
    $artifactItem = Get-Item -LiteralPath $artifactPath -Force -ErrorAction Stop
    $artifactLastWrite = [DateTimeOffset]::new($artifactItem.LastWriteTimeUtc)
    $artifactAge = $NowUtc - $artifactLastWrite
    Assert-Condition (
        $artifactAge -ge [TimeSpan]::FromMinutes(-5) -and
        $artifactAge -le $MaximumBackupAge -and
        $artifactLastWrite -le $createdAt.AddMinutes(5)
    ) "C08-PRE-02 backup artifact is stale or future-dated"
    $artifactLength = $artifactItem.Length
    $actualHash = (Get-FileHash -LiteralPath $artifactPath -Algorithm SHA256).Hash.ToLowerInvariant()
    $postHashItem = Get-Item -LiteralPath $artifactPath -Force -ErrorAction Stop
    Assert-Condition (
        -not ($postHashItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -and
        -not ($postHashItem.Attributes -band [System.IO.FileAttributes]::Directory) -and
        $postHashItem.Length -eq $artifactLength -and
        $postHashItem.LastWriteTimeUtc -eq $artifactItem.LastWriteTimeUtc
    ) "C08-PRE-02 backup artifact changed during verification"
    Assert-Condition ($actualHash -ceq [string]$document.backup_sha256) "C08-PRE-02 backup artifact hash mismatch"

    return [pscustomobject]@{
        EvidenceFileSha256 = (Get-FileHash -LiteralPath $resolvedEvidence -Algorithm SHA256).Hash.ToLowerInvariant()
        BackupArtifactPath = $artifactPath
        BackupSha256 = $actualHash
        BackupSizeBytes = $artifactLength
        BackupLastWriteUtc = $artifactLastWrite.ToUniversalTime().ToString("o")
        CreatedAtUtc = $createdAt.ToUniversalTime().ToString("o")
        MaintenanceSessionId = $ExpectedSessionId
        GitCheckpoint = $checkpoint
        DatabaseRevision = $ExpectedRevision
    }
}

function Get-EvidenceValue {
    param(
        [Parameter(Mandatory = $true)][System.Collections.IDictionary]$Evidence,
        [Parameter(Mandatory = $true)][string]$Key
    )
    if (-not $Evidence.Contains($Key)) { return $null }
    return $Evidence[$Key]
}

function Test-EvidenceText {
    param([System.Collections.IDictionary]$Evidence, [string]$Key, [string]$Expected)
    return [string](Get-EvidenceValue $Evidence $Key) -ceq $Expected
}

function Test-EvidenceBool {
    param([System.Collections.IDictionary]$Evidence, [string]$Key, [bool]$Expected)
    $actual = ([string](Get-EvidenceValue $Evidence $Key)).ToLowerInvariant()
    return $actual -eq $(if ($Expected) { "true" } else { "false" })
}

function Test-EvidenceInt {
    param([System.Collections.IDictionary]$Evidence, [string]$Key, [int]$Expected)
    return [string](Get-EvidenceValue $Evidence $Key) -eq [string]$Expected
}

function Get-RoleBoundaryState {
    param([Parameter(Mandatory = $true)][System.Collections.IDictionary]$Snapshot)

    $common = (
        (Test-EvidenceBool $Snapshot "app_role_exists" $true) -and
        (Test-EvidenceBool $Snapshot "app_role_can_login" $true) -and
        (Test-EvidenceBool $Snapshot "app_database_connect" $true) -and
        (Test-EvidenceBool $Snapshot "app_schema_usage" $true) -and
        (Test-EvidenceInt $Snapshot "managed_membership_count" 0) -and
        (Test-EvidenceInt $Snapshot "unexpected_owner_count" 0) -and
        (Test-EvidenceInt $Snapshot "public_table_count" 11) -and
        (Test-EvidenceInt $Snapshot "public_sequence_count" 9) -and
        (Test-EvidenceInt $Snapshot "expected_table_name_count" 11) -and
        (Test-EvidenceInt $Snapshot "expected_sequence_name_count" 9) -and
        (Test-EvidenceInt $Snapshot "unexpected_database_connect_grant_count" 0) -and
        (Test-EvidenceInt $Snapshot "migration_default_acl_count" 0)
    )
    if (-not $common) { return "unexpected" }

    $legacyApplication = (
        (Test-EvidenceBool $Snapshot "app_role_superuser" $true) -and
        (Test-EvidenceBool $Snapshot "app_role_createdb" $true) -and
        (Test-EvidenceBool $Snapshot "app_role_createrole" $true) -and
        (Test-EvidenceBool $Snapshot "app_role_bypassrls" $true)
    )
    $safeApplication = (
        (Test-EvidenceBool $Snapshot "app_role_superuser" $false) -and
        (Test-EvidenceBool $Snapshot "app_role_createdb" $false) -and
        (Test-EvidenceBool $Snapshot "app_role_createrole" $false) -and
        (Test-EvidenceBool $Snapshot "app_role_replication" $false) -and
        (Test-EvidenceBool $Snapshot "app_role_bypassrls" $false)
    )
    $dedicatedAbsent = (
        (Test-EvidenceBool $Snapshot "bootstrap_role_exists" $false) -and
        (Test-EvidenceBool $Snapshot "migration_role_exists" $false) -and
        (Test-EvidenceInt $Snapshot "auxiliary_role_count" 0) -and
        (Test-EvidenceInt $Snapshot "auxiliary_roles_safe_count" 0)
    )
    $dedicatedSafe = (
        (Test-EvidenceBool $Snapshot "bootstrap_role_exists" $true) -and
        (Test-EvidenceBool $Snapshot "bootstrap_role_is_oid_10" $false) -and
        (Test-EvidenceBool $Snapshot "bootstrap_role_can_login" $true) -and
        (Test-EvidenceBool $Snapshot "bootstrap_role_superuser" $true) -and
        (Test-EvidenceBool $Snapshot "bootstrap_role_createdb" $false) -and
        (Test-EvidenceBool $Snapshot "bootstrap_role_createrole" $false) -and
        (Test-EvidenceBool $Snapshot "bootstrap_role_replication" $false) -and
        (Test-EvidenceBool $Snapshot "bootstrap_role_bypassrls" $true) -and
        (Test-EvidenceBool $Snapshot "bootstrap_database_connect" $true) -and
        (Test-EvidenceBool $Snapshot "migration_role_exists" $true) -and
        (Test-EvidenceBool $Snapshot "migration_role_can_login" $true) -and
        (Test-EvidenceBool $Snapshot "migration_role_superuser" $false) -and
        (Test-EvidenceBool $Snapshot "migration_role_createdb" $false) -and
        (Test-EvidenceBool $Snapshot "migration_role_createrole" $false) -and
        (Test-EvidenceBool $Snapshot "migration_role_replication" $false) -and
        (Test-EvidenceBool $Snapshot "migration_role_bypassrls" $false) -and
        (Test-EvidenceInt $Snapshot "auxiliary_role_count" 3) -and
        (Test-EvidenceInt $Snapshot "auxiliary_roles_safe_count" 3) -and
        (Test-EvidenceBool $Snapshot "migration_connect" $true) -and
        (Test-EvidenceBool $Snapshot "migration_schema_usage" $true) -and
        (Test-EvidenceBool $Snapshot "migration_schema_create" $true) -and
        (Test-EvidenceInt $Snapshot "auxiliary_database_connect_count" 3) -and
        (Test-EvidenceInt $Snapshot "auxiliary_schema_usage_count" 3) -and
        (Test-EvidenceInt $Snapshot "auxiliary_schema_create_count" 0) -and
        (Test-EvidenceInt $Snapshot "auxiliary_no_sequence_privilege_count" 27)
    )
    $bootstrapCollision = (
        (Test-EvidenceInt $Snapshot "app_role_oid" 10) -and
        (Test-EvidenceBool $Snapshot "app_role_is_oid_10" $true) -and
        (Test-EvidenceBool $Snapshot "cluster_bootstrap_role_exists" $false) -and
        (Test-EvidenceInt $Snapshot "cluster_bootstrap_role_oid" 0) -and
        (Test-EvidenceBool $Snapshot "cluster_bootstrap_role_can_login" $false) -and
        (Test-EvidenceBool $Snapshot "cluster_bootstrap_role_superuser" $false) -and
        (Test-EvidenceInt $Snapshot "oid_10_role_count" 1) -and
        (Test-EvidenceText $Snapshot "oid_10_role_name" "alpha_data_user")
    )
    $splitIdentitySafe = (
        -not (Test-EvidenceInt $Snapshot "app_role_oid" 10) -and
        (Test-EvidenceBool $Snapshot "app_role_is_oid_10" $false) -and
        (Test-EvidenceBool $Snapshot "cluster_bootstrap_role_exists" $true) -and
        (Test-EvidenceInt $Snapshot "cluster_bootstrap_role_oid" 10) -and
        (Test-EvidenceBool $Snapshot "cluster_bootstrap_role_can_login" $false) -and
        (Test-EvidenceBool $Snapshot "cluster_bootstrap_role_superuser" $true) -and
        (Test-EvidenceInt $Snapshot "oid_10_role_count" 1) -and
        (Test-EvidenceText $Snapshot "oid_10_role_name" "alpha_data_cluster_bootstrap") -and
        (Test-EvidenceInt $Snapshot "cluster_bootstrap_owned_public_object_count" 0) -and
        (Test-EvidenceInt $Snapshot "cluster_bootstrap_explicit_connect_count" 0) -and
        (Test-EvidenceInt $Snapshot "cluster_bootstrap_explicit_object_acl_count" 0)
    )

    if (
        $legacyApplication -and $dedicatedAbsent -and $bootstrapCollision -and
        (Test-EvidenceText $Snapshot "database_owner" "alpha_data_user") -and
        (Test-EvidenceText $Snapshot "public_schema_owner" "pg_database_owner") -and
        (Test-EvidenceInt $Snapshot "app_owned_table_count" 11) -and
        (Test-EvidenceInt $Snapshot "app_owned_sequence_count" 9) -and
        (Test-EvidenceInt $Snapshot "migration_owned_table_count" 0) -and
        (Test-EvidenceInt $Snapshot "migration_owned_sequence_count" 0) -and
        (Test-EvidenceBool $Snapshot "public_database_connect" $true)
    ) { return "legacy_bootstrap_collision" }

    if (
        $legacyApplication -and $dedicatedSafe -and $bootstrapCollision -and
        (Test-EvidenceText $Snapshot "database_owner" "alpha_data_user") -and
        (Test-EvidenceText $Snapshot "public_schema_owner" "pg_database_owner") -and
        (Test-EvidenceInt $Snapshot "app_owned_table_count" 11) -and
        (Test-EvidenceInt $Snapshot "app_owned_sequence_count" 9) -and
        (Test-EvidenceInt $Snapshot "migration_owned_table_count" 0) -and
        (Test-EvidenceInt $Snapshot "migration_owned_sequence_count" 0) -and
        (Test-EvidenceInt $Snapshot "prepared_auxiliary_no_table_privilege_count" 33) -and
        (Test-EvidenceInt $Snapshot "prepared_migration_no_table_privilege_count" 11) -and
        (Test-EvidenceInt $Snapshot "prepared_migration_no_sequence_privilege_count" 9) -and
        (Test-EvidenceBool $Snapshot "public_database_connect" $true)
    ) { return "prepared_bootstrap_collision" }

    if (
        $safeApplication -and $dedicatedSafe -and $splitIdentitySafe -and
        (Test-EvidenceText $Snapshot "database_owner" "alpha_data_bootstrap") -and
        (Test-EvidenceText $Snapshot "public_schema_owner" "alpha_data_bootstrap") -and
        (Test-EvidenceInt $Snapshot "app_owned_table_count" 0) -and
        (Test-EvidenceInt $Snapshot "app_owned_sequence_count" 0) -and
        (Test-EvidenceInt $Snapshot "migration_owned_table_count" 11) -and
        (Test-EvidenceInt $Snapshot "migration_owned_sequence_count" 9) -and
        (Test-EvidenceBool $Snapshot "app_schema_create" $false) -and
        (Test-EvidenceBool $Snapshot "app_delete" $false) -and
        (Test-EvidenceBool $Snapshot "app_sequence_update" $false) -and
        (Test-EvidenceInt $Snapshot "app_table_privilege_shape_count" 11) -and
        (Test-EvidenceInt $Snapshot "app_sequence_privilege_shape_count" 9) -and
        (Test-EvidenceInt $Snapshot "readonly_table_privilege_shape_count" 11) -and
        (Test-EvidenceInt $Snapshot "backup_table_privilege_shape_count" 11) -and
        (Test-EvidenceInt $Snapshot "retention_table_privilege_shape_count" 11) -and
        (Test-EvidenceBool $Snapshot "public_database_connect" $false)
    ) { return "normalized" }

    return "unexpected"
}

function Get-RoleExecutionPlan {
    param([Parameter(Mandatory = $true)][ValidateSet("legacy_bootstrap_collision", "prepared_bootstrap_collision", "normalized", "unexpected")][string]$RoleState)

    switch ($RoleState) {
        "legacy_bootstrap_collision" { return [pscustomobject]@{ Prepare=$true; SetCredentials=$true; VerifyLogins=$true; RequireRuntimeCredential=$true; Normalize=$true; CorrectSyntheticProgress=$true } }
        "prepared_bootstrap_collision" { return [pscustomobject]@{ Prepare=$false; SetCredentials=$true; VerifyLogins=$true; RequireRuntimeCredential=$true; Normalize=$true; CorrectSyntheticProgress=$true } }
        "normalized" { return [pscustomobject]@{ Prepare=$false; SetCredentials=$false; VerifyLogins=$true; RequireRuntimeCredential=$false; Normalize=$false; CorrectSyntheticProgress=$true } }
        default { throw "C08-PRE-02 role boundary state is unexpected" }
    }
}

function Assert-ApplyConfirmation {
    param([Parameter(Mandatory = $true)][string]$Confirmation)
    Assert-Condition ($Confirmation -ceq "APPLY C08-PRE-02") "C08-PRE-02 exact interactive confirmation is required"
    return $true
}

function Assert-ApplyInvocation {
    param(
        [Parameter(Mandatory = $true)][ValidateSet("Preflight", "Apply")][string]$SelectedMode,
        [Parameter(Mandatory = $true)][bool]$ModeWasExplicit,
        [Parameter(Mandatory = $true)][bool]$CheckpointWasExplicit
    )
    if ($SelectedMode -eq "Apply") {
        Assert-Condition $ModeWasExplicit "C08-PRE-02 Apply requires explicit Mode"
        Assert-Condition $CheckpointWasExplicit "C08-PRE-02 Apply requires explicit ExpectedGitCheckpoint"
    }
    return $true
}

function Read-ReconciliationCredentials {
    param(
        [bool]$IncludeRuntimeCredential = $false,
        [scriptblock]$PromptProvider
    )

    $bootstrap = $null
    $migration = $null
    $runtime = $null
    try {
        if ($null -eq $PromptProvider) {
            if ($IncludeRuntimeCredential) {
                $runtime = Read-Host "Enter current alpha_data_user credential for replacement role" -AsSecureString
            }
            $bootstrap = Read-Host "Enter alpha_data_bootstrap credential" -AsSecureString
            $migration = Read-Host "Enter alpha_data_migration credential" -AsSecureString
        }
        else {
            if ($IncludeRuntimeCredential) {
                $runtime = & $PromptProvider "Enter current alpha_data_user credential for replacement role"
            }
            $bootstrap = & $PromptProvider "Enter alpha_data_bootstrap credential"
            $migration = & $PromptProvider "Enter alpha_data_migration credential"
        }
        if ($IncludeRuntimeCredential) {
            Assert-Condition ($runtime -is [System.Security.SecureString]) "C08-PRE-02 runtime prompt did not return SecureString"
            Assert-Condition ($runtime.Length -gt 0) "C08-PRE-02 runtime credential must not be empty"
        }
        Assert-Condition ($bootstrap -is [System.Security.SecureString]) "C08-PRE-02 bootstrap prompt did not return SecureString"
        Assert-Condition ($migration -is [System.Security.SecureString]) "C08-PRE-02 migration prompt did not return SecureString"
        Assert-Condition ($bootstrap.Length -gt 0) "C08-PRE-02 bootstrap credential must not be empty"
        Assert-Condition ($migration.Length -gt 0) "C08-PRE-02 migration credential must not be empty"
        return [pscustomobject]@{ Runtime=$runtime; Bootstrap=$bootstrap; Migration=$migration }
    }
    catch {
        if ($runtime -is [System.Security.SecureString]) { $runtime.Dispose() }
        if ($bootstrap -is [System.Security.SecureString]) { $bootstrap.Dispose() }
        if ($migration -is [System.Security.SecureString]) { $migration.Dispose() }
        $runtime = $null
        $bootstrap = $null
        $migration = $null
        throw
    }
}

function Invoke-WithSecureStringPlaintext {
    param(
        [Parameter(Mandatory = $true)][System.Security.SecureString]$SecureValue,
        [Parameter(Mandatory = $true)][scriptblock]$Operation
    )

    [IntPtr]$buffer = [IntPtr]::Zero
    $plainText = $null
    try {
        $buffer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecureValue)
        $plainText = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($buffer)
        return & $Operation $plainText
    }
    finally {
        $plainText = $null
        if ($buffer -ne [IntPtr]::Zero) {
            [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($buffer)
            $buffer = [IntPtr]::Zero
        }
    }
}

function Initialize-RunState {
    $script:GateResults = [System.Collections.Generic.List[object]]::new()
    $script:CommandResults = [System.Collections.Generic.List[object]]::new()
    $script:DatabaseEvidence = [ordered]@{}
    $script:SqlHashEvidence = [ordered]@{}
    $script:BackupEvidence = [ordered]@{}
    $script:RoleStateEvidence = $null
    $script:ReviewedGitCheckpoint = $null
    $script:FinalResult = "incomplete"
    $script:SanitizedFailure = $null
    $script:ResolvedEvidenceDirectory = $null
    $script:StartedAtUtc = [DateTimeOffset]::UtcNow
}

function Add-GateResult {
    param([string]$Name, [bool]$Passed, [string]$SafeDetail)
    $script:GateResults.Add([ordered]@{ name=$Name; passed=$Passed; detail=$SafeDetail })
}

function Assert-Gate {
    param([string]$Name, [bool]$Condition, [string]$SafeDetail)
    Add-GateResult -Name $Name -Passed $Condition -SafeDetail $SafeDetail
    Assert-Condition $Condition "C08-PRE-02 gate failed: $Name"
}

function Invoke-SafeProcess {
    param(
        [Parameter(Mandatory = $true)][string]$FileName,
        [Parameter(Mandatory = $true)][string[]]$ArgumentList,
        [string]$WorkingDirectory = "",
        [AllowEmptyString()][string]$StandardInputText = ""
    )

    $startInfo = [System.Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = $FileName
    $startInfo.UseShellExecute = $false
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    $startInfo.RedirectStandardInput = $true
    $startInfo.StandardInputEncoding = [System.Text.UTF8Encoding]::new($false)
    $startInfo.CreateNoWindow = $true
    if ($WorkingDirectory) { $startInfo.WorkingDirectory = $WorkingDirectory }
    foreach ($argument in $ArgumentList) { [void]$startInfo.ArgumentList.Add($argument) }

    $process = [System.Diagnostics.Process]::new()
    $process.StartInfo = $startInfo
    try {
        Assert-Condition ($process.Start()) "C08-PRE-02 process start failed"
        if ($StandardInputText.Length -gt 0) { $process.StandardInput.Write($StandardInputText) }
        $process.StandardInput.Close()
        $stdout = $process.StandardOutput.ReadToEnd()
        $stderr = $process.StandardError.ReadToEnd()
        $process.WaitForExit()
        $exitCode = $process.ExitCode
    }
    finally {
        $StandardInputText = $null
        $process.Dispose()
    }
    if ($null -ne $script:CommandResults) {
        $script:CommandResults.Add([ordered]@{
            executable=[System.IO.Path]::GetFileName($FileName)
            exit_code=$exitCode
        })
    }
    Assert-Condition ($exitCode -eq 0) "C08-PRE-02 external command failed"
    return [pscustomobject]@{
        ExitCode=$exitCode
        Stdout=$stdout.Trim()
        StderrPresent=-not [string]::IsNullOrWhiteSpace($stderr)
    }
}

function Invoke-Git {
    param([Parameter(Mandatory = $true)][string[]]$Arguments)
    return Invoke-SafeProcess -FileName "git" -ArgumentList $Arguments -WorkingDirectory $script:ResolvedRepositoryRoot
}

function Assert-RepositoryState {
    param([Parameter(Mandatory = $true)][string]$ReviewedCheckpoint)

    $branch = (Invoke-Git @("branch", "--show-current")).Stdout
    $head = (Invoke-Git @("rev-parse", "HEAD")).Stdout
    $originHead = (Invoke-Git @("rev-parse", "origin/dev")).Stdout
    $divergence = ((Invoke-Git @("rev-list", "--left-right", "--count", "origin/dev...HEAD")).Stdout -replace '\s+', ' ').Trim()
    $staged = (Invoke-Git @("diff", "--cached", "--name-only")).Stdout
    $tracked = (Invoke-Git @("diff", "--name-only")).Stdout
    $status = (Invoke-Git @("status", "--short", "--untracked-files=all")).Stdout
    Assert-Gate "git_branch" ($branch -eq $FrozenBranch) "Branch must remain dev."
    Assert-Gate "git_head" ($head -ceq $ReviewedCheckpoint) "HEAD must match reviewed checkpoint."
    Assert-Gate "git_origin_head" ($originHead -ceq $ReviewedCheckpoint) "origin/dev must match reviewed checkpoint."
    Assert-Gate "git_divergence" ($divergence -eq "0 0") "Git divergence must be zero."
    Assert-Gate "git_staged_clean" ([string]::IsNullOrWhiteSpace($staged)) "No staged files are allowed."
    Assert-Gate "git_tracked_clean" ([string]::IsNullOrWhiteSpace($tracked)) "No tracked modifications are allowed."
    Assert-Gate "git_untracked_clean" ([string]::IsNullOrWhiteSpace($status)) "No untracked files are allowed."
}

function Convert-KeyValueOutput {
    param([Parameter(Mandatory = $true)][string]$TextValue)
    $result = [ordered]@{}
    foreach ($line in ($TextValue -split "`r?`n")) {
        if ([string]::IsNullOrWhiteSpace($line) -or -not $line.Contains("=")) { continue }
        $parts = $line.Split("=", 2)
        $key = $parts[0].Trim()
        Assert-Condition ($key -match '^[a-z0-9_]+$') "C08-PRE-02 database evidence key was invalid"
        $result[$key] = $parts[1].Trim()
    }
    return $result
}

function Invoke-DatabaseQuery {
    param([Parameter(Mandatory = $true)][string]$Sql)
    $arguments = @(
        "compose", "exec", "-T", $DatabaseService,
        "psql", "--no-psqlrc", "--username", $InitialDatabaseIdentity,
        "--dbname", $DatabaseName, "--tuples-only", "--no-align",
        "--set", "ON_ERROR_STOP=1", "--command", $Sql
    )
    $result = Invoke-SafeProcess -FileName "docker" -ArgumentList $arguments -WorkingDirectory $script:ResolvedRepositoryRoot
    return Convert-KeyValueOutput -TextValue $result.Stdout
}

function Invoke-ReviewedSqlArtifact {
    param(
        [Parameter(Mandatory = $true)]$Artifact,
        [ValidateSet("prepare", "normalize", "correction")][string]$Phase,
        [System.Security.SecureString]$RuntimeCredential
    )
    $executionIdentity = if ($Phase -eq "normalize") { "alpha_data_bootstrap" } else { $InitialDatabaseIdentity }
    $arguments = @(
        "compose", "exec", "-T", $DatabaseService,
        "psql", "--no-psqlrc", "--username", $executionIdentity,
        "--dbname", $DatabaseName, "--set", "ON_ERROR_STOP=1"
    )
    if ($Phase -in @("prepare", "normalize")) {
        $arguments += @("--set", "c08_phase=$Phase")
    }
    $arguments += "--file=-"
    if ($Phase -ne "normalize") {
        Assert-Condition ($null -eq $RuntimeCredential) "C08-PRE-02 runtime credential is valid only for Normalize"
        [void](Invoke-SafeProcess -FileName "docker" -ArgumentList $arguments -WorkingDirectory $script:ResolvedRepositoryRoot -StandardInputText $Artifact.Text)
        return
    }

    Assert-Condition ($RuntimeCredential -is [System.Security.SecureString]) "C08-PRE-02 Normalize requires a SecureString runtime credential"
    Invoke-WithSecureStringPlaintext -SecureValue $RuntimeCredential -Operation {
        param($plainText)
        Assert-Condition (
            -not $plainText.Contains("`r") -and -not $plainText.Contains("`n")
        ) "C08-PRE-02 runtime credential contained an unsupported line break"
        $markerMatches = [regex]::Matches(
            $Artifact.Text,
            '(?m)^\\password alpha_data_user(?<eol>\r?\n)'
        )
        Assert-Condition ($markerMatches.Count -eq 1) "C08-PRE-02 reviewed Normalize credential marker mismatch"
        $inputText = $null
        try {
            $marker = $markerMatches[0]
            $lineEnding = $marker.Groups["eol"].Value
            $insertAt = $marker.Index + $marker.Length
            $inputText = $Artifact.Text.Insert(
                $insertAt,
                "$plainText$lineEnding$plainText$lineEnding"
            )
            [void](Invoke-SafeProcess -FileName "docker" -ArgumentList $arguments -WorkingDirectory $script:ResolvedRepositoryRoot -StandardInputText $inputText)
        }
        finally {
            $inputText = $null
            $plainText = $null
        }
    }
}

function Set-ProtectedRoleCredential {
    param(
        [Parameter(Mandatory = $true)][ValidateSet("alpha_data_bootstrap", "alpha_data_migration")][string]$RoleName,
        [Parameter(Mandatory = $true)][System.Security.SecureString]$Credential
    )
    Invoke-WithSecureStringPlaintext -SecureValue $Credential -Operation {
        param($plainText)
        $arguments = @(
            "compose", "exec", "-T", $DatabaseService,
            "psql", "--no-psqlrc", "--username", $InitialDatabaseIdentity,
            "--dbname", $DatabaseName, "--set", "ON_ERROR_STOP=1",
            "--command", "\password $RoleName"
        )
        [void](Invoke-SafeProcess -FileName "docker" -ArgumentList $arguments -WorkingDirectory $script:ResolvedRepositoryRoot -StandardInputText "$plainText`n$plainText`n")
    }
}

function Test-ProtectedRoleLogin {
    param(
        [Parameter(Mandatory = $true)][ValidateSet("alpha_data_bootstrap", "alpha_data_migration")][string]$RoleName,
        [Parameter(Mandatory = $true)][System.Security.SecureString]$Credential
    )
    $verificationSql = if ($RoleName -eq "alpha_data_migration") {
        "SELECT 'migration_capability=' || (current_user = 'alpha_data_migration' AND has_database_privilege(current_user, current_database(), 'CONNECT') AND has_schema_privilege(current_user, 'public', 'USAGE') AND has_schema_privilege(current_user, 'public', 'CREATE'))::text;"
    } else {
        "SELECT 'bootstrap_login=' || (current_user = 'alpha_data_bootstrap')::text;"
    }
    return Invoke-WithSecureStringPlaintext -SecureValue $Credential -Operation {
        param($plainText)
        $arguments = @(
            "compose", "exec", "-T", $DatabaseService,
            "psql", "--no-psqlrc", "--host", "127.0.0.1", "--port", "5432",
            "--username", $RoleName, "--dbname", $DatabaseName, "--password",
            "--tuples-only", "--no-align", "--set", "ON_ERROR_STOP=1",
            "--command", $verificationSql
        )
        $result = Invoke-SafeProcess -FileName "docker" -ArgumentList $arguments -WorkingDirectory $script:ResolvedRepositoryRoot -StandardInputText "$plainText`n"
        if ($RoleName -eq "alpha_data_migration") { return $result.Stdout -eq "migration_capability=true" }
        return $result.Stdout -eq "bootstrap_login=true"
    }
}

function Assert-ExactPreservedDataSnapshot {
    param([Parameter(Mandatory = $true)][System.Collections.IDictionary]$Snapshot)
    Assert-Gate "database_revision_row_count" (Test-EvidenceInt $Snapshot "revision_row_count" 1) "Exactly one revision row is required."
    Assert-Gate "database_revision_exact" (Test-EvidenceText $Snapshot "current_revision" $FrozenDatabaseRevision) "Revision must remain frozen."
    Assert-Gate "source_total_exact" (Test-EvidenceInt $Snapshot "source_total" 4) "Source total must remain four."
    Assert-Gate "target_count_exact" (Test-EvidenceInt $Snapshot "target_count" 4) "Exactly four targets are required."
    Assert-Gate "target_checkpoint_shape_exact" (Test-EvidenceInt $Snapshot "target_checkpoint_hash_count" 4) "Target checkpoints must match reviewed hash."
    Assert-Gate "target_timestamp_exact" (Test-EvidenceInt $Snapshot "target_null_timestamp_count" 4) "Target timestamps must remain null."
    Assert-Gate "target_runs_absent" (Test-EvidenceInt $Snapshot "target_run_count" 0) "Target runs must remain absent."
    Assert-Gate "target_success_absent" (Test-EvidenceInt $Snapshot "target_success_count" 0) "Target successful runs must remain absent."
    Assert-Gate "target_running_absent" (Test-EvidenceInt $Snapshot "target_running_count" 0) "Target running runs must remain absent."
    Assert-Gate "target_correlation_absent" (Test-EvidenceInt $Snapshot "target_correlation_count" 0) "Target correlation must remain absent."
    Assert-Gate "extra_correction_shape_absent" (Test-EvidenceInt $Snapshot "extra_shape_count" 0) "No non-target correction shape is allowed."
    Assert-Gate "target_enablement_unchanged" (Test-EvidenceInt $Snapshot "target_enabled_count" 4) "Target enablement must remain frozen."
    Assert-Gate "official_source_boundary_safe" (Test-EvidenceInt $Snapshot "official_unsafe_count" 0) "Official source boundary must remain safe."
    Assert-Gate "c06_schema_absent" (Test-EvidenceInt $Snapshot "c06_table_count" 0) "C06 schema must remain absent."
    Assert-Gate "c07_schema_absent" (Test-EvidenceInt $Snapshot "c07_operator_column_count" 0) "C07 operator state must remain absent."
}

function Write-SanitizedEvidence {
    if ($null -eq $script:ResolvedEvidenceDirectory) { return }
    if (-not (Test-Path -LiteralPath $script:ResolvedEvidenceDirectory)) {
        [void](New-Item -ItemType Directory -Path $script:ResolvedEvidenceDirectory)
    }
    $timestamp = [DateTimeOffset]::UtcNow.ToString("yyyyMMddTHHmmssZ")
    $evidencePath = Join-Path $script:ResolvedEvidenceDirectory "c08-pre02-$($Mode.ToLowerInvariant())-$timestamp.json"
    [ordered]@{
        timestamp_utc=[DateTimeOffset]::UtcNow.ToString("o")
        task_id=$TaskId
        mode=$Mode
        git_checkpoint=$script:ReviewedGitCheckpoint
        database_revision=$FrozenDatabaseRevision
        role_boundary_state=$script:RoleStateEvidence
        database_evidence=$script:DatabaseEvidence
        sql_file_hashes=$script:SqlHashEvidence
        backup_evidence=$script:BackupEvidence
        gates=$script:GateResults
        command_exit_statuses=$script:CommandResults
        final_result=$script:FinalResult
        sanitized_error=$script:SanitizedFailure
    } | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $evidencePath -Encoding utf8NoBOM
    Write-Host "Sanitized evidence written: $evidencePath"
}

$DatabaseSnapshotSql = @'
WITH target_slugs(slug) AS (
    VALUES ('alpha-synthetic-cve'), ('alpha-synthetic-advisories'),
           ('alpha-synthetic-news'), ('alpha-synthetic-uae')
), official_slugs(slug) AS (
    VALUES ('mitre-attack-enterprise'), ('cert-fr-security-alerts'),
           ('cert-fr-security-advisories'), ('uk-ncsc-threat-reports')
), target_rows AS (
    SELECT source.* FROM public.intelligence_sources AS source
    JOIN target_slugs ON target_slugs.slug = source.slug
), application_tables(name) AS (
    VALUES ('ingestion_errors'), ('ingestion_run_records'), ('ingestion_runs'),
           ('intelligence_item_identifiers'), ('intelligence_item_tags'),
           ('intelligence_items'), ('intelligence_sources'), ('source_records'),
           ('tags'), ('vulnerabilities')
), expected_tables(name) AS (
    VALUES ('alembic_version'), ('ingestion_errors'), ('ingestion_run_records'),
           ('ingestion_runs'), ('intelligence_item_identifiers'),
           ('intelligence_item_tags'), ('intelligence_items'),
           ('intelligence_sources'), ('source_records'), ('tags'), ('vulnerabilities')
), expected_sequences(name) AS (
    VALUES ('ingestion_errors_id_seq'), ('ingestion_run_records_id_seq'),
           ('ingestion_runs_id_seq'), ('intelligence_item_identifiers_id_seq'),
           ('intelligence_items_id_seq'), ('intelligence_sources_id_seq'),
           ('source_records_id_seq'), ('tags_id_seq'), ('vulnerabilities_id_seq')
), runtime_update_tables(name) AS (
    VALUES ('ingestion_runs'), ('intelligence_items'), ('intelligence_sources'),
           ('source_records'), ('vulnerabilities')
), retention_tables(name) AS (
    VALUES ('ingestion_errors'), ('ingestion_run_records'), ('ingestion_runs')
)
SELECT 'revision_row_count=' || count(*)::text FROM public.alembic_version
UNION ALL SELECT 'current_revision=' || coalesce(min(version_num), 'missing') FROM public.alembic_version
UNION ALL SELECT 'source_total=' || count(*)::text FROM public.intelligence_sources
UNION ALL SELECT 'target_count=' || count(*)::text FROM target_rows
UNION ALL SELECT 'target_checkpoint_hash_count=' || count(*)::text FROM target_rows WHERE checkpoint_value IS NOT NULL AND encode(sha256(convert_to(checkpoint_value, 'UTF8')), 'hex') = '1c4f57ad3b27a40b2157dd0fade25a74363f889b8a1972702e2eb9570c2c9fa4'
UNION ALL SELECT 'target_null_timestamp_count=' || count(*)::text FROM target_rows WHERE last_successful_fetch_at IS NULL
UNION ALL SELECT 'target_enabled_count=' || count(*)::text FROM target_rows WHERE is_enabled
UNION ALL SELECT 'target_run_count=' || count(run.id)::text FROM target_rows AS source LEFT JOIN public.ingestion_runs AS run ON run.source_id = source.id
UNION ALL SELECT 'target_success_count=' || count(run.id)::text FROM target_rows AS source LEFT JOIN public.ingestion_runs AS run ON run.source_id = source.id AND run.status IN ('success', 'succeeded')
UNION ALL SELECT 'target_running_count=' || count(run.id)::text FROM target_rows AS source LEFT JOIN public.ingestion_runs AS run ON run.source_id = source.id AND run.status = 'running'
UNION ALL SELECT 'target_correlation_count=' || count(run.id)::text FROM target_rows AS source LEFT JOIN public.ingestion_runs AS run ON run.source_id = source.id AND run.status IN ('success', 'succeeded') AND run.completed_at = source.last_successful_fetch_at AND run.checkpoint_after = source.checkpoint_value
UNION ALL SELECT 'target_fingerprints=' || coalesce(string_agg(encode(sha256(convert_to(id::text, 'UTF8')), 'hex'), ',' ORDER BY slug), 'none') FROM target_rows
UNION ALL SELECT 'extra_shape_count=' || count(*)::text FROM public.intelligence_sources AS source WHERE NOT EXISTS (SELECT 1 FROM target_slugs WHERE target_slugs.slug = source.slug) AND source.checkpoint_value IS NOT NULL AND source.last_successful_fetch_at IS NULL AND NOT EXISTS (SELECT 1 FROM public.ingestion_runs AS run WHERE run.source_id = source.id)
UNION ALL SELECT 'official_unsafe_count=' || count(*)::text FROM public.intelligence_sources AS source JOIN official_slugs ON official_slugs.slug = source.slug WHERE source.is_enabled OR EXISTS (SELECT 1 FROM public.ingestion_runs AS run WHERE run.source_id = source.id AND run.status = 'running')
UNION ALL SELECT 'c06_table_count=' || count(*)::text FROM (VALUES ('auth_users'), ('auth_identities'), ('auth_local_credentials'), ('auth_user_roles'), ('auth_sessions'), ('auth_login_throttles')) AS expected(name) WHERE to_regclass('public.' || expected.name) IS NOT NULL
UNION ALL SELECT 'c07_operator_column_count=' || count(*)::text FROM information_schema.columns WHERE table_schema = 'public' AND table_name = 'intelligence_sources' AND column_name = 'operator_state'
UNION ALL SELECT 'database_owner=' || pg_get_userbyid(datdba) FROM pg_database WHERE datname = current_database()
UNION ALL SELECT 'public_schema_owner=' || pg_get_userbyid(nspowner) FROM pg_namespace WHERE nspname = 'public'
UNION ALL SELECT 'app_role_exists=' || EXISTS(SELECT 1 FROM pg_roles WHERE rolname = 'alpha_data_user')::text
UNION ALL SELECT 'app_role_oid=' || coalesce((SELECT oid::text FROM pg_roles WHERE rolname = 'alpha_data_user'), '0')
UNION ALL SELECT 'app_role_is_oid_10=' || coalesce((SELECT oid = 10 FROM pg_roles WHERE rolname = 'alpha_data_user'), false)::text
UNION ALL SELECT 'app_role_can_login=' || coalesce((SELECT rolcanlogin FROM pg_roles WHERE rolname = 'alpha_data_user'), false)::text
UNION ALL SELECT 'app_role_superuser=' || coalesce((SELECT rolsuper FROM pg_roles WHERE rolname = 'alpha_data_user'), false)::text
UNION ALL SELECT 'app_role_createdb=' || coalesce((SELECT rolcreatedb FROM pg_roles WHERE rolname = 'alpha_data_user'), false)::text
UNION ALL SELECT 'app_role_createrole=' || coalesce((SELECT rolcreaterole FROM pg_roles WHERE rolname = 'alpha_data_user'), false)::text
UNION ALL SELECT 'app_role_replication=' || coalesce((SELECT rolreplication FROM pg_roles WHERE rolname = 'alpha_data_user'), false)::text
UNION ALL SELECT 'app_role_bypassrls=' || coalesce((SELECT rolbypassrls FROM pg_roles WHERE rolname = 'alpha_data_user'), false)::text
UNION ALL SELECT 'bootstrap_role_exists=' || EXISTS(SELECT 1 FROM pg_roles WHERE rolname = 'alpha_data_bootstrap')::text
UNION ALL SELECT 'bootstrap_role_oid=' || coalesce((SELECT oid::text FROM pg_roles WHERE rolname = 'alpha_data_bootstrap'), '0')
UNION ALL SELECT 'bootstrap_role_is_oid_10=' || coalesce((SELECT oid = 10 FROM pg_roles WHERE rolname = 'alpha_data_bootstrap'), false)::text
UNION ALL SELECT 'bootstrap_role_can_login=' || coalesce((SELECT rolcanlogin FROM pg_roles WHERE rolname = 'alpha_data_bootstrap'), false)::text
UNION ALL SELECT 'bootstrap_role_superuser=' || coalesce((SELECT rolsuper FROM pg_roles WHERE rolname = 'alpha_data_bootstrap'), false)::text
UNION ALL SELECT 'bootstrap_role_createdb=' || coalesce((SELECT rolcreatedb FROM pg_roles WHERE rolname = 'alpha_data_bootstrap'), false)::text
UNION ALL SELECT 'bootstrap_role_createrole=' || coalesce((SELECT rolcreaterole FROM pg_roles WHERE rolname = 'alpha_data_bootstrap'), false)::text
UNION ALL SELECT 'bootstrap_role_replication=' || coalesce((SELECT rolreplication FROM pg_roles WHERE rolname = 'alpha_data_bootstrap'), false)::text
UNION ALL SELECT 'bootstrap_role_bypassrls=' || coalesce((SELECT rolbypassrls FROM pg_roles WHERE rolname = 'alpha_data_bootstrap'), false)::text
UNION ALL SELECT 'cluster_bootstrap_role_exists=' || EXISTS(SELECT 1 FROM pg_roles WHERE rolname = 'alpha_data_cluster_bootstrap')::text
UNION ALL SELECT 'cluster_bootstrap_role_oid=' || coalesce((SELECT oid::text FROM pg_roles WHERE rolname = 'alpha_data_cluster_bootstrap'), '0')
UNION ALL SELECT 'cluster_bootstrap_role_can_login=' || coalesce((SELECT rolcanlogin FROM pg_roles WHERE rolname = 'alpha_data_cluster_bootstrap'), false)::text
UNION ALL SELECT 'cluster_bootstrap_role_superuser=' || coalesce((SELECT rolsuper FROM pg_roles WHERE rolname = 'alpha_data_cluster_bootstrap'), false)::text
UNION ALL SELECT 'oid_10_role_count=' || count(*)::text FROM pg_roles WHERE oid = 10
UNION ALL SELECT 'oid_10_role_name=' || coalesce((SELECT rolname FROM pg_roles WHERE oid = 10), 'missing')
UNION ALL SELECT 'migration_role_exists=' || EXISTS(SELECT 1 FROM pg_roles WHERE rolname = 'alpha_data_migration')::text
UNION ALL SELECT 'migration_role_can_login=' || coalesce((SELECT rolcanlogin FROM pg_roles WHERE rolname = 'alpha_data_migration'), false)::text
UNION ALL SELECT 'migration_role_superuser=' || coalesce((SELECT rolsuper FROM pg_roles WHERE rolname = 'alpha_data_migration'), false)::text
UNION ALL SELECT 'migration_role_createdb=' || coalesce((SELECT rolcreatedb FROM pg_roles WHERE rolname = 'alpha_data_migration'), false)::text
UNION ALL SELECT 'migration_role_createrole=' || coalesce((SELECT rolcreaterole FROM pg_roles WHERE rolname = 'alpha_data_migration'), false)::text
UNION ALL SELECT 'migration_role_replication=' || coalesce((SELECT rolreplication FROM pg_roles WHERE rolname = 'alpha_data_migration'), false)::text
UNION ALL SELECT 'migration_role_bypassrls=' || coalesce((SELECT rolbypassrls FROM pg_roles WHERE rolname = 'alpha_data_migration'), false)::text
UNION ALL SELECT 'auxiliary_role_count=' || count(*)::text FROM pg_roles WHERE rolname IN ('alpha_data_readonly', 'alpha_data_backup', 'alpha_data_retention')
UNION ALL SELECT 'auxiliary_roles_safe_count=' || count(*)::text FROM pg_roles AS role WHERE role.rolname IN ('alpha_data_readonly', 'alpha_data_backup', 'alpha_data_retention') AND NOT role.rolcanlogin AND NOT role.rolsuper AND NOT role.rolcreatedb AND NOT role.rolcreaterole AND NOT role.rolreplication AND NOT role.rolbypassrls
UNION ALL SELECT 'managed_membership_count=' || count(*)::text FROM pg_auth_members AS membership JOIN pg_roles AS granted_role ON granted_role.oid = membership.roleid JOIN pg_roles AS member_role ON member_role.oid = membership.member WHERE granted_role.rolname LIKE 'alpha_data_%' OR member_role.rolname LIKE 'alpha_data_%'
UNION ALL SELECT 'public_table_count=' || count(*)::text FROM pg_class AS object JOIN pg_namespace AS namespace ON namespace.oid = object.relnamespace WHERE namespace.nspname = 'public' AND object.relkind IN ('r', 'p')
UNION ALL SELECT 'public_sequence_count=' || count(*)::text FROM pg_class AS object JOIN pg_namespace AS namespace ON namespace.oid = object.relnamespace WHERE namespace.nspname = 'public' AND object.relkind = 'S'
UNION ALL SELECT 'expected_table_name_count=' || count(*)::text FROM pg_class AS object JOIN pg_namespace AS namespace ON namespace.oid = object.relnamespace JOIN expected_tables ON expected_tables.name = object.relname WHERE namespace.nspname = 'public' AND object.relkind IN ('r', 'p')
UNION ALL SELECT 'expected_sequence_name_count=' || count(*)::text FROM pg_class AS object JOIN pg_namespace AS namespace ON namespace.oid = object.relnamespace JOIN expected_sequences ON expected_sequences.name = object.relname WHERE namespace.nspname = 'public' AND object.relkind = 'S'
UNION ALL SELECT 'app_owned_table_count=' || count(*)::text FROM pg_class AS object JOIN pg_namespace AS namespace ON namespace.oid = object.relnamespace JOIN pg_roles AS owner_role ON owner_role.oid = object.relowner WHERE namespace.nspname = 'public' AND object.relkind IN ('r', 'p') AND owner_role.rolname = 'alpha_data_user'
UNION ALL SELECT 'app_owned_sequence_count=' || count(*)::text FROM pg_class AS object JOIN pg_namespace AS namespace ON namespace.oid = object.relnamespace JOIN pg_roles AS owner_role ON owner_role.oid = object.relowner WHERE namespace.nspname = 'public' AND object.relkind = 'S' AND owner_role.rolname = 'alpha_data_user'
UNION ALL SELECT 'migration_owned_table_count=' || count(*)::text FROM pg_class AS object JOIN pg_namespace AS namespace ON namespace.oid = object.relnamespace JOIN pg_roles AS owner_role ON owner_role.oid = object.relowner WHERE namespace.nspname = 'public' AND object.relkind IN ('r', 'p') AND owner_role.rolname = 'alpha_data_migration'
UNION ALL SELECT 'migration_owned_sequence_count=' || count(*)::text FROM pg_class AS object JOIN pg_namespace AS namespace ON namespace.oid = object.relnamespace JOIN pg_roles AS owner_role ON owner_role.oid = object.relowner WHERE namespace.nspname = 'public' AND object.relkind = 'S' AND owner_role.rolname = 'alpha_data_migration'
UNION ALL SELECT 'cluster_bootstrap_owned_public_object_count=' || count(*)::text FROM pg_class AS object JOIN pg_namespace AS namespace ON namespace.oid = object.relnamespace JOIN pg_roles AS owner_role ON owner_role.oid = object.relowner WHERE namespace.nspname = 'public' AND object.relkind IN ('r', 'p', 'S') AND owner_role.rolname = 'alpha_data_cluster_bootstrap'
UNION ALL SELECT 'unexpected_owner_count=' || count(*)::text FROM pg_class AS object JOIN pg_namespace AS namespace ON namespace.oid = object.relnamespace JOIN pg_roles AS owner_role ON owner_role.oid = object.relowner WHERE namespace.nspname = 'public' AND object.relkind IN ('r', 'p', 'S') AND owner_role.rolname NOT IN ('alpha_data_user', 'alpha_data_migration')
UNION ALL SELECT 'app_database_connect=' || has_database_privilege('alpha_data_user', current_database(), 'CONNECT')::text
UNION ALL SELECT 'app_schema_usage=' || has_schema_privilege('alpha_data_user', 'public', 'USAGE')::text
UNION ALL SELECT 'public_database_connect=' || EXISTS(SELECT 1 FROM pg_database AS database_record CROSS JOIN LATERAL aclexplode(coalesce(database_record.datacl, acldefault('d', database_record.datdba))) AS privilege_record WHERE database_record.datname = current_database() AND privilege_record.grantee = 0 AND privilege_record.privilege_type = 'CONNECT')::text
UNION ALL SELECT 'unexpected_database_connect_grant_count=' || count(*)::text FROM pg_database AS database_record CROSS JOIN LATERAL aclexplode(coalesce(database_record.datacl, acldefault('d', database_record.datdba))) AS privilege_record LEFT JOIN pg_roles AS grantee_role ON grantee_role.oid = privilege_record.grantee WHERE database_record.datname = current_database() AND privilege_record.privilege_type = 'CONNECT' AND privilege_record.grantee <> 0 AND grantee_role.rolname NOT IN ('alpha_data_user', 'alpha_data_bootstrap', 'alpha_data_migration', 'alpha_data_readonly', 'alpha_data_backup', 'alpha_data_retention')
UNION ALL SELECT 'cluster_bootstrap_explicit_connect_count=' || count(*)::text FROM pg_database AS database_record CROSS JOIN LATERAL aclexplode(coalesce(database_record.datacl, acldefault('d', database_record.datdba))) AS privilege_record JOIN pg_roles AS grantee_role ON grantee_role.oid = privilege_record.grantee WHERE database_record.datname = current_database() AND privilege_record.privilege_type = 'CONNECT' AND grantee_role.rolname = 'alpha_data_cluster_bootstrap'
UNION ALL SELECT 'cluster_bootstrap_explicit_object_acl_count=' || count(*)::text FROM (SELECT privilege_record.privilege_type FROM pg_class AS object JOIN pg_namespace AS namespace ON namespace.oid = object.relnamespace CROSS JOIN LATERAL aclexplode(object.relacl) AS privilege_record WHERE namespace.nspname = 'public' AND object.relkind IN ('r', 'p', 'S') AND privilege_record.grantee = (SELECT oid FROM pg_roles WHERE rolname = 'alpha_data_cluster_bootstrap') UNION ALL SELECT privilege_record.privilege_type FROM pg_namespace AS namespace CROSS JOIN LATERAL aclexplode(namespace.nspacl) AS privilege_record WHERE namespace.nspname = 'public' AND privilege_record.grantee = (SELECT oid FROM pg_roles WHERE rolname = 'alpha_data_cluster_bootstrap')) AS cluster_bootstrap_acl
UNION ALL SELECT 'bootstrap_database_connect=' || CASE WHEN EXISTS(SELECT 1 FROM pg_roles WHERE rolname = 'alpha_data_bootstrap') THEN has_database_privilege('alpha_data_bootstrap', current_database(), 'CONNECT') ELSE false END::text
UNION ALL SELECT 'migration_connect=' || CASE WHEN EXISTS(SELECT 1 FROM pg_roles WHERE rolname = 'alpha_data_migration') THEN has_database_privilege('alpha_data_migration', current_database(), 'CONNECT') ELSE false END::text
UNION ALL SELECT 'migration_schema_usage=' || CASE WHEN EXISTS(SELECT 1 FROM pg_roles WHERE rolname = 'alpha_data_migration') THEN has_schema_privilege('alpha_data_migration', 'public', 'USAGE') ELSE false END::text
UNION ALL SELECT 'migration_schema_create=' || CASE WHEN EXISTS(SELECT 1 FROM pg_roles WHERE rolname = 'alpha_data_migration') THEN has_schema_privilege('alpha_data_migration', 'public', 'CREATE') ELSE false END::text
UNION ALL SELECT 'auxiliary_database_connect_count=' || CASE WHEN (SELECT count(*) FROM pg_roles WHERE rolname IN ('alpha_data_readonly', 'alpha_data_backup', 'alpha_data_retention')) = 3 THEN (SELECT count(*)::text FROM pg_roles AS role WHERE role.rolname IN ('alpha_data_readonly', 'alpha_data_backup', 'alpha_data_retention') AND has_database_privilege(role.rolname, current_database(), 'CONNECT')) ELSE '0' END
UNION ALL SELECT 'auxiliary_schema_usage_count=' || CASE WHEN (SELECT count(*) FROM pg_roles WHERE rolname IN ('alpha_data_readonly', 'alpha_data_backup', 'alpha_data_retention')) = 3 THEN (SELECT count(*)::text FROM pg_roles AS role WHERE role.rolname IN ('alpha_data_readonly', 'alpha_data_backup', 'alpha_data_retention') AND has_schema_privilege(role.rolname, 'public', 'USAGE')) ELSE '0' END
UNION ALL SELECT 'auxiliary_schema_create_count=' || CASE WHEN (SELECT count(*) FROM pg_roles WHERE rolname IN ('alpha_data_readonly', 'alpha_data_backup', 'alpha_data_retention')) = 3 THEN (SELECT count(*)::text FROM pg_roles AS role WHERE role.rolname IN ('alpha_data_readonly', 'alpha_data_backup', 'alpha_data_retention') AND has_schema_privilege(role.rolname, 'public', 'CREATE')) ELSE '0' END
UNION ALL SELECT 'app_schema_create=' || has_schema_privilege('alpha_data_user', 'public', 'CREATE')::text
UNION ALL SELECT 'app_delete=' || has_table_privilege('alpha_data_user', 'public.intelligence_sources', 'DELETE')::text
UNION ALL SELECT 'app_sequence_update=' || has_sequence_privilege('alpha_data_user', 'public.intelligence_sources_id_seq', 'UPDATE')::text
UNION ALL SELECT 'prepared_auxiliary_no_table_privilege_count=' || CASE WHEN (SELECT count(*) FROM pg_roles WHERE rolname IN ('alpha_data_readonly', 'alpha_data_backup', 'alpha_data_retention')) = 3 THEN (SELECT count(*)::text FROM pg_roles AS role CROSS JOIN pg_class AS object JOIN pg_namespace AS namespace ON namespace.oid = object.relnamespace WHERE role.rolname IN ('alpha_data_readonly', 'alpha_data_backup', 'alpha_data_retention') AND namespace.nspname = 'public' AND object.relkind IN ('r', 'p') AND NOT (has_table_privilege(role.rolname, object.oid, 'SELECT') OR has_table_privilege(role.rolname, object.oid, 'INSERT') OR has_table_privilege(role.rolname, object.oid, 'UPDATE') OR has_table_privilege(role.rolname, object.oid, 'DELETE') OR has_table_privilege(role.rolname, object.oid, 'TRUNCATE') OR has_table_privilege(role.rolname, object.oid, 'REFERENCES') OR has_table_privilege(role.rolname, object.oid, 'TRIGGER'))) ELSE '0' END
UNION ALL SELECT 'auxiliary_no_sequence_privilege_count=' || CASE WHEN (SELECT count(*) FROM pg_roles WHERE rolname IN ('alpha_data_readonly', 'alpha_data_backup', 'alpha_data_retention')) = 3 THEN (SELECT count(*)::text FROM pg_roles AS role CROSS JOIN pg_class AS object JOIN pg_namespace AS namespace ON namespace.oid = object.relnamespace JOIN pg_sequence AS sequence_record ON sequence_record.seqrelid = object.oid WHERE role.rolname IN ('alpha_data_readonly', 'alpha_data_backup', 'alpha_data_retention') AND namespace.nspname = 'public' AND object.relkind = 'S' AND NOT (has_sequence_privilege(role.rolname, sequence_record.seqrelid, 'USAGE') OR has_sequence_privilege(role.rolname, sequence_record.seqrelid, 'SELECT') OR has_sequence_privilege(role.rolname, sequence_record.seqrelid, 'UPDATE'))) ELSE '0' END
UNION ALL SELECT 'prepared_migration_no_table_privilege_count=' || CASE WHEN EXISTS(SELECT 1 FROM pg_roles WHERE rolname = 'alpha_data_migration') THEN (SELECT count(*)::text FROM pg_class AS object JOIN pg_namespace AS namespace ON namespace.oid = object.relnamespace WHERE namespace.nspname = 'public' AND object.relkind IN ('r', 'p') AND NOT (has_table_privilege('alpha_data_migration', object.oid, 'SELECT') OR has_table_privilege('alpha_data_migration', object.oid, 'INSERT') OR has_table_privilege('alpha_data_migration', object.oid, 'UPDATE') OR has_table_privilege('alpha_data_migration', object.oid, 'DELETE') OR has_table_privilege('alpha_data_migration', object.oid, 'TRUNCATE') OR has_table_privilege('alpha_data_migration', object.oid, 'REFERENCES') OR has_table_privilege('alpha_data_migration', object.oid, 'TRIGGER'))) ELSE '0' END
UNION ALL SELECT 'prepared_migration_no_sequence_privilege_count=' || CASE WHEN EXISTS(SELECT 1 FROM pg_roles WHERE rolname = 'alpha_data_migration') THEN (SELECT count(*)::text FROM pg_class AS object JOIN pg_namespace AS namespace ON namespace.oid = object.relnamespace JOIN pg_sequence AS sequence_record ON sequence_record.seqrelid = object.oid WHERE namespace.nspname = 'public' AND object.relkind = 'S' AND NOT (has_sequence_privilege('alpha_data_migration', sequence_record.seqrelid, 'USAGE') OR has_sequence_privilege('alpha_data_migration', sequence_record.seqrelid, 'SELECT') OR has_sequence_privilege('alpha_data_migration', sequence_record.seqrelid, 'UPDATE'))) ELSE '0' END
UNION ALL SELECT 'migration_default_acl_count=' || count(*)::text FROM pg_default_acl AS default_acl JOIN pg_roles AS role ON role.oid = default_acl.defaclrole WHERE role.rolname = 'alpha_data_migration'
UNION ALL SELECT 'app_table_privilege_shape_count=' || count(*)::text FROM pg_class AS object JOIN pg_namespace AS namespace ON namespace.oid = object.relnamespace WHERE namespace.nspname = 'public' AND object.relkind IN ('r', 'p') AND ((object.relname = 'alembic_version' AND has_table_privilege('alpha_data_user', object.oid, 'SELECT') AND NOT (has_table_privilege('alpha_data_user', object.oid, 'INSERT') OR has_table_privilege('alpha_data_user', object.oid, 'UPDATE') OR has_table_privilege('alpha_data_user', object.oid, 'DELETE') OR has_table_privilege('alpha_data_user', object.oid, 'TRUNCATE') OR has_table_privilege('alpha_data_user', object.oid, 'REFERENCES') OR has_table_privilege('alpha_data_user', object.oid, 'TRIGGER'))) OR (EXISTS (SELECT 1 FROM application_tables WHERE application_tables.name = object.relname) AND has_table_privilege('alpha_data_user', object.oid, 'SELECT') AND has_table_privilege('alpha_data_user', object.oid, 'INSERT') AND (has_table_privilege('alpha_data_user', object.oid, 'UPDATE') = EXISTS (SELECT 1 FROM runtime_update_tables WHERE runtime_update_tables.name = object.relname)) AND NOT (has_table_privilege('alpha_data_user', object.oid, 'DELETE') OR has_table_privilege('alpha_data_user', object.oid, 'TRUNCATE') OR has_table_privilege('alpha_data_user', object.oid, 'REFERENCES') OR has_table_privilege('alpha_data_user', object.oid, 'TRIGGER'))))
UNION ALL SELECT 'app_sequence_privilege_shape_count=' || count(*)::text FROM pg_class AS object JOIN pg_namespace AS namespace ON namespace.oid = object.relnamespace JOIN pg_sequence AS sequence_record ON sequence_record.seqrelid = object.oid WHERE namespace.nspname = 'public' AND object.relkind = 'S' AND has_sequence_privilege('alpha_data_user', sequence_record.seqrelid, 'USAGE') AND has_sequence_privilege('alpha_data_user', sequence_record.seqrelid, 'SELECT') AND NOT has_sequence_privilege('alpha_data_user', sequence_record.seqrelid, 'UPDATE')
UNION ALL SELECT 'readonly_table_privilege_shape_count=' || CASE WHEN EXISTS(SELECT 1 FROM pg_roles WHERE rolname = 'alpha_data_readonly') THEN (SELECT count(*)::text FROM pg_class AS object JOIN pg_namespace AS namespace ON namespace.oid = object.relnamespace WHERE namespace.nspname = 'public' AND object.relkind IN ('r', 'p') AND (has_table_privilege('alpha_data_readonly', object.oid, 'SELECT') = EXISTS (SELECT 1 FROM application_tables WHERE application_tables.name = object.relname)) AND NOT (has_table_privilege('alpha_data_readonly', object.oid, 'INSERT') OR has_table_privilege('alpha_data_readonly', object.oid, 'UPDATE') OR has_table_privilege('alpha_data_readonly', object.oid, 'DELETE') OR has_table_privilege('alpha_data_readonly', object.oid, 'TRUNCATE') OR has_table_privilege('alpha_data_readonly', object.oid, 'REFERENCES') OR has_table_privilege('alpha_data_readonly', object.oid, 'TRIGGER'))) ELSE '0' END
UNION ALL SELECT 'backup_table_privilege_shape_count=' || CASE WHEN EXISTS(SELECT 1 FROM pg_roles WHERE rolname = 'alpha_data_backup') THEN (SELECT count(*)::text FROM pg_class AS object JOIN pg_namespace AS namespace ON namespace.oid = object.relnamespace WHERE namespace.nspname = 'public' AND object.relkind IN ('r', 'p') AND (has_table_privilege('alpha_data_backup', object.oid, 'SELECT') = EXISTS (SELECT 1 FROM application_tables WHERE application_tables.name = object.relname)) AND NOT (has_table_privilege('alpha_data_backup', object.oid, 'INSERT') OR has_table_privilege('alpha_data_backup', object.oid, 'UPDATE') OR has_table_privilege('alpha_data_backup', object.oid, 'DELETE') OR has_table_privilege('alpha_data_backup', object.oid, 'TRUNCATE') OR has_table_privilege('alpha_data_backup', object.oid, 'REFERENCES') OR has_table_privilege('alpha_data_backup', object.oid, 'TRIGGER'))) ELSE '0' END
UNION ALL SELECT 'retention_table_privilege_shape_count=' || CASE WHEN EXISTS(SELECT 1 FROM pg_roles WHERE rolname = 'alpha_data_retention') THEN (SELECT count(*)::text FROM pg_class AS object JOIN pg_namespace AS namespace ON namespace.oid = object.relnamespace WHERE namespace.nspname = 'public' AND object.relkind IN ('r', 'p') AND (has_table_privilege('alpha_data_retention', object.oid, 'SELECT') = EXISTS (SELECT 1 FROM retention_tables WHERE retention_tables.name = object.relname)) AND NOT (has_table_privilege('alpha_data_retention', object.oid, 'INSERT') OR has_table_privilege('alpha_data_retention', object.oid, 'UPDATE') OR has_table_privilege('alpha_data_retention', object.oid, 'DELETE') OR has_table_privilege('alpha_data_retention', object.oid, 'TRUNCATE') OR has_table_privilege('alpha_data_retention', object.oid, 'REFERENCES') OR has_table_privilege('alpha_data_retention', object.oid, 'TRIGGER'))) ELSE '0' END;
'@

$PostCorrectionSql = @'
WITH target_slugs(slug) AS (
    VALUES ('alpha-synthetic-cve'), ('alpha-synthetic-advisories'),
           ('alpha-synthetic-news'), ('alpha-synthetic-uae')
)
SELECT 'target_count=' || count(*)::text FROM public.intelligence_sources AS source JOIN target_slugs ON target_slugs.slug = source.slug
UNION ALL SELECT 'target_null_checkpoint_count=' || count(*)::text FROM public.intelligence_sources AS source JOIN target_slugs ON target_slugs.slug = source.slug WHERE source.checkpoint_value IS NULL
UNION ALL SELECT 'target_null_timestamp_count=' || count(*)::text FROM public.intelligence_sources AS source JOIN target_slugs ON target_slugs.slug = source.slug WHERE source.last_successful_fetch_at IS NULL
UNION ALL SELECT 'target_run_count=' || count(run.id)::text FROM public.intelligence_sources AS source JOIN target_slugs ON target_slugs.slug = source.slug LEFT JOIN public.ingestion_runs AS run ON run.source_id = source.id;
'@

function Invoke-C08Pre02Main {
    param([Parameter(Mandatory = $true)][System.Collections.IDictionary]$ExplicitParameters)

    Initialize-RunState
    try {
        if (-not $RepositoryRoot) { $script:RepositoryRoot = Join-Path $PSScriptRoot ".." }
        else { $script:RepositoryRoot = $RepositoryRoot }
        $script:ResolvedRepositoryRoot = [System.IO.Path]::GetFullPath((Resolve-Path -LiteralPath $script:RepositoryRoot).Path)
        [void](Assert-ApplyInvocation `
            -SelectedMode $Mode `
            -ModeWasExplicit ($ExplicitParameters.Contains("Mode")) `
            -CheckpointWasExplicit ($ExplicitParameters.Contains("ExpectedGitCheckpoint")))
        Assert-Gate "fixed_branch" ($ExpectedBranch -eq $FrozenBranch) "Expected branch must remain dev."
        Assert-Gate "fixed_revision" ($ExpectedDatabaseRevision -eq $FrozenDatabaseRevision) "Expected revision cannot be changed."
        Assert-Gate "fixed_volume" ($ExpectedDockerVolume -eq $FrozenDockerVolume) "Expected volume cannot be changed."

        $script:ReviewedGitCheckpoint = Resolve-ReviewedGitCheckpoint `
            -SubmittedCheckpoint $ExpectedGitCheckpoint `
            -ReviewedApprovalEvidencePath $ApprovalEvidencePath `
            -ResolvedRepositoryRoot $script:ResolvedRepositoryRoot `
            -ApplyMode ($Mode -eq "Apply") `
            -CheckpointWasExplicit ($ExplicitParameters.Contains("ExpectedGitCheckpoint"))

        $approvedProvision = Join-Path $script:ResolvedRepositoryRoot "database\maintenance\c08-pre02-provision-existing-volume.sql"
        $approvedCorrection = Join-Path $script:ResolvedRepositoryRoot "database\maintenance\c08-pre02-correct-synthetic-progress.sql"
        if (-not $ProvisionSqlPath) { $script:ProvisionSqlPath = $approvedProvision }
        if (-not $CorrectionSqlPath) { $script:CorrectionSqlPath = $approvedCorrection }
        $provisionArtifact = Get-ReviewedSqlArtifact -SubmittedPath $script:ProvisionSqlPath -ApprovedPath $approvedProvision -ExpectedSha256 $ProvisionSqlSha256
        $correctionArtifact = Get-ReviewedSqlArtifact -SubmittedPath $script:CorrectionSqlPath -ApprovedPath $approvedCorrection -ExpectedSha256 $CorrectionSqlSha256
        $script:SqlHashEvidence = [ordered]@{
            provision_sql_sha256=$provisionArtifact.Sha256
            correction_sql_sha256=$correctionArtifact.Sha256
        }

        if (-not $EvidenceOutputDirectory) {
            $script:EvidenceOutputDirectory = Join-Path (Split-Path $script:ResolvedRepositoryRoot -Parent) "handover-exports\C08-PRE02-runtime-evidence"
        } else { $script:EvidenceOutputDirectory = $EvidenceOutputDirectory }
        Assert-Condition ([System.IO.Path]::IsPathRooted($script:EvidenceOutputDirectory)) "C08-PRE-02 evidence path must be absolute"
        $script:ResolvedEvidenceDirectory = [System.IO.Path]::GetFullPath($script:EvidenceOutputDirectory)
        Assert-Gate "evidence_outside_repository" (-not (Test-PathInsideParent $script:ResolvedEvidenceDirectory $script:ResolvedRepositoryRoot)) "Evidence must remain outside repository."

        Assert-RepositoryState -ReviewedCheckpoint $script:ReviewedGitCheckpoint
        [void](Invoke-SafeProcess -FileName "docker" -ArgumentList @("version", "--format", "{{.Server.Version}}"))
        [void](Invoke-SafeProcess -FileName "docker" -ArgumentList @("compose", "version") -WorkingDirectory $script:ResolvedRepositoryRoot)
        $containerState = (Invoke-SafeProcess -FileName "docker" -ArgumentList @("inspect", "--format", "{{.State.Running}}", $DatabaseContainer)).Stdout
        Assert-Gate "expected_database_container" ($containerState -eq "true") "Fixed database container must be running."
        $volumeName = (Invoke-SafeProcess -FileName "docker" -ArgumentList @("volume", "inspect", "--format", "{{.Name}}", $ExpectedDockerVolume)).Stdout
        Assert-Gate "expected_persistent_volume" ($volumeName -eq $ExpectedDockerVolume) "Fixed volume must exist."

        $flowsSource = Get-Content -LiteralPath (Join-Path $script:ResolvedRepositoryRoot "backend\app\orchestration\flows.py") -Raw -Encoding UTF8
        $handlerCount = [regex]::Matches($flowsSource, 'DEFAULT_SOURCE_HANDLERS\s*:[^=]+?=\s*MappingProxyType\(\{\}\)', [System.Text.RegularExpressions.RegexOptions]::Singleline).Count
        Assert-Gate "default_source_handlers_count_zero" ($handlerCount -eq 1) "Default handler map must remain empty."

        $snapshot = Invoke-DatabaseQuery -Sql $DatabaseSnapshotSql
        $script:DatabaseEvidence = $snapshot
        Assert-ExactPreservedDataSnapshot -Snapshot $snapshot
        $roleState = Get-RoleBoundaryState -Snapshot $snapshot
        Assert-Gate "role_boundary_state_expected" ($roleState -ne "unexpected") "Role state must be legacy_bootstrap_collision, prepared_bootstrap_collision, or normalized."
        $script:RoleStateEvidence = $roleState

        if ($BackupEvidencePath) {
            $verifiedBackup = Read-VerifiedBackupEvidence `
                -EvidencePath $BackupEvidencePath `
                -ResolvedRepositoryRoot $script:ResolvedRepositoryRoot `
                -ExpectedCheckpoint $script:ReviewedGitCheckpoint `
                -ExpectedSessionId $MaintenanceSessionId `
                -ExpectedRevision $FrozenDatabaseRevision `
                -ExpectedVolume $FrozenDockerVolume
            $script:BackupEvidence = [ordered]@{
                evidence_file_sha256=$verifiedBackup.EvidenceFileSha256
                backup_artifact_path=$verifiedBackup.BackupArtifactPath
                backup_sha256=$verifiedBackup.BackupSha256
                backup_size_bytes=$verifiedBackup.BackupSizeBytes
                backup_last_write_utc=$verifiedBackup.BackupLastWriteUtc
                created_at_utc=$verifiedBackup.CreatedAtUtc
                maintenance_session_id=$verifiedBackup.MaintenanceSessionId
                git_checkpoint=$verifiedBackup.GitCheckpoint
                database_revision=$verifiedBackup.DatabaseRevision
            }
        } elseif ($Mode -eq "Apply") {
            Assert-Gate "backup_required_for_apply" $false "Apply requires verified backup evidence."
        }

        if ($Mode -eq "Preflight") {
            $script:FinalResult = "preflight_passed"
            Write-Host "C08-PRE-02 preflight passed. No database changes were made."
            return
        }

        Assert-Gate "apply_mode_explicit" ($ExplicitParameters.Contains("Mode") -and $Mode -eq "Apply") "Apply must be explicitly selected."
        Assert-Gate "apply_checkpoint_explicit" ($ExplicitParameters.Contains("ExpectedGitCheckpoint")) "Apply checkpoint must be explicit."
        Assert-Gate "maintenance_session_present" (-not [string]::IsNullOrWhiteSpace($MaintenanceSessionId)) "Apply requires maintenance session."
        [void](Assert-ApplyConfirmation -Confirmation (Read-Host "Type APPLY C08-PRE-02 to continue"))

        $plan = Get-RoleExecutionPlan -RoleState $roleState
        if ($plan.Prepare) {
            Assert-RepositoryState -ReviewedCheckpoint $script:ReviewedGitCheckpoint
            Invoke-ReviewedSqlArtifact -Artifact $provisionArtifact -Phase "prepare"
            $preparedSnapshot = Invoke-DatabaseQuery -Sql $DatabaseSnapshotSql
            Assert-Gate "post_prepare_state" ((Get-RoleBoundaryState $preparedSnapshot) -eq "prepared_bootstrap_collision") "Prepare must produce exact prepared bootstrap-collision state."
            $roleState = "prepared_bootstrap_collision"
        }

        $credentials = $null
        try {
            $credentials = Read-ReconciliationCredentials -IncludeRuntimeCredential $plan.RequireRuntimeCredential
            if ($plan.SetCredentials) {
                Assert-RepositoryState -ReviewedCheckpoint $script:ReviewedGitCheckpoint
                Set-ProtectedRoleCredential -RoleName "alpha_data_bootstrap" -Credential $credentials.Bootstrap
                Set-ProtectedRoleCredential -RoleName "alpha_data_migration" -Credential $credentials.Migration
            }
            Assert-Gate "bootstrap_login_verified" (Test-ProtectedRoleLogin -RoleName "alpha_data_bootstrap" -Credential $credentials.Bootstrap) "Bootstrap fixed loopback login must succeed."
            Assert-Gate "migration_login_and_capability_verified" (Test-ProtectedRoleLogin -RoleName "alpha_data_migration" -Credential $credentials.Migration) "Migration fixed loopback login and bounded capability must succeed."
            if ($plan.Normalize) {
                Assert-RepositoryState -ReviewedCheckpoint $script:ReviewedGitCheckpoint
                Invoke-ReviewedSqlArtifact -Artifact $provisionArtifact -Phase "normalize" -RuntimeCredential $credentials.Runtime
            }
        }
        finally {
            if ($null -ne $credentials) {
                if ($credentials.Runtime -is [System.Security.SecureString]) {
                    $credentials.Runtime.Dispose()
                }
                $credentials.Bootstrap.Dispose()
                $credentials.Migration.Dispose()
            }
            $credentials = $null
        }
        $normalizedSnapshot = Invoke-DatabaseQuery -Sql $DatabaseSnapshotSql
        Assert-Gate "normalized_role_state" ((Get-RoleBoundaryState $normalizedSnapshot) -eq "normalized") "Role boundary must be exactly normalized before correction."

        Assert-ExactPreservedDataSnapshot -Snapshot $normalizedSnapshot
        Assert-RepositoryState -ReviewedCheckpoint $script:ReviewedGitCheckpoint
        Invoke-ReviewedSqlArtifact -Artifact $correctionArtifact -Phase "correction"
        $postCorrection = Invoke-DatabaseQuery -Sql $PostCorrectionSql
        Assert-Gate "post_correction_target_count" (Test-EvidenceInt $postCorrection "target_count" 4) "All four source identities must remain."
        Assert-Gate "post_correction_checkpoint_clear" (Test-EvidenceInt $postCorrection "target_null_checkpoint_count" 4) "Exactly four checkpoints must be null."
        Assert-Gate "post_correction_timestamp_unchanged" (Test-EvidenceInt $postCorrection "target_null_timestamp_count" 4) "Timestamps must remain null."
        Assert-Gate "post_correction_no_runs" (Test-EvidenceInt $postCorrection "target_run_count" 0) "No run may be fabricated."
        $script:FinalResult = "apply_passed"
        Write-Host "C08-PRE-02 apply gates and reconciliation completed."
    }
    catch {
        $script:FinalResult = "failed_closed"
        $script:SanitizedFailure = "A reconciliation gate or approved command failed. No secret-bearing error detail was retained."
        Write-Error "C08-PRE-02 failed closed. Review sanitized evidence."
        throw
    }
    finally {
        Write-SanitizedEvidence
    }
}

if ($MyInvocation.InvocationName -ne ".") {
    try {
        Invoke-C08Pre02Main -ExplicitParameters $PSBoundParameters
    }
    catch {
        exit 1
    }
}
        $runtime = $null
