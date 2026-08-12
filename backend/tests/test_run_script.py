import ipaddress
import json
from pathlib import Path
import re
import subprocess

import pytest
import yaml


REPO_ROOT = Path(__file__).resolve().parents[2]
RUN_SCRIPT = REPO_ROOT / "run.ps1"
RUN_COMMAND = REPO_ROOT / "run.cmd"
SETUP_SCRIPT = REPO_ROOT / "scripts" / "setup-dev.ps1"
COMPOSE_FILE = REPO_ROOT / "docker-compose.yml"
POWERSHELL = "PowerShell.exe"


def run_powershell_helper(
    tmp_path: Path,
    function_names: tuple[str, ...],
    test_body: str,
    *,
    source_path: Path = RUN_SCRIPT,
) -> dict:
    quoted_source_path = str(source_path).replace("'", "''")
    quoted_names = ", ".join(f"'{name}'" for name in function_names)
    harness = tmp_path / "runner-helper-test.ps1"
    harness.write_text(
        f"""
$ErrorActionPreference = "Stop"
$tokens = $null
$parseErrors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile(
        '{quoted_source_path}',
    [ref]$tokens,
    [ref]$parseErrors
)
if ($parseErrors.Count -ne 0) {{
    throw "run.ps1 contains a PowerShell parse error."
}}
foreach ($functionName in @({quoted_names})) {{
    $definition = $ast.Find({{
        param($node)
        $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
            $node.Name -eq $functionName
    }}, $true)
    if ($null -eq $definition) {{
        throw "Required runner helper was not found."
    }}
    Invoke-Expression $definition.Extent.Text
}}
{test_body}
""",
        encoding="utf-8",
    )

    completed = subprocess.run(
        [
            POWERSHELL,
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(harness),
        ],
        cwd=REPO_ROOT,
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )

    assert completed.returncode == 0, completed.stderr
    return json.loads(completed.stdout)


def test_first_run_generates_distinct_non_placeholder_secrets_without_output(
    tmp_path: Path,
) -> None:
    example_path = tmp_path / ".env.example"
    target_path = tmp_path / ".env"
    example_path.write_text(
        "POSTGRES_PASSWORD=change-me-in-secret-store\n"
        "POSTGRES_BOOTSTRAP_PASSWORD=change-me-in-secret-store\n"
        "POSTGRES_MIGRATION_PASSWORD=change-me-in-secret-store\n"
        "APP_ENV=local\n",
        encoding="utf-8",
    )
    quoted_example = str(example_path).replace("'", "''")
    quoted_target = str(target_path).replace("'", "''")

    result = run_powershell_helper(
        tmp_path,
        (
            "Write-Success",
            "Write-WarningMessage",
            "New-CryptographicLocalSecret",
            "New-LocalRootEnvironmentFile",
        ),
        f"""
$captured = (& {{
    New-LocalRootEnvironmentFile -ExamplePath '{quoted_example}' -TargetPath '{quoted_target}'
}} *>&1 | Out-String)
$values = @{{}}
foreach ($line in [System.IO.File]::ReadAllLines('{quoted_target}')) {{
    if ($line -match '^(POSTGRES_(?:BOOTSTRAP_|MIGRATION_)?PASSWORD)=(.*)$') {{
        $values[$matches[1]] = $matches[2]
    }}
}}
$secretLeaked = $false
foreach ($value in $values.Values) {{
    if ($captured.Contains($value)) {{ $secretLeaked = $true }}
}}
[pscustomobject]@{{
    Count = $values.Count
    Distinct = @($values.Values | Select-Object -Unique).Count -eq 3
    MinimumLength = ($values.Values | ForEach-Object {{ $_.Length }} | Measure-Object -Minimum).Minimum
    PlaceholderPresent = $values.Values -contains 'change-me-in-secret-store'
    SecretLeaked = $secretLeaked
    UnrelatedFieldPreserved = [System.IO.File]::ReadAllText('{quoted_target}').Contains('APP_ENV=local')
}} | ConvertTo-Json -Compress
""",
        source_path=SETUP_SCRIPT,
    )

    assert result == {
        "Count": 3,
        "Distinct": True,
        "MinimumLength": 43,
        "PlaceholderPresent": False,
        "SecretLeaked": False,
        "UnrelatedFieldPreserved": True,
    }


def test_first_run_never_overwrites_an_existing_root_environment(
    tmp_path: Path,
) -> None:
    example_path = tmp_path / ".env.example"
    target_path = tmp_path / ".env"
    example_path.write_text(
        "POSTGRES_PASSWORD=change-me-in-secret-store\n",
        encoding="utf-8",
    )
    original = "POSTGRES_PASSWORD=existing-local-secret\nAPP_ENV=local\n"
    target_path.write_text(original, encoding="utf-8")
    quoted_example = str(example_path).replace("'", "''")
    quoted_target = str(target_path).replace("'", "''")

    result = run_powershell_helper(
        tmp_path,
        (
            "Write-Success",
            "Write-WarningMessage",
            "New-CryptographicLocalSecret",
            "New-LocalRootEnvironmentFile",
        ),
        f"""
$before = [System.IO.File]::ReadAllText('{quoted_target}')
$captured = (& {{
    New-LocalRootEnvironmentFile -ExamplePath '{quoted_example}' -TargetPath '{quoted_target}'
}} *>&1 | Out-String)
[pscustomobject]@{{
    Unchanged = [System.IO.File]::ReadAllText('{quoted_target}') -eq $before
    ExistingSecretLeaked = $captured.Contains('existing-local-secret')
}} | ConvertTo-Json -Compress
""",
        source_path=SETUP_SCRIPT,
    )

    assert result == {"Unchanged": True, "ExistingSecretLeaked": False}


@pytest.mark.parametrize(
    ("name", "placeholder"),
    (
        ("POSTGRES_PASSWORD", "change-me-in-secret-store"),
        ("POSTGRES_BOOTSTRAP_PASSWORD", "local-bootstrap-change-me"),
        ("POSTGRES_MIGRATION_PASSWORD", "local-migration-change-me"),
    ),
)
def test_known_existing_placeholders_fail_closed_by_variable_name_only(
    tmp_path: Path,
    name: str,
    placeholder: str,
) -> None:
    environment_path = tmp_path / ".env"
    environment_path.write_text(f"{name}={placeholder}\n", encoding="utf-8")
    quoted_path = str(environment_path).replace("'", "''")

    result = run_powershell_helper(
        tmp_path,
        ("Read-LocalEnvironmentSetting", "Assert-LocalSecretSetting"),
        f"""
try {{
    $null = Assert-LocalSecretSetting -Path '{quoted_path}' -Name '{name}' -KnownPlaceholders @('{placeholder}')
    $blocked = $false
    $safeMessage = ''
}}
catch {{
    $blocked = $true
    $safeMessage = $_.Exception.Message
}}
[pscustomobject]@{{
    Blocked = $blocked
    NamesField = $safeMessage.Contains('{name}')
    LeaksValue = $safeMessage.Contains('{placeholder}')
}} | ConvertTo-Json -Compress
""",
    )

    assert result == {"Blocked": True, "NamesField": True, "LeaksValue": False}


def test_existing_non_placeholder_secret_is_accepted_without_output(
    tmp_path: Path,
) -> None:
    environment_path = tmp_path / ".env"
    environment_path.write_text(
        "POSTGRES_PASSWORD=existing-non-placeholder-value\n",
        encoding="utf-8",
    )
    quoted_path = str(environment_path).replace("'", "''")

    result = run_powershell_helper(
        tmp_path,
        ("Read-LocalEnvironmentSetting", "Assert-LocalSecretSetting"),
        f"""
$script:acceptedLength = 0
$captured = (& {{
    $accepted = Assert-LocalSecretSetting -Path '{quoted_path}' -Name 'POSTGRES_PASSWORD' -KnownPlaceholders @('change-me-in-secret-store')
    $script:acceptedLength = $accepted.Length
}} *>&1 | Out-String)
[pscustomobject]@{{
    Accepted = $script:acceptedLength -gt 20
    SecretLeaked = $captured.Contains('existing-non-placeholder-value')
}} | ConvertTo-Json -Compress
""",
    )

    assert result == {"Accepted": True, "SecretLeaked": False}


def test_validated_file_secrets_override_stale_host_environment_for_compose(
    tmp_path: Path,
) -> None:
    environment_path = tmp_path / ".env"
    environment_path.write_text(
        "POSTGRES_PASSWORD=file-app-secret-value\n"
        "POSTGRES_BOOTSTRAP_PASSWORD=file-bootstrap-secret-value\n"
        "POSTGRES_MIGRATION_PASSWORD=file-migration-secret-value\n"
        "POSTGRES_APP_USER=alpha_data_runtime\n"
        "APP_ENV=local\n"
        "DEBUG=false\n"
        "ENABLE_ADMIN_INGESTION=false\n",
        encoding="utf-8",
    )
    quoted_root = str(tmp_path).replace("'", "''")

    result = run_powershell_helper(
        tmp_path,
        (
            "Write-Success",
            "Write-WarningMessage",
            "Read-LocalEnvironmentSetting",
            "Assert-LocalSecretSetting",
            "Assert-LocalConfiguration",
        ),
        f"""
$script:ProjectRoot = '{quoted_root}'
$env:POSTGRES_PASSWORD = 'change-me-in-secret-store'
$env:POSTGRES_BOOTSTRAP_PASSWORD = 'local-bootstrap-change-me'
$env:POSTGRES_MIGRATION_PASSWORD = 'local-migration-change-me'
$captured = (& {{ Assert-LocalConfiguration }} *>&1 | Out-String)
[pscustomobject]@{{
    ApplicationPinned = $env:POSTGRES_PASSWORD -eq 'file-app-secret-value'
    BootstrapPinned = $env:POSTGRES_BOOTSTRAP_PASSWORD -eq 'file-bootstrap-secret-value'
    MigrationPinned = $env:POSTGRES_MIGRATION_PASSWORD -eq 'file-migration-secret-value'
    SecretLeaked = $captured.Contains('file-app-secret-value') -or
        $captured.Contains('file-bootstrap-secret-value') -or
        $captured.Contains('file-migration-secret-value')
}} | ConvertTo-Json -Compress
""",
    )

    assert result == {
        "ApplicationPinned": True,
        "BootstrapPinned": True,
        "MigrationPinned": True,
        "SecretLeaked": False,
    }


def test_run_cmd_delegates_to_loopback_development_servers_and_preserves_endpoints() -> None:
    command_content = RUN_COMMAND.read_text(encoding="utf-8")
    script_content = RUN_SCRIPT.read_text(encoding="utf-8")

    assert 'PowerShell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0run.ps1" %*' in (
        command_content
    )
    assert re.search(r'"dev"\s*\{\s*Invoke-DevelopmentWorkflow\s*\}', script_content)
    assert (
        'ArgumentList @("run", "dev", "--", "--hostname", "127.0.0.1", '
        '"--port", "3000")'
    ) in script_content
    assert (
        'ArgumentList @("-m", "uvicorn", "app.main:app", "--reload", "--host", '
        '"127.0.0.1", "--port", "8000")'
    ) in script_content
    assert "Frontend:       http://localhost:3000/" in script_content
    assert "Backend health: http://localhost:8000/api/health" in script_content
    assert "Prefect UI:     http://localhost:4200/" in script_content


def test_successful_normal_startup_prints_operator_urls_in_readiness_summary(
    tmp_path: Path,
) -> None:
    result = run_powershell_helper(
        tmp_path,
        (
            "Write-Section",
            "Write-Success",
            "Write-WarningMessage",
            "Invoke-DockerWorkflow",
        ),
        r"""
function Assert-LocalRuntimePrerequisites {}
function Invoke-Setup {}
function Assert-LocalConfiguration {}
function Invoke-LocalInfrastructureBootstrap { param([switch]$IncludeFrontend) }
function Invoke-CheckedCommand {
    param([string]$Executable, [string[]]$Arguments, [string]$FailureMessage)
}
function Test-LocalEndpoint {
    param([string]$Name, [uri]$Uri, [int]$MaximumAttempts = 12)
}
$captured = (& { Invoke-DockerWorkflow } *>&1 | Out-String)
[pscustomobject]@{
    Output = $captured
} | ConvertTo-Json -Compress
""",
    )

    output_lines = result["Output"].splitlines()
    expected_summary = [
        "==== Readiness summary ====",
        "[PASS] Database is healthy, forward-migrated, connected, and bootstrapped.",
        "[PASS] Backend /api/health and the frontend are reachable.",
        "[PASS] Prefect server, worker, process pool, queue, and deployment are valid.",
        "[WARN] Prefect deployment is registered without changing its activation state; "
        "a new deployment starts PAUSED.",
        "[PASS] No live intelligence collection or manual Prefect flow run was launched.",
        "",
        "Application URLs:",
        "  Frontend:       http://localhost:3000/",
        "  Backend health: http://localhost:8000/api/health",
        "  Prefect UI:     http://localhost:4200/",
    ]
    summary_start = output_lines.index("==== Readiness summary ====")

    assert output_lines[summary_start : summary_start + len(expected_summary)] == (
        expected_summary
    )


def test_database_url_rewrite_is_structural_and_preserves_components(
    tmp_path: Path,
) -> None:
    result = run_powershell_helper(
        tmp_path,
        ("ConvertTo-HostDatabaseUrl",),
        r"""
$source = "postgresql+psycopg://synthetic_user:p%40ss%3Aword@db:5444/sample_db?sslmode=require#sample-fragment"
$converted = ConvertTo-HostDatabaseUrl -DatabaseUrl $source
$sourceUri = [Uri]$source
$convertedUri = [Uri]$converted
[pscustomobject]@{
    Host = $convertedUri.Host
    Scheme = $convertedUri.Scheme
    Port = $convertedUri.Port
    Path = $convertedUri.AbsolutePath
    Query = $convertedUri.Query
    Fragment = $convertedUri.Fragment
    UserInfoPreserved = $convertedUri.UserInfo -eq $sourceUri.UserInfo
} | ConvertTo-Json -Compress
""",
    )

    assert result == {
        "Host": "localhost",
        "Scheme": "postgresql+psycopg",
        "Port": 5444,
        "Path": "/sample_db",
        "Query": "?sslmode=require",
        "Fragment": "#sample-fragment",
        "UserInfoPreserved": True,
    }


@pytest.mark.parametrize(
    (
        "configured_host",
        "expected_host",
        "expected_unchanged",
        "expected_ipv6_loopback",
    ),
    [
        ("db", "localhost", False, None),
        ("DB", "localhost", False, None),
        ("localhost", "localhost", True, None),
        ("127.0.0.1", "127.0.0.1", True, None),
        ("[::1]", "::1", True, True),
        ("[2001:db8::42]", "2001:db8::42", True, False),
        ("db.internal.example", "db.internal.example", True, None),
    ],
)
def test_only_exact_db_hostname_is_rewritten(
    tmp_path: Path,
    configured_host: str,
    expected_host: str,
    expected_unchanged: bool,
    expected_ipv6_loopback: bool | None,
) -> None:
    result = run_powershell_helper(
        tmp_path,
        ("ConvertTo-HostDatabaseUrl",),
        f"""
$source = "postgresql+psycopg://synthetic_user:synthetic_pass@{configured_host}:5432/sample_db?sslmode=prefer#sample"
$converted = ConvertTo-HostDatabaseUrl -DatabaseUrl $source
[pscustomobject]@{{
    Host = ([Uri]$converted).Host
    Unchanged = $converted -eq $source
}} | ConvertTo-Json -Compress
""",
    )

    assert result["Unchanged"] is expected_unchanged
    if expected_ipv6_loopback is None:
        assert result["Host"] == expected_host
        return

    rendered_address = ipaddress.ip_address(result["Host"].strip("[]"))
    expected_address = ipaddress.ip_address(expected_host)
    assert rendered_address == expected_address
    assert rendered_address.version == 6
    assert rendered_address.is_loopback is expected_ipv6_loopback


def test_backend_env_reader_returns_database_url_without_displaying_it(
    tmp_path: Path,
) -> None:
    backend_directory = tmp_path / "backend"
    backend_directory.mkdir()
    (backend_directory / ".env").write_text(
        'DATABASE_URL="postgresql+psycopg://synthetic_user:synthetic_pass@db:5432/sample_db?sslmode=prefer#sample"\n',
        encoding="utf-8",
    )
    quoted_directory = str(backend_directory).replace("'", "''")

    result = run_powershell_helper(
        tmp_path,
        ("Get-BackendConfiguredDatabaseUrl",),
        f"""
Remove-Item -LiteralPath "Env:DATABASE_URL" -ErrorAction SilentlyContinue
$configured = Get-BackendConfiguredDatabaseUrl -BackendDirectory '{quoted_directory}'
[pscustomobject]@{{
    Host = ([Uri]$configured).Host
    OutputContainedUrl = $false
}} | ConvertTo-Json -Compress
""",
    )

    assert result == {"Host": "db", "OutputContainedUrl": False}


def test_backend_process_gets_host_url_and_parent_environment_is_restored(
    tmp_path: Path,
) -> None:
    result = run_powershell_helper(
        tmp_path,
        ("ConvertTo-HostDatabaseUrl", "Start-HostBackendProcess"),
        r"""
function Start-Process {
    param(
        [string]$FilePath,
        [string[]]$ArgumentList,
        [string]$WorkingDirectory,
        [switch]$NoNewWindow,
        [switch]$PassThru
    )
    $script:childDatabaseUrl = $env:DATABASE_URL
    return [pscustomobject]@{ HasExited = $false }
}
$parent = "postgresql+psycopg://parent_user:parent_pass@remote.example:5432/parent_db"
$configured = "postgresql+psycopg://child_user:child_pass@db:5432/child_db?sslmode=prefer#sample"
$env:DATABASE_URL = $parent
$null = Start-HostBackendProcess -FilePath "fake.exe" -ArgumentList @("safe") -WorkingDirectory "." -ConfiguredDatabaseUrl $configured
$childUri = [Uri]$script:childDatabaseUrl
[pscustomobject]@{
    ChildHost = $childUri.Host
    ChildPort = $childUri.Port
    ChildPath = $childUri.AbsolutePath
    ChildQuery = $childUri.Query
    ChildFragment = $childUri.Fragment
    ChildCredentialsPreserved = $childUri.UserInfo -eq ([Uri]$configured).UserInfo
    ParentRestored = $env:DATABASE_URL -eq $parent
} | ConvertTo-Json -Compress
Remove-Item -LiteralPath "Env:DATABASE_URL" -ErrorAction SilentlyContinue
""",
    )

    assert result == {
        "ChildHost": "localhost",
        "ChildPort": 5432,
        "ChildPath": "/child_db",
        "ChildQuery": "?sslmode=prefer",
        "ChildFragment": "#sample",
        "ChildCredentialsPreserved": True,
        "ParentRestored": True,
    }


def test_backend_process_removes_temporary_url_when_parent_had_none(
    tmp_path: Path,
) -> None:
    result = run_powershell_helper(
        tmp_path,
        ("ConvertTo-HostDatabaseUrl", "Start-HostBackendProcess"),
        r"""
function Start-Process {
    param(
        [string]$FilePath,
        [string[]]$ArgumentList,
        [string]$WorkingDirectory,
        [switch]$NoNewWindow,
        [switch]$PassThru
    )
    $script:childHost = ([Uri]$env:DATABASE_URL).Host
    return [pscustomobject]@{ HasExited = $false }
}
Remove-Item -LiteralPath "Env:DATABASE_URL" -ErrorAction SilentlyContinue
$configured = "postgresql+psycopg://child_user:child_pass@db:5432/child_db"
$null = Start-HostBackendProcess -FilePath "fake.exe" -ArgumentList @("safe") -WorkingDirectory "." -ConfiguredDatabaseUrl $configured
[pscustomobject]@{
    ChildHost = $script:childHost
    ParentVariablePresent = Test-Path -LiteralPath "Env:DATABASE_URL"
} | ConvertTo-Json -Compress
""",
    )

    assert result == {"ChildHost": "localhost", "ParentVariablePresent": False}


def test_runner_does_not_log_or_pass_database_url_as_an_argument() -> None:
    script_content = RUN_SCRIPT.read_text(encoding="utf-8")

    assert '.Replace("db", "localhost")' not in script_content
    assert not re.search(r"Write-(?:Host|Output).*DATABASE_URL", script_content)
    backend_launch = re.search(
        r"\$backendProcess\s*=\s*Start-HostBackendProcess(?P<body>.*?)\n\s*\$frontendProcess",
        script_content,
        flags=re.DOTALL,
    )
    assert backend_launch is not None
    assert "DATABASE_URL" not in backend_launch.group("body")
    assert "-ConfiguredDatabaseUrl $configuredDatabaseUrl" in backend_launch.group(
        "body"
    )


def test_compose_database_hostname_remains_db() -> None:
    compose_config = yaml.safe_load(COMPOSE_FILE.read_text(encoding="utf-8"))
    backend_environment = compose_config["services"]["backend"]["environment"]

    assert backend_environment["POSTGRES_HOST"] == "db"
    assert backend_environment["POSTGRES_PORT"] == 5432
    assert "DATABASE_URL" not in backend_environment


def test_default_runner_is_bootstrap_not_an_implicit_test_or_install_workflow() -> None:
    script_content = RUN_SCRIPT.read_text(encoding="utf-8")
    full_block = re.search(
        r'"full"\s*\{(?P<body>.*?)\n\s*\}',
        script_content,
        flags=re.DOTALL,
    )

    assert full_block is not None
    assert "Invoke-DockerWorkflow" in full_block.group("body")
    assert "Invoke-ProjectTests" not in full_block.group("body")
    assert "Install-MissingDependencies" not in full_block.group("body")


def test_runtime_pipeline_is_forward_only_state_preserving_and_non_destructive() -> None:
    script_content = RUN_SCRIPT.read_text(encoding="utf-8")
    lowered = script_content.lower()

    assert '@("compose", "config", "--quiet")' in script_content
    assert '"alembic", "-c", "/app/alembic.ini", "upgrade", "head"' in script_content
    assert '"app.runtime_bootstrap", "migration-state"' in script_content
    assert '"app.runtime_bootstrap", "application-state"' in script_content
    assert '"app.orchestration.deployments", "--verify-registration"' in script_content
    assert '"app.orchestration.deployments", "--verify-paused"' not in script_content
    assert "http://localhost:8000/api/health" in script_content
    assert "--activate" not in script_content
    assert "parent_ingestion_cycle" not in script_content
    assert (
        script_content.index("/opt/alpha-data/database/reconcile-local-database-roles.sh")
        < script_content.index('"app.runtime_bootstrap", "migration-state"')
    )
    for destructive in ("down -v", "volume rm", "reset", "downgrade", "drop schema"):
        assert destructive not in lowered


def test_environment_reader_distinguishes_missing_empty_and_present_without_output(
    tmp_path: Path,
) -> None:
    environment_path = tmp_path / ".env"
    environment_path.write_text(
        "PRESENT_FIELD='synthetic-value'\nEMPTY_FIELD=\n",
        encoding="utf-8",
    )
    quoted_path = str(environment_path).replace("'", "''")

    result = run_powershell_helper(
        tmp_path,
        ("Read-LocalEnvironmentSetting",),
        f"""
$present = Read-LocalEnvironmentSetting -Path '{quoted_path}' -Name 'PRESENT_FIELD'
$empty = Read-LocalEnvironmentSetting -Path '{quoted_path}' -Name 'EMPTY_FIELD'
$missing = Read-LocalEnvironmentSetting -Path '{quoted_path}' -Name 'MISSING_FIELD'
[pscustomobject]@{{
    PresentFound = $present.Found
    PresentLength = $present.Value.Length
    EmptyFound = $empty.Found
    EmptyLength = $empty.Value.Length
    MissingFound = $missing.Found
    MissingIsNull = $null -eq $missing.Value
}} | ConvertTo-Json -Compress
""",
    )

    assert result == {
        "PresentFound": True,
        "PresentLength": 15,
        "EmptyFound": True,
        "EmptyLength": 0,
        "MissingFound": False,
        "MissingIsNull": True,
    }


def test_environment_reader_rejects_duplicate_assignments(tmp_path: Path) -> None:
    environment_path = tmp_path / ".env"
    environment_path.write_text(
        "DEBUG=false\nDEBUG=true\n",
        encoding="utf-8",
    )
    quoted_path = str(environment_path).replace("'", "''")

    result = run_powershell_helper(
        tmp_path,
        ("Read-LocalEnvironmentSetting",),
        f"""
try {{
    Read-LocalEnvironmentSetting -Path '{quoted_path}' -Name 'DEBUG' | Out-Null
    $blocked = $false
    $safeMessage = ''
}}
catch {{
    $blocked = $true
    $safeMessage = $_.Exception.Message
}}
[pscustomobject]@{{
    Blocked = $blocked
    SafeMessage = $safeMessage
}} | ConvertTo-Json -Compress
""",
    )

    assert result == {
        "Blocked": True,
        "SafeMessage": "Duplicate local configuration field: DEBUG.",
    }
