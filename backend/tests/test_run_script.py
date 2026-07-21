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
COMPOSE_FILE = REPO_ROOT / "docker-compose.yml"
POWERSHELL = "PowerShell.exe"


def run_powershell_helper(
    tmp_path: Path,
    function_names: tuple[str, ...],
    test_body: str,
) -> dict:
    quoted_run_script = str(RUN_SCRIPT).replace("'", "''")
    quoted_names = ", ".join(f"'{name}'" for name in function_names)
    harness = tmp_path / "runner-helper-test.ps1"
    harness.write_text(
        f"""
$ErrorActionPreference = "Stop"
$tokens = $null
$parseErrors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile(
    '{quoted_run_script}',
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


def test_run_cmd_delegates_to_run_ps1_without_changing_dev_command() -> None:
    command_content = RUN_COMMAND.read_text(encoding="utf-8")
    script_content = RUN_SCRIPT.read_text(encoding="utf-8")

    assert 'PowerShell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0run.ps1" %*' in (
        command_content
    )
    assert re.search(r'"dev"\s*\{\s*Invoke-DevelopmentWorkflow\s*\}', script_content)
    assert 'ArgumentList @("run", "dev", "--", "--port", "3000")' in script_content


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
