<#
.SYNOPSIS
One-command local setup, verification, and startup for Alpha Data.

.DESCRIPTION
Safely prepares local configuration, builds the Docker runtime, migrates and
bootstraps PostgreSQL, registers the Prefect deployment while preserving an
existing activation state, starts the application, and verifies readiness
without running intelligence collection. A new deployment is created paused.
#>

[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [string]$Command = "full",

    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$ExtraArguments
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Write-Section {
    param([Parameter(Mandatory)][string]$Message)

    Write-Host ""
    Write-Host "==== $Message ====" -ForegroundColor Cyan
}

function Write-Success {
    param([Parameter(Mandatory)][string]$Message)

    Write-Host "[PASS] $Message" -ForegroundColor Green
}

function Write-WarningMessage {
    param([Parameter(Mandatory)][string]$Message)

    Write-Host "[WARN] $Message" -ForegroundColor Yellow
}

function Show-Usage {
    Write-Host @"
Alpha Data / Cyber OSINT Dashboard local runner

Usage:
  .\run.cmd             Bootstrap, start, and validate the local Docker runtime
  .\run.cmd full        Run the same safe one-command runtime workflow
  .\run.cmd setup       Check prerequisites and create missing local env files
  .\run.cmd install     Install backend and frontend dependencies
  .\run.cmd test        Run backend and frontend tests, type check, and build
  .\run.cmd docker      Run the same safe Docker runtime workflow
  .\run.cmd dev         Keep infrastructure in Docker; run apps with hot reload
  .\run.cmd help        Show this help
"@
}

function Assert-CommandAvailable {
    param(
        [Parameter(Mandatory)][string]$CommandName,
        [Parameter(Mandatory)][string]$Guidance
    )

    if ($null -eq (Get-Command $CommandName -ErrorAction SilentlyContinue)) {
        throw "$CommandName is required. $Guidance"
    }
}

function Assert-LocalRuntimePrerequisites {
    Write-Section "Validate local runtime prerequisites"
    Assert-CommandAvailable `
        -CommandName "docker" `
        -Guidance "Install Docker Desktop with Docker Compose v2, start it, and retry."

    Invoke-CheckedCommand `
        -Executable "docker" `
        -Arguments @("compose", "version") `
        -FailureMessage "Docker Compose v2 is unavailable"

    & docker info --format "{{.ServerVersion}}" | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "The Docker daemon is unavailable. Start Docker Desktop and retry."
    }
    Write-Success "Docker, Docker Compose v2, and the Docker daemon are available."
}

function Read-LocalEnvironmentSetting {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Name
    )

    $escapedName = [regex]::Escape($Name)
    $found = $false
    $resolvedValue = $null
    foreach ($line in [System.IO.File]::ReadLines($Path)) {
        $match = [regex]::Match(
            $line,
            "^\s*(?:export\s+)?$escapedName\s*=\s*(?<value>.*)$"
        )
        if (-not $match.Success) {
            continue
        }
        if ($found) {
            throw "Duplicate local configuration field: $Name."
        }
        $value = $match.Groups["value"].Value.Trim()
        if ($value.Length -ge 2 -and (
            ($value[0] -eq '"' -and $value[$value.Length - 1] -eq '"') -or
            ($value[0] -eq "'" -and $value[$value.Length - 1] -eq "'")
        )) {
            $value = $value.Substring(1, $value.Length - 2)
        }
        else {
            $value = [regex]::Replace($value, "\s+#.*$", "").TrimEnd()
        }
        $found = $true
        $resolvedValue = $value
    }
    return [pscustomobject]@{ Found = $found; Value = $resolvedValue }
}

function Assert-LocalSecretSetting {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string[]]$KnownPlaceholders
    )

    $setting = Read-LocalEnvironmentSetting -Path $Path -Name $Name
    if (-not $setting.Found) {
        throw "Missing local configuration field: $Name."
    }
    if ([string]::IsNullOrWhiteSpace($setting.Value) -or $setting.Value.Length -gt 4096) {
        throw "Invalid local configuration field: $Name."
    }
    foreach ($knownPlaceholder in $KnownPlaceholders) {
        if ([string]::Equals(
            $setting.Value,
            $knownPlaceholder,
            [StringComparison]::Ordinal
        )) {
            throw "Unsafe committed placeholder in local configuration field: $Name. Replace that field with a unique local secret."
        }
    }
    return $setting.Value
}

function Assert-LocalConfiguration {
    $environmentPath = Join-Path $script:ProjectRoot ".env"
    if (-not (Test-Path -LiteralPath $environmentPath -PathType Leaf)) {
        throw "Missing local configuration file: .env. Run '.\run.cmd setup' and review the documented local placeholders."
    }

    $script:LocalApplicationDatabasePassword = Assert-LocalSecretSetting `
        -Path $environmentPath `
        -Name "POSTGRES_PASSWORD" `
        -KnownPlaceholders @("change-me-in-secret-store")
    $script:LocalBootstrapDatabasePassword = Assert-LocalSecretSetting `
        -Path $environmentPath `
        -Name "POSTGRES_BOOTSTRAP_PASSWORD" `
        -KnownPlaceholders @(
            "change-me-in-secret-store",
            "local-bootstrap-change-me"
        )
    $script:LocalMigrationDatabasePassword = Assert-LocalSecretSetting `
        -Path $environmentPath `
        -Name "POSTGRES_MIGRATION_PASSWORD" `
        -KnownPlaceholders @(
            "change-me-in-secret-store",
            "local-migration-change-me"
        )
    $env:POSTGRES_PASSWORD = $script:LocalApplicationDatabasePassword
    $env:POSTGRES_BOOTSTRAP_PASSWORD = $script:LocalBootstrapDatabasePassword
    $env:POSTGRES_MIGRATION_PASSWORD = $script:LocalMigrationDatabasePassword

    $applicationUser = Read-LocalEnvironmentSetting `
        -Path $environmentPath `
        -Name "POSTGRES_APP_USER"
    if (-not $applicationUser.Found) {
        $script:LocalApplicationDatabaseUser = "alpha_data_runtime"
        Write-WarningMessage "POSTGRES_APP_USER is absent; the fixed non-superuser local runtime identity will be used."
    }
    elseif ($applicationUser.Value -notmatch "^[A-Za-z_][A-Za-z0-9_]{0,62}$") {
        throw "Invalid local configuration field: POSTGRES_APP_USER."
    }
    else {
        $script:LocalApplicationDatabaseUser = $applicationUser.Value
    }
    $env:POSTGRES_APP_USER = $script:LocalApplicationDatabaseUser

    $legacyApplicationUser = Read-LocalEnvironmentSetting `
        -Path $environmentPath `
        -Name "POSTGRES_USER"
    if ($legacyApplicationUser.Found) {
        if ($legacyApplicationUser.Value -notmatch "^[A-Za-z_][A-Za-z0-9_]{0,62}$") {
            throw "Invalid legacy local configuration field: POSTGRES_USER."
        }
        $env:POSTGRES_LEGACY_USER = $legacyApplicationUser.Value
    }
    else {
        Remove-Item -LiteralPath "Env:POSTGRES_LEGACY_USER" -ErrorAction SilentlyContinue
    }

    $environmentIdentity = Read-LocalEnvironmentSetting `
        -Path $environmentPath `
        -Name "APP_ENV"
    if (-not $environmentIdentity.Found) {
        Write-WarningMessage "APP_ENV is absent; the safe local Compose identity will be used."
    }
    elseif ($environmentIdentity.Value.Trim().ToLowerInvariant() -notin @("local", "development")) {
        throw "Invalid local configuration field: APP_ENV. The local runner accepts only local development identity."
    }

    foreach ($safeBoolean in @("DEBUG", "ENABLE_ADMIN_INGESTION")) {
        $setting = Read-LocalEnvironmentSetting -Path $environmentPath -Name $safeBoolean
        if (-not $setting.Found) {
            Write-WarningMessage "$safeBoolean is absent; the safe false Compose default will be used."
        }
        elseif ($setting.Value.Trim().ToLowerInvariant() -ne "false") {
            throw "Invalid local configuration field: $safeBoolean must remain false."
        }
    }
    Write-Success "Local configuration fields are present and use safe runtime settings."
}

function Invoke-CheckedCommand {
    param(
        [Parameter(Mandatory)][string]$Executable,
        [Parameter()][string[]]$Arguments = @(),
        [Parameter(Mandatory)][string]$FailureMessage
    )

    & $Executable @Arguments

    if ($LASTEXITCODE -ne 0) {
        throw "$FailureMessage (exit code $LASTEXITCODE)."
    }
}

function Invoke-Setup {
    param([switch]$InstallDependencies)

    Write-Section "Project setup"

    if ($InstallDependencies) {
        & $script:SetupScript -InstallDependencies
    }
    else {
        & $script:SetupScript
    }

    if (-not $?) {
        throw "The developer setup script failed."
    }
}

function Install-MissingDependencies {
    $backendDependenciesExist = Test-Path -LiteralPath $script:BackendPython -PathType Leaf
    $frontendDependenciesExist = Test-Path -LiteralPath $script:FrontendNodeModules -PathType Container

    if ($backendDependenciesExist) {
        Write-Success "Reusing existing backend virtual environment."
    }
    else {
        Write-Host "Backend virtual environment is missing; dependency installation is required."
    }

    if ($frontendDependenciesExist) {
        Write-Success "Reusing existing frontend node_modules directory."
    }
    else {
        Write-Host "Frontend node_modules is missing; dependency installation is required."
    }

    if (-not $backendDependenciesExist -or -not $frontendDependenciesExist) {
        Invoke-Setup -InstallDependencies
    }
}

function Assert-TestDependencies {
    if (-not (Test-Path -LiteralPath $script:BackendPython -PathType Leaf)) {
        throw "Backend dependencies are missing. Run '.\run.cmd install' first."
    }

    if (-not (Test-Path -LiteralPath $script:FrontendNodeModules -PathType Container)) {
        throw "Frontend dependencies are missing. Run '.\run.cmd install' first."
    }
}

function Invoke-ProjectTests {
    Assert-TestDependencies

    Write-Section "Backend tests"
    Push-Location (Join-Path $script:ProjectRoot "backend")
    try {
        Invoke-CheckedCommand `
            -Executable $script:BackendPython `
            -Arguments @("-m", "pytest") `
            -FailureMessage "Backend tests failed"
        Write-Success "Backend tests passed."
    }
    finally {
        Pop-Location
    }

    Write-Section "Frontend tests"
    Push-Location (Join-Path $script:ProjectRoot "frontend")
    try {
        Invoke-CheckedCommand `
            -Executable "npm" `
            -Arguments @("run", "test:run") `
            -FailureMessage "Frontend tests failed"
        Write-Success "Frontend tests passed."

        Write-Section "Frontend type check"
        Invoke-CheckedCommand `
            -Executable "npm" `
            -Arguments @("run", "type-check") `
            -FailureMessage "Frontend type check failed"

        Write-Success "Frontend type check passed."

        Write-Section "Frontend production build"
        Invoke-CheckedCommand `
            -Executable "npm" `
            -Arguments @("run", "build") `
            -FailureMessage "Frontend production build failed"
        Write-Success "Frontend production build passed."
    }
    finally {
        Pop-Location
    }
}

function Test-LocalEndpoint {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][uri]$Uri,
        [int]$MaximumAttempts = 12
    )

    for ($attempt = 1; $attempt -le $MaximumAttempts; $attempt++) {
        try {
            $response = Invoke-WebRequest -Uri $Uri -UseBasicParsing -TimeoutSec 10

            if ($response.StatusCode -ge 200 -and $response.StatusCode -lt 300) {
                Write-Success "$Name responded with HTTP $($response.StatusCode): $Uri"
                return
            }
        }
        catch {
            if ($attempt -eq $MaximumAttempts) {
                throw "$Name did not become available at $Uri. $($_.Exception.Message)"
            }
        }

        Write-Host "Waiting for $Name ($attempt/$MaximumAttempts)..."
        Start-Sleep -Seconds 5
    }

    throw "$Name returned an unsuccessful response at $Uri."
}

function Invoke-DockerWorkflow {
    Assert-LocalRuntimePrerequisites
    Invoke-Setup
    Assert-LocalConfiguration
    Invoke-LocalInfrastructureBootstrap -IncludeFrontend

    Write-Section "Start application services"
    Invoke-CheckedCommand `
        -Executable "docker" `
        -Arguments @("compose", "up", "-d", "backend", "frontend") `
        -FailureMessage "Docker Compose could not start the application services"

    Write-Section "Validate application readiness"
    Test-LocalEndpoint `
        -Name "Backend health endpoint" `
        -Uri "http://localhost:8000/api/health"
    Test-LocalEndpoint -Name "Frontend" -Uri "http://localhost:3000/"

    Write-Section "Docker Compose service status"
    Invoke-CheckedCommand `
        -Executable "docker" `
        -Arguments @("compose", "ps") `
        -FailureMessage "Docker Compose could not report service status"

    Write-Section "Readiness summary"
    Write-Success "Database is healthy, forward-migrated, connected, and bootstrapped."
    Write-Success "Backend /api/health and the frontend are reachable."
    Write-Success "Prefect server, worker, process pool, queue, and deployment are valid."
    Write-WarningMessage "Prefect deployment is registered without changing its activation state; a new deployment starts PAUSED."
    Write-Success "No live intelligence collection or manual Prefect flow run was launched."
    Write-Host ""
    Write-Host "Application URLs:"
    Write-Host "  Frontend:       http://localhost:3000/"
    Write-Host "  Backend health: http://localhost:8000/api/health"
    Write-Host "  Prefect UI:     http://localhost:4200/"
}

function Wait-ForComposeService {
    param(
        [Parameter(Mandatory)][string]$ServiceName,
        [int]$TimeoutSeconds = 120
    )

    $containerId = (& docker compose ps -q $ServiceName).Trim()
    if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($containerId)) {
        throw "Docker Compose did not report a running $ServiceName container."
    }

    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    while ((Get-Date) -lt $deadline) {
        $status = (& docker inspect --format "{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}" $containerId).Trim()
        if ($LASTEXITCODE -ne 0) {
            throw "Docker could not inspect the $ServiceName container."
        }

        if ($status -eq "healthy" -or $status -eq "running") {
            Write-Success "$ServiceName container is $status."
            return
        }

        if ($status -eq "unhealthy" -or $status -eq "exited" -or $status -eq "dead") {
            throw "$ServiceName container entered the '$status' state. Check bounded logs with 'docker compose logs --tail 100 $ServiceName'."
        }

        Write-Host "Waiting for $ServiceName health (current status: $status)..."
        Start-Sleep -Seconds 3
    }

    throw "$ServiceName did not become healthy within $TimeoutSeconds seconds. Check 'docker compose ps' and bounded service logs."
}

function Invoke-DatabaseMigrationAndBootstrap {
    Write-Section "Reconcile configured local database roles"
    Invoke-CheckedCommand `
        -Executable "docker" `
        -Arguments @(
            "compose", "exec", "-T", "db", "sh",
            "/opt/alpha-data/database/reconcile-local-database-roles.sh"
        ) `
        -FailureMessage "Configured local database roles could not be reconciled"

    Write-Section "Validate and migrate the application database"
    Invoke-CheckedCommand `
        -Executable "docker" `
        -Arguments @(
            "compose", "run", "--rm", "migrate",
            "python", "-m", "app.runtime_bootstrap", "migration-state"
        ) `
        -FailureMessage "Database migration integrity validation failed"

    Invoke-CheckedCommand `
        -Executable "docker" `
        -Arguments @(
            "compose", "run", "--rm", "migrate",
            "alembic", "-c", "/app/alembic.ini", "upgrade", "head"
        ) `
        -FailureMessage "Safe forward database migration failed"

    Invoke-CheckedCommand `
        -Executable "docker" `
        -Arguments @(
            "compose", "run", "--rm", "migrate",
            "python", "-m", "app.runtime_bootstrap", "migration-state",
            "--require-current"
        ) `
        -FailureMessage "Database did not reach the expected Alembic head"

    Write-Section "Reconcile application database grants"
    Invoke-CheckedCommand `
        -Executable "docker" `
        -Arguments @(
            "compose", "exec", "-T", "db", "sh",
            "/opt/alpha-data/database/apply-runtime-grants.sh"
        ) `
        -FailureMessage "Application database grants could not be reconciled"

    Write-Section "Bootstrap required application reference state"
    Invoke-CheckedCommand `
        -Executable "docker" `
        -Arguments @(
            "compose", "run", "--rm", "backend",
            "python", "-m", "app.runtime_bootstrap", "application-state"
        ) `
        -FailureMessage "Application reference-state bootstrap failed"
}

function Invoke-PrefectRegistration {
    Write-Section "Register and verify Prefect deployment state"
    Invoke-CheckedCommand `
        -Executable "docker" `
        -Arguments @(
            "compose", "exec", "-T", "prefect-worker",
            "python", "-m", "app.orchestration.deployments"
        ) `
        -FailureMessage "Prefect deployment state-preserving registration failed"
    Invoke-CheckedCommand `
        -Executable "docker" `
        -Arguments @(
            "compose", "exec", "-T", "prefect-worker",
            "python", "-m", "app.orchestration.deployments", "--verify-registration"
        ) `
        -FailureMessage "Prefect deployment integrity verification failed"
}

function Invoke-LocalInfrastructureBootstrap {
    param([switch]$IncludeFrontend)

    Write-Section "Validate Docker Compose configuration"
    Invoke-CheckedCommand `
        -Executable "docker" `
        -Arguments @("compose", "config", "--quiet") `
        -FailureMessage "Docker Compose configuration validation failed"
    Write-Success "Docker Compose configuration is valid without printing secrets."

    Write-Section "Build deterministic local images"
    $buildServices = @("backend", "prefect-server", "prefect-worker")
    if ($IncludeFrontend) {
        $buildServices += "frontend"
    }
    Invoke-CheckedCommand `
        -Executable "docker" `
        -Arguments (@("compose", "build") + $buildServices) `
        -FailureMessage "Docker Compose image build failed"

    Write-Section "Start persistent database and Prefect infrastructure"
    Invoke-CheckedCommand `
        -Executable "docker" `
        -Arguments @(
            "compose", "up", "-d",
            "db", "prefect-db", "prefect-server", "prefect-worker"
        ) `
        -FailureMessage "Docker Compose could not start local infrastructure"
    foreach ($service in @("db", "prefect-db", "prefect-server", "prefect-worker")) {
        Wait-ForComposeService -ServiceName $service
    }

    Invoke-DatabaseMigrationAndBootstrap
    Invoke-PrefectRegistration
}

function Stop-LocalProcessTree {
    param([Parameter(Mandatory)][System.Diagnostics.Process]$Process)

    if (-not $Process.HasExited) {
        # Both development servers may create child processes, so stop only the
        # process tree rooted at the PID that this script started.
        & taskkill.exe /PID $Process.Id /T /F 2>$null | Out-Null
    }
}

function Assert-PortAvailable {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][int]$Port
    )

    $client = [System.Net.Sockets.TcpClient]::new()
    try {
        $client.Connect("127.0.0.1", $Port)
        throw "$Name port 127.0.0.1:$Port is already occupied. Check Docker Compose services or other local processes before running dev mode."
    }
    catch [System.Net.Sockets.SocketException] {
        # A refused connection means that nothing is listening on this loopback port.
    }
    finally {
        $client.Dispose()
    }
}

function Get-BackendConfiguredDatabaseUrl {
    param([Parameter(Mandatory)][string]$BackendDirectory)

    if (Test-Path -LiteralPath "Env:DATABASE_URL") {
        if ([string]::IsNullOrWhiteSpace($env:DATABASE_URL)) {
            return $null
        }

        return $env:DATABASE_URL
    }

    $environmentPath = Join-Path $BackendDirectory ".env"
    if (-not (Test-Path -LiteralPath $environmentPath -PathType Leaf)) {
        return $null
    }

    foreach ($line in [System.IO.File]::ReadLines($environmentPath)) {
        $match = [regex]::Match(
            $line,
            "^\s*(?:export\s+)?DATABASE_URL\s*=\s*(?<value>.*)$"
        )
        if (-not $match.Success) {
            continue
        }

        $value = $match.Groups["value"].Value.Trim()
        if ($value.Length -ge 2 -and (
            ($value[0] -eq '"' -and $value[$value.Length - 1] -eq '"') -or
            ($value[0] -eq "'" -and $value[$value.Length - 1] -eq "'")
        )) {
            $value = $value.Substring(1, $value.Length - 2)
        }
        else {
            $value = [regex]::Replace($value, "\s+#.*$", "").TrimEnd()
        }

        if ([string]::IsNullOrWhiteSpace($value)) {
            return $null
        }

        return $value
    }

    return $null
}

function ConvertTo-HostDatabaseUrl {
    param([Parameter(Mandatory)][string]$DatabaseUrl)

    $parsedUrl = $null
    if (-not [Uri]::TryCreate(
        $DatabaseUrl,
        [UriKind]::Absolute,
        [ref]$parsedUrl
    ) -or [string]::IsNullOrWhiteSpace($parsedUrl.Host)) {
        throw "The configured DATABASE_URL must be a valid absolute database URL."
    }

    if (-not $parsedUrl.Host.Equals(
        "db",
        [StringComparison]::OrdinalIgnoreCase
    )) {
        return $DatabaseUrl
    }

    $hostUrl = [UriBuilder]::new($parsedUrl)
    $hostUrl.Host = "localhost"
    return $hostUrl.Uri.AbsoluteUri
}

function Start-HostBackendProcess {
    param(
        [Parameter(Mandatory)][string]$FilePath,
        [Parameter(Mandatory)][string[]]$ArgumentList,
        [Parameter(Mandatory)][string]$WorkingDirectory,
        [AllowNull()][string]$ConfiguredDatabaseUrl,
        [AllowNull()][string]$ConfiguredDatabaseUser = $null,
        [AllowNull()][string]$ConfiguredDatabasePassword = $null
    )

    $databaseUrlWasSet = Test-Path -LiteralPath "Env:DATABASE_URL"
    $previousDatabaseUrl = if ($databaseUrlWasSet) {
        $env:DATABASE_URL
    }
    else {
        $null
    }
    $databaseUserWasSet = Test-Path -LiteralPath "Env:POSTGRES_USER"
    $previousDatabaseUser = if ($databaseUserWasSet) { $env:POSTGRES_USER } else { $null }
    $databasePasswordWasSet = Test-Path -LiteralPath "Env:POSTGRES_PASSWORD"
    $previousDatabasePassword = if ($databasePasswordWasSet) { $env:POSTGRES_PASSWORD } else { $null }

    try {
        if ($null -ne $ConfiguredDatabaseUrl) {
            $env:DATABASE_URL = ConvertTo-HostDatabaseUrl $ConfiguredDatabaseUrl
        }
        if ($null -ne $ConfiguredDatabaseUser) {
            $env:POSTGRES_USER = $ConfiguredDatabaseUser
        }
        if ($null -ne $ConfiguredDatabasePassword) {
            $env:POSTGRES_PASSWORD = $ConfiguredDatabasePassword
        }

        return Start-Process `
            -FilePath $FilePath `
            -ArgumentList $ArgumentList `
            -WorkingDirectory $WorkingDirectory `
            -NoNewWindow `
            -PassThru
    }
    finally {
        if ($databaseUrlWasSet) {
            $env:DATABASE_URL = $previousDatabaseUrl
        }
        else {
            Remove-Item -LiteralPath "Env:DATABASE_URL" -ErrorAction SilentlyContinue
        }
        if ($databaseUserWasSet) {
            $env:POSTGRES_USER = $previousDatabaseUser
        }
        else {
            Remove-Item -LiteralPath "Env:POSTGRES_USER" -ErrorAction SilentlyContinue
        }
        if ($databasePasswordWasSet) {
            $env:POSTGRES_PASSWORD = $previousDatabasePassword
        }
        else {
            Remove-Item -LiteralPath "Env:POSTGRES_PASSWORD" -ErrorAction SilentlyContinue
        }
    }
}

function Invoke-DevelopmentWorkflow {
    Assert-LocalRuntimePrerequisites
    Invoke-Setup
    Assert-LocalConfiguration
    Assert-TestDependencies
    Invoke-LocalInfrastructureBootstrap

    Write-Section "Check local development ports"
    Assert-PortAvailable -Name "Backend" -Port 8000
    Assert-PortAvailable -Name "Frontend" -Port 3000
    Write-Success "Backend and frontend ports are available."

    $backendDirectory = Join-Path $script:ProjectRoot "backend"
    $frontendDirectory = Join-Path $script:ProjectRoot "frontend"
    $npmCommand = (Get-Command "npm.cmd" -ErrorAction Stop).Source
    $backendProcess = $null
    $frontendProcess = $null

    try {
        Write-Section "Start local development servers"
        $configuredDatabaseUrl = Get-BackendConfiguredDatabaseUrl `
            -BackendDirectory $backendDirectory
        $backendProcess = Start-HostBackendProcess `
            -FilePath $script:BackendPython `
            -ArgumentList @("-m", "uvicorn", "app.main:app", "--reload", "--host", "127.0.0.1", "--port", "8000") `
            -WorkingDirectory $backendDirectory `
            -ConfiguredDatabaseUrl $configuredDatabaseUrl `
            -ConfiguredDatabaseUser $script:LocalApplicationDatabaseUser `
            -ConfiguredDatabasePassword $script:LocalApplicationDatabasePassword

        $frontendProcess = Start-Process `
            -FilePath $npmCommand `
            -ArgumentList @("run", "dev", "--", "--hostname", "127.0.0.1", "--port", "3000") `
            -WorkingDirectory $frontendDirectory `
            -NoNewWindow `
            -PassThru

        Write-Host ""
        Write-Host "Backend:        http://localhost:8000/"
        Write-Host "Backend health: http://localhost:8000/api/health"
        Write-Host "Backend version: http://localhost:8000/api/version"
        Write-Host "Frontend:       http://localhost:3000/"
        Write-Host "Prefect UI:     http://localhost:4200/"
        Write-Host ""
        Write-Host "Press Ctrl+C to stop the local backend and frontend. Database and Prefect infrastructure will remain running."

        while (-not $backendProcess.HasExited -and -not $frontendProcess.HasExited) {
            Start-Sleep -Seconds 1
        }

        if ($backendProcess.HasExited) {
            throw "The local backend stopped unexpectedly. Review the server output above for details."
        }

        throw "The local frontend stopped unexpectedly. Review the server output above for details."
    }
    finally {
        Write-Host ""
        Write-Host "Stopping local development servers..."
        if ($null -ne $frontendProcess) {
            Stop-LocalProcessTree -Process $frontendProcess
        }
        if ($null -ne $backendProcess) {
            Stop-LocalProcessTree -Process $backendProcess
        }
        Write-Success "Local backend and frontend stopped. Database and Prefect infrastructure remain running."
    }
}

try {
    $script:ProjectRoot = $PSScriptRoot
    $currentDirectory = (Get-Location).Path.TrimEnd("\", "/")
    $expectedDirectory = $script:ProjectRoot.TrimEnd("\", "/")

    if (-not $currentDirectory.Equals($expectedDirectory, [StringComparison]::OrdinalIgnoreCase)) {
        throw "Run this command from the repository root: $script:ProjectRoot"
    }

    $script:SetupScript = Join-Path $script:ProjectRoot "scripts\setup-dev.ps1"
    $script:BackendPython = Join-Path $script:ProjectRoot "backend\.venv\Scripts\python.exe"
    $script:FrontendNodeModules = Join-Path $script:ProjectRoot "frontend\node_modules"

    if (-not (Test-Path -LiteralPath $script:SetupScript -PathType Leaf)) {
        throw "Required setup script was not found: $script:SetupScript"
    }

    if ($null -ne $ExtraArguments -and $ExtraArguments.Count -gt 0) {
        Write-Host "Unexpected additional arguments: $($ExtraArguments -join ' ')" -ForegroundColor Red
        Show-Usage
        exit 1
    }

    $normalizedCommand = $Command.Trim().ToLowerInvariant()

    switch ($normalizedCommand) {
        "help" {
            Show-Usage
        }
        "setup" {
            Invoke-Setup
        }
        "install" {
            Invoke-Setup -InstallDependencies
        }
        "test" {
            Invoke-ProjectTests
        }
        "docker" {
            Invoke-DockerWorkflow
        }
        "dev" {
            Invoke-DevelopmentWorkflow
        }
        "full" {
            Invoke-DockerWorkflow
        }
        default {
            Write-Host "Unknown command: $Command" -ForegroundColor Red
            Show-Usage
            exit 1
        }
    }

    Write-Section "Complete"
    Write-Success "Command '$normalizedCommand' completed successfully."
}
catch {
    Write-Host ""
    Write-Host "[BLOCKED] $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}
