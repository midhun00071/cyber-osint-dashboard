<#
.SYNOPSIS
One-command local setup, verification, and startup for Alpha Data.

.DESCRIPTION
Runs the existing setup helper, verifies the backend and frontend, starts the
Docker Compose services, and checks the local application endpoints.
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

    Write-Host "[OK] $Message" -ForegroundColor Green
}

function Show-Usage {
    Write-Host @"
Alpha Data / Cyber OSINT Dashboard local runner

Usage:
  .\run.cmd             Run the full setup, test, build, and Docker workflow
  .\run.cmd full        Run the full workflow
  .\run.cmd setup       Check prerequisites and create missing local env files
  .\run.cmd install     Install backend and frontend dependencies
  .\run.cmd test        Run backend tests and frontend checks
  .\run.cmd docker      Build, start, and verify the Docker services
  .\run.cmd dev         Run the database in Docker and apps locally
  .\run.cmd help        Show this help
"@
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

    Write-Section "Frontend type check"
    Push-Location (Join-Path $script:ProjectRoot "frontend")
    try {
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
    Write-Section "Validate Docker Compose configuration"
    Invoke-CheckedCommand `
        -Executable "docker" `
        -Arguments @("compose", "config") `
        -FailureMessage "Docker Compose configuration validation failed"
    Write-Success "Docker Compose configuration is valid."

    Write-Section "Build and start local services"
    Invoke-CheckedCommand `
        -Executable "docker" `
        -Arguments @("compose", "up", "--build", "-d") `
        -FailureMessage "Docker Compose could not start the services"
    Write-Success "Docker Compose services started."

    Write-Section "Check local application endpoints"
    Test-LocalEndpoint -Name "Backend root" -Uri "http://localhost:8000/"
    Test-LocalEndpoint -Name "Backend health endpoint" -Uri "http://localhost:8000/api/health"
    Test-LocalEndpoint -Name "Frontend" -Uri "http://localhost:3000/"

    Write-Section "Docker Compose service status"
    Invoke-CheckedCommand `
        -Executable "docker" `
        -Arguments @("compose", "ps") `
        -FailureMessage "Docker Compose could not report service status"
}

function Wait-ForDatabase {
    param([int]$TimeoutSeconds = 90)

    $containerId = (& docker compose ps -q db).Trim()
    if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($containerId)) {
        throw "Docker Compose did not report a running database container."
    }

    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    while ((Get-Date) -lt $deadline) {
        $status = (& docker inspect --format "{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}" $containerId).Trim()
        if ($LASTEXITCODE -ne 0) {
            throw "Docker could not inspect the database container."
        }

        if ($status -eq "healthy" -or $status -eq "running") {
            Write-Success "Database container is $status."
            return
        }

        if ($status -eq "unhealthy" -or $status -eq "exited" -or $status -eq "dead") {
            throw "Database container entered the '$status' state. Check it with '.\run.cmd docker' or 'docker compose logs db'."
        }

        Write-Host "Waiting for database health (current status: $status)..."
        Start-Sleep -Seconds 3
    }

    throw "Database did not become healthy within $TimeoutSeconds seconds. Check it with 'docker compose ps' and 'docker compose logs db'."
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

function Invoke-DevelopmentWorkflow {
    Assert-TestDependencies

    Write-Section "Validate Docker Compose configuration"
    Invoke-CheckedCommand `
        -Executable "docker" `
        -Arguments @("compose", "config", "--quiet") `
        -FailureMessage "Docker Compose configuration validation failed"

    Write-Section "Start local database"
    Invoke-CheckedCommand `
        -Executable "docker" `
        -Arguments @("compose", "up", "-d", "db") `
        -FailureMessage "Docker Compose could not start the database"
    Wait-ForDatabase

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
        $backendProcess = Start-Process `
            -FilePath $script:BackendPython `
            -ArgumentList @("-m", "uvicorn", "app.main:app", "--reload", "--host", "127.0.0.1", "--port", "8000") `
            -WorkingDirectory $backendDirectory `
            -NoNewWindow `
            -PassThru

        $frontendProcess = Start-Process `
            -FilePath $npmCommand `
            -ArgumentList @("run", "dev", "--", "--port", "3000") `
            -WorkingDirectory $frontendDirectory `
            -NoNewWindow `
            -PassThru

        Write-Host ""
        Write-Host "Backend:        http://127.0.0.1:8000/"
        Write-Host "Backend health: http://127.0.0.1:8000/api/health"
        Write-Host "Backend version: http://127.0.0.1:8000/api/version"
        Write-Host "Frontend:       http://127.0.0.1:3000/"
        Write-Host ""
        Write-Host "Press Ctrl+C to stop the local backend and frontend. The database will remain running."

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
        Write-Success "Local backend and frontend stopped. The database container is still running."
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
            Invoke-Setup
            Install-MissingDependencies
            Invoke-ProjectTests
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
    Write-Host "[ERROR] $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}
