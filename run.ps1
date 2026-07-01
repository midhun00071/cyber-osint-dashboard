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
