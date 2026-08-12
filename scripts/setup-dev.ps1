<#
.SYNOPSIS
Developer setup helper for the Cyber OSINT Dashboard / Alpha Data project.

.DESCRIPTION
This script helps a developer prepare their local environment safely.

It can:
- Check required tools.
- Optionally install recommended VS Code extensions.
- Create local environment files from .env.example files if missing.
- Optionally create the backend Python virtual environment.
- Optionally install backend and frontend dependencies.

Security rules:
- This script does not hardcode real secrets.
- This script does not overwrite existing .env files.
- This script does not push code to Git.
- This script does not start ingestion jobs or fetch cybersecurity data.
#>

[CmdletBinding()]
param(
    [switch]$InstallVSCodeExtensions,
    [switch]$InstallDependencies
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Write-Section {
    param([string]$Message)
    Write-Host ""
    Write-Host "==== $Message ====" -ForegroundColor Cyan
}

function Write-Success {
    param([string]$Message)
    Write-Host "[OK] $Message" -ForegroundColor Green
}

function Write-WarningMessage {
    param([string]$Message)
    Write-Host "[WARN] $Message" -ForegroundColor Yellow
}

function Test-CommandExists {
    param([string]$CommandName)

    $command = Get-Command $CommandName -ErrorAction SilentlyContinue

    if ($null -eq $command) {
        Write-WarningMessage "$CommandName was not found in PATH."
        return $false
    }

    Write-Success "$CommandName found."
    return $true
}

function Copy-ExampleEnvFile {
    param(
        [string]$ExamplePath,
        [string]$TargetPath
    )

    if (-not (Test-Path $ExamplePath)) {
        Write-WarningMessage "Example file not found: $ExamplePath"
        return
    }

    if (Test-Path $TargetPath) {
        Write-Success "Environment file already exists and was not overwritten: $TargetPath"
        return
    }

    Copy-Item $ExamplePath $TargetPath
    Write-Success "Created local environment file from example: $TargetPath"
}

function New-CryptographicLocalSecret {
    $secretBytes = New-Object byte[] 32
    $generator = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try {
        $generator.GetBytes($secretBytes)
    }
    finally {
        $generator.Dispose()
    }

    return [Convert]::ToBase64String($secretBytes).TrimEnd("=").Replace("+", "-").Replace("/", "_")
}

function New-LocalRootEnvironmentFile {
    param(
        [Parameter(Mandatory)][string]$ExamplePath,
        [Parameter(Mandatory)][string]$TargetPath
    )

    if (-not (Test-Path -LiteralPath $ExamplePath -PathType Leaf)) {
        Write-WarningMessage "Example file not found: $ExamplePath"
        return
    }
    if (Test-Path -LiteralPath $TargetPath) {
        Write-Success "Environment file already exists and was not overwritten: $TargetPath"
        return
    }

    $secretNames = @(
        "POSTGRES_PASSWORD",
        "POSTGRES_BOOTSTRAP_PASSWORD",
        "POSTGRES_MIGRATION_PASSWORD"
    )
    $generatedSecrets = @{}
    foreach ($secretName in $secretNames) {
        do {
            $generatedSecret = New-CryptographicLocalSecret
        } while ($generatedSecrets.Values -contains $generatedSecret)
        $generatedSecrets[$secretName] = $generatedSecret
    }

    $environmentContent = [System.IO.File]::ReadAllText($ExamplePath)
    foreach ($secretName in $secretNames) {
        $fieldPattern = "(?m)^$([regex]::Escape($secretName))=.*$"
        if ([regex]::Matches($environmentContent, $fieldPattern).Count -ne 1) {
            throw "Local environment template field is missing or duplicated: $secretName."
        }
        $environmentContent = [regex]::Replace(
            $environmentContent,
            $fieldPattern,
            "$secretName=$($generatedSecrets[$secretName])"
        )
    }

    $encoding = New-Object System.Text.UTF8Encoding($false)
    $contentBytes = $encoding.GetBytes($environmentContent)
    $targetStream = [System.IO.File]::Open(
        $TargetPath,
        [System.IO.FileMode]::CreateNew,
        [System.IO.FileAccess]::Write,
        [System.IO.FileShare]::None
    )
    try {
        $targetStream.Write($contentBytes, 0, $contentBytes.Length)
    }
    finally {
        $targetStream.Dispose()
    }

    Write-Success "Created local environment file with generated database credentials: $TargetPath"
}

Write-Section "Cyber OSINT Dashboard / Alpha Data setup"

$ProjectRoot = Resolve-Path "$PSScriptRoot\.."
Set-Location $ProjectRoot

Write-Success "Project root: $ProjectRoot"

Write-Section "Checking required tools"

$hasGit = Test-CommandExists "git"
$hasPythonLauncher = Test-CommandExists "py"
$hasNode = Test-CommandExists "node"
$hasNpm = Test-CommandExists "npm"
$hasDocker = Test-CommandExists "docker"
$hasCode = Test-CommandExists "code"

if ($hasGit) {
    git --version
}

if ($hasPythonLauncher) {
    try {
        py -3.13 --version
        Write-Success "Python 3.13 is available through the Python launcher."
    }
    catch {
        Write-WarningMessage "Python 3.13 was not found. Install Python 3.13 before backend dependency setup."
    }
}

if ($hasNode) {
    node -v
}

if ($hasNpm) {
    npm -v
}

if ($hasDocker) {
    docker --version

    try {
        docker compose version
        Write-Success "Docker Compose is available."
    }
    catch {
        Write-WarningMessage "Docker Compose was not found or Docker Desktop is not running."
    }
}

if ($hasCode) {
    code --version
}

if ($InstallVSCodeExtensions) {
    Write-Section "Installing recommended VS Code extensions"

    if (-not $hasCode) {
        Write-WarningMessage "VS Code CLI command 'code' was not found. Skipping extension installation."
    }
    else {
        $extensions = @(
            "ms-python.python",
            "ms-python.vscode-pylance",
            "dbaeumer.vscode-eslint",
            "esbenp.prettier-vscode",
            "ms-azuretools.vscode-docker",
            "ckolkman.vscode-postgres",
            "eamodio.gitlens",
            "mikestead.dotenv",
            "yzhang.markdown-all-in-one"
        )

        foreach ($extension in $extensions) {
            Write-Host "Installing/checking extension: $extension"
            code --install-extension $extension
        }

        Write-Success "VS Code extension setup completed."
    }
}

Write-Section "Creating local environment files if missing"

New-LocalRootEnvironmentFile ".env.example" ".env"
Copy-ExampleEnvFile "backend\.env.example" "backend\.env"
Copy-ExampleEnvFile "frontend\.env.example" "frontend\.env.local"

Write-Section "Dependency setup"

if ($InstallDependencies) {
    Write-Host "Dependency installation was requested."

    if ($hasPythonLauncher) {
        if (-not (Test-Path "backend\.venv")) {
            Write-Host "Creating backend Python virtual environment using Python 3.13..."
            py -3.13 -m venv backend\.venv
            Write-Success "Backend virtual environment created."
        }
        else {
            Write-Success "Backend virtual environment already exists."
        }

        $backendPython = "backend\.venv\Scripts\python.exe"

        if (Test-Path $backendPython) {
            Write-Host "Installing backend Python dependencies..."
            & $backendPython -m pip install --upgrade pip
            & $backendPython -m pip install -r backend\requirements.txt
            Write-Success "Backend dependencies installed."
        }
        else {
            Write-WarningMessage "Backend Python executable was not found at $backendPython"
        }
    }
    else {
        Write-WarningMessage "Python launcher not found. Skipping backend dependency installation."
    }

    if ($hasNpm) {
        Write-Host "Installing frontend npm dependencies..."
        Push-Location frontend
        npm install
        Pop-Location
        Write-Success "Frontend dependencies installed."
    }
    else {
        Write-WarningMessage "npm not found. Skipping frontend dependency installation."
    }
}
else {
    Write-Host "Dependency installation was not requested."
    Write-Host "To install dependencies later, run:"
    Write-Host ".\scripts\setup-dev.ps1 -InstallDependencies"
}

Write-Section "Next recommended commands"

Write-Host "Check repository status:"
Write-Host "git status"

Write-Host ""
Write-Host "Validate Docker Compose configuration:"
Write-Host "docker compose config --quiet"

Write-Host ""
Write-Host "Install VS Code extensions with:"
Write-Host ".\scripts\setup-dev.ps1 -InstallVSCodeExtensions"

Write-Host ""
Write-Host "Install dependencies with:"
Write-Host ".\scripts\setup-dev.ps1 -InstallDependencies"

Write-Host ""
Write-Success "Setup helper completed."
