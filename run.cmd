@echo off
where PowerShell.exe >nul 2>&1
if errorlevel 1 (
  echo [BLOCKED] Windows PowerShell is required. Install or enable Windows PowerShell and retry.
  exit /b 1
)
PowerShell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0run.ps1" %*
exit /b %ERRORLEVEL%
