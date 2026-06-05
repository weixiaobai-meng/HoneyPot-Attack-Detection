$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
$pidDir = Join-Path $repoRoot "deployment\output\pids"

function Stop-ByPidFile {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,
        [Parameter(Mandatory = $true)]
        [string]$PidFile
    )

    if (-not (Test-Path -LiteralPath $PidFile)) {
        Write-Host "[SKIP] $Name pid file not found."
        return
    }

    $pidText = (Get-Content -LiteralPath $PidFile -ErrorAction SilentlyContinue | Select-Object -First 1).Trim()
    if ([string]::IsNullOrWhiteSpace($pidText)) {
        Remove-Item -LiteralPath $PidFile -Force -ErrorAction SilentlyContinue
        Write-Host "[WARN] $Name pid file is empty. removed."
        return
    }

    $targetPid = 0
    if (-not [int]::TryParse($pidText, [ref]$targetPid)) {
        Remove-Item -LiteralPath $PidFile -Force -ErrorAction SilentlyContinue
        Write-Host "[WARN] $Name pid file invalid. removed."
        return
    }

    $proc = Get-Process -Id $targetPid -ErrorAction SilentlyContinue
    if ($null -eq $proc) {
        Remove-Item -LiteralPath $PidFile -Force -ErrorAction SilentlyContinue
        Write-Host "[SKIP] $Name process already stopped."
        return
    }

    Stop-Process -Id $targetPid -Force -ErrorAction SilentlyContinue
    Start-Sleep -Milliseconds 300
    Remove-Item -LiteralPath $PidFile -Force -ErrorAction SilentlyContinue
    Write-Host "[OK] $Name stopped (pid $targetPid)"
}

Stop-ByPidFile -Name "js-bot" -PidFile (Join-Path $pidDir "js-bot.pid")
Stop-ByPidFile -Name "agent-go" -PidFile (Join-Path $pidDir "agent-go.pid")
Stop-ByPidFile -Name "systemwire2" -PidFile (Join-Path $pidDir "systemwire2.pid")
Stop-ByPidFile -Name "alert_server" -PidFile (Join-Path $pidDir "alert_server.pid")

Write-Host ""
Write-Host "Local environment stop sequence finished."
