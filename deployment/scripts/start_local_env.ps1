$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
$pidDir = Join-Path $repoRoot "deployment\output\pids"
if (-not (Test-Path -LiteralPath $pidDir)) {
    New-Item -ItemType Directory -Path $pidDir | Out-Null
}

function Test-PortListening {
    param(
        [Parameter(Mandatory = $true)]
        [int]$Port
    )
    $result = cmd /c "netstat -ano | findstr /R /C:"":$Port[ ]"""
    return ($LASTEXITCODE -eq 0 -and -not [string]::IsNullOrWhiteSpace($result))
}

function Start-Component {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,
        [int]$ListenPort = 0,
        [string]$ExecutablePathMatch = "",
        [Parameter(Mandatory = $true)]
        [string]$WorkDir,
        [Parameter(Mandatory = $true)]
        [string]$FilePath,
        [string]$ArgumentList = "",
        [Parameter(Mandatory = $true)]
        [string]$PidFile
    )

    if (Test-Path -LiteralPath $PidFile) {
        $pidText = (Get-Content -LiteralPath $PidFile -ErrorAction SilentlyContinue | Select-Object -First 1).Trim()
        $existingPid = 0
        if ([int]::TryParse($pidText, [ref]$existingPid)) {
            $existingProc = Get-Process -Id $existingPid -ErrorAction SilentlyContinue
            if ($null -ne $existingProc) {
                if ($ListenPort -gt 0) {
                    if (Test-PortListening -Port $ListenPort) {
                        Write-Host "[SKIP] $Name already running (pid $existingPid), listening on :$ListenPort"
                        return
                    }
                } else {
                    Write-Host "[SKIP] $Name already running (pid $existingPid)"
                    return
                }
            }
        }
    }

    if (-not [string]::IsNullOrWhiteSpace($ExecutablePathMatch)) {
        $normalized = $ExecutablePathMatch.ToLower()
        $alreadyRunning = Get-CimInstance -ClassName Win32_Process -ErrorAction SilentlyContinue |
            Where-Object { $_.ExecutablePath -and ($_.ExecutablePath.ToLower() -eq $normalized) } |
            Select-Object -First 1
        if ($null -ne $alreadyRunning) {
            Write-Host "[SKIP] $Name already running (pid $($alreadyRunning.ProcessId))"
            return
        }
    }

    if ($ListenPort -gt 0 -and (Test-PortListening -Port $ListenPort)) {
        Write-Host "[SKIP] $Name port :$ListenPort already in use"
        return
    }

    if (-not (Test-Path -LiteralPath $WorkDir)) {
        throw "[ERR] Missing working directory: $WorkDir"
    }
    if (-not (Get-Command $FilePath -ErrorAction SilentlyContinue) -and -not (Test-Path -LiteralPath $FilePath)) {
        throw "[ERR] Missing executable: $FilePath"
    }

    if ([string]::IsNullOrWhiteSpace($ArgumentList)) {
        $process = Start-Process -FilePath $FilePath -WorkingDirectory $WorkDir -WindowStyle Hidden -PassThru
    } else {
        $process = Start-Process -FilePath $FilePath -ArgumentList $ArgumentList -WorkingDirectory $WorkDir -WindowStyle Hidden -PassThru
    }

    [string]$process.Id | Set-Content -LiteralPath $PidFile -Encoding ASCII
    Start-Sleep -Seconds 2

    if ($ListenPort -gt 0 -and (Test-PortListening -Port $ListenPort)) {
        Write-Host "[OK] $Name started on :$ListenPort (pid $($process.Id))"
    } else {
        Write-Host "[OK] $Name process started (pid $($process.Id))"
    }
}

Start-Component -Name "alert_server" `
    -ListenPort 9090 `
    -ExecutablePathMatch (Join-Path $repoRoot "alert_server\alert_server.exe") `
    -WorkDir (Join-Path $repoRoot "alert_server") `
    -FilePath (Join-Path $repoRoot "alert_server\alert_server.exe") `
    -PidFile (Join-Path $pidDir "alert_server.pid")

Start-Component -Name "systemwire2" `
    -ListenPort 5001 `
    -WorkDir (Join-Path $repoRoot "systemwire2") `
    -FilePath "python" `
    -ArgumentList "app.py" `
    -PidFile (Join-Path $pidDir "systemwire2.pid")

Start-Component -Name "agent-go" `
    -ExecutablePathMatch (Join-Path $repoRoot "agent-go\agent-go.exe") `
    -WorkDir (Join-Path $repoRoot "agent-go") `
    -FilePath (Join-Path $repoRoot "agent-go\agent-go.exe") `
    -PidFile (Join-Path $pidDir "agent-go.pid")

Start-Component -Name "js-bot" `
    -ListenPort 8080 `
    -ExecutablePathMatch (Join-Path $repoRoot "js\latest\bot\bot.exe") `
    -WorkDir (Join-Path $repoRoot "js\latest\bot") `
    -FilePath (Join-Path $repoRoot "js\latest\bot\bot.exe") `
    -PidFile (Join-Path $pidDir "js-bot.pid")

Write-Host ""
Write-Host "Local environment start sequence finished."
Write-Host "Run: powershell -ExecutionPolicy Bypass -File deployment/scripts/check_local_env.ps1"
