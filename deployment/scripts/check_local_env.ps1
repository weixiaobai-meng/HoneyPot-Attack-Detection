$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

function Test-PortListening {
    param(
        [Parameter(Mandatory = $true)]
        [int]$Port
    )
    $result = cmd /c "netstat -ano | findstr /R /C:"":$Port[ ]"""
    return ($LASTEXITCODE -eq 0 -and -not [string]::IsNullOrWhiteSpace($result))
}

function Test-Http {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Url
    )
    try {
        $res = Invoke-WebRequest -Uri $Url -UseBasicParsing -TimeoutSec 5
        return "HTTP $($res.StatusCode)"
    } catch {
        if ($_.Exception.Response -and $_.Exception.Response.StatusCode) {
            return "HTTP $([int]$_.Exception.Response.StatusCode)"
        }
        return "ERR"
    }
}

$checks = @(
    @{ Name = "systemwire-web"; Port = 5001; Url = "http://127.0.0.1:5001/manage/" },
    @{ Name = "systemwire-grpc"; Port = 50051; Url = "" },
    @{ Name = "js-bot"; Port = 8080; Url = "http://127.0.0.1:8080/" },
    @{ Name = "alert-public"; Port = 9090; Url = "http://127.0.0.1:9090/" },
    @{ Name = "alert-admin"; Port = 9091; Url = "http://127.0.0.1:9091/" }
)

Write-Host "Component          Port   Listening   HTTP"
Write-Host "-----------------------------------------------"

foreach ($item in $checks) {
    $listening = if (Test-PortListening -Port $item.Port) { "YES" } else { "NO" }
    $httpStatus = "-"
    if (-not [string]::IsNullOrWhiteSpace($item.Url)) {
        $httpStatus = Test-Http -Url $item.Url
    }
    "{0,-18} {1,-6} {2,-10} {3}" -f $item.Name, $item.Port, $listening, $httpStatus | Write-Host
}

Write-Host ""
Write-Host "Unified alerts API test:"
try {
    $alerts = Invoke-WebRequest -Uri "http://127.0.0.1:5001/api/alerts/unified?hours=24" -UseBasicParsing -TimeoutSec 5
    Write-Host ("OK " + $alerts.StatusCode)
} catch {
    Write-Host ("ERR " + $_.Exception.Message)
}
