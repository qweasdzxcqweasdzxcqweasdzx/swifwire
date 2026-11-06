# Run all lab smokes (null paths + core). Sets SWIF_ALLOW_NULL=1 for lab.
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$env:Path = "$env:USERPROFILE\.cargo\bin;" + $env:Path
$env:SWIF_ALLOW_NULL = "1"
$env:SWIF_LAB = "1"
Set-Location $root

Get-Process swif-edge,swif-cli,swif-core-run -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 1

$scripts = @(
  "smoke-socks.ps1",
  "smoke-tls.ps1",
  "smoke-probe-cover.ps1",
  "smoke-udp.ps1",
  "smoke-tun.ps1",
  "smoke-core.ps1"
)
foreach ($s in $scripts) {
  Write-Host "=== $s ==="
  powershell -ExecutionPolicy Bypass -File (Join-Path $PSScriptRoot $s)
  if ($LASTEXITCODE -ne 0) { throw "failed $s" }
}
Write-Host "ALL SMOKES OK"
