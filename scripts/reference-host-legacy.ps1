# Reference host contract: when core status carries legacy_fallback_hint, EXECUTE it.
# This sample only prints the URI (does not dial VLESS). Wire your VPN UI here.

param(
  [string]$ConfigPath = "deploy/client.prod.example.json"
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

Write-Host "Reference host legacy contract"
Write-Host "1) Start swif-core-run with config that sets legacy_fallback_uri"
Write-Host "2) Poll status JSON; if dials exhaust, hint is set"
Write-Host "3) Host MUST open/dial that URI with the legacy stack (xray/sing-box)"
Write-Host ""
Write-Host "C ABI: char* uri = swif_core_legacy_fallback_alloc(&err);"
Write-Host "       if (uri && uri[0]) { /* EXECUTE legacy share */ }"
Write-Host "       swif_string_free(uri);"
Write-Host ""
if (Test-Path $ConfigPath) {
  $j = Get-Content $ConfigPath -Raw | ConvertFrom-Json
  if ($j.legacy_fallback_uri) {
    Write-Host ("EXAMPLE_EXECUTE_LEGACY=" + $j.legacy_fallback_uri)
  } else {
    Write-Host "Config has no legacy_fallback_uri - add one for dual-stack."
  }
}
Write-Host "REFERENCE_HOST_CONTRACT OK"
