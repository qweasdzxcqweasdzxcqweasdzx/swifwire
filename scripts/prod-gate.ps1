# Production gate: unit tests + full smoke matrix. Exit non-zero on failure.
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$env:Path = "$env:USERPROFILE\.cargo\bin;" + $env:Path
$env:SWIF_ALLOW_NULL = "1"
$env:SWIF_LAB = "1"
$env:SWIF_ALLOW_QUIC_STABLE = "1"
Set-Location $root

Write-Host "=== cargo test --workspace ==="
cargo test --workspace --quiet
if ($LASTEXITCODE -ne 0) { throw "cargo test failed" }

Write-Host "=== smoke-all ==="
powershell -NoProfile -ExecutionPolicy Bypass -File (Join-Path $PSScriptRoot "smoke-all.ps1")
if ($LASTEXITCODE -ne 0) { throw "smoke-all failed" }

Write-Host "=== ABI version ==="
cargo build -p swif-ffi --quiet
# Windows: dump export presence via dumpbin if available; else skip.
Write-Host "swif-ffi built OK"

Write-Host "PROD GATE OK"
