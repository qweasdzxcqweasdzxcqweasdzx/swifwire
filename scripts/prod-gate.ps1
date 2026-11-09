# Production gate 0.5.0: workspace tests + craft e2e + vectors + smokes + cover-probe + ABI.
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

Write-Host "=== craft dial e2e ==="
cargo test -p swif-mask --test craft_dial_e2e --quiet
if ($LASTEXITCODE -ne 0) { throw "craft_dial_e2e failed" }

Write-Host "=== vectors / ja4 corpus ==="
cargo test -p swif-crypto --test vectors --quiet
if ($LASTEXITCODE -ne 0) { throw "crypto vectors failed" }
cargo test -p swif-mask --test ja4_corpus --quiet
if ($LASTEXITCODE -ne 0) { throw "ja4 corpus failed" }
cargo test -p swif-session --test negative_hs --quiet
if ($LASTEXITCODE -ne 0) { throw "negative_hs failed" }

Write-Host "=== smoke-all ==="
powershell -NoProfile -ExecutionPolicy Bypass -File (Join-Path $PSScriptRoot "smoke-all.ps1")
if ($LASTEXITCODE -ne 0) { throw "smoke-all failed" }

Write-Host "=== smoke-prod-0.5 (PEM+cover+ticket-master) ==="
powershell -NoProfile -ExecutionPolicy Bypass -File (Join-Path $PSScriptRoot "smoke-prod-0.5.ps1")
if ($LASTEXITCODE -ne 0) { throw "smoke-prod-0.5 failed" }

Write-Host "=== prod-cover-probe ==="
powershell -NoProfile -ExecutionPolicy Bypass -File (Join-Path $PSScriptRoot "prod-cover-probe.ps1")
if ($LASTEXITCODE -ne 0) { throw "prod-cover-probe failed" }

Write-Host "=== reference-host contract ==="
powershell -NoProfile -ExecutionPolicy Bypass -File (Join-Path $PSScriptRoot "reference-host-legacy.ps1")
if ($LASTEXITCODE -ne 0) { throw "reference-host failed" }

Write-Host "=== ABI / ffi + SBOM ==="
cargo build -p swif-ffi --quiet
powershell -NoProfile -ExecutionPolicy Bypass -File (Join-Path $PSScriptRoot "sbom.ps1")
Write-Host "swif-ffi + sbom OK"

Write-Host "PROD GATE OK (0.5.0)"
