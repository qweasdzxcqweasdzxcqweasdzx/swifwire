# Build commercial Windows x64 package into dist/swifwire-win-x64
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$env:Path = "$env:USERPROFILE\.cargo\bin;" + $env:Path
Set-Location $root

$ver = (Get-Content VERSION -Raw).Trim()
$out = Join-Path $root "dist\swifwire-win-x64"
if (Test-Path $out) { Remove-Item -Recurse -Force $out }
New-Item -ItemType Directory -Force -Path $out, (Join-Path $out "include"), (Join-Path $out "deploy"), (Join-Path $out "docs") | Out-Null

if ($env:SWIF_SKIP_GATE -ne "1") {
  Write-Host "Running prod-gate (set SWIF_SKIP_GATE=1 to skip) ..."
  powershell -NoProfile -ExecutionPolicy Bypass -File (Join-Path $PSScriptRoot "prod-gate.ps1")
  if ($LASTEXITCODE -ne 0) { throw "prod-gate failed" }
}

Write-Host "Building release $ver ..."
cargo build --release -p swif-edge -p swif-cli -p swif-core -p swif-ffi -p swif-tray -p swif-mask --quiet

$bin = Join-Path $root "target\release"
Copy-Item "$bin\swif-edge.exe","$bin\swif-cli.exe","$bin\swif-core-run.exe","$bin\swif-tray.exe","$bin\swif-pack.exe","$bin\swifwire.dll" $out
Copy-Item (Join-Path $root "include\swifwire.h") (Join-Path $out "include\")
Copy-Item (Join-Path $root "deploy\*") (Join-Path $out "deploy\") -Force
New-Item -ItemType Directory -Force -Path (Join-Path $out "packs") | Out-Null
Copy-Item (Join-Path $root "packs\*") (Join-Path $out "packs\") -Force -ErrorAction SilentlyContinue
Copy-Item (Join-Path $root "docs\EMBED.md"),(Join-Path $root "docs\COMMERCIAL.md"),(Join-Path $root "docs\EDGE_RUNBOOK.md"),(Join-Path $root "docs\CLIENT_SDK.md"),(Join-Path $root "docs\SERVER_OPS.md") (Join-Path $out "docs\")
Copy-Item (Join-Path $root "README.md"),(Join-Path $root "VERSION"),(Join-Path $root "CHANGELOG.md") $out
Copy-Item (Join-Path $root "scripts\tray-lab.ps1"),(Join-Path $root "scripts\fetch-wintun.ps1"),(Join-Path $root "scripts\prod-gate.ps1") $out -ErrorAction SilentlyContinue

# optional wintun
if (-not (Test-Path "third_party\wintun\wintun.dll")) {
  try { powershell -ExecutionPolicy Bypass -File .\scripts\fetch-wintun.ps1 } catch { Write-Host "wintun fetch skipped: $_" }
}
if (Test-Path "third_party\wintun\wintun.dll") {
  Copy-Item "third_party\wintun\wintun.dll" $out
}

$zip = Join-Path $root "dist\swifwire-win-x64-$ver.zip"
if (Test-Path $zip) { Remove-Item $zip -Force }
Compress-Archive -Path $out -DestinationPath $zip -Force
Write-Host "OK $out"
Write-Host "OK $zip"
