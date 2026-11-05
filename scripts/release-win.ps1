# Build commercial Windows x64 package into dist/swifwire-win-x64
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$env:Path = "$env:USERPROFILE\.cargo\bin;" + $env:Path
Set-Location $root

$ver = (Get-Content VERSION -Raw).Trim()
$out = Join-Path $root "dist\swifwire-win-x64"
if (Test-Path $out) { Remove-Item -Recurse -Force $out }
New-Item -ItemType Directory -Force -Path $out, (Join-Path $out "include"), (Join-Path $out "deploy"), (Join-Path $out "docs") | Out-Null

Write-Host "Building release $ver ..."
cargo build --release -p swif-edge -p swif-cli -p swif-core -p swif-ffi -p swif-tray --quiet

$bin = Join-Path $root "target\release"
Copy-Item "$bin\swif-edge.exe","$bin\swif-cli.exe","$bin\swif-core-run.exe","$bin\swif-tray.exe","$bin\swifwire.dll" $out
Copy-Item (Join-Path $root "include\swifwire.h") (Join-Path $out "include\")
Copy-Item (Join-Path $root "deploy\*") (Join-Path $out "deploy\") -Force
Copy-Item (Join-Path $root "docs\EMBED.md"),(Join-Path $root "docs\COMMERCIAL.md"),(Join-Path $root "docs\EDGE_RUNBOOK.md") (Join-Path $out "docs\")
Copy-Item (Join-Path $root "README.md"),(Join-Path $root "VERSION"),(Join-Path $root "CHANGELOG.md") $out
Copy-Item (Join-Path $root "scripts\tray-lab.ps1"),(Join-Path $root "scripts\fetch-wintun.ps1") $out -ErrorAction SilentlyContinue

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
