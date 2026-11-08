# Generate CycloneDX-ish SBOM from cargo metadata (no extra tooling required).
# Output: dist/sbom-cargo.json  (+ optional cyclonedx if cargo-cyclonedx installed)
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$env:Path = "$env:USERPROFILE\.cargo\bin;" + $env:Path
Set-Location $root

$outDir = Join-Path $root "dist"
New-Item -ItemType Directory -Force -Path $outDir | Out-Null
$meta = Join-Path $outDir "sbom-cargo-metadata.json"
$sbom = Join-Path $outDir "sbom-cargo.json"

cargo metadata --format-version 1 | Out-File -Encoding utf8 $meta
$j = Get-Content $meta -Raw | ConvertFrom-Json
$ver = (Get-Content VERSION -Raw).Trim()
$pkgs = @()
foreach ($p in $j.packages) {
  $pkgs += [ordered]@{
    name = $p.name
    version = $p.version
    id = $p.id
    license = $p.license
    source = $p.source
  }
}
$doc = [ordered]@{
  bomFormat = "CycloneDX"
  specVersion = "1.5"
  version = 1
  metadata = @{
    component = @{
      type = "application"
      name = "swifwire"
      version = $ver
    }
    tools = @(@{ name = "scripts/sbom.ps1"; vendor = "SwifTun" })
  }
  components = $pkgs
}
($doc | ConvertTo-Json -Depth 8) | Set-Content -Encoding utf8 $sbom
Write-Host "SBOM OK $sbom ($($pkgs.Count) components)"

if (Get-Command cargo-cyclonedx -ErrorAction SilentlyContinue) {
  cargo cyclonedx -f json --output-cdx (Join-Path $outDir "sbom-cyclonedx.json") 2>$null
  Write-Host "Also wrote cyclonedx via cargo-cyclonedx"
}
