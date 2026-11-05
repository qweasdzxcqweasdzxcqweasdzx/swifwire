# Download official signed wintun.dll (0.14.1) into third_party/wintun/
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root
$url = "https://www.wintun.net/builds/wintun-0.14.1.zip"
$expect = "07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51"
$deps = Join-Path $root ".deps"
$outDir = Join-Path $root "third_party\wintun"
New-Item -ItemType Directory -Force -Path $deps, $outDir | Out-Null
$zip = Join-Path $deps "wintun-0.14.1.zip"

Write-Host "Downloading $url"
curl.exe -fsSL -o $zip $url
$hash = (Get-FileHash -Algorithm SHA256 $zip).Hash.ToLowerInvariant()
if ($hash -ne $expect) { throw "SHA256 mismatch: $hash" }

$extract = Join-Path $deps "wintun-extract"
if (Test-Path $extract) { Remove-Item -Recurse -Force $extract }
Expand-Archive -Path $zip -DestinationPath $extract -Force

$arch = if ([Environment]::Is64BitOperatingSystem) { "amd64" } else { "x86" }
$dll = Join-Path $extract "wintun\bin\$arch\wintun.dll"
if (-not (Test-Path $dll)) { throw "missing $dll" }
Copy-Item $dll (Join-Path $outDir "wintun.dll") -Force
# also next to debug binaries for os-tun
foreach ($d in @("target\debug", "target\release")) {
  $td = Join-Path $root $d
  if (Test-Path $td) {
    Copy-Item $dll (Join-Path $td "wintun.dll") -Force
  }
}
Write-Host "OK → third_party\wintun\wintun.dll ($arch)"
