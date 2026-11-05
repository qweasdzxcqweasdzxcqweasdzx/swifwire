# TUN L3 echo smoke via NullTun ↔ edge (no admin). Optional: fetch-wintun + os-tun open.
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$env:Path = "$env:USERPROFILE\.cargo\bin;" + $env:Path
Set-Location $root

cargo build -p swif-edge -p swif-cli --quiet
Remove-Item "server.key","server.pub","edge.err","edge.out" -ErrorAction SilentlyContinue

$edge = Start-Process -PassThru -WorkingDirectory $root -WindowStyle Hidden `
  -FilePath ".\target\debug\swif-edge.exe" `
  -ArgumentList "--listen","127.0.0.1:9443","--key","server.key","--pub-out","server.pub","--mask","null_tcp" `
  -RedirectStandardError "edge.err" -RedirectStandardOutput "edge.out"

$deadline = (Get-Date).AddSeconds(10)
while (-not (Test-Path "server.pub")) {
  if ((Get-Date) -gt $deadline) { throw "no server.pub" }
  Start-Sleep -Milliseconds 200
}

try {
  $out = & ".\target\debug\swif-cli.exe" --server 127.0.0.1:9443 --pub-file server.pub --tun-smoke 2>&1
  Write-Host $out
  if ("$out" -notmatch "TUN_SMOKE OK") {
    Get-Content "edge.err" -ErrorAction SilentlyContinue
    throw "tun smoke failed"
  }
  Write-Host "SMOKE TUN OK"
} finally {
  Stop-Process -Id $edge.Id -Force -ErrorAction SilentlyContinue
}
