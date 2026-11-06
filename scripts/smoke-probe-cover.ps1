# Probe vs auth: without SwifWire key → HTTP cover; with key → SOCKS HTTP 200.
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$env:Path = "$env:USERPROFILE\.cargo\bin;" + $env:Path
$env:SWIF_LAB = "1"
Set-Location $root

cargo build -p swif-edge -p swif-cli --quiet
Get-Process swif-edge,swif-cli -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
Remove-Item "server.key","server.pub","edge.err","edge.out","cli.err","cli.out","lab-cert.der.json","probe.out" -ErrorAction SilentlyContinue

$edge = Start-Process -PassThru -WorkingDirectory $root -WindowStyle Hidden `
  -FilePath ".\target\debug\swif-edge.exe" `
  -ArgumentList "--listen","127.0.0.1:9443","--key","server.key","--pub-out","server.pub","--mask","tls13_stable" `
  -RedirectStandardError "edge.err" -RedirectStandardOutput "edge.out"

$deadline = (Get-Date).AddSeconds(15)
while (-not ((Test-Path "server.pub") -and (Test-Path "lab-cert.der.json"))) {
  if ((Get-Date) -gt $deadline) {
    Get-Content "edge.err" -ErrorAction SilentlyContinue
    throw "no server.pub / lab-cert"
  }
  Start-Sleep -Milliseconds 200
}

try {
  # Active probe: TLS to edge SNI, plain HTTP GET inside — expect cover HTML (no SWI1).
  $probe = curl.exe -sk --connect-timeout 8 --max-time 12 `
    --resolve "cover.local:9443:127.0.0.1" `
    "https://cover.local:9443/" -D - -o "probe.body.txt" 2>&1 | Out-String
  Set-Content -Path "probe.out" -Value $probe
  $body = Get-Content "probe.body.txt" -Raw -ErrorAction SilentlyContinue
  if ($body -notmatch "cover origin" -and $probe -notmatch "HTTP/1.1 200") {
    Write-Host "--- probe ---"; Write-Host $probe; Write-Host $body
    Write-Host "--- edge ---"; Get-Content "edge.err" -ErrorAction SilentlyContinue
    throw "probe did not get cover HTTP 200"
  }
  if ("$body$probe" -match "SWI1") {
    throw "probe response leaked SWI1 magic"
  }
  Write-Host "PROBE COVER OK"

  $cli = Start-Process -PassThru -WorkingDirectory $root -WindowStyle Hidden `
    -FilePath ".\target\debug\swif-cli.exe" `
    -ArgumentList "--server","127.0.0.1:9443","--pub-file","server.pub","--socks","127.0.0.1:11083","--mask","tls13_stable","--tls-material","lab-cert.der.json" `
    -RedirectStandardError "cli.err" -RedirectStandardOutput "cli.out"
  Start-Sleep -Seconds 2
  $r = curl.exe -s -o NUL -w "%{http_code}" --connect-timeout 10 --max-time 25 -x socks5h://127.0.0.1:11083 http://example.com/
  Write-Host "AUTH SOCKS HTTP $r"
  if ($r -ne "200") {
    Get-Content "cli.err","edge.err" -ErrorAction SilentlyContinue
    throw "expected 200 got $r"
  }
  Write-Host "SMOKE PROBE-COVER OK"
  Stop-Process -Id $cli.Id -Force -ErrorAction SilentlyContinue
} finally {
  Stop-Process -Id $edge.Id -Force -ErrorAction SilentlyContinue
  Get-Process swif-cli -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
}
