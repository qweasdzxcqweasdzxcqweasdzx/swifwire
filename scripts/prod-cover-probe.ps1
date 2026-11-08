# Prod-oriented cover probe: without pub → cover HTTP (no SWI1); timing band; with pub → SOCKS 200.
# Lab default uses SWIF_LAB builtin cover. For real upstream, set SWIF_COVER_UPSTREAM=host:port
# and provide PEM via SWIF_TLS_CERT / SWIF_TLS_KEY (then clears SWIF_LAB).
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$env:Path = "$env:USERPROFILE\.cargo\bin;" + $env:Path
Set-Location $root

$useLab = -not ($env:SWIF_TLS_CERT -and $env:SWIF_TLS_KEY -and $env:SWIF_COVER_UPSTREAM)
if ($useLab) {
  $env:SWIF_LAB = "1"
  Write-Host "prod-cover-probe: LAB mode (builtin cover). Set SWIF_TLS_CERT/KEY + SWIF_COVER_UPSTREAM for real origin."
} else {
  Remove-Item Env:SWIF_LAB -ErrorAction SilentlyContinue
  Write-Host "prod-cover-probe: PROD mode cover=$($env:SWIF_COVER_UPSTREAM)"
}

cargo build -p swif-edge -p swif-cli --quiet
Get-Process swif-edge,swif-cli -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
Remove-Item "server.key","server.pub","edge.err","edge.out","cli.err","cli.out","lab-cert.der.json","probe.out","probe.body.txt" -ErrorAction SilentlyContinue

$edgeArgs = @("--listen","127.0.0.1:9443","--key","server.key","--pub-out","server.pub","--mask","tls13_stable","--sni","cover.local")
if (-not $useLab) {
  $edgeArgs += @("--tls-cert",$env:SWIF_TLS_CERT,"--tls-key",$env:SWIF_TLS_KEY,"--cover",$env:SWIF_COVER_UPSTREAM)
}

$edge = Start-Process -PassThru -WorkingDirectory $root -WindowStyle Hidden `
  -FilePath ".\target\debug\swif-edge.exe" `
  -ArgumentList $edgeArgs `
  -RedirectStandardError "edge.err" -RedirectStandardOutput "edge.out"

$deadline = (Get-Date).AddSeconds(20)
while (-not (Test-Path "server.pub")) {
  if ((Get-Date) -gt $deadline) {
    Get-Content "edge.err" -ErrorAction SilentlyContinue
    throw "no server.pub"
  }
  Start-Sleep -Milliseconds 200
}
if ($useLab) {
  while (-not (Test-Path "lab-cert.der.json")) {
    if ((Get-Date) -gt $deadline) { throw "no lab-cert" }
    Start-Sleep -Milliseconds 200
  }
}

try {
  $sw = [System.Diagnostics.Stopwatch]::StartNew()
  $probe = curl.exe -sk --connect-timeout 8 --max-time 12 `
    --resolve "cover.local:9443:127.0.0.1" `
    "https://cover.local:9443/" -D - -o "probe.body.txt" 2>&1 | Out-String
  $sw.Stop()
  $probeMs = $sw.ElapsedMilliseconds
  Set-Content -Path "probe.out" -Value $probe
  $body = Get-Content "probe.body.txt" -Raw -ErrorAction SilentlyContinue
  if ($body -notmatch "cover origin" -and $probe -notmatch "HTTP/1\.[01] 200" -and $probe -notmatch "HTTP/2 200") {
    Write-Host $probe; Write-Host $body
    Get-Content "edge.err" -ErrorAction SilentlyContinue
    throw "probe did not get cover HTTP 200"
  }
  if ("$body$probe" -match "SWI1") { throw "probe leaked SWI1" }
  # Timing band: lab cover should be quick; soft warn if > 3s (not fail — CI variance).
  if ($probeMs -gt 3000) {
    Write-Host "WARN probe_rtt_ms=$probeMs (expected <3000 lab)"
  } else {
    Write-Host "PROBE_RTT_MS=$probeMs"
  }
  Write-Host "PROD COVER PROBE OK"

  $tlsMat = if ($useLab) { "lab-cert.der.json" } else { $env:SWIF_TLS_MATERIAL }
  if (-not $tlsMat) { $tlsMat = "lab-cert.der.json" }
  $cli = Start-Process -PassThru -WorkingDirectory $root -WindowStyle Hidden `
    -FilePath ".\target\debug\swif-cli.exe" `
    -ArgumentList "--server","127.0.0.1:9443","--pub-file","server.pub","--socks","127.0.0.1:11084","--mask","tls13_stable","--tls-material",$tlsMat `
    -RedirectStandardError "cli.err" -RedirectStandardOutput "cli.out"
  Start-Sleep -Seconds 2
  $r = curl.exe -s -o NUL -w "%{http_code}" --connect-timeout 10 --max-time 25 -x socks5h://127.0.0.1:11084 http://example.com/
  Write-Host "AUTH SOCKS HTTP $r"
  if ($r -ne "200") {
    Get-Content "cli.err","edge.err" -ErrorAction SilentlyContinue
    throw "expected 200 got $r"
  }
  Write-Host "PROD COVER AUTH OK"
  Stop-Process -Id $cli.Id -Force -ErrorAction SilentlyContinue
} finally {
  Stop-Process -Id $edge.Id -Force -ErrorAction SilentlyContinue
  Get-Process swif-cli -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
}
