# Crude lab throughput: direct HTTP download vs via SwifWire SOCKS (null_tcp).
# Target DoD: tunnel >= 70% of direct (best-effort; network dependent).
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$env:Path = "$env:USERPROFILE\.cargo\bin;" + $env:Path
Set-Location $root

$url = "http://speedtest.tele2.net/1MB.zip"
cargo build -p swif-edge -p swif-cli --quiet
Remove-Item "server.key","server.pub","edge.err","edge.out","cli.err","cli.out" -ErrorAction SilentlyContinue

$edge = Start-Process -PassThru -WorkingDirectory $root -WindowStyle Hidden `
  -FilePath ".\target\debug\swif-edge.exe" `
  -ArgumentList "--listen","127.0.0.1:9443","--key","server.key","--pub-out","server.pub","--mask","null_tcp" `
  -RedirectStandardError "edge.err" -RedirectStandardOutput "edge.out"

$deadline = (Get-Date).AddSeconds(10)
while (-not (Test-Path "server.pub")) {
  if ((Get-Date) -gt $deadline) { throw "no server.pub" }
  Start-Sleep -Milliseconds 200
}

$cli = Start-Process -PassThru -WorkingDirectory $root -WindowStyle Hidden `
  -FilePath ".\target\debug\swif-cli.exe" `
  -ArgumentList "--server","127.0.0.1:9443","--pub-file","server.pub","--socks","127.0.0.1:11080","--mask","null_tcp" `
  -RedirectStandardError "cli.err" -RedirectStandardOutput "cli.out"

Start-Sleep -Seconds 1
try {
  $tmp1 = Join-Path $env:TEMP "swif-direct.bin"
  $tmp2 = Join-Path $env:TEMP "swif-tun.bin"
  $sw = [System.Diagnostics.Stopwatch]::StartNew()
  curl.exe -s -o $tmp1 --connect-timeout 15 --max-time 60 $url | Out-Null
  $sw.Stop(); $directMs = $sw.ElapsedMilliseconds
  $directBytes = (Get-Item $tmp1).Length

  $sw.Restart()
  curl.exe -s -o $tmp2 --connect-timeout 15 --max-time 90 -x socks5h://127.0.0.1:11080 $url | Out-Null
  $sw.Stop(); $tunMs = $sw.ElapsedMilliseconds
  $tunBytes = (Get-Item $tmp2).Length

  if ($directMs -le 0 -or $tunBytes -lt 1000) { throw "download failed" }
  $ratio = [math]::Round(($directMs / [double]$tunMs) * 100.0, 1)
  Write-Host "direct ${directMs}ms ($directBytes B)  tunnel ${tunMs}ms ($tunBytes B)  ~${ratio}% of direct speed"
  if ($ratio -lt 50) {
    Write-Host "WARN: below 50% in this lab run (DoD is 70% on quiet LAN; informational)"
  } else {
    Write-Host "PERF LAB OK (informational)"
  }
} finally {
  Stop-Process -Id $edge.Id -Force -ErrorAction SilentlyContinue
  Stop-Process -Id $cli.Id -Force -ErrorAction SilentlyContinue
}
