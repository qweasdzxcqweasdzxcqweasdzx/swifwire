# Lab smoke: tls13_stable edge + cli SOCKS → HTTP 200
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$env:Path = "$env:USERPROFILE\.cargo\bin;" + $env:Path
Set-Location $root

cargo build -p swif-edge -p swif-cli --quiet
Remove-Item "server.key","server.pub","edge.err","edge.out","cli.err","cli.out","lab-cert.der.json" -ErrorAction SilentlyContinue

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

$cli = Start-Process -PassThru -WorkingDirectory $root -WindowStyle Hidden `
  -FilePath ".\target\debug\swif-cli.exe" `
  -ArgumentList "--server","127.0.0.1:9443","--pub-file","server.pub","--socks","127.0.0.1:11081","--mask","tls13_stable","--tls-material","lab-cert.der.json" `
  -RedirectStandardError "cli.err" -RedirectStandardOutput "cli.out"

Start-Sleep -Seconds 1
try {
  $r = curl.exe -s -o NUL -w "%{http_code}" --connect-timeout 10 --max-time 30 -x socks5h://127.0.0.1:11081 http://example.com/
  Write-Host "HTTP $r via SwifWire tls13_stable"
  if ($r -ne "200") {
    Write-Host "--- edge ---"; Get-Content "edge.err","edge.out" -ErrorAction SilentlyContinue
    Write-Host "--- cli ---"; Get-Content "cli.err","cli.out" -ErrorAction SilentlyContinue
    throw "expected 200 got $r"
  }
  Write-Host "SMOKE TLS OK"
} finally {
  Stop-Process -Id $edge.Id -Force -ErrorAction SilentlyContinue
  Stop-Process -Id $cli.Id -Force -ErrorAction SilentlyContinue
}
