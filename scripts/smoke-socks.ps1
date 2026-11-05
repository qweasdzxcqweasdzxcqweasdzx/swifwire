# Lab smoke: edge + cli SOCKS → fetch http://example.com
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$env:Path = "$env:USERPROFILE\.cargo\bin;" + $env:Path
Set-Location $root

cargo build -p swif-edge -p swif-cli --quiet
Remove-Item "server.key","server.pub","edge.err","edge.out","cli.err","cli.out" -ErrorAction SilentlyContinue

$edge = Start-Process -PassThru -WorkingDirectory $root -WindowStyle Hidden `
  -FilePath ".\target\debug\swif-edge.exe" `
  -ArgumentList "--listen","127.0.0.1:9443","--key","server.key","--pub-out","server.pub" `
  -RedirectStandardError "edge.err" -RedirectStandardOutput "edge.out"

$deadline = (Get-Date).AddSeconds(10)
while (-not (Test-Path "server.pub")) {
  if ((Get-Date) -gt $deadline) {
    Get-Content "edge.err" -ErrorAction SilentlyContinue
    throw "no server.pub"
  }
  Start-Sleep -Milliseconds 200
}

$cli = Start-Process -PassThru -WorkingDirectory $root -WindowStyle Hidden `
  -FilePath ".\target\debug\swif-cli.exe" `
  -ArgumentList "--server","127.0.0.1:9443","--pub-file","server.pub","--socks","127.0.0.1:11080" `
  -RedirectStandardError "cli.err" -RedirectStandardOutput "cli.out"

Start-Sleep -Seconds 1
try {
  $r = curl.exe -s -o NUL -w "%{http_code}" --connect-timeout 10 --max-time 25 -x socks5h://127.0.0.1:11080 http://example.com/
  Write-Host "HTTP $r via SwifWire SOCKS"
  if ($r -ne "200") {
    Write-Host "--- edge.err ---"; Get-Content "edge.err" -ErrorAction SilentlyContinue
    Write-Host "--- cli.err ---"; Get-Content "cli.err" -ErrorAction SilentlyContinue
    throw "expected 200 got $r"
  }
  Write-Host "SMOKE OK"
} finally {
  Stop-Process -Id $edge.Id -Force -ErrorAction SilentlyContinue
  Stop-Process -Id $cli.Id -Force -ErrorAction SilentlyContinue
}
