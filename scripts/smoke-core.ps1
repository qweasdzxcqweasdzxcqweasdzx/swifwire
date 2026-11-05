# Live core runtime: edge + swif-core-run SOCKS → HTTP 200
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$env:Path = "$env:USERPROFILE\.cargo\bin;" + $env:Path
Set-Location $root

cargo build -p swif-edge -p swif-core --quiet
Get-Process swif-edge,swif-core-run,swif-cli -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
Remove-Item "server.key","server.pub","edge.err","edge.out","core.err","core.out","core-cfg.json" -ErrorAction SilentlyContinue

$edge = Start-Process -PassThru -WorkingDirectory $root -WindowStyle Hidden `
  -FilePath ".\target\debug\swif-edge.exe" `
  -ArgumentList "--listen","127.0.0.1:9443","--key","server.key","--pub-out","server.pub","--mask","null_tcp" `
  -RedirectStandardError "edge.err" -RedirectStandardOutput "edge.out"

$deadline = (Get-Date).AddSeconds(10)
while (-not (Test-Path "server.pub")) {
  if ((Get-Date) -gt $deadline) { throw "no server.pub" }
  Start-Sleep -Milliseconds 200
}
$pub = (Get-Content "server.pub" -Raw).Trim()
# UTF-8 no BOM — serde rejects BOM
$json = @"
{"server_addr":"127.0.0.1:9443","server_static_pub_hex":"$pub","mask_profile":"null_tcp","socks_listen":"127.0.0.1:11082","start_runtime":true}
"@
[System.IO.File]::WriteAllText((Join-Path $root "core-cfg.json"), $json)

$core = Start-Process -PassThru -WorkingDirectory $root -WindowStyle Hidden `
  -FilePath ".\target\debug\swif-core-run.exe" `
  -ArgumentList "core-cfg.json","--seconds","25" `
  -RedirectStandardError "core.err" -RedirectStandardOutput "core.out"

Start-Sleep -Seconds 2
try {
  $r = curl.exe -s -o NUL -w "%{http_code}" --connect-timeout 10 --max-time 25 -x socks5h://127.0.0.1:11082 http://example.com/
  Write-Host "HTTP $r via swif-core runtime"
  if ($r -ne "200") {
    Write-Host "--- core ---"; Get-Content "core.err","core.out" -ErrorAction SilentlyContinue
    Write-Host "--- edge ---"; Get-Content "edge.err","edge.out" -ErrorAction SilentlyContinue
    throw "expected 200 got $r"
  }
  Write-Host "SMOKE CORE OK"
} finally {
  Stop-Process -Id $edge.Id -Force -ErrorAction SilentlyContinue
  Stop-Process -Id $core.Id -Force -ErrorAction SilentlyContinue
}
