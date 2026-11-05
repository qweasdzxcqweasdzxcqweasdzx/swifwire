# UDP map smoke: local echo ↔ SwifWire DATAGRAM via edge
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$env:Path = "$env:USERPROFILE\.cargo\bin;" + $env:Path
Set-Location $root

cargo build -p swif-edge -p swif-cli --quiet
Remove-Item "server.key","server.pub","edge.err","edge.out" -ErrorAction SilentlyContinue

# UDP echo on 127.0.0.1:19000
$echo = Start-Job -ScriptBlock {
  $udp = New-Object System.Net.Sockets.UdpClient 19000
  $ep = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Any, 0)
  while ($true) {
    $bytes = $udp.Receive([ref]$ep)
    $udp.Send($bytes, $bytes.Length, $ep) | Out-Null
  }
}

$edge = Start-Process -PassThru -WorkingDirectory $root -WindowStyle Hidden `
  -FilePath ".\target\debug\swif-edge.exe" `
  -ArgumentList "--listen","127.0.0.1:9443","--key","server.key","--pub-out","server.pub","--mask","null_tcp" `
  -RedirectStandardError "edge.err" -RedirectStandardOutput "edge.out"

$deadline = (Get-Date).AddSeconds(10)
while (-not (Test-Path "server.pub")) {
  if ((Get-Date) -gt $deadline) { throw "no server.pub" }
  Start-Sleep -Milliseconds 200
}
Start-Sleep -Milliseconds 500

try {
  $out = & ".\target\debug\swif-cli.exe" --server 127.0.0.1:9443 --pub-file server.pub --mask null_tcp --udp-ping 127.0.0.1:19000 2>&1
  Write-Host $out
  if ("$out" -notmatch "UDP_PING OK") {
    Get-Content "edge.err" -ErrorAction SilentlyContinue
    throw "udp ping failed"
  }
  Write-Host "SMOKE UDP OK"
} finally {
  Stop-Process -Id $edge.Id -Force -ErrorAction SilentlyContinue
  Stop-Job $echo -ErrorAction SilentlyContinue
  Remove-Job $echo -Force -ErrorAction SilentlyContinue
}
