# Release smoke: edge PEM+cover+ticket-master ↔ craft dial client → SOCKS HTTP 200.
# Does NOT set SWIF_LAB (prod ticket-master path).
# Ports isolated from smoke-all (9443/1108x) to avoid EADDRINUSE after gate.
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$env:Path = "$env:USERPROFILE\.cargo\bin;" + $env:Path
Remove-Item Env:SWIF_LAB -ErrorAction SilentlyContinue
Set-Location $root

$edgeListen = "127.0.0.1:19543"
$coverPort = 18543
$socks = "127.0.0.1:11185"
$genListen = "127.0.0.1:19544"

cargo build -p swif-edge -p swif-cli --quiet
Get-Process swif-edge,swif-cli -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep -Milliseconds 800

# Lab PEM material via temporary SWIF_LAB generate, then clear LAB for edge start.
$env:SWIF_LAB = "1"
Remove-Item "server.key","server.pub","lab-cert.der.json","lab-cover.crt","lab-cover.key","ticket.master","edge.err","edge.out","cli.err","cli.out" -ErrorAction SilentlyContinue
# Generate TLS material + keys with a throwaway edge
$gen = Start-Process -PassThru -WorkingDirectory $root -WindowStyle Hidden `
  -FilePath ".\target\debug\swif-edge.exe" `
  -ArgumentList "--listen",$genListen,"--key","server.key","--pub-out","server.pub","--mask","tls13_stable","--sni","cover.local" `
  -RedirectStandardError "edge.err" -RedirectStandardOutput "edge.out"
$deadline = (Get-Date).AddSeconds(15)
while (-not (Test-Path "lab-cover.crt")) {
  if ((Get-Date) -gt $deadline) { Get-Content edge.err -ErrorAction SilentlyContinue; throw "no lab-cover.crt" }
  Start-Sleep -Milliseconds 200
}
Stop-Process -Id $gen.Id -Force -ErrorAction SilentlyContinue
Start-Sleep -Milliseconds 500
Remove-Item Env:SWIF_LAB -ErrorAction SilentlyContinue

# 32-byte ticket master
$tm = New-Object byte[] 32
[System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($tm)
[System.IO.File]::WriteAllBytes((Join-Path $root "ticket.master"), $tm)

# Builtin cover needs SWIF_LAB OR --cover. Separate process so finally can Kill (Start-Job AcceptTcpClient hangs Stop-Job).
$coverCmd = @"
`$l = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, $coverPort)
`$l.Start()
while (`$true) {
  `$c = `$l.AcceptTcpClient()
  `$s = `$c.GetStream()
  `$buf = New-Object byte[] 4096
  try { [void]`$s.Read(`$buf, 0, `$buf.Length) } catch {}
  `$body = [Text.Encoding]::ASCII.GetBytes("HTTP/1.1 200 OK``r``nContent-Length: 12``r``nConnection: close``r``n``r``ncover origin")
  `$s.Write(`$body, 0, `$body.Length)
  `$c.Close()
}
"@
$coverProc = Start-Process -PassThru -WindowStyle Hidden -FilePath "powershell.exe" `
  -ArgumentList "-NoProfile","-ExecutionPolicy","Bypass","-Command",$coverCmd
Start-Sleep -Milliseconds 500

try {
  Remove-Item "edge.err","edge.out" -ErrorAction SilentlyContinue
  $edge = Start-Process -PassThru -WorkingDirectory $root -WindowStyle Hidden `
    -FilePath ".\target\debug\swif-edge.exe" `
    -ArgumentList "--listen",$edgeListen,"--key","server.key","--pub-out","server.pub","--mask","tls13_stable","--sni","cover.local","--tls-cert","lab-cover.crt","--tls-key","lab-cover.key","--cover","127.0.0.1:$coverPort","--ticket-master","ticket.master" `
    -RedirectStandardError "edge.err" -RedirectStandardOutput "edge.out"
  $deadline = (Get-Date).AddSeconds(15)
  $ready = $false
  while ((Get-Date) -lt $deadline) {
    if ($edge.HasExited) { Get-Content edge.err -ErrorAction SilentlyContinue; throw "edge exited early" }
    $errTxt = Get-Content edge.err -Raw -ErrorAction SilentlyContinue
    if ($errTxt -match "listen|ticket_master=separate") { $ready = $true; break }
    if ((Test-Path "server.pub") -and ((Get-Date) -gt $edge.StartTime.AddSeconds(1))) { $ready = $true; break }
    Start-Sleep -Milliseconds 200
  }
  if (-not $ready) { Get-Content edge.err -ErrorAction SilentlyContinue; throw "edge not ready" }
  if (-not (Test-Path "lab-cert.der.json")) { throw "missing lab-cert.der.json from generate step" }

  $cli = Start-Process -PassThru -WorkingDirectory $root -WindowStyle Hidden `
    -FilePath ".\target\debug\swif-cli.exe" `
    -ArgumentList "--server",$edgeListen,"--pub-file","server.pub","--socks",$socks,"--mask","tls13_stable","--tls-material","lab-cert.der.json" `
    -RedirectStandardError "cli.err" -RedirectStandardOutput "cli.out"
  Start-Sleep -Seconds 2
  $r = curl.exe -s -o NUL -w "%{http_code}" --connect-timeout 10 --max-time 25 -x ("socks5h://" + $socks) http://example.com/
  Write-Host "SMOKE PROD 0.5 SOCKS HTTP $r"
  if ($r -ne "200") {
    Get-Content cli.err,edge.err -ErrorAction SilentlyContinue
    throw "expected 200"
  }
  Write-Host "SMOKE PROD 0.5 OK (PEM+cover+ticket-master + craft dial)"
} finally {
  Get-Process swif-edge,swif-cli -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
  if ($coverProc -and -not $coverProc.HasExited) { Stop-Process -Id $coverProc.Id -Force -ErrorAction SilentlyContinue }
}
