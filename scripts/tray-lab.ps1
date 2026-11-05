# WinForms NotifyIcon tray for lab (Start/Stop swif-cli).
param(
  [string]$Server = "127.0.0.1:9443",
  [string]$PubFile = "server.pub",
  [string]$Socks = "127.0.0.1:11080",
  [string]$Mask = "null_tcp"
)
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root
$cli = Join-Path $root "target\debug\swif-cli.exe"
if (-not (Test-Path $cli)) { throw "build swif-cli first" }

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

$script:proc = $null
$notify = New-Object System.Windows.Forms.NotifyIcon
$notify.Icon = [System.Drawing.SystemIcons]::Application
$notify.Visible = $true
$notify.Text = "SwifWire lab"

$menu = New-Object System.Windows.Forms.ContextMenuStrip
$start = New-Object System.Windows.Forms.ToolStripMenuItem "Start SOCKS"
$stop = New-Object System.Windows.Forms.ToolStripMenuItem "Stop"
$quit = New-Object System.Windows.Forms.ToolStripMenuItem "Quit"
$menu.Items.AddRange(@($start, $stop, $quit))
$notify.ContextMenuStrip = $menu

$start.Add_Click({
  if ($script:proc -and -not $script:proc.HasExited) { return }
  $script:proc = Start-Process -PassThru -WindowStyle Hidden -FilePath $cli `
    -ArgumentList "--server",$Server,"--pub-file",$PubFile,"--socks",$Socks,"--mask",$Mask
  $notify.ShowBalloonTip(2000, "SwifWire", "SOCKS started on $Socks", [System.Windows.Forms.ToolTipIcon]::Info)
})
$stop.Add_Click({
  if ($script:proc -and -not $script:proc.HasExited) {
    Stop-Process -Id $script:proc.Id -Force -ErrorAction SilentlyContinue
  }
  $script:proc = $null
})
$quit.Add_Click({
  if ($script:proc -and -not $script:proc.HasExited) {
    Stop-Process -Id $script:proc.Id -Force -ErrorAction SilentlyContinue
  }
  $notify.Visible = $false
  [System.Windows.Forms.Application]::Exit()
})

[System.Windows.Forms.Application]::Run()
