$ErrorActionPreference = "Stop"
$AppName   = "YOURORG - RDP"
$TargetDir = Join-Path $env:ProgramData "Company\RDP"
$RdpDest   = Join-Path $TargetDir "YOURORG-RDP.rdp"
$Log       = Join-Path $TargetDir "install.log"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RdpCandidates = @(
    (Join-Path $ScriptDir "YOURORG - RDP.rdp"),
    (Join-Path $ScriptDir "YOURORG-RDP.rdp"),
    (Join-Path (Get-Location).Path "YOURORG - RDP.rdp"),
    (Join-Path (Get-Location).Path "YOURORG-RDP.rdp")
)
$RdpSrc = $RdpCandidates | Where-Object { $_ -and (Test-Path $_) } | Select-Object -First 1

$PublicDesktop = [Environment]::GetFolderPath('CommonDesktopDirectory')
$ShortcutPath  = Join-Path $PublicDesktop "$AppName.lnk"

try {
    New-Item -Path $TargetDir -ItemType Directory -Force | Out-Null
    "[$(Get-Date -Format s)] Start"          | Out-File $Log -Append -Encoding utf8
    "[$(Get-Date -Format s)] ScriptDir=$ScriptDir" | Out-File $Log -Append -Encoding utf8
    "[$(Get-Date -Format s)] CWD=$((Get-Location).Path)" | Out-File $Log -Append -Encoding utf8

    if (-not $RdpSrc) {
        throw "RDP source not found. Looked for: $($RdpCandidates -join '; ')"
    }
    "[$(Get-Date -Format s)] Using source: $RdpSrc" | Out-File $Log -Append -Encoding utf8

    Copy-Item -Path $RdpSrc -Destination $RdpDest -Force

    $WshShell = New-Object -ComObject WScript.Shell
    $Shortcut = $WshShell.CreateShortcut($ShortcutPath)
    $Shortcut.TargetPath      = $RdpDest
    $Shortcut.WorkingDirectory = $TargetDir
    $Shortcut.IconLocation    = "$env:SystemRoot\System32\mstsc.exe,0"
    $Shortcut.Save()

    if (-not (Test-Path $RdpDest))     { throw "RDP file missing after copy: $RdpDest" }
    if (-not (Test-Path $ShortcutPath)) { throw "Shortcut missing after create: $ShortcutPath" }

    # Version marker — used by Intune detection rule
    # Increment this value (and the detection rule) on each update
    "1" | Out-File (Join-Path $TargetDir "version.txt") -Force -Encoding utf8

    "[$(Get-Date -Format s)] Version=1"  | Out-File $Log -Append -Encoding utf8
    "[$(Get-Date -Format s)] Success"    | Out-File $Log -Append -Encoding utf8
    exit 0
}
catch {
    "[$(Get-Date -Format s)] ERROR: $($_.Exception.Message)" | Out-File $Log -Append -Encoding utf8
    exit 1
}
