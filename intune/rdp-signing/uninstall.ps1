$AppName      = "YOURORG - RDP"
$TargetDir    = "$env:ProgramData\Company\RDP"
$RdpFile      = Join-Path $TargetDir "YOURORG-RDP.rdp"
$PublicDesktop = [Environment]::GetFolderPath('CommonDesktopDirectory')
$ShortcutPath  = Join-Path $PublicDesktop "$AppName.lnk"

Remove-Item $ShortcutPath -Force -ErrorAction SilentlyContinue
Remove-Item $RdpFile      -Force -ErrorAction SilentlyContinue
Remove-Item $TargetDir    -Force -Recurse -ErrorAction SilentlyContinue
