# sign-rdp.ps1
# Creates a self-signed code signing certificate and signs a .rdp file
# Run as Administrator on a Windows machine
#
# Usage:
#   .\sign-rdp.ps1 -RdpPath "C:\path\to\your.rdp" -CertSubject "CN=YOURORG RDP Publisher"
#
# The signed .rdp file and exported .cer (for Intune deployment) will be placed
# alongside the script in the current directory.

param(
    [Parameter(Mandatory)]
    [string]$RdpPath,

    [string]$CertSubject = "CN=YOURORG RDP Publisher",
    [string]$CertExportPath = ".\YOURORG-RDP-Publisher.cer",
    [int]$ValidityYears = 3
)

# --- 1. Create self-signed code signing certificate ---
Write-Host "Creating certificate: $CertSubject" -ForegroundColor Cyan
$cert = New-SelfSignedCertificate `
    -Subject $CertSubject `
    -CertStoreLocation "Cert:\LocalMachine\My" `
    -KeyUsage DigitalSignature `
    -Type CodeSigningCert `
    -NotAfter (Get-Date).AddYears($ValidityYears)

Write-Host "Certificate created." -ForegroundColor Green
Write-Host "Thumbprint: $($cert.Thumbprint)" -ForegroundColor Yellow

# --- 2. Install cert as Trusted Root on this machine (for local validation) ---
Import-Certificate `
    -FilePath (Export-Certificate -Cert $cert -FilePath $env:TEMP\tmp-rdp-cert.cer -Force) `
    -CertStoreLocation "Cert:\LocalMachine\Root" | Out-Null
Write-Host "Certificate installed in LocalMachine\Root." -ForegroundColor Green

# --- 3. Sign the .rdp file ---
Write-Host "Signing: $RdpPath" -ForegroundColor Cyan
& rdpsign.exe /sha256 $cert.Thumbprint "`"$RdpPath`""

# --- 4. Export public .cer for Intune Trusted Certificate profile ---
Export-Certificate -Cert $cert -FilePath $CertExportPath | Out-Null
Write-Host "Public cert exported to: $CertExportPath" -ForegroundColor Green

Write-Host ""
Write-Host "Done. Next steps:" -ForegroundColor White
Write-Host "  1. Add the signed .rdp to your Intune Win32 package" -ForegroundColor Gray
Write-Host "  2. Deploy $CertExportPath via Intune Trusted Certificate profile (Computer, Root)" -ForegroundColor Gray
Write-Host "  3. Configure Settings Catalog (see README)" -ForegroundColor Gray
Write-Host "  4. Note your thumbprint for future reference: $($cert.Thumbprint)" -ForegroundColor Yellow
