#Requires -Version 5.1
<#
.SYNOPSIS
    Detects the axios npm supply chain attack IOC on Windows endpoints via Microsoft Intune.

.DESCRIPTION
    On March 31, 2026, two malicious versions of the axios npm package were published
    (axios@1.14.1 and axios@0.30.4) after attacker compromised a maintainer's credentials.
    
    The malware dropped a Windows-specific IOC: wt.exe in %ProgramData%.
    
    This script is designed to be deployed as an Intune Script (Device context) to scan
    the entire managed fleet without requiring E3/E5 licenses — works with M365 Business Premium.

.NOTES
    Author      : Bluewall (https://github.com/Bluewal)
    Date        : 2026-03-31
    Version     : 1.0
    License     : MIT

    Deployment  : Microsoft Intune > Devices > Scripts > Add (Windows 10 and later)
    Run as      : System
    Scope       : Device

    Result interpretation in Intune Device Status:
        Success  = IOC NOT found — device is clean
        Failed   = IOC FOUND — device may be compromised, investigate immediately

.LINK
    https://github.com/Bluewal/bluewall-m365-toolkit

.EXAMPLE
    Deploy via Intune Scripts.
    Filter "Failed" status in Device Status to identify potentially compromised endpoints.
#>

# IOC: wt.exe dropped in %ProgramData% by the axios malware payload (Windows stage)
$iocPath = "$env:PROGRAMDATA\wt.exe"

if (Test-Path $iocPath) {
    # Throw forces Intune to report this device as "Failed" — unambiguous signal
    throw "COMPROMISED: axios IOC detected at $iocPath"
} else {
    Write-Output "CLEAN: axios IOC not found at $iocPath"
}
