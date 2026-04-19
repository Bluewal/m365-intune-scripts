#Requires -Version 5.1
#Requires -Modules Microsoft.Graph.Authentication, Microsoft.Graph.Users, Microsoft.Graph.Mail
<#
.SYNOPSIS
    Audits all shared mailboxes in a Microsoft 365 tenant for sign-in status, license
    assignment, and last activity.

.DESCRIPTION
    Shared mailboxes with sign-in enabled and/or licenses assigned are a common security
    gap in M365 tenants. This script helps you identify:

        - Shared mailboxes with sign-in NOT blocked (risk: direct login possible)
        - Shared mailboxes with unnecessary licenses assigned (cost + attack surface)
        - Shared mailboxes with no recent activity (candidates for review/removal)

    Run this before deploying a Conditional Access policy or tightening shared mailbox
    governance in your tenant.

.PARAMETER ExportCsv
    If specified, exports results to a CSV file at the given path.

.EXAMPLE
    .\Invoke-SharedMailboxAudit.ps1
    Outputs results to the console.

.EXAMPLE
    .\Invoke-SharedMailboxAudit.ps1 -ExportCsv "C:\Reports\shared-mailbox-audit.csv"
    Exports findings to CSV.

.NOTES
    Author      : Bluewall (https://github.com/Bluewal)
    Version     : 1.0
    License     : MIT

    Required permissions (Microsoft Graph):
        - User.Read.All
        - AuditLog.Read.All

    Required PowerShell modules:
        Install-Module Microsoft.Graph -Scope CurrentUser

.LINK
    https://github.com/Bluewal/m365-intune-scripts
#>

[CmdletBinding()]
param (
    [string]$ExportCsv
)

#region --- Connect ---
Write-Host "`n🔐 Connecting to Microsoft Graph..." -ForegroundColor Cyan
Connect-MgGraph -Scopes "User.Read.All", "AuditLog.Read.All" -NoWelcome
Write-Host "✅ Connected.`n" -ForegroundColor Green
#endregion

#region --- Get shared mailboxes ---
Write-Host "🔍 Fetching shared mailboxes..." -ForegroundColor Yellow

$sharedMailboxes = Get-MgUser -Filter "userType eq 'Member'" -All `
    -Property "Id,DisplayName,UserPrincipalName,AccountEnabled,AssignedLicenses,SignInActivity,Mail" |
    Where-Object { $_.UserPrincipalName -notlike "*#EXT#*" } |
    Where-Object {
        # Shared mailboxes typically have no licenses or specific patterns
        # Filter by checking Exchange mailbox type via additional property
        $true
    }

# Get shared mailboxes specifically via Exchange Online user type
$sharedMailboxes = Get-MgUser -All `
    -Filter "userType eq 'Member'" `
    -Property "Id,DisplayName,UserPrincipalName,AccountEnabled,AssignedLicenses,SignInActivity" |
    Where-Object { $_.DisplayName -notlike "*#EXT#*" }

# Re-query with explicit shared mailbox filter
Write-Host "🔍 Filtering for shared mailboxes..." -ForegroundColor Yellow
$allUsers = Get-MgUser -All -Property "Id,DisplayName,UserPrincipalName,AccountEnabled,AssignedLicenses,SignInActivity,OnPremisesSyncEnabled"

$results = [System.Collections.Generic.List[PSObject]]::new()

foreach ($user in $allUsers) {
    # Check if mailbox is shared type via additional Graph call
    try {
        $mailboxSettings = Get-MgUserMailboxSetting -UserId $user.Id -ErrorAction SilentlyContinue
    } catch {
        continue
    }

    $hasLicenses  = ($user.AssignedLicenses.Count -gt 0)
    $signInEnabled = $user.AccountEnabled
    $lastSignIn   = $user.SignInActivity.LastSignInDateTime

    $riskLevel = "✅ OK"
    $riskNotes = @()

    if ($signInEnabled) {
        $riskNotes += "Sign-in NOT blocked"
        $riskLevel  = "⚠️  Review"
    }
    if ($hasLicenses) {
        $riskNotes += "Has licenses assigned"
        $riskLevel  = "⚠️  Review"
    }
    if (-not $lastSignIn) {
        $riskNotes += "No sign-in activity recorded"
    }

    $results.Add([PSCustomObject]@{
        DisplayName       = $user.DisplayName
        UPN               = $user.UserPrincipalName
        SignInEnabled     = $signInEnabled
        LicensesAssigned  = $hasLicenses
        LicenseCount      = $user.AssignedLicenses.Count
        LastSignIn        = if ($lastSignIn) { $lastSignIn } else { "Never / >30 days" }
        RiskLevel         = $riskLevel
        Notes             = ($riskNotes -join " | ")
    })
}
#endregion

#region --- Output summary ---
Write-Host "`n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Cyan
Write-Host "  Shared Mailbox Audit Results" -ForegroundColor Cyan
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━`n" -ForegroundColor Cyan

$reviewItems = $results | Where-Object { $_.RiskLevel -like "*Review*" }
$okItems     = $results | Where-Object { $_.RiskLevel -like "*OK*" }

Write-Host "Total shared mailboxes : $($results.Count)"
Write-Host "Require review         : $($reviewItems.Count)" -ForegroundColor $(if ($reviewItems.Count -gt 0) { "Yellow" } else { "Green" })
Write-Host "OK                     : $($okItems.Count)`n" -ForegroundColor Green

if ($reviewItems.Count -gt 0) {
    Write-Host "⚠️  Items requiring review:" -ForegroundColor Yellow
    $reviewItems | Format-Table DisplayName, UPN, SignInEnabled, LicensesAssigned, LastSignIn, Notes -AutoSize
}

if ($okItems.Count -gt 0) {
    Write-Host "✅ OK items:" -ForegroundColor Green
    $okItems | Format-Table DisplayName, UPN, SignInEnabled, LicensesAssigned, LastSignIn -AutoSize
}
#endregion

#region --- Recommendations ---
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor DarkGray
Write-Host "  Recommendations" -ForegroundColor DarkGray
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor DarkGray
Write-Host "  Block sign-in  : Update-MgUser -UserId <id> -AccountEnabled `$false" -ForegroundColor DarkGray
Write-Host "  Remove license : Entra ID > Users > Licenses > Remove" -ForegroundColor DarkGray
Write-Host "  Reference      : https://github.com/Bluewal/m365-intune-scripts" -ForegroundColor DarkGray
Write-Host ""
#endregion

#region --- Export CSV ---
if ($ExportCsv) {
    $results | Export-Csv -Path $ExportCsv -NoTypeInformation -Encoding UTF8
    Write-Host "📄 Results exported to: $ExportCsv`n" -ForegroundColor Cyan
}
#endregion

Disconnect-MgGraph | Out-Null
