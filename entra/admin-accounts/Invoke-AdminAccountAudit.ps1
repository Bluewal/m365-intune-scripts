#Requires -Version 5.1
#Requires -Modules Microsoft.Graph.Authentication, Microsoft.Graph.Users, Microsoft.Graph.Identity.DirectoryManagement
<#
.SYNOPSIS
    Audits all accounts holding administrative roles in a Microsoft 365 tenant.

.DESCRIPTION
    Privileged accounts are the highest-value targets in any M365 tenant. This script
    helps you identify:

        - All accounts assigned directory roles (Global Admin, Exchange Admin, etc.)
        - Accounts with sign-in enabled but no recent activity (stale admin accounts)
        - Accounts without MFA registered (critical risk)
        - Legacy accounts (e.g. initial tenant bootstrap accounts like admin@tenant.onmicrosoft.com)
        - Admin accounts with no last sign-in recorded in the past 30 days

    Run this as part of a regular access review, or before tightening Conditional Access
    policies targeting admin roles.

.PARAMETER ExportCsv
    If specified, exports results to a CSV file at the given path.

.PARAMETER InactiveDaysThreshold
    Number of days without sign-in before an account is flagged as inactive. Default: 30.

.EXAMPLE
    .\Invoke-AdminAccountAudit.ps1
    Outputs results to the console.

.EXAMPLE
    .\Invoke-AdminAccountAudit.ps1 -InactiveDaysThreshold 60 -ExportCsv "C:\Reports\admin-audit.csv"
    Flags accounts inactive for 60+ days and exports to CSV.

.NOTES
    Author      : Bluewall (https://github.com/Bluewal)
    Version     : 1.0
    License     : MIT

    Required permissions (Microsoft Graph):
        - User.Read.All
        - RoleManagement.Read.Directory
        - AuditLog.Read.All
        - UserAuthenticationMethod.Read.All

    Required PowerShell modules:
        Install-Module Microsoft.Graph -Scope CurrentUser

.LINK
    https://github.com/Bluewal/m365-intune-scripts
#>

[CmdletBinding()]
param (
    [int]$InactiveDaysThreshold = 30,
    [string]$ExportCsv
)

#region --- Connect ---
Write-Host "`n🔐 Connecting to Microsoft Graph..." -ForegroundColor Cyan
Connect-MgGraph -Scopes "User.Read.All", "RoleManagement.Read.Directory", "AuditLog.Read.All", "UserAuthenticationMethod.Read.All" -NoWelcome
Write-Host "✅ Connected.`n" -ForegroundColor Green
#endregion

#region --- Get all role assignments ---
Write-Host "🔍 Fetching directory role assignments..." -ForegroundColor Yellow

$roleAssignments = Get-MgRoleManagementDirectoryRoleAssignment -All -ExpandProperty "Principal,RoleDefinition"

# Group by principal to get all roles per user
$adminMap = @{}
foreach ($assignment in $roleAssignments) {
    $principalId = $assignment.PrincipalId
    $roleName    = $assignment.RoleDefinition.DisplayName

    if (-not $adminMap.ContainsKey($principalId)) {
        $adminMap[$principalId] = [System.Collections.Generic.List[string]]::new()
    }
    $adminMap[$principalId].Add($roleName)
}

Write-Host "   → Found $($adminMap.Count) accounts with admin roles`n" -ForegroundColor Green
#endregion

#region --- Enrich with user details ---
Write-Host "🔍 Fetching user details and MFA status..." -ForegroundColor Yellow

$results = [System.Collections.Generic.List[PSObject]]::new()
$cutoffDate = (Get-Date).AddDays(-$InactiveDaysThreshold)

foreach ($principalId in $adminMap.Keys) {
    try {
        $user = Get-MgUser -UserId $principalId `
            -Property "Id,DisplayName,UserPrincipalName,AccountEnabled,SignInActivity,UserType,OnPremisesSyncEnabled" `
            -ErrorAction Stop
    } catch {
        # Service principal or non-user object — skip
        continue
    }

    # MFA methods
    $authMethods = @()
    try {
        $methods = Get-MgUserAuthenticationMethod -UserId $principalId -ErrorAction Stop
        $authMethods = $methods | ForEach-Object { $_.AdditionalProperties["@odata.type"] -replace "#microsoft.graph.", "" }
    } catch {
        $authMethods = @("Unable to retrieve")
    }

    $hasMfa        = ($authMethods | Where-Object { $_ -notmatch "password" }).Count -gt 0
    $lastSignIn    = $user.SignInActivity.LastSignInDateTime
    $isInactive    = $lastSignIn -and ([datetime]$lastSignIn -lt $cutoffDate)
    $neverSignedIn = -not $lastSignIn
    $isLegacy      = $user.UserPrincipalName -match "admin@.*\.onmicrosoft\.com"

    # Risk assessment
    $riskFlags = @()
    if (-not $user.AccountEnabled)  { $riskFlags += "Account disabled" }
    if (-not $hasMfa)               { $riskFlags += "⛔ No MFA" }
    if ($isInactive)                { $riskFlags += "Inactive $InactiveDaysThreshold+ days" }
    if ($neverSignedIn)             { $riskFlags += "Never signed in" }
    if ($isLegacy)                  { $riskFlags += "Legacy bootstrap account" }

    $riskLevel = if ($riskFlags.Count -eq 0) { "✅ OK" }
                 elseif ($riskFlags -match "No MFA") { "🔴 Critical" }
                 else { "⚠️  Review" }

    $results.Add([PSCustomObject]@{
        DisplayName      = $user.DisplayName
        UPN              = $user.UserPrincipalName
        AccountEnabled   = $user.AccountEnabled
        Roles            = ($adminMap[$principalId] -join " | ")
        MfaRegistered    = $hasMfa
        AuthMethods      = ($authMethods -join ", ")
        LastSignIn       = if ($lastSignIn) { $lastSignIn } else { "Never / >30 days" }
        IsLegacyAccount  = $isLegacy
        RiskLevel        = $riskLevel
        RiskFlags        = ($riskFlags -join " | ")
    })
}
#endregion

#region --- Output summary ---
Write-Host "`n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Cyan
Write-Host "  Admin Account Audit Results" -ForegroundColor Cyan
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━`n" -ForegroundColor Cyan

$critical = $results | Where-Object { $_.RiskLevel -like "*Critical*" }
$review   = $results | Where-Object { $_.RiskLevel -like "*Review*" }
$ok       = $results | Where-Object { $_.RiskLevel -like "*OK*" }

Write-Host "Total admin accounts : $($results.Count)"
Write-Host "Critical             : $($critical.Count)" -ForegroundColor $(if ($critical.Count -gt 0) { "Red" } else { "Green" })
Write-Host "Require review       : $($review.Count)"   -ForegroundColor $(if ($review.Count -gt 0) { "Yellow" } else { "Green" })
Write-Host "OK                   : $($ok.Count)`n"     -ForegroundColor Green

if ($critical.Count -gt 0) {
    Write-Host "🔴 Critical — No MFA registered:" -ForegroundColor Red
    $critical | Format-Table DisplayName, UPN, Roles, MfaRegistered, LastSignIn, RiskFlags -AutoSize
}

if ($review.Count -gt 0) {
    Write-Host "⚠️  Requiring review:" -ForegroundColor Yellow
    $review | Format-Table DisplayName, UPN, Roles, AccountEnabled, LastSignIn, RiskFlags -AutoSize
}

if ($ok.Count -gt 0) {
    Write-Host "✅ OK:" -ForegroundColor Green
    $ok | Format-Table DisplayName, UPN, Roles, MfaRegistered, LastSignIn -AutoSize
}
#endregion

#region --- Recommendations ---
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor DarkGray
Write-Host "  Recommendations" -ForegroundColor DarkGray
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor DarkGray
Write-Host "  No MFA        : Enforce via Conditional Access Authentication Strength" -ForegroundColor DarkGray
Write-Host "  Legacy accts  : Delete if unused — reduce attack surface" -ForegroundColor DarkGray
Write-Host "  Inactive      : Disable or delete after access review" -ForegroundColor DarkGray
Write-Host "  Reference     : https://github.com/Bluewal/m365-intune-scripts" -ForegroundColor DarkGray
Write-Host ""
#endregion

#region --- Export CSV ---
if ($ExportCsv) {
    $results | Export-Csv -Path $ExportCsv -NoTypeInformation -Encoding UTF8
    Write-Host "📄 Results exported to: $ExportCsv`n" -ForegroundColor Cyan
}
#endregion

Disconnect-MgGraph | Out-Null
