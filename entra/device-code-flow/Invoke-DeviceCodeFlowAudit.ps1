#Requires -Version 5.1
#Requires -Modules Microsoft.Graph.Authentication, Microsoft.Graph.Reports
<#
.SYNOPSIS
    Audits Device Code Flow sign-in activity across all sign-in log types in a Microsoft 365 tenant.

.DESCRIPTION
    Before blocking Device Code Flow via Conditional Access (recommended mitigation against
    AiTM phishing campaigns like EvilTokens), it is critical to verify the flow is not
    legitimately used in your environment.

    This script queries all four Microsoft Entra sign-in log types for Device Code Flow
    activity over a configurable number of days, and outputs a clear summary to help you
    make an informed decision before deploying the block policy.

    Sign-in log types checked:
        - Interactive user sign-ins
        - Non-interactive user sign-ins
        - Service principal sign-ins
        - Managed identity sign-ins

    If all four return zero results: safe to block immediately via Conditional Access.
    If results are found: review before blocking to avoid breaking legitimate workflows.

.PARAMETER DaysBack
    Number of days to look back in sign-in logs. Default: 30.

.PARAMETER ExportCsv
    If specified, exports results to a CSV file at the given path.

.EXAMPLE
    .\Invoke-DeviceCodeFlowAudit.ps1
    Checks the last 30 days and outputs results to the console.

.EXAMPLE
    .\Invoke-DeviceCodeFlowAudit.ps1 -DaysBack 90 -ExportCsv "C:\Reports\dcf-audit.csv"
    Checks the last 90 days and exports findings to CSV.

.NOTES
    Author      : Bluewall (https://github.com/Bluewal)
    Version     : 1.0
    License     : MIT

    Required permissions (Microsoft Graph):
        - AuditLog.Read.All
        - Directory.Read.All

    Required PowerShell modules:
        Install-Module Microsoft.Graph -Scope CurrentUser

.LINK
    https://github.com/Bluewal/m365-intune-scripts
#>

[CmdletBinding()]
param (
    [int]$DaysBack = 30,
    [string]$ExportCsv
)

#region --- Connect ---
Write-Host "`n🔐 Connecting to Microsoft Graph..." -ForegroundColor Cyan

Connect-MgGraph -Scopes "AuditLog.Read.All", "Directory.Read.All" -NoWelcome

Write-Host "✅ Connected.`n" -ForegroundColor Green
#endregion

#region --- Build filter ---
$startDate = (Get-Date).AddDays(-$DaysBack).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
$filter = "authenticationProtocol eq 'deviceCode' and createdDateTime ge $startDate"
#endregion

#region --- Query all sign-in log types ---
$results = [System.Collections.Generic.List[PSObject]]::new()

$logTypes = @(
    @{ Name = "Interactive user sign-ins";     CmdLet = "Get-MgAuditLogSignIn";                        Params = @{ Filter = $filter; All = $true } },
    @{ Name = "Non-interactive user sign-ins"; CmdLet = "Get-MgAuditLogSignIn";                        Params = @{ Filter = $filter; All = $true } },
    @{ Name = "Service principal sign-ins";    CmdLet = "Get-MgAuditLogServicePrincipalSignIn";        Params = @{ Filter = $filter; All = $true } },
    @{ Name = "Managed identity sign-ins";     CmdLet = "Get-MgAuditLogManagedDeviceSignIn";           Params = @{ Filter = $filter; All = $true } }
)

# Note: Interactive and Non-interactive share the same cmdlet but are differentiated by
# the signInEventTypes property. We split them here for clarity in the output.
$interactiveTypes   = @("interactiveUser")
$nonInteractiveTypes = @("nonInteractiveUser")

foreach ($logType in $logTypes) {
    Write-Host "🔍 Checking: $($logType.Name)..." -ForegroundColor Yellow

    try {
        $raw = & $logType.CmdLet @($logType.Params) -ErrorAction Stop

        # Filter interactive vs non-interactive for the shared cmdlet
        if ($logType.Name -eq "Interactive user sign-ins") {
            $raw = $raw | Where-Object { $_.SignInEventTypes -contains "interactiveUser" }
        } elseif ($logType.Name -eq "Non-interactive user sign-ins") {
            $raw = $raw | Where-Object { $_.SignInEventTypes -notcontains "interactiveUser" }
        }

        $count = ($raw | Measure-Object).Count
        Write-Host "   → $count result(s) found" -ForegroundColor $(if ($count -gt 0) { "Red" } else { "Green" })

        foreach ($entry in $raw) {
            $results.Add([PSCustomObject]@{
                LogType             = $logType.Name
                CreatedDateTime     = $entry.CreatedDateTime
                UserPrincipalName   = $entry.UserPrincipalName
                AppDisplayName      = $entry.AppDisplayName
                IpAddress           = $entry.IpAddress
                CountryOrRegion     = $entry.Location.CountryOrRegion
                City                = $entry.Location.City
                StatusErrorCode     = $entry.Status.ErrorCode
                StatusFailureReason = $entry.Status.FailureReason
                CorrelationId       = $entry.CorrelationId
            })
        }
    } catch {
        Write-Warning "Could not query $($logType.Name): $_"
    }
}
#endregion

#region --- Output summary ---
Write-Host "`n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Cyan
Write-Host "  Device Code Flow Audit — Last $DaysBack days" -ForegroundColor Cyan
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━`n" -ForegroundColor Cyan

$total = $results.Count

if ($total -eq 0) {
    Write-Host "✅ No Device Code Flow activity found across all log types." -ForegroundColor Green
    Write-Host "   → Safe to block via Conditional Access immediately.`n" -ForegroundColor Green
} else {
    Write-Host "⚠️  $total Device Code Flow sign-in(s) detected!" -ForegroundColor Red
    Write-Host "   → Review results before deploying the block policy.`n" -ForegroundColor Red
    $results | Format-Table -AutoSize
}
#endregion

#region --- Export CSV ---
if ($ExportCsv -and $results.Count -gt 0) {
    $results | Export-Csv -Path $ExportCsv -NoTypeInformation -Encoding UTF8
    Write-Host "📄 Results exported to: $ExportCsv`n" -ForegroundColor Cyan
}
#endregion

#region --- Next steps ---
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor DarkGray
Write-Host "  Next steps" -ForegroundColor DarkGray
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor DarkGray
Write-Host "  Block policy : Entra > Conditional Access > New policy" -ForegroundColor DarkGray
Write-Host "                 Conditions > Authentication flows > Device code flow" -ForegroundColor DarkGray
Write-Host "                 Grant > Block access" -ForegroundColor DarkGray
Write-Host "  Reference    : https://github.com/Bluewal/m365-intune-scripts" -ForegroundColor DarkGray
Write-Host ""

Disconnect-MgGraph | Out-Null
#endregion
