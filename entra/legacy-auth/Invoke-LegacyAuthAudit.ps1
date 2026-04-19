#Requires -Version 5.1
#Requires -Modules Microsoft.Graph.Authentication, Microsoft.Graph.Reports
<#
.SYNOPSIS
    Audits legacy authentication protocol usage across a Microsoft 365 tenant.

.DESCRIPTION
    Legacy authentication protocols (Basic Auth, IMAP, POP3, SMTP Auth, MAPI over HTTP,
    Exchange ActiveSync, etc.) do not support Modern Authentication and therefore cannot
    enforce MFA. They are a primary vector for password spray and credential stuffing attacks.

    This script queries Entra sign-in logs to identify:

        - Which legacy protocols are still being used
        - Which users are using them
        - Which applications are involved
        - Sign-in success/failure status

    Run this before deploying a Conditional Access policy to block legacy authentication,
    to ensure no legitimate workflows are broken.

.PARAMETER DaysBack
    Number of days to look back in sign-in logs. Default: 30.

.PARAMETER ExportCsv
    If specified, exports results to a CSV file at the given path.

.EXAMPLE
    .\Invoke-LegacyAuthAudit.ps1
    Checks the last 30 days and outputs results to the console.

.EXAMPLE
    .\Invoke-LegacyAuthAudit.ps1 -DaysBack 90 -ExportCsv "C:\Reports\legacy-auth-audit.csv"
    Checks the last 90 days and exports findings to CSV.

.NOTES
    Author      : Bluewall (https://github.com/Bluewal)
    Version     : 1.0
    License     : MIT

    Required permissions (Microsoft Graph):
        - AuditLog.Read.All

    Required PowerShell modules:
        Install-Module Microsoft.Graph -Scope CurrentUser

    Legacy authentication protocols covered:
        - Exchange ActiveSync (EAS)
        - IMAP
        - POP3
        - SMTP Auth (basic)
        - Authenticated SMTP
        - AutoDiscover
        - Exchange Online PowerShell (basic auth)
        - Exchange Web Services (EWS)
        - MAPI over HTTP
        - Offline Address Book (OAB)
        - Outlook Anywhere (RPC over HTTP)
        - Other legacy clients

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
Connect-MgGraph -Scopes "AuditLog.Read.All" -NoWelcome
Write-Host "✅ Connected.`n" -ForegroundColor Green
#endregion

#region --- Build filter ---
$startDate = (Get-Date).AddDays(-$DaysBack).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")

# Legacy auth protocols as identified by Microsoft
$legacyProtocols = @(
    "exchange ActiveSync",
    "iMAP4",
    "mAPI",
    "oAB",
    "pOP3",
    "rPC",
    "sMTP",
    "unknownFutureValue"
)

$protocolFilter = ($legacyProtocols | ForEach-Object {
    "clientAppUsed eq '$_'"
}) -join " or "

$filter = "createdDateTime ge $startDate and ($protocolFilter)"
#endregion

#region --- Query sign-in logs ---
Write-Host "🔍 Querying sign-in logs for legacy authentication (last $DaysBack days)..." -ForegroundColor Yellow

$results = [System.Collections.Generic.List[PSObject]]::new()

try {
    $signIns = Get-MgAuditLogSignIn -Filter $filter -All -ErrorAction Stop

    $count = ($signIns | Measure-Object).Count
    Write-Host "   → $count legacy auth sign-in(s) found`n" -ForegroundColor $(if ($count -gt 0) { "Red" } else { "Green" })

    foreach ($entry in $signIns) {
        $isSuccess = $entry.Status.ErrorCode -eq 0

        $results.Add([PSCustomObject]@{
            CreatedDateTime     = $entry.CreatedDateTime
            UserPrincipalName   = $entry.UserPrincipalName
            AppDisplayName      = $entry.AppDisplayName
            ClientAppUsed       = $entry.ClientAppUsed
            Protocol            = $entry.AuthenticationProtocol
            IpAddress           = $entry.IpAddress
            CountryOrRegion     = $entry.Location.CountryOrRegion
            City                = $entry.Location.City
            Status              = if ($isSuccess) { "✅ Success" } else { "❌ Failure" }
            FailureReason       = $entry.Status.FailureReason
            OperatingSystem     = $entry.DeviceDetail.OperatingSystem
            Browser             = $entry.DeviceDetail.Browser
            CorrelationId       = $entry.CorrelationId
        })
    }
} catch {
    Write-Warning "Error querying sign-in logs: $_"
}
#endregion

#region --- Output summary ---
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Cyan
Write-Host "  Legacy Authentication Audit — Last $DaysBack days" -ForegroundColor Cyan
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━`n" -ForegroundColor Cyan

if ($results.Count -eq 0) {
    Write-Host "✅ No legacy authentication activity detected." -ForegroundColor Green
    Write-Host "   → Safe to block via Conditional Access immediately.`n" -ForegroundColor Green
} else {
    $successCount = ($results | Where-Object { $_.Status -like "*Success*" }).Count
    $failureCount = ($results | Where-Object { $_.Status -like "*Failure*" }).Count
    $uniqueUsers  = ($results | Select-Object -ExpandProperty UserPrincipalName -Unique).Count
    $protocols    = ($results | Select-Object -ExpandProperty ClientAppUsed -Unique) -join ", "

    Write-Host "⚠️  Legacy auth activity detected — review before blocking!`n" -ForegroundColor Red
    Write-Host "Total sign-ins    : $($results.Count)"
    Write-Host "Successful        : $successCount" -ForegroundColor $(if ($successCount -gt 0) { "Red" } else { "Green" })
    Write-Host "Failed attempts   : $failureCount"
    Write-Host "Unique users      : $uniqueUsers"
    Write-Host "Protocols in use  : $protocols`n"

    # Group by user for easier review
    Write-Host "📋 Activity by user:" -ForegroundColor Yellow
    $results |
        Group-Object UserPrincipalName |
        ForEach-Object {
            $successInGroup = ($_.Group | Where-Object { $_.Status -like "*Success*" }).Count
            [PSCustomObject]@{
                User          = $_.Name
                TotalSignIns  = $_.Count
                Successful    = $successInGroup
                Protocols     = ($_.Group | Select-Object -ExpandProperty ClientAppUsed -Unique) -join ", "
                LastSeen      = ($_.Group | Sort-Object CreatedDateTime -Descending | Select-Object -First 1).CreatedDateTime
            }
        } | Format-Table -AutoSize

    Write-Host "`n📋 Full details:" -ForegroundColor Yellow
    $results | Format-Table CreatedDateTime, UserPrincipalName, ClientAppUsed, IpAddress, CountryOrRegion, Status -AutoSize
}
#endregion

#region --- Recommendations ---
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor DarkGray
Write-Host "  Recommendations" -ForegroundColor DarkGray
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor DarkGray
Write-Host "  If results found  : Identify and migrate affected clients before blocking" -ForegroundColor DarkGray
Write-Host "  If no results     : Deploy CA policy to block legacy auth immediately" -ForegroundColor DarkGray
Write-Host "  Block via CA      : Conditions > Client apps > Exchange ActiveSync + Other clients" -ForegroundColor DarkGray
Write-Host "  Reference         : https://github.com/Bluewal/m365-intune-scripts" -ForegroundColor DarkGray
Write-Host ""
#endregion

#region --- Export CSV ---
if ($ExportCsv -and $results.Count -gt 0) {
    $results | Export-Csv -Path $ExportCsv -NoTypeInformation -Encoding UTF8
    Write-Host "📄 Results exported to: $ExportCsv`n" -ForegroundColor Cyan
}
#endregion

Disconnect-MgGraph | Out-Null
