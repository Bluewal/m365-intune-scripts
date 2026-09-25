<#
.SYNOPSIS
    Lists sign-ins that a report-only Conditional Access policy would have blocked.

.DESCRIPTION
    Before switching a Conditional Access policy from report-only to On, this script
    pulls interactive sign-ins from Microsoft Graph and extracts those where the policy
    result is reportOnlyFailure (optionally reportOnlyInterrupted).

    Each event gets a heuristic Hint to help separate real gaps from false positives:
      - Shared IP                 : IP used by many distinct users (likely RDS/VDI/proxy)
      - No device claim (browser) : empty DeviceId from a browser client
      - Unmanaged device          : device known but not managed or not compliant

    Hints are heuristics, not verdicts. Review before excluding anything.
    Read-only: the script makes no change to the tenant.

.PARAMETER PolicyName
    DisplayName of the Conditional Access policy to analyse.

.PARAMETER Days
    How many days back to look (1-30, default 30; Entra ID P1 keeps sign-ins 30 days).

.PARAMETER Since
    Explicit start date. Overrides -Days.

.PARAMETER IncludeInterrupted
    Also include reportOnlyInterrupted (user would have been prompted).

.PARAMETER UserPrincipalName
    Limit to one account. In this mode all report-only results are shown,
    including reportOnlySuccess, to validate a fix.

.PARAMETER SharedIpThreshold
    Minimum number of distinct users behind one IP to flag it as shared (default 5).

.PARAMETER OutputPath
    Optional CSV export path (UTF-8).

.EXAMPLE
    .\Invoke-CAReportOnlyAnalysis.ps1 -PolicyName "Require compliant device (pilot)"

.EXAMPLE
    .\Invoke-CAReportOnlyAnalysis.ps1 -PolicyName "Require compliant device (pilot)" -Days 14 -IncludeInterrupted -OutputPath .\ca-reportonly.csv

.EXAMPLE
    .\Invoke-CAReportOnlyAnalysis.ps1 -PolicyName "Require compliant device (pilot)" -Days 1 -UserPrincipalName admin@contoso.onmicrosoft.com

.NOTES
    Requires: Microsoft.Graph.Authentication, Microsoft.Graph.Reports,
              Microsoft.Graph.Identity.SignIns
    Scopes:   AuditLog.Read.All, Policy.Read.All
    Role:     Security Reader or Global Reader. Reports Reader can read sign-ins
              but NOT Conditional Access data: appliedConditionalAccessPolicies
              is then omitted and every result looks empty.
    Only interactive sign-ins are returned by the v1.0 endpoint.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$PolicyName,

    [ValidateRange(1, 30)]
    [int]$Days = 30,

    [datetime]$Since,

    [switch]$IncludeInterrupted,

    [string]$UserPrincipalName,

    [ValidateRange(2, 1000)]
    [int]$SharedIpThreshold = 5,

    [string]$OutputPath
)

$ErrorActionPreference = 'Stop'

# --- Connection -------------------------------------------------------------
$requiredScopes = @('AuditLog.Read.All', 'Policy.Read.All')
$ctx = Get-MgContext
if (-not $ctx -or ($requiredScopes | Where-Object { $_ -notin $ctx.Scopes })) {
    Connect-MgGraph -Scopes $requiredScopes -NoWelcome
}

# --- Policy check -----------------------------------------------------------
$policy = Get-MgIdentityConditionalAccessPolicy -All | Where-Object DisplayName -eq $PolicyName
if (-not $policy) {
    throw "Conditional Access policy '$PolicyName' not found (check the exact DisplayName)."
}
if (@($policy).Count -gt 1) {
    Write-Warning "Several policies are named '$PolicyName'. Results mix them."
}
if (@($policy)[0].State -ne 'enabledForReportingButNotEnforced') {
    Write-Warning "Policy state is '$(@($policy)[0].State)', not report-only. Report-only results may be absent."
}

# --- Sign-ins ---------------------------------------------------------------
$start = if ($PSBoundParameters.ContainsKey('Since')) { $Since } else { (Get-Date).AddDays(-$Days) }
$startUtc = $start.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')

$filter = "createdDateTime ge $startUtc"
if ($UserPrincipalName) { $filter += " and userPrincipalName eq '$UserPrincipalName'" }

Write-Host "Fetching interactive sign-ins since $startUtc (this can take several minutes)..." -ForegroundColor Cyan
$signIns = @(Get-MgAuditLogSignIn -Filter $filter -All)
Write-Host "$($signIns.Count) sign-ins retrieved." -ForegroundColor Cyan

if ($signIns.Count -gt 0 -and -not ($signIns | Where-Object { $_.AppliedConditionalAccessPolicies })) {
    Write-Warning ("No sign-in contains Conditional Access data. Your role can probably read sign-ins " +
                   "but not CA data (e.g. Reports Reader). Use Security Reader or Global Reader.")
}

# --- Filter on the policy result -------------------------------------------
$wanted = if ($UserPrincipalName) {
    @('reportOnlySuccess', 'reportOnlyFailure', 'reportOnlyInterrupted', 'reportOnlyNotApplied')
} else {
    @('reportOnlyFailure') + $(if ($IncludeInterrupted) { 'reportOnlyInterrupted' })
}

$results = foreach ($s in $signIns) {
    $p = $s.AppliedConditionalAccessPolicies | Where-Object DisplayName -eq $PolicyName | Select-Object -First 1
    if ($p -and $p.Result -in $wanted) {
        [pscustomobject]@{
            Date        = $s.CreatedDateTime
            User        = $s.UserPrincipalName
            App         = $s.AppDisplayName
            ClientApp   = $s.ClientAppUsed
            Browser     = $s.DeviceDetail.Browser
            OS          = $s.DeviceDetail.OperatingSystem
            DeviceId    = $s.DeviceDetail.DeviceId
            DeviceName  = $s.DeviceDetail.DisplayName
            TrustType   = $s.DeviceDetail.TrustType
            IsManaged   = $s.DeviceDetail.IsManaged
            IsCompliant = $s.DeviceDetail.IsCompliant
            IpAddress   = $s.IpAddress
            Result      = $p.Result
            Hint        = $null
        }
    }
}
$results = @($results)

if ($results.Count -eq 0) {
    Write-Host "No matching report-only result for '$PolicyName'." -ForegroundColor Green
    return
}

# --- Hints ------------------------------------------------------------------
$sharedIps = $results | Group-Object IpAddress |
    Where-Object { @($_.Group.User | Sort-Object -Unique).Count -ge $SharedIpThreshold } |
    ForEach-Object Name

foreach ($r in $results) {
    $hints = @()
    if ($r.IpAddress -in $sharedIps) { $hints += 'Shared IP' }
    if ([string]::IsNullOrEmpty($r.DeviceId) -and $r.ClientApp -eq 'Browser') { $hints += 'No device claim (browser)' }
    elseif (-not [string]::IsNullOrEmpty($r.DeviceId) -and (-not $r.IsManaged -or -not $r.IsCompliant)) { $hints += 'Unmanaged device' }
    $r.Hint = $hints -join '; '
}

# --- Summary ----------------------------------------------------------------
Write-Host ""
Write-Host "Events: $($results.Count) | Distinct users: $(@($results.User | Sort-Object -Unique).Count)" -ForegroundColor Yellow

Write-Host "`nTop IPs:" -ForegroundColor Yellow
$results | Group-Object IpAddress | Sort-Object Count -Descending | Select-Object -First 10 |
    Select-Object @{n = 'IpAddress'; e = { $_.Name } }, Count,
                  @{n = 'Users'; e = { @($_.Group.User | Sort-Object -Unique).Count } } |
    Format-Table -AutoSize -Wrap | Out-Host

Write-Host "By user / device / hint:" -ForegroundColor Yellow
$results | Group-Object User, DeviceName, Result, Hint | Sort-Object Name |
    Select-Object Count, @{n = 'User'; e = { $_.Group[0].User } },
                  @{n = 'Device'; e = { $_.Group[0].DeviceName } },
                  @{n = 'Result'; e = { $_.Group[0].Result } },
                  @{n = 'Hint'; e = { $_.Group[0].Hint } } |
    Format-Table -AutoSize -Wrap | Out-Host

if ($OutputPath) {
    $results | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
    Write-Host "Exported to $OutputPath" -ForegroundColor Green
}
