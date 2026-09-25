# Conditional Access — Report-only Analysis

Alternative to the **Conditional Access insights and reporting** workbook for tenants without Log Analytics (e.g. Microsoft 365 Business Premium).

## ⚠️ The Problem

Report-only mode is the safe way to test a Conditional Access policy, but reviewing its impact normally relies on the insights workbook, which requires sign-in logs streamed to a Log Analytics workspace. Without it, the only option left in the portal is filtering sign-ins one by one.

This script pulls sign-ins from Microsoft Graph and lists every event where the policy result is `reportOnlyFailure` (optionally `reportOnlyInterrupted`) — the sign-ins that would have been blocked or prompted once the policy is switched **On**. Each event gets a heuristic hint to help separate real gaps from false positives.

## 📁 Contents

| File | Description |
|------|-------------|
| `Invoke-CAReportOnlyAnalysis.ps1` | Lists sign-ins a report-only CA policy would have blocked, with hints (shared IP, no device claim, unmanaged device) and optional CSV export |

## ✅ Prerequisites

- PowerShell modules:
  - `Microsoft.Graph.Authentication`
  - `Microsoft.Graph.Reports`
  - `Microsoft.Graph.Identity.SignIns`
- Graph scopes: `AuditLog.Read.All`, `Policy.Read.All`
- Entra role: **Security Reader** or **Global Reader**

```powershell
Install-Module Microsoft.Graph.Authentication, Microsoft.Graph.Reports, Microsoft.Graph.Identity.SignIns -Scope CurrentUser
```

> ⚠️ **Reports Reader is not enough.** It can read sign-ins but **not** Conditional Access data: `appliedConditionalAccessPolicies` is then omitted from every sign-in and the script finds nothing. See [List signIns — Microsoft Graph](https://learn.microsoft.com/en-us/graph/api/signin-list).

## 🔧 Usage

### Default — last 30 days, would-be blocks only
```powershell
.\Invoke-CAReportOnlyAnalysis.ps1 -PolicyName "Require compliant device (pilot)"
```

### Shorter window, include interrupts, export to CSV
```powershell
.\Invoke-CAReportOnlyAnalysis.ps1 -PolicyName "Require compliant device (pilot)" -Days 14 -IncludeInterrupted -OutputPath .\ca-reportonly.csv
```

### Validate a fix for one account
```powershell
.\Invoke-CAReportOnlyAnalysis.ps1 -PolicyName "Require compliant device (pilot)" -Days 1 -UserPrincipalName admin@contoso.onmicrosoft.com
```
In single-user mode, all report-only results are shown (including `reportOnlySuccess`), so you can confirm the account now passes.

## 🔍 Common Findings

### RDS / VDI servers
Sessions on shared RDS or VDI hosts often carry no device claim and all come from the same shared IP, so every user on the host shows up as a would-be block.
**Option:** create a dedicated named location for these hosts and exclude it from the policy. Do **not** mark it as *Trusted*, so it is not implicitly trusted by other policies or risk evaluations.

### Cloud-only admin accounts
If an Edge policy `RestrictSigninToPattern` restricts the browser profile to the organization domain, cloud-only admin accounts (`*.onmicrosoft.com`) are pushed into InPrivate windows, where no device claim is sent — and the sign-in fails the policy.
**Fix:** add the `onmicrosoft.com` domain to the pattern and use a **dedicated Edge profile per admin account**.
Do **not** add the admin account to Windows (*Settings → Accounts*): it would be registered in WAM and any process running in the user session could obtain its tokens.

### Personal devices
Sign-ins from personal, unmanaged devices are true positives. Blocking them or allowing them (e.g. browser-only access with app restrictions) is a business decision, not a technical fix.

### B2B guests and technical accounts
Guests and service or technical accounts often cannot satisfy device requirements. Exclude them only with compensating controls (dedicated policy, location or MFA restrictions). For partners with compliant devices, configure **cross-tenant access settings** to trust their compliant / hybrid-joined device claims.

## 🚧 Limitations

- **Interactive sign-ins only.** The v1.0 `signIns` endpoint does not return non-interactive sign-ins; those require the beta endpoint, which is not implemented.
- **Hints are heuristics**, not verdicts. Verify each case manually before excluding anything.
- **Read-only.** The script makes no change to the tenant.

## 📖 References

- [List signIns — Microsoft Graph](https://learn.microsoft.com/en-us/graph/api/signin-list)
- [Conditional Access insights and reporting](https://learn.microsoft.com/en-us/entra/identity/conditional-access/howto-conditional-access-insights-reporting)
- [Conditional Access report-only mode](https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-conditional-access-report-only)
