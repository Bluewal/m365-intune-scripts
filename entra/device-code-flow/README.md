# Device Code Flow — Audit & Block

Mitigation resources for AiTM phishing attacks abusing the OAuth 2.0 Device Authorization Grant (Device Code Flow), as used by campaigns like **EvilTokens**.

## ⚠️ The Attack

The attacker requests a device code from Microsoft's real API, sends it to the victim via phishing, and tricks them into authenticating at `microsoft.com/devicelogin`. Once authenticated, the attacker retrieves valid access + refresh tokens — **MFA fully bypassed, no password needed**.

## 📁 Contents

| File | Description |
|------|-------------|
| `Invoke-DeviceCodeFlowAudit.ps1` | Checks all 4 Entra sign-in log types for Device Code Flow activity before blocking |
| `ca-block-device-code-flow.json` | Conditional Access policy template to block the flow tenant-wide |

## 🔧 Recommended Workflow

### Step 1 — Audit first
```powershell
.\Invoke-DeviceCodeFlowAudit.ps1 -DaysBack 30
```
✅ All results empty → safe to block immediately  
⚠️ Results found → review usage before deploying the block

### Step 2 — Deploy the CA policy

**Via Entra Portal (recommended):**
1. Go to **Entra ID → Security → Conditional Access → New policy**
2. Name: `Block - Device Code Flow`
3. Users: **All users** (exclude your break-glass group)
4. Target resources: **All resources**
5. Conditions → Authentication flows → **Device code flow ✓**
6. Grant → **Block access**
7. Enable policy: **On**

**Via Microsoft Graph (import JSON):**
```powershell
Connect-MgGraph -Scopes "Policy.ReadWrite.ConditionalAccess"

$policy = Get-Content "ca-block-device-code-flow.json" | ConvertFrom-Json

# Replace placeholder with your actual break-glass group Object ID
# $policy.conditions.users.excludeGroups = @("<YOUR_GROUP_ID>")

New-MgIdentityConditionalAccessPolicy -BodyParameter $policy
```

## 🔑 Placeholders

Before importing the JSON, replace:

| Placeholder | Replace with |
|-------------|-------------|
| `<BREAK_GLASS_GROUP_OBJECT_ID>` | Object ID of your break-glass / emergency access group in Entra ID |

## 📖 References

- [Microsoft: Block Device Code Flow with Conditional Access](https://learn.microsoft.com/en-us/entra/identity/conditional-access/policy-block-authentication-flows)
- [EvilTokens campaign analysis](https://www.microsoft.com/en-us/security/blog/)
