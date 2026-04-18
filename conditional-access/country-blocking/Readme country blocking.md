# Conditional Access — Block Unauthorized Countries

Blocks all Microsoft 365 sign-ins from countries outside your defined allowed list. One of the highest-ROI Conditional Access policies for organizations with a predictable user geography.

## 📁 Contents

| File | Description |
|------|-------------|
| `ca-block-unauthorized-countries.json` | CA policy template — blocks all locations except your allowed Named Location |

## 🔧 Setup

### Step 1 — Create a Named Location for allowed countries

1. **Entra ID → Security → Conditional Access → Named locations**
2. **+ Countries location**
3. Name it something like `Allowed Countries - <ORG>`
4. Select your allowed countries (e.g. Switzerland, France, Germany...)
5. Save and **copy the Object ID** from the URL — you'll need it for the policy

### Step 2 — Deploy the CA policy

**Via Entra Portal:**
1. **Conditional Access → New policy**
2. Name: `Block - Sign-ins from unauthorized countries`
3. Users: **All users** (exclude your break-glass group)
4. Target resources: **All resources**
5. Conditions → Locations → Include: **Any location** / Exclude: your Named Location
6. Grant → **Block access**
7. Start with **Report-only** for 7 days, then switch to **On**

**Via Microsoft Graph (import JSON):**
```powershell
Connect-MgGraph -Scopes "Policy.ReadWrite.ConditionalAccess"

$policy = Get-Content "ca-block-unauthorized-countries.json" | ConvertFrom-Json

# Replace placeholders with your actual Object IDs
$policy.conditions.users.excludeGroups = @("<YOUR_BREAK_GLASS_GROUP_ID>")
$policy.conditions.locations.excludeLocations = @("<YOUR_NAMED_LOCATION_ID>")

# Deploy in report-only first
$policy.state = "enabledForReportingButNotEnforced"

New-MgIdentityConditionalAccessPolicy -BodyParameter $policy
```

## 🔑 Placeholders

| Placeholder | Replace with |
|-------------|-------------|
| `<BREAK_GLASS_GROUP_OBJECT_ID>` | Object ID of your break-glass group in Entra ID |
| `<ALLOWED_COUNTRIES_NAMED_LOCATION_ID>` | Object ID of your Named Location (visible in the URL when editing it) |

## ⚠️ Before enabling

- **Always start in Report-only mode** — check Sign-in logs for 7 days to catch any legitimate traffic you may have missed
- Consider users traveling internationally — you may want a separate policy or exclusion group for travelers
- Guest users and B2B partners may sign in from unexpected countries — check your guest sign-in patterns first

## 📖 References

- [Microsoft: Named locations in Conditional Access](https://learn.microsoft.com/en-us/entra/identity/conditional-access/location-condition)
- [Microsoft: Block access by location](https://learn.microsoft.com/en-us/entra/identity/conditional-access/policy-block-by-location)
