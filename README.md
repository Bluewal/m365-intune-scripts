# 🛡️ m365-intune-scripts

> PowerShell scripts, Conditional Access templates and Microsoft 365 security resources — built in the field by a solo IT/Security engineer running a real-world M365 Business Premium environment.

---

## 👋 About

I'm a solo IT & Security Manager at a small nonprofit in Europe, managing the full Microsoft 365 stack (Entra ID, Intune, Defender XDR, Exchange Online, SharePoint, Teams).

This repo is a collection of scripts, configs, and templates I've built and battle-tested in production. No fluff — everything here has been deployed on real hardware.

**Secure Score progression: 56% → 91%+** from near-zero security posture.

---

## 📁 Contents

### 🔍 Defender / Threat Response

| File | Description |
|------|-------------|
| [`defender/threat-response/Invoke-NpmAxiosScan.ps1`](defender/threat-response/Invoke-NpmAxiosScan.ps1) | Detects the axios npm supply chain attack IOC (`wt.exe` in `%ProgramData%`) across Intune-managed fleet — no E3/E5 required |

### 🔐 Entra / Audit Scripts

| File | Description |
|------|-------------|
| [`entra/shared-mailboxes/Invoke-SharedMailboxAudit.ps1`](entra/shared-mailboxes/Invoke-SharedMailboxAudit.ps1) | Audits all shared mailboxes for sign-in status, license assignment, and last activity |
| [`entra/admin-accounts/Invoke-AdminAccountAudit.ps1`](entra/admin-accounts/Invoke-AdminAccountAudit.ps1) | Audits all admin accounts for MFA status, last sign-in, and legacy/stale accounts |
| [`entra/legacy-auth/Invoke-LegacyAuthAudit.ps1`](entra/legacy-auth/Invoke-LegacyAuthAudit.ps1) | Audits legacy authentication protocol usage across all sign-in logs before blocking |

### 🔐 Entra / Device Code Flow

| File | Description |
|------|-------------|
| [`entra/device-code-flow/Invoke-DeviceCodeFlowAudit.ps1`](entra/device-code-flow/Invoke-DeviceCodeFlowAudit.ps1) | Audits all 4 Entra sign-in log types for Device Code Flow activity before blocking |
| [`entra/device-code-flow/ca-block-device-code-flow.json`](entra/device-code-flow/ca-block-device-code-flow.json) | CA policy template to block Device Code Flow tenant-wide |

### 🌍 Conditional Access / Country Blocking

| File | Description |
|------|-------------|
| [`conditional-access/country-blocking/ca-block-unauthorized-countries.json`](conditional-access/country-blocking/ca-block-unauthorized-countries.json) | CA policy template to block sign-ins from unauthorized countries |

---

## 🔄 Audit Before You Block

A recurring pattern in this repo: **always audit before deploying a block policy.**

```
Invoke-SharedMailboxAudit.ps1    → then block shared mailbox sign-ins
Invoke-AdminAccountAudit.ps1     → then enforce MFA / clean up stale accounts
Invoke-LegacyAuthAudit.ps1       → then block legacy auth via CA
Invoke-DeviceCodeFlowAudit.ps1   → then block Device Code Flow via CA
```

---

## ⚠️ Usage Notes

- All files use **placeholder values** for tenant-specific information. Search and replace before deploying:
  - `<BREAK_GLASS_GROUP_OBJECT_ID>` → Object ID of your break-glass group
  - `<ALLOWED_COUNTRIES_NAMED_LOCATION_ID>` → Object ID of your Named Location
- Always test CA policies in **Report-only mode** for 7 days before enforcing
- Scripts are provided as-is — review before running in your environment

---

## 🏷️ Tech Stack

![Microsoft 365](https://img.shields.io/badge/Microsoft_365-Business_Premium-0078D4?logo=microsoft)
![Intune](https://img.shields.io/badge/Intune-MDM%2FMAM-0078D4?logo=microsoft)
![Defender XDR](https://img.shields.io/badge/Defender-XDR-00B4D8?logo=microsoft)
![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2B-5391FE?logo=powershell)

---

## 📬 Contact

- Mastodon: [@Bluewall@infosec.exchange](https://infosec.exchange/@Bluewall)
- GitHub: [@Bluewal](https://github.com/Bluewal)

---

## 📄 License

Scripts and configurations: [MIT License](LICENSE)
