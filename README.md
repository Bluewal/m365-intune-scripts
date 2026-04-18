# 🛡️ bluewall-m365-toolkit

> PowerShell scripts, Intune configurations, and Microsoft 365 security hardening resources — built in the field by a solo IT/Security engineer running a real-world M365 Business Premium environment.

---

## 👋 About

I'm a solo IT & Security Manager at a ~50-person nonprofit in Switzerland, managing the full Microsoft 365 stack (Entra ID, Intune, Defender XDR, Exchange Online, SharePoint, Teams).

This repo is a collection of scripts, configs, and writeups I've built and battle-tested in production. No fluff — everything here has been deployed on real hardware.

**Current Secure Score progression: 56% → 91%+** working from near-zero security posture.

---

## 📁 Repository Structure

```
bluewall-m365-toolkit/
│
├── intune/
│   ├── scripts/              # PowerShell detection & remediation scripts
│   ├── printer-deployment/   # Ricoh IPP + Kyocera KX Win32 packaging guides
│   └── update-rings/         # Windows Update ring configurations
│
├── conditional-access/
│   ├── country-blocking/
│   ├── device-code-flow-block/
│   └── fido2-admin-enforcement/
│
├── defender/
│   ├── asr-rules/            # Attack Surface Reduction configurations
│   └── threat-response/      # Incident response scripts
│
├── entra/
│   └── sensitivity-labels/   # Bilingual FR/DE label setup
│
└── guides/
    ├── secure-score-journey.md
    ├── dmarc-reject-deployment.md
    └── mde-linux-onboarding.md
```

---

## 📜 Scripts & Configs

### 🔍 Threat Response

| Script | Description |
|--------|-------------|
| `defender/threat-response/Invoke-NpmAxiosScan.ps1` | Detects compromised axios npm packages across Intune-managed fleet (supply chain attack — March 2026) |
| `entra/Check-DeviceCodeFlowUsage.ps1` | Audits Device Code Flow sign-in activity in the tenant before blocking |

### 🖨️ Intune — Printer Deployment

| Resource | Description |
|----------|-------------|
| `intune/printer-deployment/ricoh-ipp/` | Ricoh deployment via Microsoft IPP Class Driver (zero-touch) |
| `intune/printer-deployment/kyocera-kx/` | Kyocera TASKalfa via KX driver Win32 app packaging, with troubleshooting notes |

### 🔒 Conditional Access

| Policy | Description |
|--------|-------------|
| `conditional-access/country-blocking/` | Block sign-ins from outside allowed countries |
| `conditional-access/device-code-flow-block/` | Block Device Code Flow authentication (AiTM/EvilTokens mitigation) |
| `conditional-access/fido2-admin-enforcement/` | Require FIDO2 phishing-resistant MFA for all admin accounts |

### 🛡️ Defender — ASR Rules

Deployment templates for Attack Surface Reduction rules via Intune Settings Catalog, including known false-positive behaviors on Windows 24H2 with WUfB deadline CSPs.

---

## 📖 Guides

### [Secure Score Journey: 56% → 91%](guides/secure-score-journey.md)
A practical walkthrough of what actually moved the needle — not generic advice, but the specific controls deployed in sequence for a small nonprofit environment.

**Key milestones covered:**
- BitLocker + LAPS rollout
- Credential Guard via Settings Catalog
- SMB signing via Intune
- DMARC p=reject on all domains
- Sensitivity Labels (FR/DE bilingual)
- Conditional Access baseline suite
- MDE full onboarding (Windows + Linux)

### [DMARC p=reject Deployment](guides/dmarc-reject-deployment.md)
Step-by-step guide to reach p=reject safely, including the monitoring phase and handling legitimate mail flows before enforcement.

### [MDE Onboarding — Ubuntu 24.04 + Intune](guides/mde-linux-onboarding.md)
End-to-end guide for enrolling a Linux workstation (Ubuntu 24.04, Arrow Lake-U) into Microsoft Defender for Endpoint via Intune, with onboarding script deployment and validation steps.

---

## ⚠️ Usage Notes

- All scripts use **placeholder values** for tenant-specific information. Search and replace before deploying:
  - `<TENANT_ID>` → your Entra tenant ID
  - `<DOMAIN>` → your primary domain
  - `<UPN_SUFFIX>` → your UPN suffix
- Always test in a **pilot/staging group** before broad deployment
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
Guides and documentation: [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/)
