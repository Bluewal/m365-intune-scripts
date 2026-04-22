# 🔐 RDP File Signing — Intune Deployment

> Fix for the April 2026 Windows security update that flags unsigned `.rdp` files as "Unknown Publisher".

## Context

Starting with the **April 2026 cumulative updates** (KB5083769 / KB5082200), Windows displays a red security warning when opening any unsigned `.rdp` file:

> *"Caution: Unknown remote connection — The publisher of this remote connection can't be identified."*

This was introduced by Microsoft to combat widespread RDP phishing attacks (notably by state-sponsored groups like APT29), where attackers send malicious `.rdp` files via email to redirect local resources and steal credentials.

The fix: **sign your `.rdp` file** with a code signing certificate and deploy trust to all endpoints via Intune. Signed files show a blue "Verified Publisher" dialog instead of the red warning, and users can save their "Don't ask again" preference.

---

## What's in this folder

| File | Description |
|---|---|
| `sign-rdp.ps1` | One-shot script: creates cert, signs `.rdp`, exports `.cer` |
| `install.ps1` | Intune Win32 install script — copies signed `.rdp` + creates desktop shortcut |
| `uninstall.ps1` | Intune Win32 uninstall script |

---

## Step-by-step

### 1. Sign your .rdp file

Run as **Administrator** on any Windows machine:

```powershell
.\sign-rdp.ps1 -RdpPath "C:\path\to\yourconnection.rdp" -CertSubject "CN=YOURORG RDP Publisher"
```

This will:
- Create a self-signed code signing certificate (valid 3 years)
- Install it in `LocalMachine\Root` on the current machine
- Sign the `.rdp` file in place
- Export the public `.cer` for Intune deployment

> **Note:** `Get-AuthenticodeSignature` returns `UnknownError` on `.rdp` files — this is expected. RDP files use a proprietary signature format, not Authenticode. The real validation is opening the file with `mstsc.exe`.

**Save your thumbprint** — you'll need it for the Settings Catalog policy.

---

### 2. Deploy the trusted certificate via Intune

`Devices → Configuration → Create → New policy`
- Platform: **Windows 10 and later**
- Profile type: **Templates → Trusted certificate**
- Upload: `YOURORG-RDP-Publisher.cer`
- Destination store: **Computer certificate store – Root**
- Assign to: All Devices

---

### 3. Configure Settings Catalog

`Devices → Configuration → Create → New policy`
- Platform: **Windows 10 and later**  
- Profile type: **Settings Catalog**

Search `rdp publisher` → add (Device, not User):
- ✅ **Specify SHA1 thumbprints of certificates representing trusted .rdp publishers**
  - Value: `YOUR_CERT_THUMBPRINT`

Search `valid publishers` → add (Device, not User):
- ✅ **Allow .rdp files from valid publishers and user's default .rdp settings**
  - Set to: **Enabled**

Assign to: All Devices

---

### 4. Package and deploy the signed .rdp via Intune (Win32)

Package with `IntuneWinAppUtil.exe`:

```powershell
IntuneWinAppUtil.exe -c ".\Source" -s "install.ps1" -o ".\Output"
```

Intune Win32 app settings:
- **Install command:** `powershell.exe -ExecutionPolicy Bypass -File install.ps1`
- **Uninstall command:** `powershell.exe -ExecutionPolicy Bypass -File uninstall.ps1`
- **Install behavior:** System
- **Detection rule:** File — `%ProgramData%\YOURORG\RDP\version.txt` — File or folder exists

> To support versioned updates, the install script writes a `version.txt` file. Increment the version number in `install.ps1` and the detection rule on each update.

---

### 5. Supersedence (optional, for migrating from unsigned package)

If you're replacing an existing unsigned deployment:
1. Deploy the new signed package to a **pilot group** first
2. Validate (blue "Verified Publisher" dialog, no red warning)
3. Add the old package as a **Supersedence** target in the new app
4. Expand assignment to All Devices

---

## Result

| Before | After |
|---|---|
| 🔴 Red warning — Unknown Publisher | 🔵 Blue dialog — Verified Publisher: YOURORG |
| No "Don't ask again" option | "Don't ask again" available |

---

## Notes

- The self-signed cert is valid for **3 years** — set a calendar reminder to renew before expiry
- Renewing requires re-signing the `.rdp`, exporting a new `.cer`, updating the Intune Trusted Cert profile and thumbprint in Settings Catalog
- These settings are **permissive**, not restrictive — unsigned `.rdp` files continue to work (with the red warning), nothing breaks during rollout
- Tested on Windows 11 with KB5083769

---

## Related

- [Microsoft: Understanding security warnings when opening RDP files](https://learn.microsoft.com/en-us/windows-server/remote/remote-desktop-services/remotepc/understanding-security-warnings)
- [BleepingComputer: Microsoft adds Windows protections for malicious Remote Desktop files](https://www.bleepingcomputer.com/news/microsoft/microsoft-adds-windows-protections-for-malicious-remote-desktop-files/)
