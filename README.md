# Tenant Security Auditor

A Python tool that connects to the **Microsoft Graph API** to audit an Entra ID (Azure AD) tenant's security posture, score it against **CIS Microsoft 365 Foundations Benchmark** controls, and generate a visual report.

Built as a portfolio project to demonstrate real-world API integration, security engineering, and full-stack tooling.

<img width="1879" height="907" alt="image" src="https://github.com/user-attachments/assets/c67ca20c-df77-4f2a-8e28-bd5c39a355e5" />



---

## Features

- **10 security checks** across identity, access, and mail
- **Scored 0–100** against CIS benchmark controls
- **Web dashboard** with score trend history (Flask)
- **HTML report** export
- **CLI interface** with flags

---

## Checks Performed

| Check | CIS Control | Description |
|---|---|---|
| MFA Registration | CIS 1.1.1 | Detects users with no MFA method registered |
| Conditional Access | CIS 1.1.2 | Flags tenants with no CA policies configured |
| Named Locations | CIS 1.1.3 | Checks if trusted network locations are defined |
| Legacy Auth Blocked | CIS 1.1.4 | Checks if legacy auth protocols are blocked |
| SSPR | CIS 1.1.5 | Verifies Self-Service Password Reset is enabled |
| Admin Role Hygiene | CIS 1.2.1 | Reviews privileged role assignments, role stacking, and guests with roles |
| PIM / Standing Roles | CIS 1.2.3 | Flags permanent privileged assignments with no PIM gating |
| App Credential Expiry | CIS 1.3.1 | Detects expired or soon-expiring app secrets and SSO certs |
| App Permissions | CIS 1.3.2 | Flags app registrations with overly broad API permissions |
| Password Policy | CIS 2.1.1 | Checks for accounts with non-expiring passwords |
| Mailbox Forwarding | CIS 6.1.1 | Detects external mail forwarding rules |
| Stale Accounts | — | Flags accounts with no sign-in in 90+ days (requires P1/P2) |
| Risky Users | — | Surfaces Entra ID Identity Protection findings (requires P2) |
| Guest Users | — | Enumerates external guest accounts |

---

## Requirements

- Python 3.10+
- Microsoft 365 tenant (dev tenant works)
- Azure App Registration with the following **Application** permissions (admin consent required):
  - `User.Read.All`
  - `Policy.Read.All`
  - `UserAuthenticationMethod.Read.All`
  - `AuditLog.Read.All`
  - `Directory.Read.All`
  - `IdentityRiskyUser.Read.All`
  - `MailboxSettings.Read`
  - `RoleManagement.Read.All`
  - `Application.Read.All`

---

## Setup

**1. Clone the repo**
```bash
git clone https://github.com/bryce141/Tenant-Auditor.git
cd Tenant-Auditor
```

**2. Install dependencies**
```bash
pip install -r requirements.txt
```

**3. Configure credentials**

Create a `.env` file in the project root:
```env
TENANT_ID=your-tenant-id
CLIENT_ID=your-client-id
CLIENT_SECRET=your-client-secret
```

> The `.env` file is gitignored and never committed.

---

## Usage

**Run a CLI audit:**
```bash
python main.py
```

**Specify output file:**
```bash
python main.py --output my-report.html
```

**Skip HTML generation:**
```bash
python main.py --no-html
```

**Run the web dashboard:**
```bash
python app.py
```
Then open [http://localhost:5000](http://localhost:5000)

---

## Project Structure

```
tenant-auditor/
├── app.py                  # Flask web dashboard
├── main.py                 # CLI entry point
├── requirements.txt
├── auditor/
│   ├── auth.py             # MSAL token acquisition
│   ├── scorer.py           # Weighted scoring engine
│   ├── reporter.py         # HTML report generator
│   ├── cis_mapping.py      # CIS benchmark references
│   └── checks/
│       ├── mfa.py
│       ├── conditional_access.py
│       ├── stale_accounts.py
│       ├── risky_users.py
│       ├── mailbox_forwarding.py
│       ├── admin_roles.py
│       ├── guest_users.py
│       ├── legacy_auth.py
│       ├── password_policy.py
│       ├── sspr.py
│       ├── pim_roles.py
│       ├── app_registrations.py
│       └── named_locations.py
```

---

## Tech Stack

- **Python** — core logic and API integration
- **Microsoft Graph API** — tenant data source
- **MSAL** — Azure AD authentication (client credentials flow)
- **Flask** — web dashboard
- **Chart.js** — score trend visualization

---

## Notes

- Checks requiring **Entra ID P1/P2** (stale accounts, risky users) grfully degrade on free/developer tenants
- All credentials are loaded from environment variables — never hardcoded
- Each audit run is saved to `runs/` as JSON for historical tracking
