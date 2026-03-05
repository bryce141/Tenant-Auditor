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
| Legacy Auth Blocked | CIS 1.1.4 | Checks if legacy auth protocols are blocked |
| Admin Role Hygiene | CIS 1.2.1 | Reviews privileged role assignments |
| Mailbox Forwarding | CIS 6.1.1 | Detects external mail forwarding rules |
| Stale Accounts | — | Flags accounts with no sign-in in 90+ days |
| Risky Users | — | Surfaces Entra ID Identity Protection findings |
| Guest Users | — | Enumerates external guest accounts |
| Password Policy | CIS 2.1.1 | Checks for accounts with non-expiring passwords |
| SSPR | CIS 1.1.5 | Verifies Self-Service Password Reset is enabled |

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

---

## Setup

**1. Clone the repo**
```bash
git clone https://github.com/ayace/Tenant-Auditor.git
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
│       └── sspr.py
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

- Checks requiring **Entra ID P1/P2** (stale accounts, risky users) gracefully degrade on free/developer tenants
- All credentials are loaded from environment variables — never hardcoded
- Each audit run is saved to `runs/` as JSON for historical tracking
