# Tenant Security Auditor

A Flask application that connects to the **Microsoft Graph API** to audit an
Entra ID (Azure AD) tenant, score it against **CIS Microsoft 365 Foundations
Benchmark** controls, and track posture over time.

Built as a portfolio project to demonstrate real-world API integration, security
engineering, and full-stack tooling.

<img width="1879" height="907" alt="image" src="https://github.com/user-attachments/assets/c67ca20c-df77-4f2a-8e28-bd5c39a355e5" />

---

## Features

- **27 checks** across 8 categories — identity, conditional access, mail
  security, licensing, users, SharePoint, Exchange, and groups
- **Weighted 0–100 score** over 110 points of CIS-mapped security controls
- **Web dashboard** with score trend history and cross-category alerts
- **Per-category runs** or a full audit with live progress
- **Every run persisted** to SQLite, so history survives restarts
- **CSV export** per report
- **Credentials configured in the UI** — no redeploy to point at a new tenant

---

## Checks Performed

### Scored — security posture (110 pts)

| Check | CIS Control | Weight | Description |
|---|---|---|---|
| MFA Registration | CIS 1.1.1 | 20 | Users with no non-password auth method registered |
| Conditional Access Policies | CIS 1.1.2 | 15 | CA policies present, enabled, and not stuck in report-only |
| Legacy Auth Blocked | CIS 1.1.4 | 10 | A policy actually blocks legacy authentication |
| Admin Role Hygiene | CIS 1.2.1 | 10 | Privileged role counts, role stacking, guests holding roles |
| PIM / Standing Roles | CIS 1.2.3 | 10 | Permanent privileged assignments with no PIM gating |
| Email Authentication | CIS 6.2.2 | 10 | SPF (3) + DMARC (4) + DKIM (3) per verified domain, via live DNS |
| Mailbox Forwarding | CIS 6.1.1 | 8 | External auto-forwarding on any mailbox |
| App Credential Expiry | CIS 1.3.1 | 8 | Expired or soon-expiring app secrets and SSO certificates |
| App Permissions | CIS 1.3.2 | 5 | App registrations holding overly broad Graph permissions |
| Password Policy | CIS 2.1.1 | 5 | Accounts with passwords set to never expire |
| SSPR Enabled | CIS 1.1.5 | 5 | Self-Service Password Reset is turned on |
| Named Locations | CIS 1.1.3 | 4 | Trusted network locations are defined |

### Informational — inventory and hygiene

| Category | Checks |
|---|---|
| Identity | Stale Accounts (90+ days), Guest Users, Risky Users, Microsoft Secure Score |
| Licensing | License Summary, Per-User Licenses |
| Users | User Sign-in Activity, M365 App Usage |
| SharePoint | Site Usage, External Sharing Policy, OneDrive Usage |
| Exchange | Mailbox Sizes, Shared Mailboxes, Distribution Lists |
| Groups | Group Inventory, Group Expiration Policy |

### How scoring works

Each scored check returns `points_earned` out of `points_possible`; the overall
score is `earned / possible * 100` across the three security categories. Checks
that can't run — missing permission, absent license, workload not provisioned —
return a `skip` status and are excluded from the denominator rather than counted
as failures. A tenant is never penalised for a check that couldn't execute.

---

## Requirements

- Python 3.10+
- Microsoft 365 tenant (dev tenant works)
- Azure App Registration with the **Application** permissions below

### Graph API permissions

All are **Application** permissions and all require **admin consent** — they do
nothing until consent is granted, even after they're added.

| Permission | Needed for |
|---|---|
| `User.Read.All` | User enumeration — underpins MFA, password policy, guests, forwarding |
| `AuditLog.Read.All` | `signInActivity` field — stale accounts, user activity |
| `UserAuthenticationMethod.Read.All` | MFA registration |
| `MailboxSettings.Read` | Mailbox forwarding |
| `Directory.Read.All` | Directory roles, group lifecycle policy |
| `RoleManagement.Read.Directory` | PIM / standing role assignments |
| `Policy.Read.All` | Conditional access, named locations, SSPR |
| `IdentityRiskyUser.Read.All` | Risky users — requires Entra ID **P2** |
| `SecurityEvents.Read.All` | Microsoft Secure Score |
| `Application.Read.All` | App registration credentials and permissions |
| `Domain.Read.All` | SPF / DKIM / DMARC email authentication |
| `Organization.Read.All` | License SKU summary |
| `Group.Read.All` | Groups, owners, distribution lists |
| `Reports.Read.All` | Mailbox, SharePoint, OneDrive, and M365 app usage reports |
| `SharePointTenantSettings.Read.All` | SharePoint external sharing settings |

To verify what's actually granted, run:

```bash
python scripts/check_permissions.py           # granted vs. required
python scripts/check_permissions.py --probe   # also call each endpoint live
```

`--probe` is the one to reach for when a check is silently skipping — it reports
the real HTTP status per endpoint, which tells a missing permission (403) apart
from a workload that isn't provisioned in the tenant (404).

---

## Setup

**1. Clone the repo**
```bash
git clone https://github.com/bryce141/Tenant-Auditor.git
cd Tenant-Auditor
```

**2. Create a virtualenv and install dependencies**
```bash
python -m venv .venv
source .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

**3. Run it**
```bash
python run.py
```

Open [http://localhost:5000](http://localhost:5000) and enter your tenant ID,
client ID, and client secret on the setup screen. **Test Connection** validates
them against Entra ID before saving.

Credentials are written to `config.json` (gitignored). If you'd rather supply
them out-of-band, set `TENANT_ID`, `CLIENT_ID`, and `CLIENT_SECRET` in a `.env`
file instead — `config.json` takes precedence when both are present.

> Neither `.env` nor `config.json` is ever committed.

---

## Usage

Once credentials are saved:

- **Dashboard** (`/dashboard`) — overall score, per-category tiles, alerts, and
  score history. **Run Full Audit** executes all 8 categories in the background
  with a live progress overlay.
- **Security** (`/security`) — the scored checks in detail, with CIS references
  and per-check issue lists. Categories can be re-run individually.
- **Licensing / Users / SharePoint / Exchange / Groups** — inventory views, each
  independently runnable.
- **Reports** (`/reports`) — every run, with CSV export and delete.
- **Settings** (`/settings`) — update or re-test tenant credentials.

Runs execute in a background thread, so the UI stays responsive; the relevant
page polls its `api/status` endpoint until the run completes.

---

## Deployment

`render.yaml` provisions the app on [Render](https://render.com) with a 1 GB
persistent disk mounted at `/var/data`. Both `config.json` and the SQLite
database live there so credentials and audit history survive redeploys.

```yaml
startCommand: gunicorn run:app --bind 0.0.0.0:$PORT --workers 2
```

Set `SECRET_KEY` in the Render dashboard. Tenant credentials are entered through
the UI rather than baked into the environment.

---

## Project Structure

```
tenant-auditor/
├── run.py                        # entry point — creates the Flask app
├── requirements.txt
├── render.yaml                   # Render deploy config
├── scripts/
│   └── check_permissions.py      # Graph permission diagnostic
└── app/
    ├── __init__.py               # app factory, blueprint registration
    ├── config.py
    ├── auth/
    │   └── graph_auth.py         # MSAL token acquisition, credential storage
    ├── models/
    │   └── report.py             # Report + ReportCheck (SQLAlchemy)
    ├── services/
    │   ├── graph_client.py       # paginated Graph wrapper (JSON + CSV reports)
    │   ├── report_runner.py      # orchestration, background runs, progress
    │   └── scoring.py            # weights and CIS mapping
    ├── checks/                   # one module per category, each exposing run_all()
    │   ├── identity.py
    │   ├── conditional_access.py
    │   ├── mail_security.py
    │   ├── licensing.py
    │   ├── users.py
    │   ├── sharepoint.py
    │   ├── exchange.py
    │   └── groups.py
    ├── routes/                   # one blueprint per section
    └── templates/
```

Adding a category is: a module in `checks/` exposing `run_all(client)`, an entry
in `CATEGORY_MAP` in `report_runner.py`, and a blueprint in `routes/`.

---

## Tech Stack

- **Python** — core logic and API integration
- **Microsoft Graph API** — tenant data source (v1.0, with beta for SharePoint settings)
- **MSAL** — Entra ID authentication (client credentials flow)
- **Flask** + **Flask-SQLAlchemy** — web app and persistence
- **SQLite** — report storage
- **dnspython** — live SPF/DKIM/DMARC record lookups
- **Tailwind** + **Chart.js** — UI and score trend visualization

---

## Notes

- Checks requiring **Entra ID P1/P2** (stale accounts, risky users) degrade
  gracefully on free and developer tenants — they skip rather than fail
- Credentials are never hardcoded; `config.json` and `.env` are both gitignored
- `secureScores` reflects Microsoft's own scoring and is surfaced alongside the
  CIS score rather than folded into it — the two measure different things
