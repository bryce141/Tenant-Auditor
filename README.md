# Tenant Security Auditor

A Flask application that connects to the **Microsoft Graph API** to audit an
Entra ID (Azure AD) tenant, score it against **CIS Microsoft 365 Foundations
Benchmark** controls, and track posture over time.

Built as a portfolio project to demonstrate real-world API integration, security
engineering, and full-stack tooling.

<img width="1879" height="907" alt="image" src="https://github.com/user-attachments/assets/c67ca20c-df77-4f2a-8e28-bd5c39a355e5" />

---

## Features

- **Password-protected** — every route requires a session; secrets and audit
  data are never served to an anonymous visitor
- **Multi-tenant** — audit any number of tenants from one install, switching
  between them without redeploying; client secrets encrypted at rest
- **27 checks** across 8 categories — identity, conditional access, mail
  security, licensing, users, SharePoint, Exchange, and groups
- **Weighted 0–100 score** over 110 points of CIS-mapped security controls
- **Web dashboard** with score trend history and cross-category alerts
- **Per-category runs** or a full audit with live progress
- **Every run persisted** to SQLite, so history survives restarts
- **Change detection** — each audit is diffed against the previous one: new
  findings, resolutions, regressions, and controls that stopped being measured
- **Scheduled audits and email digest** — one command for cron, leading with
  what changed rather than restating the score
- **Client-ready HTML report** with severity-ranked findings and remediation,
  plus CSV export
- **Credentials configured in the UI** — no redeploy to point at a new tenant
- **Conditional Access simulator** — compose a draft CA policy and see which
  real users and sign-ins it would have broken, before it touches the tenant
- **"What's missing"** — the audit's findings turned into the policies that fix
  them, each priced against the tenant's own traffic

---

## Conditional Access simulator

Entra's own *What If* tool evaluates one hypothetical sign-in at a time, so you
have to already imagine the scenario that breaks. This evaluates a draft policy
against **real observed traffic** — the last 30 days of the tenant's sign-in log
— and surfaces breakage nobody thought to test for.

> 312 sign-ins across 21 users would be affected
> out of 476 sign-ins by 21 users over the last 30 days

Impact is a **delta**: a control users are already subject to is not counted, so
a draft that duplicates an existing policy correctly reports that it changes
nothing.

**Nothing is ever written to the tenant.** The draft is evaluated and handed
back as Graph JSON to apply yourself.

### Why you can believe the numbers

Microsoft's `POST /identity/conditionalAccess/evaluate` can only score policies
that already exist in a tenant, so it cannot evaluate a draft. This tool
implements its own Conditional Access evaluation engine — and then checks that
engine against Microsoft's, on the tenant's real policies and real sign-ins:

```
476 sign-ins, 68 distinct condition sets
Microsoft What If endpoint   756/756 verdicts agree   100.00%
Sign-in log cross-check      720/720 verdicts agree   100.00%
```

The second row is the stronger one: it compares against
`appliedConditionalAccessPolicies`, which records what the tenant *actually did*
at real sign-in time. That report is a page in the app (**Why trust these
numbers?**), not a footnote, and `flask ca-validate` exits non-zero on any
disagreement so it can gate a change to the engine.

Conditions the engine cannot evaluate are reported as **declared gaps**, counted
separately and never as agreement. A policy it cannot read is never silently
scored as inapplicable — that would report the policy as breaking nobody, which
is the one failure a simulator must not have.

### What's missing

The simulator answers "what would this policy break". `/simulator/recommendations`
answers the reverse — which policies the tenant is missing, and what each would
cost — by joining the audit's findings to the engine's impact assessment:

```
[SAFE]         Block legacy authentication
               Would affect nobody — safe to enable
               addresses: Legacy Auth Blocked (FAIL)

[SIGNIFICANT]  Require MFA for administrators
               149 sign-ins across 5 users would be affected
               PARTIAL: PIM is the actual fix — this makes the role harder to
                        use, not shorter-lived
```

Findings no Conditional Access policy can fix — SPF and DKIM, password policy,
app credentials — are listed separately with where the fix does live, so the
recommendations never read as the whole job.

### Command line

```bash
flask ca-corpus   --tenant X          # sign-in traffic reduced to condition sets
flask ca-validate --tenant X          # check the engine against Microsoft
flask ca-impact   draft.json --tenant X   # what a draft policy would break
```

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

**Onboarding a client tenant:** send them
**[ONBOARDING.md](ONBOARDING.md)** — a one-page guide for their administrator,
with a script (`scripts/setup_tenant.ps1` or `setup_tenant.sh`) that creates the
registration, grants consent, and prints the three values to send back. Manual
portal steps are included for anyone who can't run scripts.

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
python run.py            # PORT=8080 python run.py to use another port
```

> Port 5001, not 5000 — macOS ControlCenter (AirPlay Receiver) holds 5000.

Open [http://localhost:5001](http://localhost:5001). On first run you'll be
asked to create an administrator account — nothing is reachable until it
exists. Then go to **Tenants** and add one. **Test connection** validates the credentials against Entra ID before
saving.

Each tenant needs its own app registration with the permissions above. Secrets
are encrypted with a key derived from `SECRET_KEY` before being stored, so set
a real one in production — if it changes, stored secrets can't be decrypted and
must be re-entered.

An existing single-tenant `config.json` or `.env` is imported automatically on
first start, so upgrading installs keep working. Neither file is ever committed.

---

## Usage

Once credentials are saved:

- **Tenants** (`/tenants`) — add, edit, and switch tenants. With more than one
  configured, a switcher appears in the sidebar; everything else on the site is
  scoped to the selected tenant.
- **Dashboard** (`/dashboard`) — overall score, per-category tiles, alerts, and
  score history. A **Since last audit** panel lists what moved since the previous
  full run. A tenant with no audits yet gets a first-run screen instead.
  **Run Full Audit** executes all 8 categories in the background with a live
  progress overlay.
- **Security** (`/security`) — the scored checks in detail, with CIS references
  and per-check issue lists. Filters default to **Needs action**, since that is
  what the page is usually opened for. Categories can be re-run individually.
- **Licensing / Users / SharePoint / Exchange / Groups** — inventory views, each
  independently runnable.
- **Reports** (`/reports`) — every run for the active tenant. **Report** opens a
  standalone HTML audit document — executive summary, what changed since the
  previous audit, findings ranked worst-first with remediation, then passing and
  skipped checks as evidence of scope. It is fully self-contained and prints to PDF. **CSV** gives the raw
  rows.
- **CA Simulator** (`/simulator`) — load the tenant's sign-in traffic once, then
  compose draft Conditional Access policies against it. Start from a preset —
  block legacy auth, require MFA for admins — or build one from scratch; the
  form offers exactly the conditions the engine can evaluate and lists the ones
  it cannot. **Why trust these numbers?** runs the agreement check against
  Microsoft's What If endpoint.
- **Settings** (`/settings`) — update or re-test tenant credentials.

Runs execute in a background thread, so the UI stays responsive; the relevant
page polls its `api/status` endpoint until the run completes.

---

## Scheduled audits

Scheduling lives outside the app deliberately. An in-process scheduler only
runs while the web process is alive, and a host that sleeps an idle service
would stop auditing without telling anyone — a security tool silently not
running is a worse failure than a crontab entry.

```bash
flask audit                    # audit every tenant
flask audit --tenant Contoso   # just one
flask digest --dry-run         # preview the email, send nothing
flask digest                   # send it
flask scheduled-run            # audit everything, then send the digest
```

`audit` exits non-zero if any tenant fails, so cron and CI can alert on it.
`scheduled-run` still sends the digest when an audit fails — a tenant that
didn't audit is exactly what the recipient needs to know.

Weekly, Monday at 07:00:

```cron
0 7 * * 1 cd /path/to/tenant-auditor && FLASK_APP=run.py .venv/bin/flask scheduled-run
```

On Render, use a Cron Job service with the same command against the same disk.

### Email configuration

SMTP only, via environment variables — no third-party account needed:

| Variable | Notes |
|---|---|
| `SMTP_HOST` | required to send |
| `SMTP_PORT` | default `587` |
| `SMTP_USER` | omit for a relay that doesn't authenticate |
| `SMTP_PASSWORD` | |
| `SMTP_FROM` | defaults to `SMTP_USER` |
| `SMTP_TLS` | `false` to disable STARTTLS |
| `DIGEST_TO` | comma-separated recipients |

`flask digest --dry-run` prints the digest and shows which settings are set,
without ever printing the password.

---

## Deployment

See **[DEPLOYING.md](DEPLOYING.md)** for the full checklist and the traps.

`render.yaml` provisions the app on [Render](https://render.com) with a 1 GB
persistent disk mounted at `/var/data`. Both `config.json` and the SQLite
database live there so credentials and audit history survive redeploys.

```yaml
startCommand: gunicorn run:app --bind 0.0.0.0:$PORT --workers 2
```

Set `SECRET_KEY` in the Render dashboard, and **`SESSION_COOKIE_SECURE=true`**
for any deployment served over TLS — otherwise the session cookie travels in
the clear. Tenant credentials are entered through the UI rather than baked into
the environment.

On first visit you'll be asked to create the administrator account. Do that
immediately after deploying: until it exists the setup page is open to whoever
reaches it first.

---

## Project Structure

```
tenant-auditor/
├── run.py                        # entry point — creates the Flask app
├── requirements.txt
├── render.yaml                   # Render deploy config
├── scripts/
│   ├── check_permissions.py      # Graph permission diagnostic
│   ├── setup_tenant.ps1 / .sh    # create + consent the app registration
│   ├── prepare_sim_tenant.ps1    # build a dev tenant to simulate against
│   ├── seed_test_users.ps1       # test users and groups
│   ├── seed_ca_test_policies.ps1 # report-only CA policies
│   ├── seed_demo_findings.ps1    # real misconfiguration, for demos
│   ├── generate_signin_traffic.py# fill the corpus with sign-ins
│   └── ingest_tenant_credentials.py # store a secret without displaying it
└── app/
    ├── __init__.py               # app factory, blueprint registration
    ├── config.py
    ├── cli.py                    # flask audit / digest / scheduled-run
    │                             #   + ca-corpus / ca-validate / ca-impact
    ├── auth/
    │   ├── graph_auth.py         # MSAL tokens, tenant selection
    │   └── session_auth.py       # login state, fail-closed request guard
    ├── models/
    │   ├── report.py             # Report + ReportCheck (SQLAlchemy)
    │   ├── tenant.py             # Tenant, with encrypted client secret
    │   └── user.py               # the administrator account
    ├── services/
    │   ├── graph_client.py       # paginated Graph wrapper (JSON + CSV reports)
    │   ├── report_runner.py      # orchestration, background runs, progress
    │   ├── report_export.py      # standalone HTML report
    │   ├── remediation.py        # per-check guidance and severity
    │   ├── comparison.py         # run-to-run diffing
    │   ├── digest.py             # scheduled email summary
    │   ├── mailer.py             # SMTP delivery
    │   ├── formatting.py         # display labels, relative times
    │   ├── crypto.py             # secret encryption at rest
    │   ├── scoring.py            # weights and CIS mapping
    │   │
    │   │                         # — Conditional Access simulator —
    │   ├── signin_corpus.py      # sign-in log → distinct condition tuples
    │   ├── ca_memberships.py     # group and role membership per user
    │   ├── ca_locations.py       # IP / country → named locations
    │   ├── ca_app_groups.py      # Office365 and admin-portal app groups
    │   ├── ca_engine.py          # evaluate(policy, tuple) — pure, no I/O
    │   ├── ca_validation.py      # agreement harness vs Microsoft What If
    │   ├── ca_impact.py          # what a draft would change, as a delta
    │   ├── ca_builder.py         # form input → Graph policy JSON
    │   ├── ca_recommendations.py # audit findings → priced policies
    │   └── ca_workspace.py       # per-tenant corpus cache
    ├── checks/                   # one module per category, each exposing run_all()
    │   ├── base.py               # @check decorator, GraphError to skip
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
- **cryptography** — Fernet encryption for stored client secrets
- **Tailwind** + **Chart.js** — UI and score trend visualization

---

## Database migrations

Alembic, via Flask-Migrate. The schema updates itself when the app starts, so
an upgrade needs no manual step — including on a database created before
migrations existed, which is stamped and brought forward with its data intact.

After changing a model:

```bash
FLASK_APP=run.py flask db migrate -m "what changed"
```

Read the generated file before committing it; autogenerate doesn't catch
everything.

---

## Tests

```bash
pip install -r requirements-dev.txt
pytest
```

`tests/test_check_contract.py` runs every check module against a client where
all Graph calls fail and one where they all succeed empty, asserting results
stay well-formed and no check silently disappears. That covers all 28 checks
without needing a tenant.

---

## Notes

- Checks requiring **Entra ID P1/P2** (stale accounts, risky users) degrade
  gracefully on free and developer tenants — they skip rather than fail
- Credentials are never hardcoded, and stored secrets are encrypted at rest.
  That protects a leaked database file, not someone who already holds the
  application environment — the key is derived from `SECRET_KEY`
- `secureScores` reflects Microsoft's own scoring and is surfaced alongside the
  CIS score rather than folded into it — the two measure different things
