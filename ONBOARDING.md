# Connecting a Microsoft 365 tenant

*Send this page to whoever administers the tenant being audited. It needs a
Global Administrator once, takes about ten minutes, and grants read-only access.*

---

## What this does

Creates an **app registration** in your Microsoft 365 tenant — a service
identity that can read configuration through the Microsoft Graph API. It is how
the audit reads your settings without anyone sharing a password or being made an
administrator.

**Every permission is read-only.** The application cannot change a setting,
read the contents of a mailbox or file, reset a password, or sign in as a user.

You can revoke it at any time by deleting the app registration. No further
coordination needed.

---

## The fast way (about 2 minutes)

Run one script as a Global Administrator. It creates the registration, grants
consent, and prints the three values to send back.

**Windows / PowerShell 7**

```powershell
./setup_tenant.ps1 -DisplayName "Tenant Auditor (Your Firm)"
```

**macOS / Linux, with Azure CLI**

```bash
az login --allow-no-subscriptions
./setup_tenant.sh "Tenant Auditor (Your Firm)"
```

Both look permission IDs up from Microsoft Graph as they run, so there is
nothing to copy by hand.

---

## The manual way (about 10 minutes)

If you would rather not run a script, or scripting is restricted.

**1. Create the app registration**

[entra.microsoft.com](https://entra.microsoft.com) → **Applications** → **App
registrations** → **New registration**.

- Name: `Tenant Auditor`
- Supported account types: **Accounts in this organizational directory only**
- Redirect URI: leave blank
- **Register**

Copy the **Application (client) ID** and **Directory (tenant) ID** from the
overview page.

**2. Add the permissions**

**API permissions** → **Add a permission** → **Microsoft Graph** →
**Application permissions** *(not Delegated — there is no signed-in user)*.

Tick these fifteen:

| Permission | What it reads |
|---|---|
| `User.Read.All` | User accounts |
| `AuditLog.Read.All` | Last sign-in dates |
| `UserAuthenticationMethod.Read.All` | Whether MFA is registered |
| `MailboxSettings.Read` | Mailbox forwarding rules |
| `Directory.Read.All` | Directory roles |
| `RoleManagement.Read.Directory` | Privileged role assignments |
| `Policy.Read.All` | Conditional Access policies |
| `IdentityRiskyUser.Read.All` | Identity Protection risk (needs Entra ID P2) |
| `SecurityEvents.Read.All` | Microsoft Secure Score |
| `Application.Read.All` | App registrations and their credentials |
| `Domain.Read.All` | Verified domains, for SPF/DKIM/DMARC |
| `Organization.Read.All` | Licence subscriptions |
| `Group.Read.All` | Groups and owners |
| `Reports.Read.All` | Usage reports |
| `SharePointTenantSettings.Read.All` | External sharing configuration |

**3. Grant admin consent — this is the step that matters**

Click **Grant admin consent for \<your organisation\>** and confirm. Every row
should show a green tick under *Status*.

Without this the permissions are requested but inert, and the audit returns
nothing.

**4. Create a client secret**

**Certificates & secrets** → **Client secrets** → **New client secret**.

- Description: `Tenant Auditor`
- Expires: 12 or 24 months

**Copy the `Value` column immediately** — not `Secret ID`. It is shown once and
cannot be retrieved afterwards.

> Note the expiry date. When the secret lapses the audit stops working, and the
> error says only that authentication failed.

---

## What to send back

Three values:

```
Directory (tenant) ID  : xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
Application (client) ID: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
Client secret          : the Value you copied
```

**Send them over something private** — a password manager share, or a call.
Not email, and not chat that keeps history. The secret grants read access to
your whole directory until it is revoked.

---

## Checks that need a licence

These skip on tenants without the relevant plan. They are reported as *not
measured* rather than as failures, and are excluded from the score — a tenant is
never marked down for a control that could not be checked.

| Check | Requires |
|---|---|
| Risky Users | Entra ID **P2** |
| PIM / Standing Roles | Entra ID **P2** to remediate |
| Stale Accounts, User Activity | Entra ID **P1** or **P2** |
| Mailbox, SharePoint, OneDrive usage | The corresponding workload |

---

## Revoking access

**App registrations** → select `Tenant Auditor` → **Delete**. Access stops
immediately.
