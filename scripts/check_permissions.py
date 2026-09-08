#!/usr/bin/env python3
"""
Diagnose Graph API permissions for the tenant auditor.

Acquires a token with the configured credentials, reads the granted
application permissions out of the token's `roles` claim, and compares
them against what the checks actually need.

    python scripts/check_permissions.py           # compare granted vs required
    python scripts/check_permissions.py --probe   # also call each endpoint live

The --probe mode is the useful one when a check is silently skipping:
it reports the real HTTP status per endpoint, which distinguishes a
missing permission (403) from a wrong URL or absent workload (404).
"""
import argparse
import base64
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import requests  # noqa: E402
from app.auth.graph_auth import get_token  # noqa: E402

# What the checks need. Derived from the endpoints in app/checks/.
#
# "alt" holds broader permissions that also satisfy the requirement, so an app
# consented with Directory.Read.All isn't told it's missing User.Read.All.
REQUIRED = [
    ("User.Read.All", {"Directory.Read.All"},
     "User enumeration — underpins MFA, password policy, guests, forwarding"),
    ("AuditLog.Read.All", set(),
     "signInActivity field — stale accounts, user activity"),
    ("UserAuthenticationMethod.Read.All", set(),
     "MFA registration check"),
    ("MailboxSettings.Read", {"MailboxSettings.ReadWrite"},
     "Mailbox forwarding check"),
    ("Directory.Read.All", set(),
     "Directory roles, group lifecycle policy"),
    ("RoleManagement.Read.Directory", {"RoleManagement.Read.All", "Directory.Read.All"},
     "PIM / standing role assignments"),
    ("Policy.Read.All", set(),
     "Conditional access, named locations, SSPR"),
    ("IdentityRiskyUser.Read.All", set(),
     "Risky users (requires Entra ID P2)"),
    ("SecurityEvents.Read.All", set(),
     "Microsoft Secure Score"),
    ("Application.Read.All", {"Directory.Read.All"},
     "App registration credentials and permissions"),
    ("Domain.Read.All", {"Directory.Read.All"},
     "SPF / DKIM / DMARC email authentication"),
    ("Organization.Read.All", {"Directory.Read.All"},
     "License SKU summary"),
    ("Group.Read.All", {"Directory.Read.All"},
     "Groups, owners, distribution lists"),
    ("Reports.Read.All", set(),
     "Mailbox / SharePoint / OneDrive / M365 app usage reports"),
    ("SharePointTenantSettings.Read.All", set(),
     "SharePoint external sharing settings"),
]

# Endpoints probed in --probe mode: (label, path, beta)
PROBES = [
    ("users", "/users?$select=id&$top=1", False),
    ("users + signInActivity", "/users?$select=id,signInActivity&$top=1", False),
    ("directoryRoles", "/directoryRoles", False),
    ("roleAssignments", "/roleManagement/directory/roleAssignments?$top=1", False),
    ("roleEligibilitySchedules", "/roleManagement/directory/roleEligibilitySchedules?$top=1", False),
    ("conditionalAccess policies", "/identity/conditionalAccess/policies", False),
    ("namedLocations", "/identity/conditionalAccess/namedLocations", False),
    ("authorizationPolicy", "/policies/authorizationPolicy", False),
    ("riskyUsers", "/identityProtection/riskyUsers?$top=1", False),
    ("secureScores", "/security/secureScores?$top=1", False),
    ("applications", "/applications?$select=id&$top=1", False),
    ("servicePrincipals", "/servicePrincipals?$select=id&$top=1", False),
    ("domains", "/domains", False),
    ("subscribedSkus", "/subscribedSkus", False),
    ("groups", "/groups?$select=id&$top=1", False),
    ("groupLifecyclePolicies", "/groupLifecyclePolicies", False),
    ("report: mailbox usage", "/reports/getMailboxUsageDetail(period='D30')", False),
    ("report: SharePoint sites", "/reports/getSharePointSiteUsageDetail(period='D30')", False),
    ("report: OneDrive usage", "/reports/getOneDriveUsageAccountDetail(period='D30')", False),
    ("report: M365 app usage", "/reports/getM365AppUserDetail(period='D30')", False),
    ("sharepoint settings (beta)", "/admin/sharepoint/settings", True),
]

GREEN, RED, YELLOW, DIM, RESET = "\033[32m", "\033[31m", "\033[33m", "\033[2m", "\033[0m"


def decode_roles(token):
    """Read the `roles` claim from a JWT without verifying it (local inspection only)."""
    try:
        payload = token.split(".")[1]
        payload += "=" * (-len(payload) % 4)
        claims = json.loads(base64.urlsafe_b64decode(payload))
        return set(claims.get("roles", [])), claims
    except Exception as e:
        print(f"{RED}Could not decode token: {e}{RESET}")
        return set(), {}


def probe(headers, label, path, beta):
    base = "https://graph.microsoft.com/beta" if beta else "https://graph.microsoft.com/v1.0"
    try:
        # Do not follow redirects: report endpoints answer 302 to a pre-authenticated
        # download URL, and a 302 is the success signal we care about here.
        r = requests.get(f"{base}{path}", headers=headers, allow_redirects=False, timeout=30)
    except Exception as e:
        return "ERR", str(e)[:60]

    code = r.status_code
    if code in (200, 302):
        return "OK", str(code)
    if code == 403:
        detail = ""
        try:
            detail = r.json().get("error", {}).get("message", "")[:70]
        except Exception:
            pass
        return "FORBIDDEN", f"403 {detail}"
    if code == 404:
        return "NOTFOUND", "404 — endpoint or workload not present in tenant"
    return "FAIL", str(code)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--probe", action="store_true", help="call each endpoint live")
    args = ap.parse_args()

    try:
        token, tenant_id = get_token()
    except Exception as e:
        print(f"{RED}Auth failed:{RESET} {e}")
        return 1

    granted, claims = decode_roles(token)
    print(f"\nTenant: {tenant_id}")
    print(f"App ID: {claims.get('appid', 'unknown')}\n")

    missing = []
    print("Permissions")
    print("-" * 78)
    for perm, alt, why in sorted(REQUIRED):
        if perm in granted:
            print(f"  {GREEN}granted{RESET}  {perm}")
        elif alt & granted:
            covering = ", ".join(sorted(alt & granted))
            print(f"  {GREEN}granted{RESET}  {perm} {DIM}(via {covering}){RESET}")
        else:
            missing.append(perm)
            print(f"  {RED}MISSING{RESET}  {perm}")
            print(f"           {DIM}{why}{RESET}")

    known = {p for p, _, _ in REQUIRED} | {a for _, alt, _ in REQUIRED for a in alt}
    extra = granted - known
    if extra:
        print(f"\n  {DIM}Also granted (unused by the checks): {', '.join(sorted(extra))}{RESET}")

    if args.probe:
        headers = {"Authorization": f"Bearer {token}"}
        print("\n\nLive endpoint probe")
        print("-" * 78)
        for label, path, beta in PROBES:
            state, detail = probe(headers, label, path, beta)
            colour = {"OK": GREEN, "FORBIDDEN": RED, "NOTFOUND": YELLOW}.get(state, RED)
            print(f"  {colour}{state:<10}{RESET} {label:<30} {DIM}{detail}{RESET}")
        print(f"\n  {DIM}403 = permission missing. 404 = wrong URL, or the workload"
              f"\n  (Exchange/SharePoint) is not provisioned in this tenant.{RESET}")

    print()
    if missing:
        print(f"{RED}{len(missing)} permission(s) missing.{RESET} Add them in Azure:")
        print(f"  {DIM}Entra ID > App registrations > your app > API permissions >{RESET}")
        print(f"  {DIM}Add a permission > Microsoft Graph > Application permissions{RESET}")
        print(f"  {DIM}...then 'Grant admin consent' — permissions are inert without it.{RESET}\n")
        for p in missing:
            print(f"    {p}")
        print()
        return 1

    print(f"{GREEN}All required permissions granted.{RESET}\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
