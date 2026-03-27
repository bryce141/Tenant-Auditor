"""
Mail Security checks:
  - Mailbox Forwarding    (8 pts)
  - App Registrations     (credential expiry: 8 pts, permissions: 5 pts)
"""
from datetime import datetime, timezone, timedelta
from app.services.graph_client import GraphClient
from app.services.scoring import CIS_MAP

EXPIRY_WARN_DAYS = 30

DANGEROUS_PERMISSIONS = {
    "19dbc75e-c2e2-444c-a770-ec69d8559fc7": "Directory.ReadWrite.All",
    "62a82d76-70ea-41e2-9197-370581804d09": "Group.ReadWrite.All",
    "741f803b-c850-494e-b5df-cde7c675a1ca": "User.ReadWrite.All",
    "1bfefb4e-e0b5-418b-a88f-73c46d2cc8e9": "Application.ReadWrite.All",
    "9e3f62cf-ca93-4989-b6ce-bf83c28f9fe8": "RoleManagement.ReadWrite.Directory",
    "e2a3a72e-5f79-4c64-b1b1-878b674786c9": "Mail.ReadWrite",
    "75359482-378d-4052-8f01-80520e7db3cd": "Files.ReadWrite.All",
    "dc50a0fb-09a3-484d-be87-e023b12c6440": "SecurityEvents.ReadWrite.All",
}


def check_mailbox_forwarding(client: GraphClient):
    users = client.get_all("/users?$select=id,displayName,userPrincipalName")
    if isinstance(users, dict):
        return {"check_name": "mailbox_forwarding", "display_name": "Mailbox Forwarding",
                "category": "mail_security", "status": "skip", "points_earned": None, "points_possible": 8,
                "summary": users["error"], "issues": [], "details": [], "cis_reference": CIS_MAP["mailbox_forwarding"]["id"]}

    results = []
    for u in users:
        uid, upn, name = u["id"], u["userPrincipalName"], u["displayName"]
        mb = client.get_one(f"/users/{uid}/mailboxSettings")
        if mb is None or (isinstance(mb, dict) and "error" in mb):
            results.append({"user": upn, "display_name": name, "status": "unavailable", "forwarding_address": None})
            continue
        fwd = mb.get("forwardingSmtpAddress")
        results.append({"user": upn, "display_name": name,
                        "forwarding_address": fwd, "status": "forwarding" if fwd else "clean"})

    forwarding = [r for r in results if r["status"] == "forwarding"]
    issues = [f"{r['display_name']} forwarding to {r['forwarding_address']}" for r in forwarding]
    return {
        "check_name": "mailbox_forwarding", "display_name": "Mailbox Forwarding",
        "category": "mail_security", "status": "fail" if forwarding else "pass",
        "points_earned": 0 if forwarding else 8, "points_possible": 8,
        "summary": f"{len(forwarding)} mailboxes have external forwarding enabled",
        "issues": issues, "details": results, "cis_reference": CIS_MAP["mailbox_forwarding"]["id"],
    }


def _check_expiry(credentials, app_name, cred_type):
    now = datetime.now(timezone.utc)
    warn_cutoff = now + timedelta(days=EXPIRY_WARN_DAYS)
    findings = []
    for cred in credentials:
        end_str = cred.get("endDateTime")
        if not end_str:
            continue
        end_dt = datetime.fromisoformat(end_str.replace("Z", "+00:00"))
        if end_dt < now:
            findings.append({"app": app_name, "type": cred_type, "expires": end_str, "status": "expired"})
        elif end_dt < warn_cutoff:
            findings.append({"app": app_name, "type": cred_type, "expires": end_str, "status": "expiring_soon"})
    return findings


def check_app_registrations(client: GraphClient):
    apps = client.get_all("/applications?$select=id,displayName,passwordCredentials,keyCredentials,requiredResourceAccess")
    if isinstance(apps, dict):
        return {"check_name": "app_credential_expiry", "display_name": "App Credential Expiry",
                "category": "mail_security", "status": "skip", "points_earned": None, "points_possible": 8,
                "summary": apps["error"], "issues": [], "details": {}, "cis_reference": CIS_MAP["app_credential_expiry"]["id"]}

    sps = client.get_all("/servicePrincipals?$select=id,displayName,keyCredentials&$top=200")
    if isinstance(sps, dict):
        sps = []

    cred_issues, perm_issues = [], []
    for app in apps:
        name = app.get("displayName", "Unknown")
        cred_issues += _check_expiry(app.get("passwordCredentials", []), name, "Client Secret")
        cred_issues += _check_expiry(app.get("keyCredentials", []), name, "Certificate")
        for resource in app.get("requiredResourceAccess", []):
            for access in resource.get("resourceAccess", []):
                pid = access.get("id")
                if pid in DANGEROUS_PERMISSIONS:
                    perm_issues.append({"app": name, "permission": DANGEROUS_PERMISSIONS[pid]})

    for sp in sps:
        name = sp.get("displayName", "Unknown SP")
        cred_issues += _check_expiry(sp.get("keyCredentials", []), f"{name} (SP)", "SSO Certificate")

    expired = [c for c in cred_issues if c["status"] == "expired"]
    expiring = [c for c in cred_issues if c["status"] == "expiring_soon"]
    cred_deductions = min(8, len(expired) * 4 + len(expiring) * 2)
    cred_earned = max(0, 8 - cred_deductions)
    cred_issues_str = [f"{c['app']} — {c['type']} {'EXPIRED' if c['status'] == 'expired' else 'expiring soon'} ({c['expires'][:10]})" for c in cred_issues]

    perm_deductions = min(5, len(perm_issues) * 2)
    perm_earned = max(0, 5 - perm_deductions)
    perm_issues_str = [f"{p['app']} has {p['permission']}" for p in perm_issues]

    return [
        {
            "check_name": "app_credential_expiry", "display_name": "App Credential Expiry",
            "category": "mail_security", "status": "fail" if expired else ("warn" if expiring else "pass"),
            "points_earned": cred_earned, "points_possible": 8,
            "summary": f"{len(expired)} expired, {len(expiring)} expiring soon across {len(apps)} app registrations",
            "issues": cred_issues_str,
            "details": {"total_apps": len(apps), "credential_issues": cred_issues},
            "cis_reference": CIS_MAP["app_credential_expiry"]["id"],
        },
        {
            "check_name": "app_permissions", "display_name": "App Permissions",
            "category": "mail_security", "status": "fail" if perm_issues else "pass",
            "points_earned": perm_earned, "points_possible": 5,
            "summary": f"{len(perm_issues)} overly-broad permission assignments across {len(apps)} apps",
            "issues": perm_issues_str,
            "details": {"permission_issues": perm_issues},
            "cis_reference": CIS_MAP["app_permissions"]["id"],
        },
    ]


def run_all(client: GraphClient):
    checks = [check_mailbox_forwarding(client)]
    app_checks = check_app_registrations(client)
    if isinstance(app_checks, list):
        checks.extend(app_checks)
    else:
        checks.append(app_checks)
    return checks
