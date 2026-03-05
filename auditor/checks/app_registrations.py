import requests
from datetime import datetime, timezone, timedelta

GRAPH_BASE = "https://graph.microsoft.com/v1.0"

EXPIRY_WARN_DAYS = 30

# Permissions considered overly broad / high risk
DANGEROUS_PERMISSIONS = {
    "19dbc75e-c2e2-444c-a770-ec69d8559fc7": "Directory.ReadWrite.All",
    "62a82d76-70ea-41e2-9197-370581804d09": "Group.ReadWrite.All",
    "741f803b-c850-494e-b5df-cde7c675a1ca": "User.ReadWrite.All",
    "1bfefb4e-e0b5-418b-a88f-73c46d2cc8e9": "Application.ReadWrite.All",
    "9e3f62cf-ca93-4989-b6ce-bf83c28f9fe8": "RoleManagement.ReadWrite.Directory",
    "e2a3a72e-5f79-4c64-b1b1-878b674786c9": "Mail.ReadWrite",
    "75359482-378d-4052-8f01-80520e7db3cd": "Files.ReadWrite.All",
    "dc50a0fb-09a3-484d-be87-e023b12c6440": "SecurityEvents.ReadWrite.All",
    "b0afded3-3588-46d8-8b3d-9842eff778da": "AuditLog.Read.All",
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
            findings.append({
                "app": app_name,
                "type": cred_type,
                "hint": cred.get("displayName") or cred.get("keyId", ""),
                "expires": end_str,
                "status": "expired",
            })
        elif end_dt < warn_cutoff:
            findings.append({
                "app": app_name,
                "type": cred_type,
                "hint": cred.get("displayName") or cred.get("keyId", ""),
                "expires": end_str,
                "status": "expiring_soon",
            })
    return findings


def check_app_registrations(headers):
    if not headers:
        return {"error": "No auth token", "credential_issues": [], "permission_issues": []}

    apps_resp = requests.get(
        f"{GRAPH_BASE}/applications?$select=id,displayName,passwordCredentials,keyCredentials,requiredResourceAccess",
        headers=headers
    )
    if apps_resp.status_code == 403:
        return {"error": "Requires Application.Read.All permission", "credential_issues": [], "permission_issues": []}
    apps_resp.raise_for_status()
    apps = apps_resp.json().get("value", [])

    # Also check service principal certs (SSO/SAML)
    sp_resp = requests.get(
        f"{GRAPH_BASE}/servicePrincipals?$select=id,displayName,keyCredentials&$top=200",
        headers=headers
    )
    service_principals = []
    if sp_resp.status_code == 200:
        service_principals = sp_resp.json().get("value", [])

    credential_issues = []
    permission_issues = []

    for app in apps:
        name = app.get("displayName", "Unknown App")

        # Check secret expiry
        credential_issues += _check_expiry(app.get("passwordCredentials", []), name, "Client Secret")

        # Check cert expiry
        credential_issues += _check_expiry(app.get("keyCredentials", []), name, "Certificate")

        # Check for broad permissions
        for resource in app.get("requiredResourceAccess", []):
            for access in resource.get("resourceAccess", []):
                perm_id = access.get("id")
                if perm_id in DANGEROUS_PERMISSIONS:
                    permission_issues.append({
                        "app": name,
                        "permission": DANGEROUS_PERMISSIONS[perm_id],
                        "permission_id": perm_id,
                    })

    # Check SSO/SAML certs on service principals
    for sp in service_principals:
        name = sp.get("displayName", "Unknown SP")
        credential_issues += _check_expiry(sp.get("keyCredentials", []), f"{name} (SP)", "SSO Certificate")

    return {
        "total_apps": len(apps),
        "credential_issues": credential_issues,
        "permission_issues": permission_issues,
    }
