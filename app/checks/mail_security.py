"""
Mail Security checks:
  - Mailbox Forwarding        (8 pts)
  - App Registrations         (credential expiry: 8 pts, permissions: 5 pts)
  - Email Authentication      (10 pts — SPF, DKIM, DMARC per domain)
"""
from datetime import datetime, timezone, timedelta
from app.checks.base import check
from app.services.graph_client import GraphClient, GraphError
from app.services.scoring import CIS_MAP

try:
    import dns.resolver
    _DNS_AVAILABLE = True
except ImportError:
    _DNS_AVAILABLE = False


def _lookup_txt(hostname):
    """Return list of TXT record strings for hostname. Returns [] on any error."""
    if not _DNS_AVAILABLE:
        return []
    try:
        answers = dns.resolver.resolve(hostname, "TXT", lifetime=5)
        records = []
        for rdata in answers:
            joined = "".join(
                s.decode("utf-8", errors="ignore") if isinstance(s, bytes) else s
                for s in rdata.strings
            )
            records.append(joined)
        return records
    except Exception:
        return []

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


@check("mailbox_forwarding", "Mailbox Forwarding", "mail_security",
       points_possible=8, cis_reference=CIS_MAP["mailbox_forwarding"]["id"])
def check_mailbox_forwarding(client: GraphClient):
    users = client.get_all("/users?$select=id,displayName,userPrincipalName")

    # Batched rather than one request per user. Note this deliberately does not
    # filter to licensed users: shared mailboxes are unlicensed and can carry
    # forwarding rules, which is exactly where an attacker would put one.
    endpoints = [f"/users/{u['id']}/mailboxSettings" for u in users]
    settings = client.batch_get(endpoints)

    results = []
    for u in users:
        upn, name = u["userPrincipalName"], u["displayName"]
        mb = settings.get(f"/users/{u['id']}/mailboxSettings")
        if not isinstance(mb, dict):
            # No mailbox, or settings unreadable — unknown, not clean.
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


@check("app_credential_expiry", "App Credential Expiry", "mail_security",
       points_possible=8, cis_reference=CIS_MAP["app_credential_expiry"]["id"],
       empty_details={},
       also=[{"check_name": "app_permissions", "display_name": "App Permissions",
              "points_possible": 5, "cis_reference": CIS_MAP["app_permissions"]["id"]}])
def check_app_registrations(client: GraphClient):
    apps = client.get_all("/applications?$select=id,displayName,passwordCredentials,keyCredentials,requiredResourceAccess")

    # Service principal certificates are a bonus; app registrations alone still
    # give a useful answer if this call is denied.
    try:
        sps = client.get_all("/servicePrincipals?$select=id,displayName,keyCredentials&$top=200")
    except GraphError:
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


@check("email_authentication", "Email Authentication (SPF/DKIM/DMARC)", "mail_security",
       points_possible=10, cis_reference=CIS_MAP["email_authentication"]["id"],
       empty_details={})
def check_email_authentication(client: GraphClient):
    """Check SPF, DKIM, and DMARC records for all verified tenant domains."""
    if not _DNS_AVAILABLE:
        return {
            "check_name": "email_authentication", "display_name": "Email Authentication (SPF/DKIM/DMARC)",
            "category": "mail_security", "status": "skip",
            "points_earned": None, "points_possible": 10,
            "summary": "dnspython not installed — run: pip install dnspython",
            "issues": [], "details": {}, "cis_reference": CIS_MAP["email_authentication"]["id"],
        }

    domains_resp = client.get_all("/domains?$select=id,isVerified,isDefault")

    verified = [d for d in domains_resp if d.get("isVerified") and not d["id"].endswith(".onmicrosoft.com")]
    if not verified:
        return {
            "check_name": "email_authentication", "display_name": "Email Authentication (SPF/DKIM/DMARC)",
            "category": "mail_security", "status": "skip",
            "points_earned": None, "points_possible": 10,
            "summary": "No custom verified domains found",
            "issues": [], "details": {}, "cis_reference": CIS_MAP["email_authentication"]["id"],
        }

    results = []
    for d in verified:
        domain = d["id"]
        entry = {"domain": domain, "is_default": d.get("isDefault", False), "issues": []}

        # SPF — TXT record at the domain root containing v=spf1
        txt_records = _lookup_txt(domain)
        spf_record = next((r for r in txt_records if r.lower().startswith("v=spf1")), None)
        entry["spf"] = {"present": bool(spf_record), "record": spf_record or ""}
        if not spf_record:
            entry["issues"].append("SPF record missing")

        # DMARC — TXT record at _dmarc.<domain>
        dmarc_records = _lookup_txt(f"_dmarc.{domain}")
        dmarc_record = next((r for r in dmarc_records if r.upper().startswith("V=DMARC1")), None)
        dmarc_policy = None
        if dmarc_record:
            for tag in dmarc_record.split(";"):
                tag = tag.strip()
                if tag.lower().startswith("p="):
                    dmarc_policy = tag[2:].strip().lower()
                    break
        entry["dmarc"] = {
            "present": bool(dmarc_record),
            "record": dmarc_record or "",
            "policy": dmarc_policy or "",
        }
        if not dmarc_record:
            entry["issues"].append("DMARC record missing")
        elif dmarc_policy == "none":
            entry["issues"].append("DMARC policy is 'none' (monitoring only — not blocking spoofed email)")

        # DKIM — check Microsoft 365 default selectors (selector1, selector2)
        dkim_found = False
        dkim_selector = None
        for selector in ("selector1", "selector2"):
            recs = _lookup_txt(f"{selector}._domainkey.{domain}")
            if any("v=DKIM1" in r or "k=rsa" in r for r in recs):
                dkim_found = True
                dkim_selector = selector
                break
        entry["dkim"] = {"present": dkim_found, "selector": dkim_selector or ""}
        if not dkim_found:
            entry["issues"].append("DKIM not configured (checked selector1, selector2)")

        results.append(entry)

    total = len(results)
    spf_pass = sum(1 for r in results if r["spf"]["present"])
    dmarc_enforce = sum(1 for r in results if r["dmarc"]["policy"] in ("reject", "quarantine"))
    dkim_pass = sum(1 for r in results if r["dkim"]["present"])

    # Score: SPF 3pts, DMARC enforcement 4pts, DKIM 3pts — weighted by pass rate
    spf_rate = spf_pass / total if total else 0
    dmarc_rate = dmarc_enforce / total if total else 0
    dkim_rate = dkim_pass / total if total else 0
    earned = round(3 * spf_rate + 4 * dmarc_rate + 3 * dkim_rate)

    all_issues = []
    for r in results:
        for issue in r["issues"]:
            all_issues.append(f"{r['domain']}: {issue}")

    status = "pass" if not all_issues else ("warn" if earned >= 5 else "fail")

    return {
        "check_name": "email_authentication", "display_name": "Email Authentication (SPF/DKIM/DMARC)",
        "category": "mail_security", "status": status,
        "points_earned": earned, "points_possible": 10,
        "summary": (f"{spf_pass}/{total} domains have SPF, "
                    f"{dmarc_enforce}/{total} have enforced DMARC, "
                    f"{dkim_pass}/{total} have DKIM"),
        "issues": all_issues,
        "details": {"domains": results, "total": total},
        "cis_reference": CIS_MAP["email_authentication"]["id"],
    }


def run_all(client: GraphClient):
    checks = [check_mailbox_forwarding(client), check_email_authentication(client)]
    app_checks = check_app_registrations(client)
    if isinstance(app_checks, list):
        checks.extend(app_checks)
    else:
        checks.append(app_checks)
    return checks
