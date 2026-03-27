"""
Identity & Access checks:
  - MFA Registration         (20 pts)
  - Stale Accounts           (info)
  - Admin Role Hygiene       (10 pts)
  - Guest Users              (info)
  - Risky Users              (info)
  - PIM / Standing Roles     (10 pts)
  - Password Policy          (5 pts)
  - SSPR Enabled             (5 pts)
"""
from datetime import datetime, timezone, timedelta
from collections import defaultdict
from app.services.graph_client import GraphClient
from app.services.scoring import CIS_MAP

STALE_DAYS = 90

PRIVILEGED_ROLE_IDS = {
    "62e90394-69f5-4237-9190-012177145e10": "Global Administrator",
    "e8611ab8-c189-46e8-94e1-60213ab1f814": "Privileged Role Administrator",
    "194ae4cb-b126-40b2-bd5b-6091b380977d": "Security Administrator",
    "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3": "Application Administrator",
    "158c047a-c907-4556-b7ef-446551a6b5f7": "Cloud Application Administrator",
    "b0f54661-2d74-4c50-afa3-1ec803f12efe": "Billing Administrator",
    "29232cdf-9323-42fd-ade2-1d097af3e4de": "Exchange Administrator",
    "f28a1f50-f6e7-4571-818b-6a12f2af6b6c": "SharePoint Administrator",
    "fe930be7-5e62-47db-91af-98c3a49a38b1": "User Administrator",
}


def check_mfa(client: GraphClient):
    users = client.get_all("/users?$select=id,displayName,userPrincipalName")
    if isinstance(users, dict):
        return {"check_name": "mfa_registration", "display_name": "MFA Registration",
                "category": "identity", "status": "skip", "points_earned": None, "points_possible": 20,
                "summary": users["error"], "issues": [], "details": [], "cis_reference": CIS_MAP["mfa_registration"]["id"]}

    results = []
    for user in users:
        uid, name, upn = user["id"], user["displayName"], user["userPrincipalName"]
        methods_resp = client.get_all(f"/users/{uid}/authentication/methods")
        if isinstance(methods_resp, dict):
            results.append({"user": upn, "display_name": name, "mfa_registered": None})
            continue
        non_pw = [m.get("@odata.type", "") for m in methods_resp if "password" not in m.get("@odata.type", "").lower()]
        results.append({"user": upn, "display_name": name, "mfa_registered": len(non_pw) > 0, "methods": non_pw})

    total = len(results)
    no_mfa = [r for r in results if r["mfa_registered"] is False]
    pct = (total - len(no_mfa)) / total if total else 1
    earned = round(20 * pct)
    issues = [f"{r['display_name']} ({r['user']}) has no MFA registered" for r in no_mfa]
    status = "pass" if not no_mfa else ("warn" if len(no_mfa) / total < 0.25 else "fail")

    return {
        "check_name": "mfa_registration", "display_name": "MFA Registration",
        "category": "identity", "status": status,
        "points_earned": earned, "points_possible": 20,
        "summary": f"{total - len(no_mfa)}/{total} users have MFA registered",
        "issues": issues, "details": results,
        "cis_reference": CIS_MAP["mfa_registration"]["id"],
    }


def check_stale_accounts(client: GraphClient):
    users = client.get_all("/users?$select=id,displayName,userPrincipalName,signInActivity,accountEnabled")
    fallback = isinstance(users, dict)
    if fallback:
        users = client.get_all("/users?$select=id,displayName,userPrincipalName,accountEnabled")
    if isinstance(users, dict):
        return {"check_name": "stale_accounts", "display_name": "Stale Accounts",
                "category": "identity", "status": "skip", "points_earned": None, "points_possible": None,
                "summary": users["error"], "issues": [], "details": [], "cis_reference": None}

    cutoff = datetime.now(timezone.utc) - timedelta(days=STALE_DAYS)
    results = []
    for u in users:
        upn, name = u["userPrincipalName"], u["displayName"]
        if fallback:
            results.append({"user": upn, "display_name": name, "status": "no_signin_data"})
            continue
        sa = u.get("signInActivity")
        if sa is None:
            results.append({"user": upn, "display_name": name, "status": "no_signin_data"}); continue
        last = sa.get("lastSignInDateTime")
        if not last:
            results.append({"user": upn, "display_name": name, "status": "never_signed_in"}); continue
        dt = datetime.fromisoformat(last.replace("Z", "+00:00"))
        results.append({"user": upn, "display_name": name, "last_signin": last,
                        "status": "stale" if dt < cutoff else "active"})

    stale = [r for r in results if r["status"] == "stale"]
    never = [r for r in results if r["status"] == "never_signed_in"]
    issues = [f"{r['display_name']} — last sign-in: {r.get('last_signin', 'N/A')}" for r in stale]
    issues += [f"{r['display_name']} — never signed in" for r in never]

    return {
        "check_name": "stale_accounts", "display_name": "Stale Accounts (90+ days)",
        "category": "identity", "status": "info",
        "points_earned": None, "points_possible": None,
        "summary": f"{len(stale)} stale, {len(never)} never signed in out of {len(results)} users",
        "issues": issues, "details": results, "cis_reference": None,
    }


def check_admin_roles(client: GraphClient):
    roles = client.get_all("/directoryRoles")
    if isinstance(roles, dict):
        return {"check_name": "admin_role_hygiene", "display_name": "Admin Role Hygiene",
                "category": "identity", "status": "skip", "points_earned": None, "points_possible": 10,
                "summary": roles["error"], "issues": [], "details": [], "cis_reference": CIS_MAP["admin_role_hygiene"]["id"]}

    user_roles = defaultdict(lambda: {"name": "", "upn": "", "user_type": "", "roles": []})
    results = []

    for role in roles:
        members = client.get_all(f"/directoryRoles/{role['id']}/members")
        if isinstance(members, dict) or not members:
            continue
        role_id = role.get("roleTemplateId")
        is_privileged = role_id in PRIVILEGED_ROLE_IDS
        results.append({
            "role": role.get("displayName"), "role_template_id": role_id,
            "is_privileged": is_privileged, "member_count": len(members),
            "members": [{"name": m.get("displayName"), "upn": m.get("userPrincipalName"),
                         "user_type": m.get("userType", "Member")} for m in members],
        })
        for m in members:
            uid = m.get("id", m.get("userPrincipalName", ""))
            user_roles[uid]["name"] = m.get("displayName", "")
            user_roles[uid]["upn"] = m.get("userPrincipalName", "")
            user_roles[uid]["user_type"] = m.get("userType", "Member")
            user_roles[uid]["roles"].append(role.get("displayName"))

    role_stacking = [v for v in user_roles.values() if len(v["roles"]) >= 2]
    guests_with_roles = [v for v in user_roles.values() if v.get("user_type") == "Guest"]

    issues = []
    deductions = 0
    for r in [r for r in results if r["is_privileged"] and r["member_count"] > 2]:
        issues.append(f"{r['role']} has {r['member_count']} members (consider reducing)")
        deductions += 3
    for s in role_stacking:
        issues.append(f"{s['name']} holds {len(s['roles'])} roles: {', '.join(s['roles'])}")
        deductions += 3
    for g in guests_with_roles:
        issues.append(f"Guest {g['name']} has role assignments: {', '.join(g['roles'])}")
        deductions += 4

    earned = max(0, 10 - deductions)
    return {
        "check_name": "admin_role_hygiene", "display_name": "Admin Role Hygiene",
        "category": "identity", "status": "pass" if not issues else "warn",
        "points_earned": earned, "points_possible": 10,
        "summary": f"{len(results)} roles active, {len(role_stacking)} role-stacking, {len(guests_with_roles)} guests with roles",
        "issues": issues,
        "details": {"roles": results, "role_stacking": role_stacking, "guests_with_roles": guests_with_roles},
        "cis_reference": CIS_MAP["admin_role_hygiene"]["id"],
    }


def check_guest_users(client: GraphClient):
    guests = client.get_all("/users?$filter=userType eq 'Guest'&$select=id,displayName,userPrincipalName,createdDateTime,accountEnabled")
    if isinstance(guests, dict):
        return {"check_name": "guest_users", "display_name": "Guest Users",
                "category": "identity", "status": "skip", "points_earned": None, "points_possible": None,
                "summary": guests["error"], "issues": [], "details": [], "cis_reference": None}

    details = [{"user": g.get("userPrincipalName"), "display_name": g.get("displayName"),
                "enabled": g.get("accountEnabled", True), "created": g.get("createdDateTime")} for g in guests]
    return {
        "check_name": "guest_users", "display_name": "Guest Users",
        "category": "identity", "status": "info",
        "points_earned": None, "points_possible": None,
        "summary": f"{len(details)} guest users in tenant",
        "issues": [], "details": details, "cis_reference": None,
    }


def check_risky_users(client: GraphClient):
    data = client.get_all("/identityProtection/riskyUsers")
    if isinstance(data, dict):
        return {"check_name": "risky_users", "display_name": "Risky Users",
                "category": "identity", "status": "skip", "points_earned": None, "points_possible": None,
                "summary": data["error"], "issues": [], "details": [], "cis_reference": None}

    details = [{"user": u.get("userPrincipalName"), "display_name": u.get("userDisplayName"),
                "risk_level": u.get("riskLevel"), "risk_state": u.get("riskState"),
                "last_updated": u.get("riskLastUpdatedDateTime")} for u in data]
    high_risk = [d for d in details if d["risk_level"] in ("high", "medium")]
    issues = [f"{d['display_name']} — {d['risk_level']} risk ({d['risk_state']})" for d in high_risk]
    return {
        "check_name": "risky_users", "display_name": "Risky Users",
        "category": "identity", "status": "fail" if high_risk else "pass",
        "points_earned": None, "points_possible": None,
        "summary": f"{len(high_risk)} high/medium risk users detected" if high_risk else "No risky users detected",
        "issues": issues, "details": details, "cis_reference": None,
    }


def check_pim_roles(client: GraphClient):
    assignments = client.get_all("/roleManagement/directory/roleAssignments?$expand=principal")
    if isinstance(assignments, dict):
        return {"check_name": "pim_standing_roles", "display_name": "PIM / Standing Roles",
                "category": "identity", "status": "skip", "points_earned": None, "points_possible": 10,
                "summary": assignments["error"], "issues": [], "details": {}, "cis_reference": CIS_MAP["pim_standing_roles"]["id"]}

    eligible_resp = client.get_all("/roleManagement/directory/roleEligibilitySchedules")
    pim_in_use = not isinstance(eligible_resp, dict) and len(eligible_resp) > 0

    roles_resp = client.get_all("/roleManagement/directory/roleDefinitions")
    role_map = {}
    if not isinstance(roles_resp, dict):
        role_map = {r["id"]: r.get("displayName", r["id"]) for r in roles_resp}

    standing = []
    for a in assignments:
        role_def_id = a.get("roleDefinitionId", "")
        role_name = role_map.get(role_def_id, role_def_id)
        if role_def_id not in PRIVILEGED_ROLE_IDS and role_name not in PRIVILEGED_ROLE_IDS.values():
            continue
        principal = a.get("principal", {})
        standing.append({
            "role": role_name,
            "principal_name": principal.get("displayName", "Unknown"),
            "principal_upn": principal.get("userPrincipalName") or principal.get("appId", ""),
            "principal_type": principal.get("@odata.type", "").split(".")[-1],
        })

    issues = []
    if not pim_in_use:
        issues.append("No PIM eligible assignments found — all privileged roles are permanent")
    for a in standing:
        issues.append(f"{a['principal_name']} has permanent {a['role']} assignment (no PIM)")

    deductions = min(10, len(standing) * 3 + (3 if not pim_in_use else 0))
    earned = max(0, 10 - deductions)

    return {
        "check_name": "pim_standing_roles", "display_name": "PIM / Standing Roles",
        "category": "identity", "status": "pass" if not issues else "warn",
        "points_earned": earned, "points_possible": 10,
        "summary": f"PIM {'in use' if pim_in_use else 'not in use'}, {len(standing)} standing privileged assignments",
        "issues": issues,
        "details": {"pim_in_use": pim_in_use, "standing_assignments": standing},
        "cis_reference": CIS_MAP["pim_standing_roles"]["id"],
    }


def check_password_policy(client: GraphClient):
    users = client.get_all("/users?$select=id,displayName,userPrincipalName,passwordPolicies")
    if isinstance(users, dict):
        return {"check_name": "password_policy", "display_name": "Password Policy",
                "category": "identity", "status": "skip", "points_earned": None, "points_possible": 5,
                "summary": users["error"], "issues": [], "details": [], "cis_reference": CIS_MAP["password_policy"]["id"]}

    results = [{"user": u.get("userPrincipalName"), "display_name": u.get("displayName"),
                "password_never_expires": "DisablePasswordExpiration" in (u.get("passwordPolicies") or "")}
               for u in users]
    never_expires = [r for r in results if r["password_never_expires"]]
    pct = (len(results) - len(never_expires)) / len(results) if results else 1
    earned = round(5 * pct)
    issues = [f"{r['display_name']} — password never expires" for r in never_expires]

    return {
        "check_name": "password_policy", "display_name": "Password Policy",
        "category": "identity", "status": "pass" if not never_expires else "warn",
        "points_earned": earned, "points_possible": 5,
        "summary": f"{len(never_expires)} accounts have passwords set to never expire",
        "issues": issues, "details": results, "cis_reference": CIS_MAP["password_policy"]["id"],
    }


def check_sspr(client: GraphClient):
    data = client.get_one("/policies/authorizationPolicy")
    if isinstance(data, dict) and "error" in data:
        return {"check_name": "sspr_enabled", "display_name": "SSPR Enabled",
                "category": "identity", "status": "skip", "points_earned": None, "points_possible": 5,
                "summary": data["error"], "issues": [], "details": {}, "cis_reference": CIS_MAP["sspr_enabled"]["id"]}

    scope = (data or {}).get("allowedToUseSSPR", "none")
    enabled = scope != "none"
    return {
        "check_name": "sspr_enabled", "display_name": "SSPR Enabled",
        "category": "identity", "status": "pass" if enabled else "fail",
        "points_earned": 5 if enabled else 0, "points_possible": 5,
        "summary": f"Self-Service Password Reset is {'enabled' if enabled else 'not enabled'} (scope: {scope})",
        "issues": [] if enabled else ["Self-Service Password Reset is not enabled"],
        "details": {"enabled": enabled, "scope": scope},
        "cis_reference": CIS_MAP["sspr_enabled"]["id"],
    }


def run_all(client: GraphClient):
    return [
        check_mfa(client),
        check_stale_accounts(client),
        check_admin_roles(client),
        check_guest_users(client),
        check_risky_users(client),
        check_pim_roles(client),
        check_password_policy(client),
        check_sspr(client),
    ]
