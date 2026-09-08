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
from app.checks.base import check
from app.services.graph_client import GraphClient, GraphError
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


def _mfa_from_registration_report(client: GraphClient):
    """Read MFA state from the bulk registration report — one paginated call.

    Note this report omits disabled users, which is the desired behaviour here:
    a blocked account without MFA isn't a live gap. Returns None if the report
    is unavailable so the caller can fall back.
    """
    try:
        rows = client.get_all("/reports/authenticationMethods/userRegistrationDetails")
    except GraphError:
        return None
    return [{
        "user": r.get("userPrincipalName"),
        "display_name": r.get("userDisplayName") or r.get("userPrincipalName"),
        "mfa_registered": bool(r.get("isMfaRegistered")),
        "methods": r.get("methodsRegistered") or [],
    } for r in rows]


def _mfa_from_user_enumeration(client: GraphClient):
    """Fallback: one authentication/methods call per user.

    Costs a request per user, so it only runs when the registration report
    isn't available. Propagates GraphError if user listing itself fails.
    """
    users = client.get_all("/users?$select=id,displayName,userPrincipalName")

    results = []
    for user in users:
        uid, name, upn = user["id"], user["displayName"], user["userPrincipalName"]
        try:
            methods_resp = client.get_all(f"/users/{uid}/authentication/methods")
        except GraphError:
            # One unreadable user shouldn't sink the whole check.
            results.append({"user": upn, "display_name": name, "mfa_registered": None})
            continue
        non_pw = [m.get("@odata.type", "") for m in methods_resp if "password" not in m.get("@odata.type", "").lower()]
        results.append({"user": upn, "display_name": name, "mfa_registered": len(non_pw) > 0, "methods": non_pw})
    return results


@check("mfa_registration", "MFA Registration", "identity",
       points_possible=20, cis_reference=CIS_MAP["mfa_registration"]["id"])
def check_mfa(client: GraphClient):
    results = _mfa_from_registration_report(client)
    if results is None:
        results = _mfa_from_user_enumeration(client)

    # Users whose state couldn't be read are excluded from the ratio rather
    # than counted as failures.
    known = [r for r in results if r["mfa_registered"] is not None]
    total = len(known)
    no_mfa = [r for r in known if r["mfa_registered"] is False]

    if not total:
        return {"check_name": "mfa_registration", "display_name": "MFA Registration",
                "category": "identity", "status": "skip", "points_earned": None, "points_possible": 20,
                "summary": "No users with readable MFA registration state",
                "issues": [], "details": results, "cis_reference": CIS_MAP["mfa_registration"]["id"]}

    missing_ratio = len(no_mfa) / total
    earned = round(20 * (1 - missing_ratio))
    issues = [f"{r['display_name']} ({r['user']}) has no MFA registered" for r in no_mfa]
    status = "pass" if not no_mfa else ("warn" if missing_ratio < 0.25 else "fail")

    return {
        "check_name": "mfa_registration", "display_name": "MFA Registration",
        "category": "identity", "status": status,
        "points_earned": earned, "points_possible": 20,
        "summary": f"{total - len(no_mfa)}/{total} users have MFA registered",
        "issues": issues, "details": results,
        "cis_reference": CIS_MAP["mfa_registration"]["id"],
    }


@check("stale_accounts", "Stale Accounts (90+ days)", "identity")
def check_stale_accounts(client: GraphClient):
    # signInActivity needs AuditLog.Read.All and an Entra ID P1/P2 licence, so
    # fall back to a plain user list and report "no sign-in data" rather than
    # failing the whole check on a free tenant.
    fallback = False
    try:
        users = client.get_all("/users?$select=id,displayName,userPrincipalName,signInActivity,accountEnabled")
    except GraphError:
        fallback = True
        users = client.get_all("/users?$select=id,displayName,userPrincipalName,accountEnabled")

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


@check("admin_role_hygiene", "Admin Role Hygiene", "identity",
       points_possible=10, cis_reference=CIS_MAP["admin_role_hygiene"]["id"])
def check_admin_roles(client: GraphClient):
    roles = client.get_all("/directoryRoles")

    user_roles = defaultdict(lambda: {"name": "", "upn": "", "user_type": "", "roles": []})
    results = []

    for role in roles:
        try:
            members = client.get_all(f"/directoryRoles/{role['id']}/members")
        except GraphError:
            continue
        if not members:
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


@check("guest_users", "Guest Users", "identity")
def check_guest_users(client: GraphClient):
    guests = client.get_all("/users?$filter=userType eq 'Guest'&$select=id,displayName,userPrincipalName,createdDateTime,accountEnabled")

    details = [{"user": g.get("userPrincipalName"), "display_name": g.get("displayName"),
                "enabled": g.get("accountEnabled", True), "created": g.get("createdDateTime")} for g in guests]
    return {
        "check_name": "guest_users", "display_name": "Guest Users",
        "category": "identity", "status": "info",
        "points_earned": None, "points_possible": None,
        "summary": f"{len(details)} guest users in tenant",
        "issues": [], "details": details, "cis_reference": None,
    }


@check("risky_users", "Risky Users", "identity")
def check_risky_users(client: GraphClient):
    # Identity Protection requires Entra ID P2; without it Graph answers 403,
    # which the decorator turns into a skip.
    data = client.get_all("/identityProtection/riskyUsers")

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


@check("pim_standing_roles", "PIM / Standing Roles", "identity",
       points_possible=10, cis_reference=CIS_MAP["pim_standing_roles"]["id"],
       empty_details={})
def check_pim_roles(client: GraphClient):
    assignments = client.get_all("/roleManagement/directory/roleAssignments?$expand=principal")

    # Eligible schedules need P2. Their absence is the finding, not an error.
    try:
        eligible_resp = client.get_all("/roleManagement/directory/roleEligibilitySchedules")
        pim_in_use = len(eligible_resp) > 0
    except GraphError:
        pim_in_use = False

    # Role names are cosmetic; fall back to raw ids if the lookup fails.
    try:
        role_map = {r["id"]: r.get("displayName", r["id"])
                    for r in client.get_all("/roleManagement/directory/roleDefinitions")}
    except GraphError:
        role_map = {}

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


@check("password_policy", "Password Policy", "identity",
       points_possible=5, cis_reference=CIS_MAP["password_policy"]["id"])
def check_password_policy(client: GraphClient):
    users = client.get_all("/users?$select=id,displayName,userPrincipalName,passwordPolicies")

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


@check("sspr_enabled", "SSPR Enabled", "identity",
       points_possible=5, cis_reference=CIS_MAP["sspr_enabled"]["id"],
       empty_details={})
def check_sspr(client: GraphClient):
    data = client.get_one("/policies/authorizationPolicy")

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


@check("secure_score", "Microsoft Secure Score", "identity", empty_details={})
def check_secure_score(client: GraphClient):
    """Fetch Microsoft Secure Score and top improvement actions."""
    scores = client.get_all("/security/secureScores", params={"$top": "1"})
    if not scores:
        return {
            "check_name": "secure_score", "display_name": "Microsoft Secure Score",
            "category": "identity", "status": "skip",
            "points_earned": None, "points_possible": None,
            "summary": "No score data available yet", "issues": [], "details": {},
            "cis_reference": None,
        }

    latest = scores[0]
    current = latest.get("currentScore") or 0
    max_score = latest.get("maxScore") or 100
    pct = round((current / max_score) * 100) if max_score else 0
    active_users = latest.get("activeUserCount", 0)
    created = latest.get("createdDateTime", "")

    # Fetch control profiles for titles, remediation, and max scores
    # Profiles supply titles and remediation text; without them the check still
    # reports the score, just without per-control detail.
    profile_map = {}
    try:
        for p in client.get_all("/security/secureScoreControlProfiles"):
            profile_map[p.get("id") or p.get("controlName", "")] = p
    except GraphError:
        pass

    # Build improvement actions list from control scores
    control_scores = latest.get("controlScores", [])
    improvements = []
    for c in control_scores:
        name = c.get("controlName", "")
        score = c.get("score") or 0
        profile = profile_map.get(name, {})
        max_pts = profile.get("maxScore") or 0
        if max_pts > 0 and score < max_pts:
            improvements.append({
                "name": name,
                "title": profile.get("title") or name,
                "score": round(score, 1),
                "max_score": round(max_pts, 1),
                "gap": round(max_pts - score, 1),
                "category": profile.get("controlCategory", ""),
                "remediation": profile.get("remediation", ""),
                "action_url": profile.get("actionUrl", ""),
                "implementation_status": c.get("implementationStatus", "notImplemented"),
            })

    improvements.sort(key=lambda x: x["gap"], reverse=True)
    issues = [f"{i['title']} — +{i['gap']} pts available" for i in improvements[:5]]

    return {
        "check_name": "secure_score", "display_name": "Microsoft Secure Score",
        "category": "identity", "status": "info",
        "points_earned": None, "points_possible": None,
        "summary": f"{pct}% ({current:.0f}/{max_score:.0f} pts) — {len(improvements)} improvement actions available",
        "issues": issues,
        "details": {
            "current_score": round(current, 1),
            "max_score": round(max_score, 1),
            "percentage": pct,
            "active_users": active_users,
            "created_date": created[:10] if created else "",
            "improvements": improvements[:15],
        },
        "cis_reference": None,
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
        check_secure_score(client),
    ]
