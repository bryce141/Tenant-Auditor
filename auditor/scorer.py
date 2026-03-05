"""
Scoring weights (total = 100 points):
  MFA registered for all users         20 pts
  Conditional Access policies exist    15 pts
  Legacy auth blocked                  10 pts
  No highly privileged role sprawl     10 pts
  No mailbox forwarding                 8 pts
  Password expiration enforced          5 pts
  SSPR enabled                          5 pts
  PIM / no standing assignments        10 pts
  App credential expiry                 8 pts
  App permissions hygiene               5 pts
  Named locations configured            4 pts
"""


def score_mfa(mfa_results):
    if not mfa_results:
        return 20, 20, []
    total = len(mfa_results)
    no_mfa = [r for r in mfa_results if r["mfa_registered"] is False]
    pct = (total - len(no_mfa)) / total
    earned = round(20 * pct)
    issues = [f"{r['display_name']} has no MFA registered" for r in no_mfa]
    return earned, 20, issues


def score_conditional_access(ca):
    if ca.get("enabled", 0) > 0:
        return 15, 15, []
    if ca.get("total", 0) == 0:
        return 0, 15, ["No Conditional Access policies configured"]
    return 5, 15, ["No CA policies are currently enabled"]


def score_legacy_auth(legacy):
    if legacy.get("error"):
        return None, 10, []
    if legacy.get("legacy_auth_blocked"):
        return 10, 10, []
    return 0, 10, ["No Conditional Access policy blocks legacy authentication"]


def score_admin_roles(roles_data):
    if roles_data.get("error"):
        return None, 10, []
    roles = roles_data.get("roles", [])
    privileged = [r for r in roles if r.get("is_privileged")]
    issues = []
    deductions = 0

    for r in privileged:
        if r["member_count"] > 2:
            issues.append(f"{r['role']} has {r['member_count']} members (consider reducing)")
            deductions += 3

    for s in roles_data.get("role_stacking", []):
        issues.append(f"{s['name']} holds {len(s['roles'])} roles: {', '.join(s['roles'])}")
        deductions += 3

    for g in roles_data.get("guests_with_roles", []):
        issues.append(f"Guest {g['name']} has role assignments: {', '.join(g['roles'])}")
        deductions += 4

    return max(0, 10 - deductions), 10, issues


def score_mailbox_forwarding(fwd_results):
    forwarding = [r for r in fwd_results if r["status"] == "forwarding"]
    if not forwarding:
        return 8, 8, []
    issues = [f"{r['display_name']} forwarding to {r['forwarding_address']}" for r in forwarding]
    return 0, 8, issues


def score_password_policy(pw_results):
    never_expires = [r for r in pw_results if r["password_never_expires"]]
    if not never_expires:
        return 5, 5, []
    issues = [f"{r['display_name']} — password never expires" for r in never_expires]
    pct = (len(pw_results) - len(never_expires)) / len(pw_results)
    return round(5 * pct), 5, issues


def score_sspr(sspr):
    if sspr.get("error"):
        return None, 5, []
    if sspr.get("enabled"):
        return 5, 5, []
    return 0, 5, ["Self-Service Password Reset is not enabled"]


def score_pim_roles(pim):
    if pim.get("error"):
        return None, 10, []
    issues = []
    if not pim.get("pim_in_use"):
        issues.append("No PIM eligible assignments found — all privileged roles are permanent")
    for a in pim.get("standing_assignments", []):
        issues.append(f"{a['principal_name']} has permanent {a['role']} assignment (no PIM)")
    if not issues:
        return 10, 10, []
    deductions = min(10, len(pim.get("standing_assignments", [])) * 3 + (3 if not pim.get("pim_in_use") else 0))
    return max(0, 10 - deductions), 10, issues


def score_app_credentials(app_data):
    if app_data.get("error"):
        return None, 8, []
    issues = []
    for c in app_data.get("credential_issues", []):
        if c["status"] == "expired":
            issues.append(f"{c['app']} — {c['type']} EXPIRED ({c['expires'][:10]})")
        else:
            issues.append(f"{c['app']} — {c['type']} expiring soon ({c['expires'][:10]})")
    if not issues:
        return 8, 8, []
    deductions = min(8, len([c for c in app_data["credential_issues"] if c["status"] == "expired"]) * 4
                     + len([c for c in app_data["credential_issues"] if c["status"] == "expiring_soon"]) * 2)
    return max(0, 8 - deductions), 8, issues


def score_app_permissions(app_data):
    if app_data.get("error"):
        return None, 5, []
    issues = [f"{p['app']} has {p['permission']}" for p in app_data.get("permission_issues", [])]
    if not issues:
        return 5, 5, []
    deductions = min(5, len(issues) * 2)
    return max(0, 5 - deductions), 5, issues


def score_named_locations(loc_data):
    if loc_data.get("error"):
        return None, 4, []
    if loc_data.get("configured"):
        return 4, 4, []
    return 0, 4, ["No named locations defined — CA policies cannot target trusted networks"]


def calculate_score(results):
    from auditor.cis_mapping import CIS_CONTROLS
    sections = []
    total_earned = 0
    total_possible = 0

    checks = [
        ("MFA Registration",        score_mfa(results["mfa"])),
        ("Conditional Access",      score_conditional_access(results["conditional_access"])),
        ("Legacy Auth Blocked",     score_legacy_auth(results["legacy_auth"])),
        ("Admin Role Hygiene",      score_admin_roles(results["admin_roles"])),
        ("Mailbox Forwarding",      score_mailbox_forwarding(results["mailbox_forwarding"])),
        ("Password Policy",         score_password_policy(results["password_policy"])),
        ("SSPR Enabled",            score_sspr(results["sspr"])),
        ("PIM / Standing Roles",    score_pim_roles(results["pim_roles"])),
        ("App Credential Expiry",   score_app_credentials(results["app_registrations"])),
        ("App Permissions",         score_app_permissions(results["app_registrations"])),
        ("Named Locations",         score_named_locations(results["named_locations"])),
    ]

    for name, (earned, possible, issues) in checks:
        cis = CIS_CONTROLS.get(name, {})
        if earned is None:
            sections.append({"name": name, "earned": None, "possible": possible, "issues": issues, "skipped": True, "cis": cis})
            continue
        total_earned += earned
        total_possible += possible
        sections.append({"name": name, "earned": earned, "possible": possible, "issues": issues, "skipped": False, "cis": cis})

    overall = round((total_earned / total_possible) * 100) if total_possible > 0 else 0

    return {
        "overall": overall,
        "earned": total_earned,
        "possible": total_possible,
        "sections": sections,
    }
