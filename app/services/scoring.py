"""
Scoring weights (100 pts total — security checks only):
  MFA Registration              20
  Conditional Access            15
  Legacy Auth Blocked           10
  Admin Role Hygiene            10
  PIM / Standing Roles          10
  Mailbox Forwarding             8
  App Credential Expiry          8
  App Permissions                5
  Password Policy                5
  SSPR Enabled                   5
  Named Locations                4
"""

CIS_MAP = {
    "mfa_registration":       {"id": "CIS 1.1.1", "title": "Ensure MFA is enabled for all users"},
    "conditional_access":     {"id": "CIS 1.1.2", "title": "Ensure Conditional Access policies are configured"},
    "legacy_auth_blocked":    {"id": "CIS 1.1.4", "title": "Ensure legacy authentication is blocked"},
    "admin_role_hygiene":     {"id": "CIS 1.2.1", "title": "Ensure administrative accounts are cloud-only"},
    "pim_standing_roles":     {"id": "CIS 1.2.3", "title": "Ensure PIM is used for privileged roles"},
    "mailbox_forwarding":     {"id": "CIS 6.1.1", "title": "Ensure auto-forward to external domains is disabled"},
    "app_credential_expiry":  {"id": "CIS 1.3.1", "title": "Ensure app credentials are not expired"},
    "app_permissions":        {"id": "CIS 1.3.2", "title": "Ensure app registrations have minimal permissions"},
    "password_policy":        {"id": "CIS 2.1.1", "title": "Ensure password expiration is enforced"},
    "sspr_enabled":           {"id": "CIS 1.1.5", "title": "Ensure Self-Service Password Reset is enabled"},
    "named_locations":        {"id": "CIS 1.1.3", "title": "Ensure named locations are defined"},
}


def calculate_security_score(checks):
    """
    Given a list of ReportCheck dicts (from report.to_dict()),
    compute the aggregate security score.
    Returns {"overall": int, "earned": int, "possible": int}
    """
    earned = 0
    possible = 0
    for c in checks:
        if c.get("points_earned") is not None and c.get("points_possible"):
            earned += c["points_earned"]
            possible += c["points_possible"]
    overall = round((earned / possible) * 100) if possible else 0
    return {"overall": overall, "earned": earned, "possible": possible}
