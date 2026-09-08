"""
Scoring weights (110 pts total — security checks only):
  MFA Registration              20
  Conditional Access            15
  Legacy Auth Blocked           10
  Admin Role Hygiene            10
  PIM / Standing Roles          10
  Email Authentication          10  (SPF 3 + DMARC 4 + DKIM 3)
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
    "email_authentication":   {"id": "CIS 6.2.2", "title": "Ensure SPF, DKIM, and DMARC are configured for all domains"},
}


def _points(check):
    """Read points off either a result dict or a ReportCheck row."""
    if isinstance(check, dict):
        return check.get("points_earned"), check.get("points_possible")
    return getattr(check, "points_earned", None), getattr(check, "points_possible", None)


def calculate_security_score(checks):
    """Aggregate score over checks that actually ran.

    Accepts result dicts or ReportCheck rows.

    A check that could not run contributes to neither side of the ratio. It
    keeps points_possible set so the UI can show what was at stake, which makes
    it tempting to sum that column directly — doing so quietly penalises a
    tenant for a control that was never measured, and produces a different
    number here than on the report. Callers should use this rather than summing
    by hand.

    Returns {"overall": int, "earned": int, "possible": int}
    """
    earned = 0
    possible = 0
    for check in checks:
        got, out_of = _points(check)
        if got is not None and out_of:
            earned += got
            possible += out_of
    overall = round((earned / possible) * 100) if possible else 0
    return {"overall": overall, "earned": earned, "possible": possible}
