"""
Users & Activity checks:
  - Sign-in activity breakdown (info)
  - Inactive licensed users / wasted spend (warn)
  - M365 app usage per user (info)
"""
from datetime import datetime, timezone, timedelta
from app.checks.base import check
from app.services.graph_client import GraphClient, GraphError

INACTIVE_DAYS = 90


@check("user_activity", "User Sign-in Activity", "users", empty_details={})
def check_user_activity(client: GraphClient):
    try:
        users = client.get_all("/users?$select=id,displayName,userPrincipalName,accountEnabled,signInActivity,assignedLicenses")
    except GraphError:
        # signInActivity needs AuditLog.Read.All plus P1/P2; without it, report
        # the roster with no activity data rather than skipping entirely.
        users = client.get_all("/users?$select=id,displayName,userPrincipalName,accountEnabled,assignedLicenses")
        for u in users:
            u["signInActivity"] = None

    now = datetime.now(timezone.utc)
    cutoff_90 = now - timedelta(days=90)
    cutoff_30 = now - timedelta(days=30)
    cutoff_7 = now - timedelta(days=7)

    buckets = {"7d": 0, "30d": 0, "90d": 0, "90d_plus": 0, "never": 0, "no_data": 0}
    details = []
    inactive_licensed = []

    for u in users:
        if not u.get("accountEnabled", True):
            continue
        upn = u.get("userPrincipalName")
        name = u.get("displayName")
        sa = u.get("signInActivity")
        licenses = u.get("assignedLicenses", [])
        has_license = len(licenses) > 0

        last_signin = None
        last_signin_str = None
        bucket = "no_data"

        if sa:
            last_signin_str = sa.get("lastSignInDateTime") or sa.get("lastNonInteractiveSignInDateTime")
            if last_signin_str:
                last_signin = datetime.fromisoformat(last_signin_str.replace("Z", "+00:00"))
                if last_signin >= cutoff_7:
                    bucket = "7d"
                elif last_signin >= cutoff_30:
                    bucket = "30d"
                elif last_signin >= cutoff_90:
                    bucket = "90d"
                else:
                    bucket = "90d_plus"
            else:
                bucket = "never"

        buckets[bucket] = buckets.get(bucket, 0) + 1

        entry = {"user": upn, "display_name": name, "last_signin": last_signin_str,
                 "bucket": bucket, "has_license": has_license}
        details.append(entry)

        if has_license and bucket in ("90d_plus", "never", "no_data") and bucket != "no_data":
            inactive_licensed.append(entry)

    issues = [f"{u['display_name']} ({u['user']}) — licensed but inactive 90+ days" for u in inactive_licensed]

    return {
        "check_name": "user_activity", "display_name": "User Sign-in Activity",
        "category": "users", "status": "warn" if inactive_licensed else "info",
        "points_earned": None, "points_possible": None,
        "summary": f"{len(details)} active users — {len(inactive_licensed)} licensed users inactive 90+ days",
        "issues": issues,
        "details": {"buckets": buckets, "users": details, "inactive_licensed": inactive_licensed},
        "cis_reference": None,
    }


@check("app_usage", "M365 App Usage", "users")
def check_app_usage(client: GraphClient):
    rows = client.get_report_csv("/reports/getM365AppUserDetail(period='D30')")

    details = []
    for row in rows:
        details.append({
            "user": row.get("User Principal Name", ""),
            "display_name": row.get("Display Name", ""),
            "last_activity": row.get("Last Activity Date", ""),
            "teams": row.get("Used Teams", ""),
            "outlook": row.get("Used Outlook", ""),
            "sharepoint": row.get("Used SharePoint", ""),
            "onedrive": row.get("Used OneDrive", ""),
            "word": row.get("Used Word", ""),
            "excel": row.get("Used Excel", ""),
            "powerpoint": row.get("Used PowerPoint", ""),
        })

    return {
        "check_name": "app_usage", "display_name": "M365 App Usage (30 days)",
        "category": "users", "status": "info",
        "points_earned": None, "points_possible": None,
        "summary": f"App usage data for {len(details)} users over the last 30 days",
        "issues": [], "details": details, "cis_reference": None,
    }


def run_all(client: GraphClient):
    return [
        check_user_activity(client),
        check_app_usage(client),
    ]
