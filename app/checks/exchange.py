"""
Exchange Online checks:
  - Mailbox sizes & near-quota (info/warn)
  - Shared mailboxes (info)
  - Distribution lists (info)
"""
from app.checks.base import check
from app.services.graph_client import GraphClient, GraphError

QUOTA_WARN_PCT = 80


@check("mailbox_usage", "Mailbox Sizes", "exchange", empty_details={})
def check_mailbox_usage(client: GraphClient):
    rows = client.get_report_csv("/reports/getMailboxUsageDetail(period='D30')")

    mailboxes = []
    near_quota = []

    for row in rows:
        upn = row.get("User Principal Name", "")
        display = row.get("Display Name", "")
        storage_str = row.get("Storage Used (Byte)", "0") or "0"
        quota_str = row.get("Prohibit Send Quota (Byte)", "0") or "0"
        item_count_str = row.get("Item Count", "0") or "0"

        try:
            storage_bytes = int(storage_str)
            quota_bytes = int(quota_str)
        except ValueError:
            storage_bytes, quota_bytes = 0, 0

        usage_pct = round((storage_bytes / quota_bytes) * 100, 1) if quota_bytes else 0
        is_near_quota = usage_pct >= QUOTA_WARN_PCT

        entry = {
            "user": upn,
            "display_name": display,
            "storage_bytes": storage_bytes,
            "storage_gb": round(storage_bytes / 1024 / 1024 / 1024, 2),
            "quota_gb": round(quota_bytes / 1024 / 1024 / 1024, 2),
            "usage_pct": usage_pct,
            "item_count": int(item_count_str) if item_count_str.isdigit() else 0,
            "is_near_quota": is_near_quota,
        }
        mailboxes.append(entry)
        if is_near_quota:
            near_quota.append(entry)

    total_gb = round(sum(m["storage_bytes"] for m in mailboxes) / 1024 / 1024 / 1024, 2)
    issues = [f"{m['display_name']} — {m['usage_pct']}% of quota used ({m['storage_gb']} GB)" for m in near_quota]

    return {
        "check_name": "mailbox_usage", "display_name": "Mailbox Sizes",
        "category": "exchange", "status": "warn" if near_quota else "info",
        "points_earned": None, "points_possible": None,
        "summary": f"{len(mailboxes)} mailboxes, {len(near_quota)} near quota (80%+), {total_gb} GB total",
        "issues": issues,
        "details": {"mailboxes": mailboxes, "near_quota": near_quota, "total_gb": total_gb},
        "cis_reference": None,
    }


@check("shared_mailboxes", "Shared Mailboxes", "exchange")
def check_shared_mailboxes(client: GraphClient):
    # Shared mailboxes show as users with no license and a specific mailbox type
    # Graph doesn't directly expose mailbox type, but we can use the Exchange recipient type via beta
    users = client.get_all("/users?$select=id,displayName,userPrincipalName,mail,assignedLicenses&$filter=userType eq 'Member'", beta=False)

    # Heuristic: users with no license assigned but a mail address are likely shared mailboxes
    shared = [u for u in users if u.get("mail") and not u.get("assignedLicenses")]
    details = [{"user": u.get("userPrincipalName"), "display_name": u.get("displayName"),
                "mail": u.get("mail")} for u in shared]

    return {
        "check_name": "shared_mailboxes", "display_name": "Shared Mailboxes",
        "category": "exchange", "status": "info",
        "points_earned": None, "points_possible": None,
        "summary": f"{len(details)} likely shared mailboxes (unlicensed mail-enabled accounts)",
        "issues": [], "details": details, "cis_reference": None,
    }


@check("distribution_lists", "Distribution Lists", "exchange")
def check_distribution_lists(client: GraphClient):
    groups = client.get_all(
        "/groups?$select=id,displayName,mail,groupTypes,mailEnabled,securityEnabled,members&$filter=mailEnabled eq true"
    )

    # Distribution lists: mailEnabled=true, securityEnabled=false, not a unified group
    dls = [g for g in groups if g.get("mailEnabled") and not g.get("securityEnabled")
           and "Unified" not in g.get("groupTypes", [])]

    details = []
    for g in dls:
        try:
            member_count = len(client.get_all(f"/groups/{g['id']}/members?$select=id"))
        except GraphError:
            member_count = 0
        details.append({
            "display_name": g.get("displayName"),
            "mail": g.get("mail"),
            "member_count": member_count,
        })

    return {
        "check_name": "distribution_lists", "display_name": "Distribution Lists",
        "category": "exchange", "status": "info",
        "points_earned": None, "points_possible": None,
        "summary": f"{len(details)} distribution lists",
        "issues": [], "details": details, "cis_reference": None,
    }


def run_all(client: GraphClient):
    return [
        check_mailbox_usage(client),
        check_shared_mailboxes(client),
        check_distribution_lists(client),
    ]
