"""
Groups checks:
  - Group inventory by type (info)
  - Ownerless groups (warn)
  - Empty groups (warn)
  - Large groups (info)
  - Group expiration policy (info)
"""
from app.checks.base import check
from app.services.graph_client import GraphClient, GraphError


@check("groups", "Group Inventory", "groups", empty_details={})
def check_groups(client: GraphClient):
    groups = client.get_all("/groups?$select=id,displayName,groupTypes,mailEnabled,securityEnabled,mail,createdDateTime")

    ownerless, empty, large = [], [], []
    type_counts = {"m365": 0, "security": 0, "distribution": 0, "mail_security": 0, "other": 0}
    details = []

    for g in groups:
        gid = g["id"]
        name = g.get("displayName", "")
        gtypes = g.get("groupTypes", [])
        mail_enabled = g.get("mailEnabled", False)
        security_enabled = g.get("securityEnabled", False)

        # Classify group type
        if "Unified" in gtypes:
            gtype = "m365"
            type_counts["m365"] += 1
        elif security_enabled and not mail_enabled:
            gtype = "security"
            type_counts["security"] += 1
        elif mail_enabled and not security_enabled:
            gtype = "distribution"
            type_counts["distribution"] += 1
        elif mail_enabled and security_enabled:
            gtype = "mail_security"
            type_counts["mail_security"] += 1
        else:
            gtype = "other"
            type_counts["other"] += 1

        # Get owners and members
        # -1 marks "couldn't read", distinct from a genuine count of 0 — an
        # unreadable group must not be reported as ownerless.
        try:
            owner_count = len(client.get_all(f"/groups/{gid}/owners?$select=id,displayName"))
        except GraphError:
            owner_count = -1
        try:
            member_count = len(client.get_all(f"/groups/{gid}/members?$select=id"))
        except GraphError:
            member_count = -1

        entry = {
            "id": gid,
            "display_name": name,
            "type": gtype,
            "mail": g.get("mail"),
            "owner_count": owner_count,
            "member_count": member_count,
            "created": g.get("createdDateTime"),
        }
        details.append(entry)

        if owner_count == 0:
            ownerless.append({"display_name": name, "type": gtype, "member_count": member_count})
        if member_count == 0:
            empty.append({"display_name": name, "type": gtype})
        if member_count >= 100:
            large.append({"display_name": name, "type": gtype, "member_count": member_count})

    issues = [f"{g['display_name']} ({g['type']}) has no owners" for g in ownerless]
    issues += [f"{g['display_name']} ({g['type']}) has no members" for g in empty]

    status = "warn" if (ownerless or empty) else "info"

    return {
        "check_name": "groups", "display_name": "Group Inventory",
        "category": "groups", "status": status,
        "points_earned": None, "points_possible": None,
        "summary": f"{len(groups)} total groups — {type_counts['m365']} M365, {type_counts['security']} security, {type_counts['distribution']} DL",
        "issues": issues,
        "details": {
            "groups": details,
            "type_counts": type_counts,
            "ownerless": ownerless,
            "empty": empty,
            "large": large,
            "total": len(groups),
        },
        "cis_reference": None,
    }


@check("group_expiration", "Group Expiration Policy", "groups", empty_details={})
def check_group_expiration_policy(client: GraphClient):
    policies = client.get_all("/groupLifecyclePolicies")

    configured = len(policies) > 0
    details = [{"lifetime_days": p.get("groupLifetimeInDays"),
                "managed_group_types": p.get("managedGroupTypes"),
                "notification_email": p.get("alternateNotificationEmails")} for p in policies]

    return {
        "check_name": "group_expiration", "display_name": "Group Expiration Policy",
        "category": "groups", "status": "info",
        "points_earned": None, "points_possible": None,
        "summary": f"Group expiration policy {'configured' if configured else 'not configured'}",
        "issues": [] if configured else ["No group expiration policy configured"],
        "details": {"configured": configured, "policies": details},
        "cis_reference": None,
    }


def run_all(client: GraphClient):
    return [
        check_groups(client),
        check_group_expiration_policy(client),
    ]
