"""
Licensing checks:
  - License summary (info)
  - Unused licenses / wasted spend (warn)
  - Per-user license breakdown (info)
  - Unlicensed active users (warn)
"""
from app.services.graph_client import GraphClient

# Friendly SKU name map (add more as needed)
SKU_NAMES = {
    "SPE_E3": "Microsoft 365 E3",
    "SPE_E5": "Microsoft 365 E5",
    "O365_BUSINESS_PREMIUM": "Microsoft 365 Business Premium",
    "O365_BUSINESS_ESSENTIALS": "Microsoft 365 Business Basic",
    "ENTERPRISEPACK": "Office 365 E3",
    "ENTERPRISEPREMIUM": "Office 365 E5",
    "EXCHANGESTANDARD": "Exchange Online Plan 1",
    "EXCHANGEENTERPRISE": "Exchange Online Plan 2",
    "AAD_PREMIUM": "Azure AD Premium P1",
    "AAD_PREMIUM_P2": "Azure AD Premium P2",
    "INTUNE_A": "Microsoft Intune",
    "TEAMS_ESSENTIALS": "Microsoft Teams Essentials",
    "FLOW_FREE": "Power Automate Free",
    "POWER_BI_STANDARD": "Power BI (free)",
}


def _friendly_sku(sku_part):
    return SKU_NAMES.get(sku_part, sku_part)


def check_license_summary(client: GraphClient):
    skus = client.get_all("/subscribedSkus")
    if isinstance(skus, dict):
        return {"check_name": "license_summary", "display_name": "License Summary",
                "category": "licensing", "status": "skip", "points_earned": None, "points_possible": None,
                "summary": skus["error"], "issues": [], "details": [], "cis_reference": None}

    details = []
    unused_licenses = []
    total_assigned = 0
    total_available = 0

    for sku in skus:
        name = _friendly_sku(sku.get("skuPartNumber", "Unknown"))
        total = sku.get("prepaidUnits", {}).get("enabled", 0)
        assigned = sku.get("consumedUnits", 0)
        available = total - assigned

        details.append({
            "sku_id": sku.get("skuId"),
            "sku_part": sku.get("skuPartNumber"),
            "name": name,
            "total": total,
            "assigned": assigned,
            "available": available,
        })
        total_assigned += assigned
        total_available += available

        if available > 0 and total > 0:
            unused_licenses.append({"name": name, "available": available, "total": total, "assigned": assigned})

    issues = [f"{u['name']}: {u['available']} of {u['total']} licenses unassigned" for u in unused_licenses]

    return {
        "check_name": "license_summary", "display_name": "License Summary",
        "category": "licensing", "status": "warn" if unused_licenses else "pass",
        "points_earned": None, "points_possible": None,
        "summary": f"{total_assigned} licenses assigned, {total_available} unassigned across {len(details)} SKUs",
        "issues": issues,
        "details": {"skus": details, "total_assigned": total_assigned, "total_available": total_available,
                    "unused": unused_licenses},
        "cis_reference": None,
    }


def check_user_licenses(client: GraphClient):
    users = client.get_all("/users?$select=id,displayName,userPrincipalName,assignedLicenses,accountEnabled")
    if isinstance(users, dict):
        return {"check_name": "user_licenses", "display_name": "Per-User Licenses",
                "category": "licensing", "status": "skip", "points_earned": None, "points_possible": None,
                "summary": users["error"], "issues": [], "details": [], "cis_reference": None}

    # Get SKU map for name resolution
    skus = client.get_all("/subscribedSkus")
    sku_map = {}
    if not isinstance(skus, dict):
        sku_map = {s["skuId"]: _friendly_sku(s.get("skuPartNumber", s["skuId"])) for s in skus}

    details = []
    unlicensed = []

    for u in users:
        if not u.get("accountEnabled", True):
            continue
        licenses = u.get("assignedLicenses", [])
        sku_names = [sku_map.get(lic["skuId"], lic["skuId"]) for lic in licenses]
        entry = {
            "user": u.get("userPrincipalName"),
            "display_name": u.get("displayName"),
            "license_count": len(licenses),
            "licenses": sku_names,
        }
        details.append(entry)
        if not licenses:
            unlicensed.append(entry)

    issues = [f"{u['display_name']} ({u['user']}) has no licenses assigned" for u in unlicensed]

    return {
        "check_name": "user_licenses", "display_name": "Per-User Licenses",
        "category": "licensing", "status": "warn" if unlicensed else "pass",
        "points_earned": None, "points_possible": None,
        "summary": f"{len(unlicensed)} active users have no licenses assigned",
        "issues": issues, "details": details, "cis_reference": None,
    }


def run_all(client: GraphClient):
    return [
        check_license_summary(client),
        check_user_licenses(client),
    ]
