"""
SharePoint & OneDrive checks:
  - Site inventory & inactive sites (info/warn)
  - Site storage usage (info)
  - Tenant external sharing policy (security/info)
  - OneDrive usage per user (info)
  - Inactive OneDrive accounts (warn)
"""
from datetime import datetime, timezone, timedelta
from app.checks.base import check
from app.services.graph_client import GraphClient, GraphError

INACTIVE_DAYS = 90


@check("sharepoint_sites", "SharePoint Site Usage", "sharepoint", empty_details={})
def check_sharepoint_sites(client: GraphClient):
    rows = client.get_report_csv("/reports/getSharePointSiteUsageDetail(period='D30')")

    now = datetime.now(timezone.utc)
    cutoff = now - timedelta(days=INACTIVE_DAYS)

    sites = []
    inactive = []
    total_storage_bytes = 0

    for row in rows:
        url = row.get("Site URL", "")
        owner = row.get("Owner Display Name", "")
        storage_str = row.get("Storage Used (Byte)", "0") or "0"
        last_activity = row.get("Last Activity Date", "")
        file_count = row.get("File Count", "0") or "0"

        try:
            storage_bytes = int(storage_str)
        except ValueError:
            storage_bytes = 0
        total_storage_bytes += storage_bytes

        is_inactive = False
        if last_activity:
            try:
                last_dt = datetime.strptime(last_activity, "%Y-%m-%d").replace(tzinfo=timezone.utc)
                is_inactive = last_dt < cutoff
            except ValueError:
                pass
        else:
            is_inactive = True

        entry = {
            "url": url,
            "owner": owner,
            "storage_bytes": storage_bytes,
            "storage_mb": round(storage_bytes / 1024 / 1024, 1),
            "file_count": int(file_count) if file_count.isdigit() else 0,
            "last_activity": last_activity,
            "is_inactive": is_inactive,
        }
        sites.append(entry)
        if is_inactive:
            inactive.append(entry)

    total_storage_gb = round(total_storage_bytes / 1024 / 1024 / 1024, 2)
    issues = [f"{s['url']} — no activity since {s['last_activity'] or 'unknown'}" for s in inactive[:20]]

    return {
        "check_name": "sharepoint_sites", "display_name": "SharePoint Site Usage",
        "category": "sharepoint", "status": "warn" if inactive else "info",
        "points_earned": None, "points_possible": None,
        "summary": f"{len(sites)} sites, {len(inactive)} inactive 90+ days, {total_storage_gb} GB total storage",
        "issues": issues,
        "details": {"sites": sites, "inactive": inactive, "total_storage_gb": total_storage_gb, "total_sites": len(sites)},
        "cis_reference": None,
    }


@check("external_sharing", "External Sharing Policy", "sharepoint", empty_details={})
def check_external_sharing(client: GraphClient):
    # A tenant with no SharePoint answers 400 "Tenant does not have a SPO
    # license", which get_one surfaces as a GraphError carrying that text. Only
    # an empty-but-successful response reaches the raise below.
    settings = client.get_one("/admin/sharepoint/settings", beta=True)
    if not settings:
        raise GraphError("SharePoint tenant settings returned no data",
                         endpoint="/admin/sharepoint/settings")

    sharing_capability = settings.get("sharingCapability", "unknown")
    # Values: disabled, existingExternalUserSharingOnly, externalUserSharingOnly, externalUserAndGuestSharing
    risky = sharing_capability in ("externalUserSharingOnly", "externalUserAndGuestSharing")
    anonymous = sharing_capability == "externalUserAndGuestSharing"

    issues = []
    if anonymous:
        issues.append(f"Tenant allows anonymous (Anyone) sharing links — sharing capability: {sharing_capability}")
    elif risky:
        issues.append(f"External sharing is enabled — sharing capability: {sharing_capability}")

    return {
        "check_name": "external_sharing", "display_name": "External Sharing Policy",
        "category": "sharepoint", "status": "fail" if anonymous else ("warn" if risky else "pass"),
        "points_earned": None, "points_possible": None,
        "summary": f"Tenant sharing capability: {sharing_capability}",
        "issues": issues,
        "details": {"sharing_capability": sharing_capability, "settings": settings},
        "cis_reference": None,
    }


@check("onedrive_usage", "OneDrive Usage", "sharepoint", empty_details={})
def check_onedrive_usage(client: GraphClient):
    rows = client.get_report_csv("/reports/getOneDriveUsageAccountDetail(period='D30')")

    now = datetime.now(timezone.utc)
    cutoff = now - timedelta(days=INACTIVE_DAYS)

    accounts = []
    inactive = []

    for row in rows:
        upn = row.get("Owner Principal Name", "") or row.get("Site URL", "")
        storage_str = row.get("Storage Used (Byte)", "0") or "0"
        last_activity = row.get("Last Activity Date", "")

        try:
            storage_bytes = int(storage_str)
        except ValueError:
            storage_bytes = 0

        is_inactive = False
        if last_activity:
            try:
                last_dt = datetime.strptime(last_activity, "%Y-%m-%d").replace(tzinfo=timezone.utc)
                is_inactive = last_dt < cutoff
            except ValueError:
                pass
        else:
            is_inactive = True

        entry = {
            "user": upn,
            "storage_bytes": storage_bytes,
            "storage_mb": round(storage_bytes / 1024 / 1024, 1),
            "file_count": int(row.get("File Count", "0") or "0"),
            "last_activity": last_activity,
            "is_inactive": is_inactive,
        }
        accounts.append(entry)
        if is_inactive:
            inactive.append(entry)

    issues = [f"{a['user']} — OneDrive inactive since {a['last_activity'] or 'unknown'}" for a in inactive[:20]]

    return {
        "check_name": "onedrive_usage", "display_name": "OneDrive Usage",
        "category": "sharepoint", "status": "warn" if inactive else "info",
        "points_earned": None, "points_possible": None,
        "summary": f"{len(accounts)} OneDrive accounts, {len(inactive)} inactive 90+ days",
        "issues": issues,
        "details": {"accounts": accounts, "inactive": inactive, "total_accounts": len(accounts)},
        "cis_reference": None,
    }


def run_all(client: GraphClient):
    return [
        check_sharepoint_sites(client),
        check_external_sharing(client),
        check_onedrive_usage(client),
    ]
