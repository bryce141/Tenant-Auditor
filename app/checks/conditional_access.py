"""
Conditional Access checks:
  - CA Policies          (15 pts)
  - Legacy Auth Blocked  (10 pts)
  - Named Locations      (4 pts)
"""
from app.checks.base import check
from app.services.graph_client import GraphClient
from app.services.scoring import CIS_MAP

LEGACY_CLIENT_TYPES = {"exchangeActiveSync", "other"}


@check("conditional_access", "Conditional Access Policies", "conditional_access",
       points_possible=15, cis_reference=CIS_MAP["conditional_access"]["id"],
       empty_details={})
def check_conditional_access(client: GraphClient):
    policies = client.get_all("/identity/conditionalAccess/policies")

    results = [{"name": p.get("displayName"), "state": p.get("state"), "id": p.get("id")} for p in policies]
    enabled = sum(1 for p in results if p["state"] == "enabled")
    disabled = sum(1 for p in results if p["state"] == "disabled")
    report_only = sum(1 for p in results if p["state"] == "enabledForReportingButNotEnforced")

    if enabled > 0:
        earned, status, issues = 15, "pass", []
    elif len(policies) == 0:
        earned, status, issues = 0, "fail", ["No Conditional Access policies configured"]
    else:
        earned, status, issues = 5, "warn", ["No CA policies are currently enabled"]

    return {
        "check_name": "conditional_access", "display_name": "Conditional Access Policies",
        "category": "conditional_access", "status": status,
        "points_earned": earned, "points_possible": 15,
        "summary": f"{len(policies)} total — {enabled} enabled, {disabled} disabled, {report_only} report-only",
        "issues": issues,
        "details": {"total": len(policies), "enabled": enabled, "disabled": disabled,
                    "report_only": report_only, "policies": results},
        "cis_reference": CIS_MAP["conditional_access"]["id"],
    }


@check("legacy_auth_blocked", "Legacy Auth Blocked", "conditional_access",
       points_possible=10, cis_reference=CIS_MAP["legacy_auth_blocked"]["id"],
       empty_details={})
def check_legacy_auth(client: GraphClient):
    policies = client.get_all("/identity/conditionalAccess/policies")

    blocking = []
    for p in policies:
        if p.get("state") != "enabled":
            continue
        client_types = set(p.get("conditions", {}).get("clientAppTypes", []))
        controls = (p.get("grantControls") or {}).get("builtInControls", [])
        if client_types & LEGACY_CLIENT_TYPES and "block" in controls:
            blocking.append(p.get("displayName"))

    blocked = len(blocking) > 0
    return {
        "check_name": "legacy_auth_blocked", "display_name": "Legacy Auth Blocked",
        "category": "conditional_access", "status": "pass" if blocked else "fail",
        "points_earned": 10 if blocked else 0, "points_possible": 10,
        "summary": (f"Legacy auth blocked by {len(blocking)} "
                    f"{'policy' if len(blocking) == 1 else 'policies'}"
                    if blocked else
                    "Legacy auth is not blocked — no policy blocks legacy clients"),
        "issues": [] if blocked else ["No Conditional Access policy blocks legacy authentication"],
        "details": {"legacy_auth_blocked": blocked, "blocking_policies": blocking},
        "cis_reference": CIS_MAP["legacy_auth_blocked"]["id"],
    }


@check("named_locations", "Named Locations", "conditional_access",
       points_possible=4, cis_reference=CIS_MAP["named_locations"]["id"],
       empty_details={})
def check_named_locations(client: GraphClient):
    locations = client.get_all("/identity/conditionalAccess/namedLocations")

    details = [{"name": loc.get("displayName"),
                "type": loc.get("@odata.type", "").split(".")[-1],
                "is_trusted": loc.get("isTrusted", False)} for loc in locations]
    configured = len(details) > 0
    return {
        "check_name": "named_locations", "display_name": "Named Locations",
        "category": "conditional_access", "status": "pass" if configured else "warn",
        "points_earned": 4 if configured else 0, "points_possible": 4,
        "summary": f"{len(details)} named location(s) configured",
        "issues": [] if configured else ["No named locations defined — CA policies cannot target trusted networks"],
        "details": {"configured": configured, "locations": details},
        "cis_reference": CIS_MAP["named_locations"]["id"],
    }


def run_all(client: GraphClient):
    return [
        check_conditional_access(client),
        check_legacy_auth(client),
        check_named_locations(client),
    ]
