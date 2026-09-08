"""
Conditional Access checks:
  - CA Policies          (15 pts)
  - Legacy Auth Blocked  (10 pts)
  - Named Locations      (4 pts)
"""
from app.checks.base import check
from app.services.graph_client import GraphClient
from app.services.scoring import CIS_MAP

# The portal's "Legacy authentication clients" toggle maps to exchangeActiveSync
# and other. easSupported and easUnsupported are older spellings that still turn
# up on policies created years ago — easUnsupported is deprecated in favour of
# exchangeActiveSync but Graph still returns it.
LEGACY_CLIENT_TYPES = {"exchangeActiveSync", "other", "easSupported", "easUnsupported"}

# "all" means every client app type, legacy included. A policy set to "all" with
# a block control does block legacy auth, and matching only the explicit legacy
# values reported such a tenant as unprotected when it wasn't.
ALL_CLIENT_TYPES = "all"


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
    caveats = []

    for p in policies:
        if p.get("state") != "enabled":
            continue

        conditions = p.get("conditions") or {}
        client_types = set(conditions.get("clientAppTypes") or [])
        controls = (p.get("grantControls") or {}).get("builtInControls") or []

        covers_legacy = bool(client_types & LEGACY_CLIENT_TYPES) or ALL_CLIENT_TYPES in client_types
        if not (covers_legacy and "block" in controls):
            continue

        name = p.get("displayName") or "(unnamed policy)"
        blocking.append(name)

        # A block with carve-outs is not a block for everyone. Report it rather
        # than awarding full marks silently — the excluded accounts are exactly
        # the ones an attacker would look for.
        users = conditions.get("users") or {}
        excluded = (len(users.get("excludeUsers") or [])
                    + len(users.get("excludeGroups") or [])
                    + len(users.get("excludeRoles") or []))
        if excluded:
            caveats.append(f"{name} excludes {excluded} user/group/role(s) from the block")

        included = users.get("includeUsers") or []
        if included and "All" not in included:
            caveats.append(f"{name} applies to {len(included)} specific principal(s), not all users")

    blocked = len(blocking) > 0
    status = "pass" if blocked and not caveats else ("warn" if blocked else "fail")
    earned = 10 if blocked and not caveats else (7 if blocked else 0)

    if blocked:
        summary = (f"Legacy auth blocked by {len(blocking)} "
                   f"{'policy' if len(blocking) == 1 else 'policies'}")
        if caveats:
            summary += " — with exclusions"
    else:
        summary = "Legacy auth is not blocked — no policy blocks legacy clients"

    return {
        "check_name": "legacy_auth_blocked", "display_name": "Legacy Auth Blocked",
        "category": "conditional_access", "status": status,
        "points_earned": earned, "points_possible": 10,
        "summary": summary,
        "issues": caveats if blocked else ["No Conditional Access policy blocks legacy authentication"],
        "details": {"legacy_auth_blocked": blocked, "blocking_policies": blocking,
                    "caveats": caveats},
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
