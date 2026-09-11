"""Compose a Graph conditionalAccessPolicy from builder form input.

The builder and the engine have to stay in lockstep. A form that can express a
condition the engine cannot evaluate produces drafts whose impact report is
mostly UNSUPPORTED, which teaches people the tool doesn't work; a form that
cannot express a condition the engine handles wastes coverage that was paid
for. So the vocabulary lives here, in one place, and `tests/test_ca_builder.py`
asserts that every condition this module can emit is one the engine implements.

The output is a Graph-shaped policy document. It is never written to a tenant —
`export()` hands it back for manual deployment or an existing PowerShell
workflow, which is the whole point of the tool being read-only.
"""
from app.services.ca_engine import (
    ALL_LOCATIONS,
    ALL_TRUSTED,
    CLIENT_APP_TYPES_SUPPORTED,
    DEVICE_PLATFORMS_SUPPORTED,
    ENABLED,
    REPORT_ONLY,
    RISK_LEVELS_SUPPORTED,
)

# Every value the form may offer, derived from the engine's own vocabulary
# rather than restated here — a second copy would drift, and the drift would
# show up as drafts whose impact report is entirely UNSUPPORTED.
CLIENT_APP_CHOICES = list(CLIENT_APP_TYPES_SUPPORTED)
PLATFORM_CHOICES = list(DEVICE_PLATFORMS_SUPPORTED)
RISK_CHOICES = list(RISK_LEVELS_SUPPORTED)
GRANT_CHOICES = ["block", "mfa", "compliantDevice", "domainJoinedDevice",
                 "approvedApplication", "compliantApplication"]
APP_GROUP_CHOICES = ["Office365", "MicrosoftAdminPortals"]
LOCATION_TOKENS = [ALL_LOCATIONS, ALL_TRUSTED]
STATE_CHOICES = [ENABLED, REPORT_ONLY, "disabled"]


class BuilderError(ValueError):
    """The form described a policy that could not be built."""


def _clean(values):
    """Strip empties out of a multi-select without reordering what is left."""
    return [v for v in (values or []) if v not in (None, "", "none")]


def build_policy(form):
    """A Graph conditionalAccessPolicy from a dict of form values.

    `form` maps directly to the builder fields; `getlist`-style values arrive
    as lists. Raises BuilderError rather than emitting a policy Entra would
    reject, so the failure is explained here instead of surfacing later as an
    opaque 400 from Graph.
    """
    def many(key):
        value = form.get(key)
        if value is None:
            return []
        return _clean(value if isinstance(value, list) else [value])

    name = (form.get("displayName") or "").strip() or "Untitled draft policy"
    state = form.get("state") or REPORT_ONLY
    if state not in STATE_CHOICES:
        raise BuilderError(f"Unknown policy state {state!r}")

    include_users = many("includeUsers")
    include_groups = many("includeGroups")
    include_roles = many("includeRoles")
    include_guests = form.get("includeGuests") in ("on", "true", True)

    users = {}
    if include_guests:
        include_users = include_users + ["GuestsOrExternalUsers"]
    if form.get("allUsers") in ("on", "true", True):
        users["includeUsers"] = ["All"]
    elif include_users or include_groups or include_roles:
        # "None" is how the portal writes an empty user list on a policy that
        # targets groups or roles. It does not mean "nobody".
        users["includeUsers"] = include_users or ["None"]
        if include_groups:
            users["includeGroups"] = include_groups
        if include_roles:
            users["includeRoles"] = include_roles
    else:
        raise BuilderError(
            "Select who the policy applies to — all users, specific users, "
            "groups, roles, or guests.")

    for key, field in (("excludeUsers", "excludeUsers"),
                       ("excludeGroups", "excludeGroups"),
                       ("excludeRoles", "excludeRoles")):
        excluded = many(key)
        if excluded:
            users[field] = excluded

    include_apps = many("includeApplications")
    app_groups = [g for g in many("appGroups") if g in APP_GROUP_CHOICES]
    applications = {}
    if form.get("allApplications") in ("on", "true", True):
        applications["includeApplications"] = ["All"]
    elif include_apps or app_groups:
        applications["includeApplications"] = include_apps + app_groups
    else:
        raise BuilderError(
            "Select which resources the policy applies to — all, specific "
            "cloud apps, or an app group.")

    exclude_apps = many("excludeApplications") + [
        g for g in many("excludeAppGroups") if g in APP_GROUP_CHOICES]
    if exclude_apps:
        applications["excludeApplications"] = exclude_apps

    client_apps = [c for c in many("clientAppTypes") if c in CLIENT_APP_CHOICES]
    conditions = {
        "users": users,
        "applications": applications,
        # "all" is the Entra default and means every client type, legacy
        # included — not "none selected".
        "clientAppTypes": client_apps or ["all"],
        "signInRiskLevels": [r for r in many("signInRiskLevels") if r in RISK_CHOICES],
        "userRiskLevels": [r for r in many("userRiskLevels") if r in RISK_CHOICES],
    }

    include_platforms = [p for p in many("includePlatforms") if p in PLATFORM_CHOICES]
    exclude_platforms = [p for p in many("excludePlatforms") if p in PLATFORM_CHOICES]
    if form.get("allPlatforms") in ("on", "true", True):
        conditions["platforms"] = {"includePlatforms": ["all"],
                                   "excludePlatforms": exclude_platforms}
    elif include_platforms or exclude_platforms:
        conditions["platforms"] = {"includePlatforms": include_platforms or ["all"],
                                   "excludePlatforms": exclude_platforms}

    include_locations = many("includeLocations")
    exclude_locations = many("excludeLocations")
    if include_locations or exclude_locations:
        conditions["locations"] = {
            "includeLocations": include_locations or [ALL_LOCATIONS],
            "excludeLocations": exclude_locations,
        }

    controls = [c for c in many("grantControls") if c in GRANT_CHOICES]
    if not controls:
        raise BuilderError("Select at least one access control to grant or block.")
    if "block" in controls and len(controls) > 1:
        # Entra treats block as absolute; pairing it with a grant is a policy
        # that reads as doing two contradictory things.
        raise BuilderError("Block cannot be combined with other controls.")

    operator = form.get("grantOperator") or "OR"
    if operator not in ("AND", "OR"):
        raise BuilderError(f"Unknown grant operator {operator!r}")

    return {
        "displayName": name,
        "state": state,
        "conditions": conditions,
        "grantControls": {"operator": operator, "builtInControls": controls},
    }


def export(policy):
    """The policy as Graph-ready JSON, for manual deployment.

    Read-only is the product's central promise, so the draft leaves here as a
    document the admin applies themselves — never as a write.
    """
    import json

    return json.dumps(policy, indent=2)


def describe_gaps():
    """Conditions the engine cannot evaluate, for the builder to say so plainly.

    Shown in the UI rather than hidden, so nobody composes a policy around a
    condition and then wonders why the impact report is empty.
    """
    return [
        ("Device filters", "Rules over device properties are not evaluated."),
        ("Authentication context", "Not reported on a sign-in record."),
        ("User actions", "Register security info / join device are not sign-ins."),
        ("Workload identities", "The corpus covers interactive user sign-ins only."),
        ("Insider risk", "Not reported on a sign-in record."),
        ("Authentication flows", "Device code and transfer flows are not evaluated."),
    ]
