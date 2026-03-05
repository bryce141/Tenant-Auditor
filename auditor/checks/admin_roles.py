import requests
from collections import defaultdict

GRAPH_BASE = "https://graph.microsoft.com/v1.0"

HIGHLY_PRIVILEGED_ROLES = {
    "62e90394-69f5-4237-9190-012177145e10": "Global Administrator",
    "e8611ab8-c189-46e8-94e1-60213ab1f814": "Privileged Role Administrator",
    "194ae4cb-b126-40b2-bd5b-6091b380977d": "Security Administrator",
    "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3": "Application Administrator",
    "158c047a-c907-4556-b7ef-446551a6b5f7": "Cloud Application Administrator",
    "b0f54661-2d74-4c50-afa3-1ec803f12efe": "Billing Administrator",
    "29232cdf-9323-42fd-ade2-1d097af3e4de": "Exchange Administrator",
    "f28a1f50-f6e7-4571-818b-6a12f2af6b6c": "SharePoint Administrator",
    "fe930be7-5e62-47db-91af-98c3a49a38b1": "User Administrator",
}

def check_admin_roles(headers):
    resp = requests.get(f"{GRAPH_BASE}/directoryRoles", headers=headers)
    if resp.status_code == 403:
        return {"error": "Requires RoleManagement.Read.All permission", "roles": [], "role_stacking": [], "guests_with_roles": []}
    resp.raise_for_status()

    roles = resp.json().get("value", [])
    results = []

    # Track roles per user for stacking detection
    user_roles = defaultdict(lambda: {"name": "", "upn": "", "user_type": "", "roles": []})

    for role in roles:
        role_id = role.get("roleTemplateId")
        role_name = role.get("displayName")

        members_resp = requests.get(
            f"{GRAPH_BASE}/directoryRoles/{role['id']}/members",
            headers=headers
        )
        if members_resp.status_code != 200:
            continue

        members = members_resp.json().get("value", [])
        if not members:
            continue

        is_privileged = role_id in HIGHLY_PRIVILEGED_ROLES

        results.append({
            "role": role_name,
            "role_template_id": role_id,
            "is_privileged": is_privileged,
            "member_count": len(members),
            "members": [
                {
                    "name": m.get("displayName"),
                    "upn": m.get("userPrincipalName"),
                    "user_type": m.get("userType", "Member"),
                }
                for m in members
            ]
        })

        for m in members:
            uid = m.get("id", m.get("userPrincipalName", ""))
            user_roles[uid]["name"] = m.get("displayName", "")
            user_roles[uid]["upn"] = m.get("userPrincipalName", "")
            user_roles[uid]["user_type"] = m.get("userType", "Member")
            user_roles[uid]["roles"].append(role_name)

    # Multi-role stacking: users with 2+ privileged roles
    role_stacking = [
        {"name": v["name"], "upn": v["upn"], "roles": v["roles"]}
        for v in user_roles.values()
        if len(v["roles"]) >= 2
    ]

    # Guests with any role assignment
    guests_with_roles = [
        {"name": v["name"], "upn": v["upn"], "roles": v["roles"]}
        for v in user_roles.values()
        if v.get("user_type") == "Guest"
    ]

    return {
        "roles": results,
        "role_stacking": role_stacking,
        "guests_with_roles": guests_with_roles,
    }
