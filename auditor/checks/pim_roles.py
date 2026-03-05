import requests

GRAPH_BASE = "https://graph.microsoft.com/v1.0"

PRIVILEGED_ROLE_TEMPLATES = {
    "62e90394-69f5-4237-9190-012177145e10": "Global Administrator",
    "e8611ab8-c189-46e8-94e1-60213ab1f814": "Privileged Role Administrator",
    "194ae4cb-b126-40b2-bd5b-6091b380977d": "Security Administrator",
    "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3": "Application Administrator",
    "158c047a-c907-4556-b7ef-446551a6b5f7": "Cloud Application Administrator",
    "29232cdf-9323-42fd-ade2-1d097af3e4de": "Exchange Administrator",
    "f28a1f50-f6e7-4571-818b-6a12f2af6b6c": "SharePoint Administrator",
    "fe930be7-5e62-47db-91af-98c3a49a38b1": "User Administrator",
}

def check_pim_roles(headers):
    # Get all permanent active role assignments
    assignments_resp = requests.get(
        f"{GRAPH_BASE}/roleManagement/directory/roleAssignments?$expand=principal",
        headers=headers
    )
    if assignments_resp.status_code == 403:
        return {"error": "Requires RoleManagement.Read.All permission", "assignments": []}
    assignments_resp.raise_for_status()
    assignments = assignments_resp.json().get("value", [])

    # Get eligible (PIM) schedules to see what's properly gated
    eligible_resp = requests.get(
        f"{GRAPH_BASE}/roleManagement/directory/roleEligibilitySchedules",
        headers=headers
    )
    pim_in_use = eligible_resp.status_code == 200 and len(eligible_resp.json().get("value", [])) > 0

    # Get role definitions to resolve names
    roles_resp = requests.get(f"{GRAPH_BASE}/roleManagement/directory/roleDefinitions", headers=headers)
    role_map = {}
    if roles_resp.status_code == 200:
        for r in roles_resp.json().get("value", []):
            role_map[r["id"]] = r.get("displayName", r["id"])

    standing = []
    for a in assignments:
        role_def_id = a.get("roleDefinitionId", "")
        role_name = role_map.get(role_def_id, role_def_id)
        principal = a.get("principal", {})
        principal_name = principal.get("displayName", "Unknown")
        principal_upn = principal.get("userPrincipalName") or principal.get("appId", "")
        principal_type = principal.get("@odata.type", "").split(".")[-1]

        # Only flag highly privileged roles
        template_id = a.get("roleDefinitionId")
        if template_id not in PRIVILEGED_ROLE_TEMPLATES and role_name not in PRIVILEGED_ROLE_TEMPLATES.values():
            continue

        standing.append({
            "role": role_name,
            "principal_name": principal_name,
            "principal_upn": principal_upn,
            "principal_type": principal_type,
            "is_permanent": True,  # all direct assignments in v1.0 are permanent
        })

    return {
        "pim_in_use": pim_in_use,
        "standing_assignments": standing,
        "total_standing": len(standing),
    }
