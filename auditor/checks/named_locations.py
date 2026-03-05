import requests

GRAPH_BASE = "https://graph.microsoft.com/v1.0"

def check_named_locations(headers):
    resp = requests.get(
        f"{GRAPH_BASE}/identity/conditionalAccess/namedLocations",
        headers=headers
    )
    if resp.status_code == 403:
        return {"error": "Requires Policy.Read.All permission", "locations": []}
    resp.raise_for_status()

    locations = resp.json().get("value", [])
    results = []
    for loc in locations:
        loc_type = loc.get("@odata.type", "").split(".")[-1]
        results.append({
            "name": loc.get("displayName"),
            "type": loc_type,           # ipNamedLocation or countryNamedLocation
            "is_trusted": loc.get("isTrusted", False),
            "id": loc.get("id"),
        })

    return {
        "configured": len(results) > 0,
        "total": len(results),
        "locations": results,
    }
