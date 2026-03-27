import csv
import io
import requests

GRAPH_BASE = "https://graph.microsoft.com/v1.0"
GRAPH_BETA = "https://graph.microsoft.com/beta"


class GraphClient:
    def __init__(self, headers):
        self.headers = headers

    def _url(self, endpoint, beta=False):
        base = GRAPH_BETA if beta else GRAPH_BASE
        if endpoint.startswith("http"):
            return endpoint
        return f"{base}{endpoint}"

    def get_all(self, endpoint, params=None, beta=False):
        """Fetch all pages of a paginated collection. Returns list or error dict."""
        url = self._url(endpoint, beta)
        results = []
        while url:
            resp = requests.get(url, headers=self.headers, params=params)
            if resp.status_code == 403:
                return {"error": f"Insufficient permissions ({endpoint})"}
            if resp.status_code == 404:
                return {"error": f"Resource not found ({endpoint})"}
            if not resp.ok:
                return {"error": f"HTTP {resp.status_code} for {endpoint}"}
            data = resp.json()
            results.extend(data.get("value", []))
            url = data.get("@odata.nextLink")
            params = None  # only apply params on first request
        return results

    def get_one(self, endpoint, params=None, beta=False):
        """Fetch a single JSON object. Returns dict or None."""
        url = self._url(endpoint, beta)
        resp = requests.get(url, headers=self.headers, params=params)
        if resp.status_code == 403:
            return {"error": f"Insufficient permissions ({endpoint})"}
        if resp.status_code == 404:
            return None
        if not resp.ok:
            return {"error": f"HTTP {resp.status_code}"}
        return resp.json()

    def get_count(self, endpoint):
        """Fetch a $count value. Requires ConsistencyLevel: eventual."""
        url = self._url(endpoint)
        headers = {**self.headers, "ConsistencyLevel": "eventual"}
        resp = requests.get(url, headers=headers)
        if not resp.ok:
            return 0
        try:
            return int(resp.text)
        except (ValueError, TypeError):
            return 0

    def get_report_csv(self, endpoint):
        """Fetch a Graph usage report (CSV). Returns list of row dicts or error dict."""
        url = self._url(endpoint)
        resp = requests.get(url, headers=self.headers, allow_redirects=True)
        if resp.status_code == 403:
            return {"error": "Reports.Read.All permission required"}
        if not resp.ok:
            return {"error": f"HTTP {resp.status_code}"}
        try:
            content = resp.content.decode("utf-8-sig")
            reader = csv.DictReader(io.StringIO(content))
            return list(reader)
        except Exception as e:
            return {"error": f"Failed to parse report CSV: {e}"}
