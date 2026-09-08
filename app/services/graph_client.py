import csv
import io
import requests

GRAPH_BASE = "https://graph.microsoft.com/v1.0"
GRAPH_BETA = "https://graph.microsoft.com/beta"


class GraphError(Exception):
    """A Graph call that could not be completed.

    Checks catch this to report a 'skip' rather than a failure: a missing
    permission or an unprovisioned workload means the control wasn't measured,
    which is different from measuring it and finding it wanting.
    """

    def __init__(self, message, status=None, endpoint=None):
        super().__init__(message)
        self.message = message
        self.status = status
        self.endpoint = endpoint

    def __str__(self):
        return self.message


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

    def batch_get(self, endpoints, beta=False):
        """GET many endpoints via Graph JSON batching.

        Some resources — mailboxSettings above all — have no bulk equivalent, so
        the alternative is one request per user. Batching caps that at 20 per
        round trip, turning 5,000 requests into 250.

        Returns {endpoint: body_or_None}. A per-request failure yields None for
        that endpoint rather than failing the batch, since a user without a
        mailbox legitimately 404s. Raises on total batch failure.
        """
        results = {}
        endpoints = list(endpoints)

        for i in range(0, len(endpoints), 20):  # Graph caps a batch at 20
            chunk = endpoints[i:i + 20]
            # Batch URLs are relative to the version root, without the prefix.
            payload = {"requests": [{"id": str(n), "method": "GET", "url": ep}
                                    for n, ep in enumerate(chunk)]}
            base = GRAPH_BETA if beta else GRAPH_BASE
            resp = requests.post(f"{base}/$batch", headers={**self.headers,
                                                            "Content-Type": "application/json"},
                                 json=payload, timeout=60)
            if not resp.ok:
                raise GraphError(f"Batch request failed: HTTP {resp.status_code}",
                                 status=resp.status_code, endpoint="/$batch")

            # Responses can come back out of order, so map them by id.
            by_id = {r.get("id"): r for r in resp.json().get("responses", [])}
            for n, ep in enumerate(chunk):
                item = by_id.get(str(n))
                if item and item.get("status", 500) < 300:
                    results[ep] = item.get("body")
                else:
                    results[ep] = None

        return results

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
