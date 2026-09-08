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

    @staticmethod
    def _graph_message(resp):
        """The human-readable reason Graph gave, if it gave one.

        Worth surfacing verbatim: a 400 from Graph is often a licensing answer
        ("Tenant does not have a SPO license", "requires Microsoft Entra ID P2")
        rather than a malformed request, and reporting it as "HTTP 400" sends
        you looking for a bug that isn't there.
        """
        try:
            err = resp.json().get("error", {})
            message = (err.get("message") or "").strip()
            if message:
                return message.split("\n")[0][:180]
        except Exception:
            pass
        return None

    def _raise_for(self, resp, endpoint):
        """Translate an unsuccessful response into GraphError."""
        detail = self._graph_message(resp)

        if resp.status_code == 403:
            reason = detail or "Insufficient permissions"
            raise GraphError(f"{reason} ({endpoint})", status=403, endpoint=endpoint)
        if resp.status_code == 404:
            raise GraphError(f"Resource not found ({endpoint})",
                             status=404, endpoint=endpoint)
        if resp.status_code == 429:
            raise GraphError(f"Throttled by Graph ({endpoint})",
                             status=429, endpoint=endpoint)

        reason = detail or f"HTTP {resp.status_code}"
        raise GraphError(f"{reason} ({endpoint})",
                         status=resp.status_code, endpoint=endpoint)

    def get_all(self, endpoint, params=None, beta=False):
        """Fetch every page of a paginated collection. Raises GraphError."""
        url = self._url(endpoint, beta)
        results = []
        while url:
            resp = requests.get(url, headers=self.headers, params=params)
            if not resp.ok:
                self._raise_for(resp, endpoint)
            data = resp.json()
            results.extend(data.get("value", []))
            url = data.get("@odata.nextLink")
            params = None  # only apply params on the first request
        return results

    def get_one(self, endpoint, params=None, beta=False):
        """Fetch a single JSON object.

        A 404 returns None rather than raising: for singleton settings
        resources, absent is a legitimate answer the caller interprets.
        """
        url = self._url(endpoint, beta)
        resp = requests.get(url, headers=self.headers, params=params)
        if resp.status_code == 404:
            return None
        if not resp.ok:
            self._raise_for(resp, endpoint)
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
        """Fetch a Graph usage report as a list of row dicts. Raises GraphError.

        These endpoints answer 302 to a short-lived pre-authenticated download
        URL on another host; requests drops the Authorization header across that
        redirect, which is both expected and required — the download URL rejects
        it. A 404 here usually means the workload isn't provisioned in the
        tenant rather than a bad path.
        """
        url = self._url(endpoint)
        resp = requests.get(url, headers=self.headers, allow_redirects=True)
        if resp.status_code == 403:
            raise GraphError(f"Reports.Read.All permission required ({endpoint})",
                             status=403, endpoint=endpoint)
        if resp.status_code == 404:
            raise GraphError(
                f"Report unavailable — workload may not be provisioned ({endpoint})",
                status=404, endpoint=endpoint)
        if not resp.ok:
            self._raise_for(resp, endpoint)
        try:
            content = resp.content.decode("utf-8-sig")
            return list(csv.DictReader(io.StringIO(content)))
        except Exception as e:
            raise GraphError(f"Failed to parse report CSV: {e}", endpoint=endpoint)
