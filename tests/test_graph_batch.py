"""Tests for Graph JSON batching and the batched forwarding check."""
import json

import pytest

from app.checks.mail_security import check_mailbox_forwarding
from app.services.graph_client import GraphClient, GraphError


class FakeResponse:
    def __init__(self, payload, status=200):
        self._payload = payload
        self.status_code = status
        self.ok = status < 400

    def json(self):
        return self._payload


@pytest.fixture
def posted(monkeypatch):
    """Capture outgoing batch requests and reply with a scripted response."""
    calls = []
    state = {"responder": None}

    def fake_post(url, headers=None, json=None, timeout=None):
        calls.append({"url": url, "body": json})
        return state["responder"](json)

    monkeypatch.setattr("app.services.graph_client.requests.post", fake_post)
    return calls, state


def echo_ok(payload):
    """Reply 200 to every sub-request, echoing which URL it was."""
    return FakeResponse({"responses": [
        {"id": r["id"], "status": 200, "body": {"url": r["url"]}}
        for r in payload["requests"]
    ]})


def test_batches_are_capped_at_twenty(posted):
    calls, state = posted
    state["responder"] = echo_ok

    client = GraphClient({"Authorization": "Bearer x"})
    endpoints = [f"/users/{i}/mailboxSettings" for i in range(45)]
    results = client.batch_get(endpoints)

    assert len(calls) == 3, "45 endpoints should batch into 20 + 20 + 5"
    assert [len(c["body"]["requests"]) for c in calls] == [20, 20, 5]
    assert len(results) == 45


def test_results_map_correctly_when_responses_arrive_out_of_order(posted):
    """Graph does not guarantee response order; mapping by index would corrupt data."""
    calls, state = posted

    def reversed_order(payload):
        return FakeResponse({"responses": list(reversed([
            {"id": r["id"], "status": 200, "body": {"url": r["url"]}}
            for r in payload["requests"]
        ]))})

    state["responder"] = reversed_order

    client = GraphClient({"Authorization": "Bearer x"})
    endpoints = [f"/users/{i}/mailboxSettings" for i in range(5)]
    results = client.batch_get(endpoints)

    for ep in endpoints:
        assert results[ep]["url"] == ep, f"{ep} got another endpoint's body"


def test_individual_failures_do_not_sink_the_batch(posted):
    calls, state = posted

    def mixed(payload):
        out = []
        for n, r in enumerate(payload["requests"]):
            if n == 1:
                out.append({"id": r["id"], "status": 404})
            else:
                out.append({"id": r["id"], "status": 200, "body": {"url": r["url"]}})
        return FakeResponse({"responses": out})

    state["responder"] = mixed

    client = GraphClient({"Authorization": "Bearer x"})
    endpoints = ["/users/a/mailboxSettings", "/users/b/mailboxSettings", "/users/c/mailboxSettings"]
    results = client.batch_get(endpoints)

    assert results["/users/a/mailboxSettings"] is not None
    assert results["/users/b/mailboxSettings"] is None, "a 404 user yields None, not an exception"
    assert results["/users/c/mailboxSettings"] is not None


def test_total_batch_failure_raises(posted):
    calls, state = posted
    state["responder"] = lambda payload: FakeResponse({}, status=403)

    client = GraphClient({"Authorization": "Bearer x"})
    with pytest.raises(GraphError) as exc:
        client.batch_get(["/users/a/mailboxSettings"])
    assert exc.value.status == 403


class ForwardingClient:
    """Minimal client for the forwarding check."""

    def __init__(self, users, settings):
        self.users = users
        self.settings = settings
        self.batch_calls = 0

    def get_all(self, endpoint, params=None, beta=False):
        return self.users

    def batch_get(self, endpoints, beta=False):
        self.batch_calls += 1
        return {ep: self.settings.get(ep) for ep in endpoints}


def test_forwarding_check_uses_one_batch_not_per_user():
    users = [{"id": str(i), "displayName": f"U{i}", "userPrincipalName": f"u{i}@x.com"}
             for i in range(10)]
    settings = {f"/users/{i}/mailboxSettings": {"forwardingSmtpAddress": None} for i in range(10)}
    settings["/users/3/mailboxSettings"] = {"forwardingSmtpAddress": "attacker@evil.com"}

    client = ForwardingClient(users, settings)
    result = check_mailbox_forwarding(client)

    assert client.batch_calls == 1, "should batch, not fan out per user"
    assert result["status"] == "fail"
    assert result["points_earned"] == 0
    assert result["issues"] == ["U3 forwarding to attacker@evil.com"]


def test_users_without_mailboxes_are_unavailable_not_clean():
    """A user with no mailbox is unknown; counting them clean would overstate the result."""
    users = [{"id": "1", "displayName": "A", "userPrincipalName": "a@x.com"},
             {"id": "2", "displayName": "B", "userPrincipalName": "b@x.com"}]
    settings = {"/users/1/mailboxSettings": {"forwardingSmtpAddress": None},
                "/users/2/mailboxSettings": None}

    result = check_mailbox_forwarding(ForwardingClient(users, settings))

    statuses = {d["user"]: d["status"] for d in result["details"]}
    assert statuses["a@x.com"] == "clean"
    assert statuses["b@x.com"] == "unavailable"
    assert result["status"] == "pass"


def test_forwarding_check_skips_when_batch_fails():
    class Failing(ForwardingClient):
        def batch_get(self, endpoints, beta=False):
            raise GraphError("Batch request failed: HTTP 403", status=403)

    users = [{"id": "1", "displayName": "A", "userPrincipalName": "a@x.com"}]
    result = check_mailbox_forwarding(Failing(users, {}))

    assert result["status"] == "skip"
    assert result["points_earned"] is None
    assert "403" in result["summary"]


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))
