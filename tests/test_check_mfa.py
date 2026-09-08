"""Tests for the MFA registration check.

check_mfa reads from the bulk registration report when it can and falls back
to per-user enumeration when it can't, so both paths need covering — along
with the tenant shapes that used to divide by zero.
"""
import pytest

from app.checks.identity import check_mfa

REPORT = "/reports/authenticationMethods/userRegistrationDetails"


class FakeClient:
    """Stands in for GraphClient. Maps endpoint prefixes to canned responses.

    Records every call so tests can assert on request count — the whole point
    of preferring the bulk report is that it costs one call, not one per user.
    """

    def __init__(self, responses):
        self.responses = responses
        self.calls = []

    def get_all(self, endpoint, params=None, beta=False):
        self.calls.append(endpoint)
        for prefix, value in self.responses.items():
            if endpoint.startswith(prefix):
                return value
        raise AssertionError(f"unexpected endpoint: {endpoint}")


def test_uses_bulk_report_and_costs_one_call():
    client = FakeClient({REPORT: [
        {"userPrincipalName": "a@x.com", "userDisplayName": "A", "isMfaRegistered": True,
         "methodsRegistered": ["microsoftAuthenticatorPush"]},
        {"userPrincipalName": "b@x.com", "userDisplayName": "B", "isMfaRegistered": False,
         "methodsRegistered": []},
    ]})

    result = check_mfa(client)

    assert len(client.calls) == 1, "bulk report should not fan out per user"
    assert result["status"] == "fail"          # 50% missing, over the 25% threshold
    assert result["points_earned"] == 10       # half of 20
    assert result["points_possible"] == 20
    assert "1/2 users have MFA registered" in result["summary"]
    assert result["issues"] == ["B (b@x.com) has no MFA registered"]


def test_all_registered_scores_full_marks():
    client = FakeClient({REPORT: [
        {"userPrincipalName": "a@x.com", "userDisplayName": "A", "isMfaRegistered": True,
         "methodsRegistered": ["push"]},
    ]})

    result = check_mfa(client)

    assert result["status"] == "pass"
    assert result["points_earned"] == 20
    assert result["issues"] == []


def test_warns_rather_than_fails_below_25_percent():
    rows = [{"userPrincipalName": f"u{i}@x.com", "userDisplayName": f"U{i}",
             "isMfaRegistered": i != 0, "methodsRegistered": []} for i in range(10)]
    client = FakeClient({REPORT: rows})

    result = check_mfa(client)

    assert result["status"] == "warn"          # 1 of 10 == 10%, under the threshold
    assert result["points_earned"] == 18


def test_falls_back_to_per_user_when_report_unavailable():
    client = FakeClient({
        REPORT: {"error": "Insufficient permissions"},
        "/users?": [
            {"id": "1", "displayName": "A", "userPrincipalName": "a@x.com"},
            {"id": "2", "displayName": "B", "userPrincipalName": "b@x.com"},
        ],
        "/users/1/authentication/methods": [
            {"@odata.type": "#microsoft.graph.passwordAuthenticationMethod"},
            {"@odata.type": "#microsoft.graph.phoneAuthenticationMethod"},
        ],
        "/users/2/authentication/methods": [
            {"@odata.type": "#microsoft.graph.passwordAuthenticationMethod"},
        ],
    })

    result = check_mfa(client)

    assert REPORT in client.calls[0], "should try the bulk report first"
    assert len(client.calls) == 4, "fallback costs one call per user"
    assert "1/2 users have MFA registered" in result["summary"]
    # A password method alone must not count as MFA.
    assert result["issues"] == ["B (b@x.com) has no MFA registered"]


def test_skips_when_user_listing_also_fails():
    client = FakeClient({
        REPORT: {"error": "Insufficient permissions"},
        "/users?": {"error": "Insufficient permissions (/users)"},
    })

    result = check_mfa(client)

    assert result["status"] == "skip"
    assert result["points_earned"] is None
    assert result["points_possible"] == 20, "possible points stay set so the UI can show the weight"


def test_empty_tenant_skips_instead_of_dividing_by_zero():
    client = FakeClient({REPORT: []})

    result = check_mfa(client)

    assert result["status"] == "skip"
    assert result["points_earned"] is None


def test_unreadable_users_excluded_from_ratio_not_counted_as_failures():
    """A user whose methods can't be read is unknown, not non-compliant."""
    client = FakeClient({
        REPORT: {"error": "nope"},
        "/users?": [
            {"id": "1", "displayName": "A", "userPrincipalName": "a@x.com"},
            {"id": "2", "displayName": "B", "userPrincipalName": "b@x.com"},
        ],
        "/users/1/authentication/methods": [
            {"@odata.type": "#microsoft.graph.phoneAuthenticationMethod"},
        ],
        "/users/2/authentication/methods": {"error": "403"},
    })

    result = check_mfa(client)

    assert "1/1 users have MFA registered" in result["summary"]
    assert result["points_earned"] == 20
    assert len(result["details"]) == 2, "both users still reported in details"


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))
